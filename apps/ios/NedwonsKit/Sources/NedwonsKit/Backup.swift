import CommonCrypto
import CryptoKit
import Foundation

/// Encrypted chat backups (docs/BACKUPS.md): the crypto and the container format, pure and
/// unit-tested. What goes in a backup and what a restore may touch is `NedwonsAppKit`'s
/// `BackupManager`; THIS file only guarantees that the archive is opaque without the passphrase
/// and fails closed on tamper or a wrong passphrase.
///
/// Format v1, one file:
///
///     magic "NEDWONSBK" || version(1) || salt(16) || iterations(u32 BE) || nonce(12) || GCM ct
///
/// - KEK = PBKDF2-HMAC-SHA256(passphrase, salt, iterations). PBKDF2 because it ships in the OS
///   (CommonCrypto) with zero new dependencies; 600k iterations follows current OWASP guidance.
///   Argon2id would resist GPU attackers better and is tracked as an upgrade — version-gated, so
///   v2 archives can switch KDFs without breaking v1 restores. Stated, not hidden.
/// - Payload (before sealing): `root(32) || u32(count) || count × [lp(name) || lp(bytes)]`,
///   strict bounded decode — trailing bytes, over-long names, or absurd counts are refused.
public enum Backup {
    static let magic = Data("NEDWONSBK".utf8)
    static let version: UInt8 = 1
    public static let defaultIterations: UInt32 = 600_000
    static let maxFiles = 4096
    static let maxNameBytes = 512
    /// One file inside the archive is capped; the whole archive is bounded by what the caller
    /// gathers (the MLS stores), not enforced here.
    static let maxFileBytes = 512 * 1024 * 1024

    public struct Archive: Equatable, Sendable {
        /// The at-rest ROOT key — the reason a backup must never exist unencrypted.
        public let atRestRoot: Data
        /// (relative name, bytes) for every store file.
        public let files: [(name: String, bytes: Data)]

        public init(atRestRoot: Data, files: [(name: String, bytes: Data)]) {
            self.atRestRoot = atRestRoot
            self.files = files
        }

        public static func == (l: Archive, r: Archive) -> Bool {
            l.atRestRoot == r.atRestRoot
                && l.files.map(\.name) == r.files.map(\.name)
                && l.files.map(\.bytes) == r.files.map(\.bytes)
        }
    }

    public enum BackupError: Error, Equatable {
        case malformed
        case unsupportedVersion(UInt8)
        /// Wrong passphrase or a tampered archive — indistinguishable by design (GCM).
        case cannotOpen
        case kdfFailure
    }

    /// Seal an archive under a passphrase. The salt is fresh per backup, so identical content
    /// backs up to unlinkable files.
    public static func seal(
        _ archive: Archive, passphrase: String, iterations: UInt32 = defaultIterations
    ) throws -> Data {
        var salt = Data(count: 16)
        let saltResult = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard saltResult == errSecSuccess else { throw BackupError.kdfFailure }
        let key = try deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)
        let sealed = try AES.GCM.seal(encode(archive), using: key)
        var out = magic
        out.append(version)
        out.append(salt)
        out.append(contentsOf: withUnsafeBytes(of: iterations.bigEndian) { Data($0) })
        out.append(sealed.nonce.withUnsafeBytes { Data($0) })
        out.append(sealed.ciphertext)
        out.append(sealed.tag)
        return out
    }

    /// Open a sealed backup. A wrong passphrase and a tampered file fail identically (closed).
    public static func open(_ data: Data, passphrase: String) throws -> Archive {
        let headerLen = magic.count + 1 + 16 + 4 + 12
        guard data.count > headerLen + 16, data.prefix(magic.count) == magic else {
            throw BackupError.malformed
        }
        var at = magic.count
        let fileVersion = data[at]
        guard fileVersion == version else { throw BackupError.unsupportedVersion(fileVersion) }
        at += 1
        let salt = data.subdata(in: at..<at + 16)
        at += 16
        let iterations = data.subdata(in: at..<at + 4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard iterations >= 100_000 else { throw BackupError.malformed } // refuse weakened KDFs
        at += 4
        let nonce = data.subdata(in: at..<at + 12)
        at += 12
        let ciphertextAndTag = data.suffix(from: at)
        let key = try deriveKey(passphrase: passphrase, salt: salt, iterations: iterations)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertextAndTag.dropLast(16),
            tag: ciphertextAndTag.suffix(16))
        guard let plaintext = try? AES.GCM.open(box, using: key) else {
            throw BackupError.cannotOpen
        }
        return try decode(plaintext)
    }

    static func deriveKey(
        passphrase: String, salt: Data, iterations: UInt32
    ) throws -> SymmetricKey {
        var derived = Data(count: 32)
        let status = derived.withUnsafeMutableBytes { out in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passphrase, passphrase.utf8.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations,
                    out.baseAddress?.assumingMemoryBound(to: UInt8.self), 32)
            }
        }
        guard status == kCCSuccess else { throw BackupError.kdfFailure }
        return SymmetricKey(data: derived)
    }

    static func encode(_ archive: Archive) -> Data {
        var out = archive.atRestRoot
        out.append(contentsOf: withUnsafeBytes(of: UInt32(archive.files.count).bigEndian) { Data($0) })
        for (name, bytes) in archive.files {
            let nameData = Data(name.utf8)
            out.append(contentsOf: withUnsafeBytes(of: UInt32(nameData.count).bigEndian) { Data($0) })
            out.append(nameData)
            out.append(contentsOf: withUnsafeBytes(of: UInt32(bytes.count).bigEndian) { Data($0) })
            out.append(bytes)
        }
        return out
    }

    static func decode(_ data: Data) throws -> Archive {
        let bytes = [UInt8](data)
        guard bytes.count >= 36 else { throw BackupError.malformed }
        let root = Data(bytes[0..<32])
        func u32(_ at: Int) -> UInt32 {
            (UInt32(bytes[at]) << 24) | (UInt32(bytes[at + 1]) << 16)
                | (UInt32(bytes[at + 2]) << 8) | UInt32(bytes[at + 3])
        }
        let count = Int(u32(32))
        guard count <= maxFiles else { throw BackupError.malformed }
        var at = 36
        var files: [(String, Data)] = []
        for _ in 0..<count {
            guard at + 4 <= bytes.count else { throw BackupError.malformed }
            let nameLen = Int(u32(at))
            at += 4
            guard nameLen <= maxNameBytes, at + nameLen + 4 <= bytes.count else {
                throw BackupError.malformed
            }
            guard let name = String(bytes: bytes[at..<at + nameLen], encoding: .utf8),
                !name.contains("/"), !name.contains(".."), !name.isEmpty
            else { throw BackupError.malformed } // names are FLAT: no traversal, ever
            at += nameLen
            let byteLen = Int(u32(at))
            at += 4
            guard byteLen <= maxFileBytes, at + byteLen <= bytes.count else {
                throw BackupError.malformed
            }
            files.append((name, Data(bytes[at..<at + byteLen])))
            at += byteLen
        }
        guard at == bytes.count else { throw BackupError.malformed } // no trailer
        return Archive(atRestRoot: root, files: files)
    }
}
