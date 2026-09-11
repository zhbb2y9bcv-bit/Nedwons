import CryptoKit
import Foundation

/// Second-device pairing over QR, with a short authentication string (ADR-0008, BN-4).
///
/// ## The shape of the problem
///
/// `POST /v1/devices/enroll/*` is signed by an ALREADY-TRUSTED device over the NEW device's public
/// key, and returns the new device's `Session` to the trusted one. So pairing needs two transfers,
/// not one:
///
///   1. **offer** — new device → trusted device: "here is my public key, enroll it";
///   2. **grant** — trusted device → new device: "here is the session you were issued".
///
/// Both travel as QR codes, so the account never has to be reachable from both devices at once and
/// no new server endpoint is involved.
///
/// ## Why the grant is sealed
///
/// A session is a bearer credential. A grant QR displayed in the open can be photographed from
/// across a room, and a plaintext one would hand the photographer the account. The grant is
/// therefore encrypted under a **pairing key the new device generated and put in its own offer**:
/// whoever photographs the grant cannot open it without also having captured the offer from the new
/// device's screen moments earlier.
///
/// ## Why there is a SAS
///
/// The attack QR pairing actually has is substitution: the user points the trusted phone at an
/// attacker's code instead of their new phone's, and the trusted device happily enrolls the
/// attacker's device into the account. Nothing cryptographic detects that — both codes are
/// well-formed — so a human check is required.
///
/// Both devices derive the same six-group code from the offer alone. The new device computes it
/// from the offer it generated; the trusted device from the offer it scanned. If a different offer
/// was scanned, the codes differ. The user compares them BEFORE the enrollment is signed, which is
/// the only moment at which refusing still costs nothing.
public enum DevicePairing {
    static let offerPrefix = "nedwons-pair:1:"
    static let grantPrefix = "nedwons-paired:1:"
    static let sasDomain = "app.nedwons.device-pairing.sas.v1"
    /// Matches `SafetyNumber`: six groups of five digits, a length people will actually compare.
    static let sasGroups = 6

    /// What the NEW device shows. Public key plus a fresh symmetric key that only it holds.
    public struct Offer: Equatable, Sendable {
        /// X9.63 uncompressed P-256 public key of the new device's enrolled signer (65 bytes).
        public let devicePublicKeyX963: Data
        /// 32 random bytes; the grant is sealed under this. Never leaves the new device except
        /// inside its own offer QR.
        public let pairingKey: Data
        /// 16 random bytes, so two pairings from the same device produce different codes.
        public let nonce: Data

        public init(devicePublicKeyX963: Data, pairingKey: Data, nonce: Data) {
            self.devicePublicKeyX963 = devicePublicKeyX963
            self.pairingKey = pairingKey
            self.nonce = nonce
        }

        /// A fresh offer for `devicePublicKeyX963`.
        public static func create(devicePublicKeyX963: Data) -> Offer {
            create(devicePublicKeyX963: devicePublicKeyX963, randomBytes: DevicePairing.randomData)
        }

        /// Seam for tests: deterministic bytes make the wire format and the SAS reproducible.
        static func create(
            devicePublicKeyX963: Data,
            randomBytes: (Int) -> Data
        ) -> Offer {
            Offer(
                devicePublicKeyX963: devicePublicKeyX963,
                pairingKey: randomBytes(32),
                nonce: randomBytes(16))
        }

        /// Canonical, length-prefixed encoding — the same shape every other Nedwons transcript
        /// uses, so the SAS commits to field boundaries and not merely to concatenated bytes.
        func canonicalBytes() -> Data {
            var out = Data(sasDomain.utf8)
            out.append(0)
            appendLengthPrefixed(&out, devicePublicKeyX963)
            appendLengthPrefixed(&out, pairingKey)
            appendLengthPrefixed(&out, nonce)
            return out
        }
    }

    /// What the TRUSTED device shows back: the issued session, sealed under the offer's pairing key.
    public struct Grant: Equatable, Sendable {
        /// AES-GCM sealed box (nonce ‖ ciphertext ‖ tag) over the encoded session.
        public let sealedSession: Data

        public init(sealedSession: Data) {
            self.sealedSession = sealedSession
        }
    }

    // MARK: Wire format

    /// The offer QR payload.
    public static func encode(_ offer: Offer) -> String {
        var body = Data()
        appendLengthPrefixed(&body, offer.devicePublicKeyX963)
        appendLengthPrefixed(&body, offer.pairingKey)
        appendLengthPrefixed(&body, offer.nonce)
        return offerPrefix + Hex.encode(body)
    }

    /// Parse a scanned offer. `nil` for anything that is not a well-formed v1 offer — including a
    /// future version, which must read as "not something I understand" rather than being
    /// half-interpreted.
    public static func decodeOffer(_ raw: String) -> Offer? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(offerPrefix),
            let body = Hex.decode(String(trimmed.dropFirst(offerPrefix.count)))
        else { return nil }
        var cursor = 0
        guard let key = readLengthPrefixed(body, &cursor),
            let pairingKey = readLengthPrefixed(body, &cursor),
            let nonce = readLengthPrefixed(body, &cursor),
            cursor == body.count
        else { return nil }
        // Exact sizes. A short pairing key would silently weaken the seal, and a wrong-length
        // public key cannot be an enrollable P-256 key.
        guard key.count == 65, pairingKey.count == 32, nonce.count == 16 else { return nil }
        return Offer(devicePublicKeyX963: key, pairingKey: pairingKey, nonce: nonce)
    }

    public static func encode(_ grant: Grant) -> String {
        grantPrefix + Hex.encode(grant.sealedSession)
    }

    public static func decodeGrant(_ raw: String) -> Grant? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(grantPrefix),
            let sealed = Hex.decode(String(trimmed.dropFirst(grantPrefix.count))),
            !sealed.isEmpty
        else { return nil }
        return Grant(sealedSession: sealed)
    }

    // MARK: Sealing the session

    /// Codable mirror of the session, so the grant carries exactly the fields a client needs.
    struct PairedSession: Codable, Equatable {
        let accountID: String
        let deviceID: String
        let accessToken: String
        let accessExpiresAt: UInt64
        let refreshToken: String
        let refreshExpiresAt: UInt64
    }

    /// Seal `session` under the offer's pairing key.
    public static func seal(
        session: NedwonsClient.Session, under offer: Offer
    ) throws -> Grant {
        let encoded = try JSONEncoder().encode(
            PairedSession(
                accountID: session.accountID,
                deviceID: session.deviceID,
                accessToken: session.accessToken,
                accessExpiresAt: session.accessExpiresAt,
                refreshToken: session.refreshToken,
                refreshExpiresAt: session.refreshExpiresAt))
        let box = try AES.GCM.seal(encoded, using: SymmetricKey(data: offer.pairingKey))
        guard let combined = box.combined else { throw PairingError.sealFailed }
        return Grant(sealedSession: combined)
    }

    /// Open a grant with the pairing key from the offer THIS device generated.
    ///
    /// A failure here is not a decoding nicety: it means the grant was produced for a different
    /// offer, so the session inside belongs to someone else's pairing and must be refused.
    public static func open(grant: Grant, with offer: Offer) throws -> NedwonsClient.Session {
        guard let box = try? AES.GCM.SealedBox(combined: grant.sealedSession),
            let plaintext = try? AES.GCM.open(box, using: SymmetricKey(data: offer.pairingKey)),
            let decoded = try? JSONDecoder().decode(PairedSession.self, from: plaintext)
        else { throw PairingError.grantNotForThisOffer }
        return NedwonsClient.Session(
            accountID: decoded.accountID,
            deviceID: decoded.deviceID,
            accessToken: decoded.accessToken,
            accessExpiresAt: decoded.accessExpiresAt,
            refreshToken: decoded.refreshToken,
            refreshExpiresAt: decoded.refreshExpiresAt)
    }

    // MARK: Short authentication string

    /// Six groups of five digits, derived from the offer alone.
    ///
    /// Computable by BOTH sides before the enrollment is signed — the new device from the offer it
    /// created, the trusted device from the offer it scanned — which is what makes a substituted QR
    /// visible to the user while refusing is still free.
    public static func shortAuthenticationString(for offer: Offer) -> [String] {
        let digest = Data(SHA256.hash(data: offer.canonicalBytes()))
        return (0 ..< sasGroups).map { group in
            var value: UInt64 = 0
            for i in 0 ..< 5 { value = value << 8 | UInt64(digest[group * 5 + i]) }
            return String(format: "%05d", value % 100_000)
        }
    }

    public enum PairingError: Error, Equatable {
        case sealFailed
        /// The grant does not open under this device's pairing key.
        case grantNotForThisOffer
    }

    // MARK: Encoding helpers

    static func randomData(_ count: Int) -> Data {
        Data(RecoverySecret.secureRandomBytes(count))
    }

    private static func appendLengthPrefixed(_ out: inout Data, _ field: Data) {
        var length = UInt16(clamping: field.count).bigEndian
        withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
        out.append(field)
    }

    private static func readLengthPrefixed(_ data: Data, _ cursor: inout Int) -> Data? {
        guard cursor + 2 <= data.count else { return nil }
        let length = Int(data[data.startIndex + cursor]) << 8 | Int(data[data.startIndex + cursor + 1])
        cursor += 2
        guard cursor + length <= data.count else { return nil }
        let field = data.subdata(in: (data.startIndex + cursor) ..< (data.startIndex + cursor + length))
        cursor += length
        return field
    }
}
