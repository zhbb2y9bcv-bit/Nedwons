import CryptoKit
import Foundation

/// Validation for a private, viewer-local nickname. An alias is display-only: it never becomes an
/// identity, so the rules here exist to stop *spoofing the UI*, not to constrain a name space.
public enum AliasValidation: Equatable, Sendable {
    case valid(String)
    case empty
    case tooLong
    /// Control characters, bidi overrides, or other invisible formatting that could disguise the
    /// alias as system text or reverse the rendered order of the real username beneath it.
    case unsafeCharacters

    public static let maxLength = 40
}

public enum ContactAlias {
    /// Trims, then rejects anything that could visually impersonate. Bidi controls are the real
    /// hazard: they can make an alias render as though it were a different account's handle.
    public static func validate(_ raw: String) -> AliasValidation {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return .empty }
        if trimmed.count > AliasValidation.maxLength { return .tooLong }
        for scalar in trimmed.unicodeScalars {
            // C0/C1 controls, and the explicit bidi/format overrides.
            if scalar.properties.generalCategory == .control
                || scalar.properties.generalCategory == .format
                || (0x202A...0x202E).contains(scalar.value)
                || (0x2066...0x2069).contains(scalar.value)
            {
                return .unsafeCharacters
            }
        }
        return .valid(trimmed)
    }
}

/// Viewer-private nicknames, encrypted at rest and keyed by the peer's **immutable account id** —
/// never by username, which is a public lookup handle and must not become an identity.
///
/// This is deliberately one-sided: nothing here is ever transmitted, so the renamed person cannot
/// learn their alias and no server table holds it in plaintext.
public final class ContactAliasStore: @unchecked Sendable {
    private let url: URL
    private let key: SymmetricKey
    private var cache: [String: String]
    private let lock = NSLock()

    /// `atRestKey` comes from `AtRestKeyHierarchy`, so aliases die with the root on sign-out.
    public init(fileURL: URL, atRestKey: Data) {
        self.url = fileURL
        self.key = SymmetricKey(data: atRestKey)
        self.cache = Self.read(url: fileURL, key: self.key)
    }

    private static func read(url: URL, key: SymmetricKey) -> [String: String] {
        guard let blob = try? Data(contentsOf: url),
            let sealed = try? AES.GCM.SealedBox(combined: blob),
            let plain = try? AES.GCM.open(sealed, using: key),
            let map = try? JSONDecoder().decode([String: String].self, from: plain)
        else { return [:] }
        return map
    }

    private func flush() {
        guard let plain = try? JSONEncoder().encode(cache),
            let sealed = try? AES.GCM.seal(plain, using: key).combined
        else { return }
        try? sealed.write(to: url, options: .atomic)
    }

    public func alias(for accountID: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return cache[accountID]
    }

    /// Returns the validation outcome so the UI can explain a rejection instead of silently failing.
    @discardableResult
    public func setAlias(_ raw: String, for accountID: String) -> AliasValidation {
        let result = ContactAlias.validate(raw)
        guard case .valid(let clean) = result else { return result }
        lock.lock()
        cache[accountID] = clean
        flush()
        lock.unlock()
        return result
    }

    public func removeAlias(for accountID: String) {
        lock.lock()
        cache.removeValue(forKey: accountID)
        flush()
        lock.unlock()
    }

    /// What the conversation header shows. The real username is always rendered somewhere alongside
    /// this (see the header/profile views) so an alias can never fully mask the account.
    public func displayName(for accountID: String, username: String) -> String {
        alias(for: accountID) ?? username
    }
}
