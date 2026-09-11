import CryptoKit
import Foundation

/// The single owner of the live session: the current tokens, their persistence, and the ONE
/// refresh that may be in flight at a time (ADR-0011, R-308).
///
/// ## Why this is an actor and not a lock
///
/// The refresh token is single-use and rotating: presenting a retired one revokes the entire
/// refresh family, signing the account out of every device. So two concurrent requests that both
/// see a 401 must NOT both refresh — the second would present a token the first had already
/// retired. `refreshedSession(replacing:)` therefore collapses concurrent callers onto one task:
/// the check of `inFlight` and its assignment happen with no `await` between them, which on an
/// actor is atomic by construction. Everyone else awaits that same task's value.
///
/// ## Why refresh has its own transport
///
/// Refresh deliberately does NOT go through `NedwonsClient.perform`. That path attaches a proof
/// and retries once on 401 by asking *this* type for a fresh session — so routing refresh through
/// it would let a failing refresh recurse into itself. Refresh is one unauthenticated POST
/// (it authenticates by signing the rotating token, not by a bearer header), so it is implemented
/// here directly and the recursion is structurally impossible rather than merely avoided.
public actor SessionAuthority {
    /// Raised when there is nothing to refresh with, or the server refused the rotation.
    public enum AuthorityError: Error, Equatable {
        /// No stored session — the caller must sign in.
        case noSession
        /// The server refused the refresh; the session is dead and has been cleared.
        case refreshRejected
        /// The enrolled device key is unavailable, so no refresh can be signed (INV-2).
        case noSigner
    }

    private var session: NedwonsClient.Session?
    private let store: SessionStore
    private let signer: (any DeviceSigner)?
    private let baseURL: URL
    private let urlSession: URLSession

    /// The one refresh allowed to be in flight. Concurrent callers await this instead of starting
    /// their own.
    private var inFlight: Task<NedwonsClient.Session, Error>?

    /// Notified after a rotation is durably persisted, so UI state can follow the tokens rather
    /// than holding a stale copy. Called on an arbitrary task, never inside the actor's lock.
    private var observers: [@Sendable (NedwonsClient.Session) -> Void] = []

    public init(
        session: NedwonsClient.Session?,
        store: SessionStore,
        signer: (any DeviceSigner)?,
        baseURL: URL,
        urlSession: URLSession = .shared
    ) {
        self.session = session
        self.store = store
        self.signer = signer
        self.baseURL = baseURL
        self.urlSession = urlSession
    }

    public func addObserver(_ observer: @escaping @Sendable (NedwonsClient.Session) -> Void) {
        observers.append(observer)
    }

    public func currentSession() -> NedwonsClient.Session? { session }

    public func currentAccessToken() -> String? { session?.accessToken }

    /// Adopt a session established by register/login/recover.
    public func adopt(_ new: NedwonsClient.Session) throws {
        try store.save(new)
        session = new
    }

    public func clear() {
        session = nil
        inFlight?.cancel()
        inFlight = nil
        store.clear()
    }

    /// The signer used for per-request proofs. `nil` disables proof generation entirely rather
    /// than sending an unsigned or bogus header.
    public func proofSigner() -> (any DeviceSigner)? { signer }

    /// Return a session whose access token is not `stale`, refreshing at most once across all
    /// concurrent callers.
    ///
    /// `stale` is the token the caller just had refused. If another task already rotated past it
    /// while this one was waiting, the rotation is reused and no second refresh happens — which is
    /// the case that would otherwise present a retired refresh token and revoke the family.
    public func refreshedSession(replacing stale: String) async throws -> NedwonsClient.Session {
        if let current = session, current.accessToken != stale {
            return current
        }
        if let existing = inFlight {
            return try await existing.value
        }
        guard let current = session else { throw AuthorityError.noSession }
        guard let signer else { throw AuthorityError.noSigner }

        // No `await` between the check above and this assignment, so on an actor this is the
        // atomic claim that makes the flight single.
        let task = Task<NedwonsClient.Session, Error> { [baseURL, urlSession, store] in
            try await Self.performRefresh(
                current: current, signer: signer, baseURL: baseURL, urlSession: urlSession,
                store: store)
        }
        inFlight = task
        do {
            let rotated = try await task.value
            inFlight = nil
            session = rotated
            let toNotify = observers
            Task { for observe in toNotify { observe(rotated) } }
            return rotated
        } catch {
            inFlight = nil
            // A refused rotation is terminal: the refresh token is spent either way, so keeping it
            // would only let a later attempt present a retired token and revoke the family.
            if case NedwonsClient.ClientError.http = error {
                session = nil
                store.clear()
                throw AuthorityError.refreshRejected
            }
            throw error
        }
    }

    /// One `POST /v1/session/refresh`, signed over the `Refresh` transcript whose nonce is
    /// SHA-256(refresh token). Persisted BEFORE it is published in memory: if the process dies
    /// between the two, the next launch reads the rotated token, whereas the other order would
    /// leave the durable copy holding a token the server has already retired.
    private static func performRefresh(
        current: NedwonsClient.Session,
        signer: any DeviceSigner,
        baseURL: URL,
        urlSession: URLSession,
        store: SessionStore
    ) async throws -> NedwonsClient.Session {
        guard
            let accountID = Hex.decode(current.accountID),
            let deviceID = Hex.decode(current.deviceID),
            let refreshToken = Hex.decode(current.refreshToken)
        else { throw NedwonsClient.ClientError.decoding }

        let transcript = ClientTranscripts.refresh(
            accountID: accountID,
            deviceID: deviceID,
            publicKey: signer.publicKeyX963,
            refreshToken: refreshToken
        )
        let signature = try signer.sign(transcript)

        var request = URLRequest(url: baseURL.appendingPathComponent("/v1/session/refresh"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            RefreshBody(
                refresh_token: current.refreshToken,
                signature: Hex.encode(signature)
            ))

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw NedwonsClient.ClientError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw NedwonsClient.ClientError.decoding
        }
        guard (200 ..< 300).contains(http.statusCode) else {
            throw NedwonsClient.ClientError.http(
                status: http.statusCode, body: String(decoding: data, as: UTF8.self))
        }
        guard let decoded = try? JSONDecoder().decode(RefreshedSession.self, from: data) else {
            throw NedwonsClient.ClientError.decoding
        }
        let rotated = decoded.model
        // Durable first. A failure here must fail the refresh: reporting success while the rotated
        // token exists only in memory is how a relaunch ends up presenting a retired token.
        try store.save(rotated)
        return rotated
    }

    private struct RefreshBody: Encodable {
        let refresh_token: String
        let signature: String
    }

    private struct RefreshedSession: Decodable {
        let account_id: String
        let device_id: String
        let access_token: String
        let access_expires_at: UInt64
        let refresh_token: String
        let refresh_expires_at: UInt64

        var model: NedwonsClient.Session {
            NedwonsClient.Session(
                accountID: account_id,
                deviceID: device_id,
                accessToken: access_token,
                accessExpiresAt: access_expires_at,
                refreshToken: refresh_token,
                refreshExpiresAt: refresh_expires_at
            )
        }
    }
}
