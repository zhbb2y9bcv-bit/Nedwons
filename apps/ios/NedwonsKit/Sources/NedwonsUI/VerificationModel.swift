import Foundation
import NedwonsKit

/// Persists the set of peers the user marked verified, per signed-in account. No secrets — the
/// stored values are account ids — so `UserDefaults` is the right weight; the protocol exists so
/// tests inject memory.
public protocol VerifiedPeersStoring {
    func load(account: String) -> Set<String>
    func save(_ peers: Set<String>, account: String)
}

public struct UserDefaultsVerifiedPeersStore: VerifiedPeersStoring {
    let defaults: UserDefaults
    public init(defaults: UserDefaults = .standard) { self.defaults = defaults }
    private func key(_ account: String) -> String { "nedwons.verified-peers.\(account)" }
    public func load(account: String) -> Set<String> {
        Set(defaults.stringArray(forKey: key(account)) ?? [])
    }
    public func save(_ peers: Set<String>, account: String) {
        defaults.set(peers.sorted(), forKey: key(account))
    }
}

/// In-memory store for tests and previews.
public final class MemoryVerifiedPeersStore: VerifiedPeersStoring, @unchecked Sendable {
    public private(set) var byAccount: [String: Set<String>] = [:]
    public init() {}
    public func load(account: String) -> Set<String> { byAccount[account] ?? [] }
    public func save(_ peers: Set<String>, account: String) { byAccount[account] = peers }
}

/// Everything the safety-number screen needs, computed once from transparency-verified keys.
public struct SafetyNumberInfo: Equatable, Sendable {
    /// 12 groups of 5 digits — the number both people read aloud.
    public let digitGroups: [String]
    /// The exact-compare payload rendered as a QR code and matched on scan.
    public let qrPayload: String
    /// How many active devices each side's number covers, for honest on-screen copy.
    public let myDeviceCount: Int
    public let peerDeviceCount: Int
}

/// Safety numbers, peer verification state, and invite joining (roadmap step 4). The security
/// content — iterated-hash fingerprint over transparency-verified key sets — lives in
/// `NedwonsKit.SafetyNumber`; this extension fetches, publishes, and persists.
extension AppModel {

    /// Compute the safety number between the signed-in account and `peerAccountID`. Both key sets
    /// come from the transparency log and are verified against the STH under the *pinned* log key
    /// before a single digit is derived — a number computed from unproven keys would be theater.
    /// Returns nil (with a banner) when verification or the network fails.
    public func safetyNumber(with peerAccountID: String) async -> SafetyNumberInfo? {
        guard let token, let account = session?.accountID else { return nil }
        do {
            let pinned = try await currentPinnedLogKey()
            let mine = try await client.verifiedAccountKeys(
                accessToken: token, accountID: account, pinnedLogPublicKeyX963: pinned)
            let theirs = try await client.verifiedAccountKeys(
                accessToken: token, accountID: peerAccountID, pinnedLogPublicKeyX963: pinned)
            guard !mine.isEmpty, !theirs.isEmpty else {
                banner = "No logged keys to compare yet — the other person may not have finished setting up."
                return nil
            }
            let myKeys = mine.map(\.publicKeyX963)
            let peerKeys = theirs.map(\.publicKeyX963)
            return SafetyNumberInfo(
                digitGroups: SafetyNumber.displayGroups(
                    accountID: account, keysX963: myKeys,
                    peerAccountID: peerAccountID, peerKeysX963: peerKeys),
                qrPayload: SafetyNumber.qrPayload(
                    accountID: account, keysX963: myKeys,
                    peerAccountID: peerAccountID, peerKeysX963: peerKeys),
                myDeviceCount: mine.count,
                peerDeviceCount: theirs.count)
        } catch NedwonsClient.ClientError.verificationFailed {
            banner = "Key verification failed — the transparency proof did not check out. Do not trust this conversation until it does."
            return nil
        } catch {
            banner = "Couldn't fetch keys to compare. Check your connection."
            return nil
        }
    }

    /// Load the persisted verified set for the signed-in account into published state.
    public func loadVerifiedPeers() {
        guard let account = session?.accountID else { return }
        verifiedPeers = verifiedPeersStore.load(account: account)
    }

    public func isPeerVerified(_ accountID: String) -> Bool {
        verifiedPeers.contains(accountID)
    }

    /// Record the user's judgment after comparing numbers (or a successful scan). Local only.
    public func setPeerVerified(_ accountID: String, _ verified: Bool) {
        guard let account = session?.accountID else { return }
        if verified { verifiedPeers.insert(accountID) } else { verifiedPeers.remove(accountID) }
        verifiedPeersStore.save(verifiedPeers, account: account)
    }

    /// Compare a scanned safety-number QR against the freshly computed one. `true` = exact match
    /// (and the peer is marked verified); `false` = mismatch or a stale/foreign code.
    public func confirmScannedSafetyCode(_ scanned: String, peerAccountID: String) async -> Bool {
        guard let info = await safetyNumber(with: peerAccountID) else { return false }
        let matches = scanned == info.qrPayload
        if matches {
            setPeerVerified(peerAccountID, true)
            banner = "Verified — the scanned code matches."
        } else {
            banner = "The scanned code does NOT match. Someone's keys differ from what you see — compare in person before trusting this chat."
        }
        return matches
    }

    // MARK: Joining by invite

    /// Join a conversation with an invite token (pasted or scanned — `InviteCode.parse` already
    /// validated its shape). Joining is the joiner's own consent (ADR-0009); approval-gated groups
    /// return a pending request instead of a membership.
    ///
    /// Honest limit, surfaced in the banner: an invite join adds this account to the relay's
    /// routing. The group's *encryption* still has to admit you — a current member's device adds
    /// you to the MLS group (the same add used when members are added directly), after which new
    /// messages decrypt. Until then the group shows without readable history.
    public func joinWithInvite(token inviteToken: String) async -> Bool {
        var joined = false
        await run { [self] in
            guard let token else { return }
            let accepted = try await client.acceptInvite(
                accessToken: token, inviteToken: inviteToken)
            if accepted.status == "joined" {
                joined = true
                banner = "You're in. Messages appear once a member finishes your encryption setup."
                await refreshConversations()
            } else {
                banner = "Request sent — an admin has to approve you."
            }
        }
        return joined
    }
}
