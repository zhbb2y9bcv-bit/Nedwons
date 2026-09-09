//! Message relay storage: key packages, conversation routing membership, and the opaque envelope
//! queue. `ciphertext` is stored and returned as-is (INV-1), and this module does not depend on
//! `mls-core` — the server cannot read message content by construction.

use auth_core::ids::{AccountId, DeviceId};
use auth_core::store::{StoreError, StoreResult};

use crate::pgstore::PgPool;
use r2d2_postgres::postgres::NoTls;

/// A stale prekey must never be used to add a device. Clients replenish below the low-watermark.
pub const KEY_PACKAGE_TTL_SECS: u64 = 30 * 24 * 3600;
/// Suggested client replenishment threshold (surfaced via the count endpoint).
pub const KEY_PACKAGE_LOW_WATERMARK: u64 = 5;

/// Relay storage over the shared connection pool.
#[derive(Clone)]
pub struct PgRelay {
    pool: PgPool,
}

/// A queued envelope handed back to a recipient device.
pub struct EnvelopeOut {
    pub id: i64,
    pub conversation_id: [u8; 16],
    pub sender_device: [u8; 16],
    pub ciphertext: Vec<u8>,
}

/// ADR-0014: the relay knows only the recipient and the ciphertext — never sender or conversation.
pub struct SealedEnvelopeOut {
    pub id: i64,
    pub ciphertext: Vec<u8>,
}

/// ADR-0015: ciphertext for one of the account's OWN devices. Both endpoints are the same account's
/// authenticated devices, so the sender device is recorded.
pub struct SelfGroupEnvelopeOut {
    pub id: i64,
    pub sender_device: [u8; 16],
    pub ciphertext: Vec<u8>,
}

/// Outcome of a self-group delivery (targeted or fan-out).
#[derive(Debug, PartialEq, Eq)]
pub enum SelfGroupSendOutcome {
    /// The recipient device is not a device of the delivering account (targeted delivery only).
    Forbidden,
    /// Carries only the devices that received a *new* envelope, so only those get woken.
    Delivered { newly_queued: Vec<[u8; 16]> },
}

/// Outcome of a sealed delivery.
#[derive(Debug, PartialEq, Eq)]
pub enum SealedSendOutcome {
    /// Stored for the recipient device.
    Enqueued { id: i64 },
    /// The (recipient_device, idempotency_key) pair already exists — a retry, deduplicated.
    Duplicate,
}

/// A claimed key package plus the device it belongs to.
pub struct ClaimedKeyPackage {
    pub device_id: [u8; 16],
    pub key_package: Vec<u8>,
}

/// How long a reconcile claim on a setup target lives before another device may take over
/// (migration V27). Long enough to claim a prekey + deliver a Welcome; short enough that a
/// crashed reconciler delays a join by seconds, not forever.
pub const SETUP_CLAIM_TTL_SECS: u64 = 60;

/// One routing member still awaiting its MLS add (V27 setup queue).
pub struct SetupTarget {
    pub conversation_id: [u8; 16],
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
}

/// A conversation the caller belongs to, with its member accounts (for the Chats list).
pub struct ConversationSummary {
    pub conversation_id: [u8; 16],
    pub member_account_ids: Vec<[u8; 16]>,
}

/// Result of a fanout send.
pub enum FanoutOutcome {
    /// The sender is not a member of the conversation.
    Forbidden,
    /// The idempotency key was already used by this sender for a DIFFERENT payload or
    /// conversation. Refused: silently deduping would drop the new message while reporting
    /// success (a client bug becomes silent data loss). The client must use a fresh key.
    IdempotencyMismatch,
    /// Delivered (or already delivered, on an idempotent retry). Carries the recipient
    /// devices that received a *new* envelope, so only those get woken.
    Delivered { newly_queued: Vec<[u8; 16]> },
    /// The sender is a member, but an admin has muted them or put the group in announcement mode
    /// (ADR-0009 moderation). Distinct from `Forbidden` on purpose: a muted member is entitled to
    /// know why their message did not send, and their client shows that state rather than a
    /// generic failure.
    Muted { reason: SendRefusal },
}

/// Result of a targeted send.
pub enum SendOutcome {
    /// The sender is not a member of the conversation.
    Forbidden,
    /// Same as [`FanoutOutcome::IdempotencyMismatch`].
    IdempotencyMismatch,
    /// Queued (or already queued, on an idempotent retry) under this envelope id.
    Queued(i64),
    /// Same as [`FanoutOutcome::Muted`]. The targeted path is gated too: it accepts
    /// caller-supplied ciphertext for a member device, so leaving it open would make a mute
    /// bypassable by anyone willing to modify their client — which is exactly who gets muted.
    Muted { reason: SendRefusal },
}

/// Whether a device may upload an attachment to a conversation.
pub enum AttachmentPermission {
    Allowed,
    /// Not a member (or the conversation does not exist): one generic refusal.
    Denied,
    /// A member, but muted or in an announcement-only group.
    Muted {
        reason: SendRefusal,
    },
}

/// Why a member in good standing was refused a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRefusal {
    /// This member is individually muted.
    MemberMuted,
    /// The whole group is in announcement mode and this member is not an admin.
    AnnouncementsOnly,
}

impl SendRefusal {
    /// The stable wire code the client matches on.
    pub fn code(self) -> &'static str {
        match self {
            SendRefusal::MemberMuted => "muted",
            SendRefusal::AnnouncementsOnly => "announcements_only",
        }
    }
}

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("relay db: {e}"))
}

/// Membership check inside an open transaction, holding the member row until commit so the check
/// and the dependent write really are atomic — a member removed concurrently can't slip a message
/// in.
///
/// `FOR UPDATE` is load-bearing, not decoration. At READ COMMITTED an unlocked read gives no such
/// guarantee, and the fanout INSERT cannot self-correct: its predicate is `cm.device_id <> $2`, so
/// it enumerates the OTHER members and the sender's own removal never changes the rows it inserts.
/// Locking the sender's row makes a concurrent removal wait for this send to finish, and a removal
/// that already committed leaves no row to lock, so the caller refuses. Proved by
/// `fanout_refuses_a_sender_removed_concurrently`.
fn member_in_txn(
    txn: &mut postgres::Transaction<'_>,
    conversation_id: &[u8; 16],
    device: &[u8],
) -> StoreResult<bool> {
    let row = txn
        .query_opt(
            "SELECT 1 FROM conversation_members
             WHERE conversation_id = $1 AND device_id = $2
             FOR UPDATE",
            &[&conversation_id.as_slice(), &device],
        )
        .map_err(db_err)?;
    Ok(row.is_some())
}

/// Moderation gate (ADR-0009): may this sender's device put a message into this conversation?
///
/// Called inside the send transaction, immediately after [`member_in_txn`] has locked the sender's
/// routing row, so the permission that is checked is the permission that applies to the write —
/// the same discipline the membership check uses, for the same reason.
///
/// Two locks, in the order every other governance path takes them (members, then conversations):
///
///   * the sender's `conversation_members` rows are already held `FOR UPDATE` by the membership
///     check, and `mute_member` locks those same rows, so a mute and a send by the muted account
///     serialize against each other instead of interleaving;
///   * the conversation row is taken `FOR SHARE` here and `FOR UPDATE` by
///     `set_announcements_only`, so concurrent senders never block each other while a mode flip
///     still cannot slip between this read and the insert it authorizes.
///
/// Returns `None` when the send is permitted.
fn send_refusal_in_txn(
    txn: &mut postgres::Transaction<'_>,
    conversation_id: &[u8; 16],
    device: &[u8],
) -> StoreResult<Option<SendRefusal>> {
    let row = txn
        .query_opt(
            "SELECT c.announcements_only,
                    EXISTS (SELECT 1 FROM group_admins ga
                             WHERE ga.conversation_id = c.conversation_id
                               AND ga.account_id = cm.account_id),
                    EXISTS (SELECT 1 FROM group_mutes gm
                             WHERE gm.conversation_id = c.conversation_id
                               AND gm.account_id = cm.account_id
                               AND (gm.expires_at IS NULL OR gm.expires_at > now()))
             FROM conversations c
             JOIN conversation_members cm
                  ON cm.conversation_id = c.conversation_id AND cm.device_id = $2
             WHERE c.conversation_id = $1
             FOR SHARE OF c",
            &[&conversation_id.as_slice(), &device],
        )
        .map_err(db_err)?;
    // No row means the conversation is gone (the last member left mid-send); the membership check
    // that runs first is the authority on that, so treat it as permitted here and let the write
    // fail on its own foreign key rather than reporting a mute that nobody applied.
    let Some(row) = row else { return Ok(None) };
    let announcements_only: bool = row.get(0);
    let is_admin: bool = row.get(1);
    let is_muted: bool = row.get(2);
    if is_muted {
        // Checked before announcement mode so the client can say something true and specific:
        // "an admin muted you" is different feedback from "the group is locked".
        return Ok(Some(SendRefusal::MemberMuted));
    }
    if announcements_only && !is_admin {
        return Ok(Some(SendRefusal::AnnouncementsOnly));
    }
    Ok(None)
}

fn id16(bytes: &[u8]) -> StoreResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError("bad id length".into()))
}

impl PgRelay {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn conn(
        &self,
    ) -> StoreResult<r2d2::PooledConnection<r2d2_postgres::PostgresConnectionManager<NoTls>>> {
        self.pool
            .get()
            .map_err(|e| StoreError(format!("pool: {e}")))
    }

    /// Register (or rotate) the account's sealed-sender **delivery access verifier**
    /// `V_r = SHA-256(K_r)` (ADR-0014 Slice 2a). Upsert: a second call replaces the previous
    /// verifier (rotation), instantly revoking every holder of the old key at the relay. The relay
    /// stores only the 32-byte hash, never `K_r`.
    pub fn set_delivery_verifier(&self, account: &AccountId, verifier: &[u8]) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO delivery_access_keys (account_id, verifier, updated_at)
             VALUES ($1, $2, now())
             ON CONFLICT (account_id) DO UPDATE SET verifier = EXCLUDED.verifier, updated_at = now()",
            &[&account.as_bytes(), &verifier],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// The owning account of a **non-revoked** device, or `None` if the device is unknown or
    /// revoked. Used by sealed delivery to find whose delivery-access verifier gates the recipient.
    pub fn account_for_device(&self, device: &DeviceId) -> StoreResult<Option<AccountId>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT account_id FROM devices WHERE device_id = $1 AND NOT revoked",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;
        match row {
            Some(r) => Ok(Some(AccountId(id16(r.get::<_, &[u8]>(0))?))),
            None => Ok(None),
        }
    }

    /// The account's registered delivery access verifier, or `None` if it has not set one. Used by
    /// the sealed-delivery endpoint to gate a presented key.
    pub fn delivery_verifier(&self, account: &AccountId) -> StoreResult<Option<Vec<u8>>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT verifier FROM delivery_access_keys WHERE account_id = $1",
                &[&account.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| r.get::<_, Vec<u8>>(0)))
    }

    /// Publish a key package for a device.
    pub fn publish_key_package(
        &self,
        account: AccountId,
        device: DeviceId,
        key_package: &[u8],
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO key_packages (account_id, device_id, key_package) VALUES ($1, $2, $3)",
            &[&account.as_bytes(), &device.as_bytes(), &key_package],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Claim (pop) one **non-expired** key package for the given account's device. `DELETE ...
    /// RETURNING` with a subquery makes claiming atomic — two claimants cannot get the same
    /// package. Key packages older than `ttl_secs` are ignored (a stale prekey must never be used
    /// to add a device — MLS key-package hygiene); the purge task deletes them.
    pub fn claim_key_package(
        &self,
        account: &AccountId,
        ttl_secs: u64,
    ) -> StoreResult<Option<ClaimedKeyPackage>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "DELETE FROM key_packages WHERE id = (
                     SELECT id FROM key_packages
                     WHERE account_id = $1 AND created_at > now() - make_interval(secs => $2)
                     ORDER BY id LIMIT 1
                     FOR UPDATE SKIP LOCKED
                 ) RETURNING device_id, key_package",
                &[&account.as_bytes(), &(ttl_secs as f64)],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok(ClaimedKeyPackage {
                device_id: id16(r.get::<_, &[u8]>(0))?,
                key_package: r.get::<_, Vec<u8>>(1),
            })
        })
        .transpose()
    }

    /// How many non-expired key packages a device still has published. The client publishes more
    /// when this drops below a low-watermark, so the device stays addable offline (replenishment).
    pub fn count_available_key_packages(
        &self,
        device: &DeviceId,
        ttl_secs: u64,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let count: i64 = conn
            .query_one(
                "SELECT count(*) FROM key_packages
                 WHERE device_id = $1 AND created_at > now() - make_interval(secs => $2)",
                &[&device.as_bytes(), &(ttl_secs as f64)],
            )
            .map_err(db_err)?
            .get(0);
        Ok(count as u64)
    }

    /// Delete key packages older than `ttl_secs` (MLS prekey hygiene). Returns rows purged.
    pub fn purge_expired_key_packages(&self, ttl_secs: u64) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let purged = conn
            .execute(
                "DELETE FROM key_packages WHERE created_at <= now() - make_interval(secs => $1)",
                &[&(ttl_secs as f64)],
            )
            .map_err(db_err)?;
        Ok(purged)
    }

    /// Create a conversation and add the creator as its first member (one transaction). When
    /// `mls_authoritative`, membership afterwards may change ONLY through an MLS commit
    /// (ADR-0010): the legacy direct-mutation endpoints refuse.
    pub fn create_conversation(
        &self,
        conversation_id: [u8; 16],
        creator_account: AccountId,
        creator_device: DeviceId,
        mls_authoritative: bool,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        Self::create_conversation_in_txn(
            &mut txn,
            conversation_id,
            creator_account,
            creator_device,
            mls_authoritative,
        )?;
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// As [`Self::create_conversation`], but joins a caller-owned transaction so it can commit
    /// atomically with work in another store — notably `PgGroups::bootstrap_admin_in_txn`, since a
    /// conversation created without its first admin can never acquire one (`promote` requires an
    /// existing admin).
    pub fn create_conversation_in_txn(
        txn: &mut postgres::Transaction<'_>,
        conversation_id: [u8; 16],
        creator_account: AccountId,
        creator_device: DeviceId,
        mls_authoritative: bool,
    ) -> StoreResult<()> {
        txn.execute(
            "INSERT INTO conversations (conversation_id, mls_authoritative) VALUES ($1, $2)",
            &[&conversation_id.as_slice(), &mls_authoritative],
        )
        .map_err(db_err)?;
        txn.execute(
            "INSERT INTO conversation_members (conversation_id, account_id, device_id)
             VALUES ($1, $2, $3)",
            &[
                &conversation_id.as_slice(),
                &creator_account.as_bytes(),
                &creator_device.as_bytes(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Whether a conversation is MLS-authoritative (membership changes only via `/commit`).
    /// Returns `false` for an unknown conversation (safe default; ids are opaque so this leaks
    /// nothing).
    pub fn is_authoritative(&self, conversation_id: &[u8; 16]) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT mls_authoritative FROM conversations WHERE conversation_id = $1",
                &[&conversation_id.as_slice()],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| r.get::<_, bool>(0)).unwrap_or(false))
    }

    /// Add a device to a conversation's routing membership (idempotent).
    pub fn add_member(
        &self,
        conversation_id: &[u8; 16],
        account: AccountId,
        device: DeviceId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO conversation_members (conversation_id, account_id, device_id)
             VALUES ($1, $2, $3) ON CONFLICT (conversation_id, device_id) DO NOTHING",
            &[
                &conversation_id.as_slice(),
                &account.as_bytes(),
                &device.as_bytes(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// As [`Self::add_member`], but joins a caller-owned transaction. Entry paths that CONSUME
    /// something to earn the membership — an invite use, a join request — must add the member in
    /// the same transaction that consumes it, or a failure in between spends the user's one chance
    /// to join without joining them.
    pub fn add_member_in_txn(
        txn: &mut postgres::Transaction<'_>,
        conversation_id: &[u8; 16],
        account: AccountId,
        device: DeviceId,
    ) -> StoreResult<()> {
        txn.execute(
            "INSERT INTO conversation_members (conversation_id, account_id, device_id)
             VALUES ($1, $2, $3) ON CONFLICT (conversation_id, device_id) DO NOTHING",
            &[
                &conversation_id.as_slice(),
                &account.as_bytes(),
                &device.as_bytes(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// As [`Self::add_member`], but the new row lands in the **MLS setup queue** (`mls_added =
    /// FALSE`): the device is routed mail from now on, and some current member's device will
    /// claim it, deliver a Welcome, and confirm (migration V27). This is the entry point for
    /// every path where the adder is NOT the device performing the MLS add — invite joins,
    /// join approvals, direct adds, deferred adds, newly linked siblings.
    pub fn add_pending_member(
        &self,
        conversation_id: &[u8; 16],
        account: AccountId,
        device: DeviceId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        Self::add_pending_member_in_txn(&mut txn, conversation_id, account, device)?;
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn add_pending_member_in_txn(
        txn: &mut postgres::Transaction<'_>,
        conversation_id: &[u8; 16],
        account: AccountId,
        device: DeviceId,
    ) -> StoreResult<()> {
        txn.execute(
            "INSERT INTO conversation_members (conversation_id, account_id, device_id, mls_added)
             VALUES ($1, $2, $3, FALSE) ON CONFLICT (conversation_id, device_id) DO NOTHING",
            &[
                &conversation_id.as_slice(),
                &account.as_bytes(),
                &device.as_bytes(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ----- MLS setup queue (V27): multi-device + automatic/deferred adds ----------------------

    /// Setup work visible to `caller`: members of the caller's conversations that still need an
    /// MLS add, unclaimed (or whose claim expired — a reconciler that crashed or found no prekey
    /// must not wedge its target forever). Only a caller that has itself COMPLETED setup for a
    /// conversation sees its queue — a device with no group keys cannot add anyone.
    pub fn setup_needed(&self, caller: &DeviceId, limit: i64) -> StoreResult<Vec<SetupTarget>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT t.conversation_id, t.account_id, t.device_id
                 FROM conversation_members t
                 JOIN conversation_members me
                   ON me.conversation_id = t.conversation_id
                 WHERE me.device_id = $1 AND me.mls_added
                   AND NOT t.mls_added AND t.device_id <> $1
                   AND (t.setup_claimed_at IS NULL
                        OR t.setup_claimed_at < now() - make_interval(secs => $2))
                 ORDER BY t.conversation_id
                 LIMIT $3",
                &[&caller.as_bytes(), &(SETUP_CLAIM_TTL_SECS as f64), &limit],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(SetupTarget {
                    conversation_id: id16(r.get::<_, &[u8]>(0))?,
                    account_id: id16(r.get::<_, &[u8]>(1))?,
                    device_id: id16(r.get::<_, &[u8]>(2))?,
                })
            })
            .collect()
    }

    /// Atomically claim one setup target so exactly ONE member's device performs the add — two
    /// reconcilers double-adding the same device would fork the group. Returns false when someone
    /// else holds a live claim, the target is already set up, or the caller isn't a set-up member.
    pub fn claim_setup(
        &self,
        claimer: &DeviceId,
        conversation_id: &[u8; 16],
        target_device: &DeviceId,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let updated = conn
            .execute(
                "UPDATE conversation_members t SET setup_claimed_by = $1, setup_claimed_at = now()
                 WHERE t.conversation_id = $2 AND t.device_id = $3 AND NOT t.mls_added
                   AND (t.setup_claimed_at IS NULL
                        OR t.setup_claimed_at < now() - make_interval(secs => $4)
                        OR t.setup_claimed_by = $1)
                   AND EXISTS (SELECT 1 FROM conversation_members me
                               WHERE me.conversation_id = $2 AND me.device_id = $1 AND me.mls_added)",
                &[
                    &claimer.as_bytes(),
                    &conversation_id.as_slice(),
                    &target_device.as_bytes(),
                    &(SETUP_CLAIM_TTL_SECS as f64),
                ],
            )
            .map_err(db_err)?;
        Ok(updated == 1)
    }

    /// The Welcome is on its way: the target now holds (or is one queued envelope away from
    /// holding) the conversation's keys. Requires the confirmer to hold the live claim, so a
    /// stale reconciler cannot confirm over a newer one's work.
    pub fn confirm_setup(
        &self,
        confirmer: &DeviceId,
        conversation_id: &[u8; 16],
        target_device: &DeviceId,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let updated = conn
            .execute(
                "UPDATE conversation_members SET mls_added = TRUE,
                        setup_claimed_by = NULL, setup_claimed_at = NULL
                 WHERE conversation_id = $1 AND device_id = $2 AND NOT mls_added
                   AND setup_claimed_by = $3",
                &[
                    &conversation_id.as_slice(),
                    &target_device.as_bytes(),
                    &confirmer.as_bytes(),
                ],
            )
            .map_err(db_err)?;
        Ok(updated == 1)
    }

    /// Whether `caller` shares at least one conversation with `target` — the authorization for
    /// claiming a SPECIFIC device's prekey (a reconciler adding that device to a shared group).
    pub fn shares_conversation(&self, caller: &DeviceId, target: &DeviceId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT 1 FROM conversation_members a
                 JOIN conversation_members b ON a.conversation_id = b.conversation_id
                 WHERE a.device_id = $1 AND b.device_id = $2 LIMIT 1",
                &[&caller.as_bytes(), &target.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    /// A freshly linked sibling joins all of its account's conversations — queued for MLS setup,
    /// which the account's OWN other device (or any member) completes on its next sync. Called
    /// when the device registers self-group membership: linking is the trust ceremony, so an
    /// enrolled-but-unlinked device deliberately gets no conversation routing.
    pub fn seed_linked_device_conversations(
        &self,
        account: &AccountId,
        device: &DeviceId,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let inserted = conn
            .execute(
                "INSERT INTO conversation_members (conversation_id, account_id, device_id, mls_added)
                 SELECT DISTINCT cm.conversation_id, $1::bytea, $2::bytea, FALSE
                 FROM conversation_members cm WHERE cm.account_id = $1
                 ON CONFLICT (conversation_id, device_id) DO NOTHING",
                &[&account.as_bytes(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(inserted)
    }

    /// Membership by ACCOUNT (any of its devices), inside a caller-owned transaction. Used by the
    /// authorization gate so the check and the write it authorizes share one transaction.
    pub fn is_member_account_in_txn(
        txn: &mut postgres::Transaction<'_>,
        conversation_id: &[u8; 16],
        device: &DeviceId,
    ) -> StoreResult<bool> {
        Ok(txn
            .query_opt(
                "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
                &[&conversation_id.as_slice(), &device.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    /// Store one opt-in diagnostic payload (crash/hang report). No account linkage, on purpose.
    pub fn store_diagnostic(&self, payload: &str) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute("INSERT INTO diagnostics (payload) VALUES ($1)", &[&payload])
            .map_err(db_err)?;
        Ok(())
    }

    /// Sweep diagnostics past the retention TTL (they are debugging aids, not records).
    pub fn purge_stale_diagnostics(&self, ttl: std::time::Duration) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let n = conn
            .execute(
                "DELETE FROM diagnostics WHERE created_at < now() - make_interval(secs => $1)",
                &[&ttl.as_secs_f64()],
            )
            .map_err(db_err)?;
        Ok(n)
    }

    /// The shared pool. Every store is built from it, so cross-store work can run in ONE
    /// transaction via [`crate::tx::transaction`].
    pub fn pool_clone(&self) -> PgPool {
        self.pool.clone()
    }

    // NOTE: leaving/removal moved to `groups::PgGroups::leave_conversation` (ADR-0009), which
    // additionally handles admin-role cleanup and auto-promotion. The relay stays mail-only.

    /// May this device put an attachment in this conversation? Membership AND the moderation gate,
    /// evaluated exactly as a send is: an upload is the first half of sending a message, so anyone
    /// who cannot send cannot stage bytes for one either.
    pub fn attachment_upload_permission(
        &self,
        conversation_id: &[u8; 16],
        device: &DeviceId,
    ) -> StoreResult<AttachmentPermission> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        if !member_in_txn(&mut txn, conversation_id, device.as_bytes())? {
            return Ok(AttachmentPermission::Denied);
        }
        let permission = match send_refusal_in_txn(&mut txn, conversation_id, device.as_bytes())? {
            Some(reason) => AttachmentPermission::Muted { reason },
            None => AttachmentPermission::Allowed,
        };
        txn.commit().map_err(db_err)?;
        Ok(permission)
    }

    // ----- attachment metadata (V26) -------------------------------------------------------
    //
    // The BYTES live in the blob store; these rows answer "may this device fetch this blob?" and
    // give retention something to sweep. See `blobs.rs` and `V26__attachments.sql`.

    /// Record an uploaded blob against a conversation. The caller has already verified that
    /// `uploader_device` may send there, and has written the bytes.
    pub fn record_attachment(
        &self,
        blob_id: &[u8; 16],
        conversation_id: &[u8; 16],
        uploader_device: &DeviceId,
        size_bytes: i64,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO attachments (blob_id, conversation_id, uploader_device, size_bytes)
             VALUES ($1, $2, $3, $4)",
            &[
                &blob_id.as_slice(),
                &conversation_id.as_slice(),
                &uploader_device.as_bytes(),
                &size_bytes,
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// May `device` fetch this blob? True only if the blob exists AND the device is currently in
    /// the conversation it belongs to — the same rule the envelope path uses, so leaving a group
    /// ends access to its files as well as its messages.
    ///
    /// A blob id is 16 random bytes and therefore unguessable, but that is not relied on for
    /// authorization: a link that leaks would otherwise be a capability with no way to revoke it.
    pub fn may_fetch_attachment(&self, blob_id: &[u8; 16], device: &DeviceId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT 1 FROM attachments a
                  JOIN conversation_members m ON m.conversation_id = a.conversation_id
                 WHERE a.blob_id = $1 AND m.device_id = $2",
                &[&blob_id.as_slice(), &device.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    /// Delete attachment rows past the TTL, returning the ids so their bytes can be removed too.
    /// Bounded like the envelope sweep so a backlog drains across ticks instead of locking.
    pub fn purge_stale_attachments(
        &self,
        ttl: std::time::Duration,
        batch_size: i64,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "DELETE FROM attachments WHERE blob_id IN (
                     SELECT blob_id FROM attachments
                     WHERE created_at < now() - make_interval(secs => $1)
                     ORDER BY created_at
                     LIMIT $2)
                 RETURNING blob_id",
                &[&ttl.as_secs_f64(), &batch_size],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| id16(r.get::<_, &[u8]>(0)))
            .collect()
    }

    /// List the conversations a device belongs to, most recent first, each with its member
    /// account ids. Rows for one conversation are contiguous (ordered by created_at then
    /// conversation_id), so they group in a single pass.
    pub fn list_conversations(&self, device: &DeviceId) -> StoreResult<Vec<ConversationSummary>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT c.conversation_id, m2.account_id
                 FROM conversation_members m1
                 JOIN conversations c ON c.conversation_id = m1.conversation_id
                 JOIN conversation_members m2 ON m2.conversation_id = c.conversation_id
                 WHERE m1.device_id = $1
                 ORDER BY c.created_at DESC, c.conversation_id, m2.account_id",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;

        let mut out: Vec<ConversationSummary> = Vec::new();
        for row in rows {
            let cid = id16(row.get::<_, &[u8]>(0))?;
            let account = id16(row.get::<_, &[u8]>(1))?;
            match out.last_mut() {
                Some(last) if last.conversation_id == cid => {
                    if !last.member_account_ids.contains(&account) {
                        last.member_account_ids.push(account);
                    }
                }
                _ => out.push(ConversationSummary {
                    conversation_id: cid,
                    member_account_ids: vec![account],
                }),
            }
        }
        Ok(out)
    }

    pub fn is_member(&self, conversation_id: &[u8; 16], device: &DeviceId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND device_id = $2",
                &[&conversation_id.as_slice(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    /// Store an opaque envelope for a single recipient device (used for targeted messages
    /// like MLS Welcomes). Idempotent: a retry with the same `idempotency_key` **and identical
    /// payload** returns the existing envelope id rather than inserting a duplicate.
    ///
    /// Idempotency-key scope (defined precisely): a key belongs to the **sender device** and
    /// identifies one logical send — same conversation, same ciphertext bytes. Reusing a key with
    /// a different payload or conversation is refused (`IdempotencyMismatch`), never silently
    /// deduplicated: silent dedup would drop the new message while reporting success.
    pub fn send_targeted(
        &self,
        conversation_id: &[u8; 16],
        sender_device: &DeviceId,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SendOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        if !member_in_txn(&mut txn, conversation_id, sender_device.as_bytes())? {
            return Ok(SendOutcome::Forbidden);
        }
        if let Some(reason) =
            send_refusal_in_txn(&mut txn, conversation_id, sender_device.as_bytes())?
        {
            return Ok(SendOutcome::Muted { reason });
        }
        if idem_key_conflicts(
            &mut txn,
            conversation_id,
            sender_device,
            ciphertext,
            idempotency_key,
        )? {
            return Ok(SendOutcome::IdempotencyMismatch);
        }
        // Insert, or on idempotent conflict fetch the existing row's id.
        let inserted = txn
            .query_opt(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (sender_device, recipient_device, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
                 RETURNING id",
                &[
                    &conversation_id.as_slice(),
                    &sender_device.as_bytes(),
                    &recipient_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        let id = match inserted {
            Some(row) => row.get::<_, i64>(0),
            None => txn
                .query_one(
                    "SELECT id FROM envelopes
                     WHERE sender_device = $1 AND recipient_device = $2 AND idempotency_key = $3",
                    &[
                        &sender_device.as_bytes(),
                        &recipient_device.as_bytes(),
                        &idempotency_key.as_slice(),
                    ],
                )
                .map_err(db_err)?
                .get::<_, i64>(0),
        };
        txn.commit().map_err(db_err)?;
        Ok(SendOutcome::Queued(id))
    }

    /// Fan out one ciphertext to every OTHER member device of a conversation in a single
    /// round trip and a single statement (`INSERT ... SELECT ... ON CONFLICT DO NOTHING`).
    /// This matches MLS semantics — an application message is one ciphertext the whole group
    /// decrypts — so the client uploads once instead of once per recipient. Idempotent per
    /// `idempotency_key`.
    pub fn fanout_message(
        &self,
        conversation_id: &[u8; 16],
        sender_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<FanoutOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        if !member_in_txn(&mut txn, conversation_id, sender_device.as_bytes())? {
            return Ok(FanoutOutcome::Forbidden);
        }
        if let Some(reason) =
            send_refusal_in_txn(&mut txn, conversation_id, sender_device.as_bytes())?
        {
            return Ok(FanoutOutcome::Muted { reason });
        }
        if idem_key_conflicts(
            &mut txn,
            conversation_id,
            sender_device,
            ciphertext,
            idempotency_key,
        )? {
            return Ok(FanoutOutcome::IdempotencyMismatch);
        }
        let rows = txn
            .query(
                "INSERT INTO envelopes
                     (conversation_id, sender_device, recipient_device, ciphertext, idempotency_key)
                 SELECT $1, $2, cm.device_id, $3, $4
                 FROM conversation_members cm
                 WHERE cm.conversation_id = $1 AND cm.device_id <> $2
                 ON CONFLICT (sender_device, recipient_device, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
                 RETURNING recipient_device",
                &[
                    &conversation_id.as_slice(),
                    &sender_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;

        let newly_queued = rows
            .into_iter()
            .map(|r| id16(r.get::<_, &[u8]>(0)))
            .collect::<StoreResult<Vec<_>>>()?;
        crate::metrics::ENVELOPES_ENQUEUED.add(newly_queued.len() as u64);
        Ok(FanoutOutcome::Delivered { newly_queued })
    }

    /// **Peek** a device's undelivered envelopes, in order, WITHOUT marking them delivered.
    /// This is at-least-once delivery: the client persists them locally and then calls
    /// [`Self::ack_envelopes`]. If the client crashes between peek and ack, it simply
    /// re-peeks and re-processes (deduping by envelope id) — no message is lost, unlike the
    /// old mark-on-fetch model where a lost response silently dropped mail.
    pub fn peek_inbox(&self, device: &DeviceId, limit: i64) -> StoreResult<Vec<EnvelopeOut>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT id, conversation_id, sender_device, ciphertext
                 FROM envelopes
                 WHERE recipient_device = $1 AND NOT delivered
                 ORDER BY id LIMIT $2",
                &[&device.as_bytes(), &limit],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(EnvelopeOut {
                    id: r.get(0),
                    conversation_id: id16(r.get::<_, &[u8]>(1))?,
                    sender_device: id16(r.get::<_, &[u8]>(2))?,
                    ciphertext: r.get::<_, Vec<u8>>(3),
                })
            })
            .collect()
    }

    /// Acknowledge durably-persisted envelopes: **delete** them. DATA_RETENTION.md commits to
    /// "purged from server on delivery ack" — the recipient's device is the store, so retaining
    /// acked ciphertext would be a silent retention violation. Scoped to the caller's own device,
    /// so a client cannot ack (delete) another device's mail. Idempotent: re-acking deleted ids is
    /// a no-op. Returns the number of rows purged.
    pub fn ack_envelopes(&self, device: &DeviceId, ids: &[i64]) -> StoreResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn()?;
        let acked = conn
            .execute(
                "DELETE FROM envelopes WHERE recipient_device = $1 AND id = ANY($2)",
                &[&device.as_bytes(), &ids],
            )
            .map_err(db_err)?;
        crate::metrics::ENVELOPES_DELIVERED.add(acked);
        Ok(acked)
    }

    /// Sample the gauges that describe capacity rather than events.
    ///
    /// Polled on the existing retention tick rather than maintained incrementally: queue depth is
    /// a property of the DATABASE, not of this process, so a counter kept in memory would be wrong
    /// the moment a second instance existed or this one restarted. Failure is not fatal — stale
    /// metrics are better than a monitoring path that can take the service down.
    pub fn sample_capacity_gauges(&self) {
        if let Ok(mut conn) = self.pool.get() {
            if let Ok(row) =
                conn.query_one("SELECT count(*) FROM envelopes WHERE NOT delivered", &[])
            {
                crate::metrics::QUEUE_DEPTH.set(row.get::<_, i64>(0));
            }
        } else {
            // A checkout timeout here is itself the signal: the pool is saturated.
            crate::metrics::DB_POOL_WAIT_FAILURES.incr();
        }
        let state = self.pool.state();
        crate::metrics::DB_POOL_IN_USE
            .set(i64::from(state.connections) - i64::from(state.idle_connections));
    }

    /// Retention TTL (DATA_RETENTION.md): purge envelopes older than `ttl` (the 30-day queue
    /// TTL — the sender's client shows "failed" after this). Returns rows purged.
    ///
    /// Deletes in **bounded batches** (`batch_size` rows via the `envelopes_created_at` index, at
    /// most `max_batches` per call): one unbounded `DELETE` over a large backlog would hold locks
    /// and generate a WAL spike that stalls concurrent sends — the failure mode that matters at
    /// scale. A backlog larger than `batch_size * max_batches` simply drains across successive
    /// ticks of the minutely purge task.
    pub fn purge_stale_envelopes(
        &self,
        ttl: std::time::Duration,
        batch_size: i64,
        max_batches: u32,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let ttl_secs = ttl.as_secs_f64();
        let mut total: u64 = 0;
        for _ in 0..max_batches {
            let purged = conn
                .execute(
                    "DELETE FROM envelopes WHERE id IN (
                         SELECT id FROM envelopes
                         WHERE created_at < now() - make_interval(secs => $1)
                         ORDER BY created_at
                         LIMIT $2)",
                    &[&ttl_secs, &batch_size],
                )
                .map_err(db_err)?;
            total += purged;
            if purged < batch_size as u64 {
                break; // backlog drained
            }
        }
        Ok(total)
    }

    /// Store a **sealed** envelope for `recipient_device` (ADR-0014 Slice 2b). No sender or
    /// conversation is recorded. Idempotent on `(recipient_device, idempotency_key)`: a retry with
    /// the same key is a `Duplicate` no-op (the key is a 128-bit sender-chosen random, so a
    /// cross-sender collision is ~2^-128). The DAK gate is enforced by the caller *before* this.
    pub fn deliver_sealed(
        &self,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SealedSendOutcome> {
        let mut conn = self.conn()?;
        let idem = idempotency_key.as_slice();
        let row = conn
            .query_opt(
                "INSERT INTO sealed_envelopes (recipient_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (recipient_device, idempotency_key) DO NOTHING
                 RETURNING id",
                &[&recipient_device.as_bytes(), &ciphertext, &idem],
            )
            .map_err(db_err)?;
        Ok(match row {
            Some(r) => SealedSendOutcome::Enqueued { id: r.get(0) },
            None => SealedSendOutcome::Duplicate,
        })
    }

    /// Peek a device's undelivered **sealed** envelopes (at-least-once, like [`Self::peek_inbox`]).
    pub fn peek_sealed_inbox(
        &self,
        device: &DeviceId,
        limit: i64,
    ) -> StoreResult<Vec<SealedEnvelopeOut>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT id, ciphertext FROM sealed_envelopes
                 WHERE recipient_device = $1 AND NOT delivered
                 ORDER BY id LIMIT $2",
                &[&device.as_bytes(), &limit],
            )
            .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| SealedEnvelopeOut {
                id: r.get(0),
                ciphertext: r.get::<_, Vec<u8>>(1),
            })
            .collect())
    }

    /// Acknowledge (delete) sealed envelopes, scoped to the caller's own device.
    pub fn ack_sealed(&self, device: &DeviceId, ids: &[i64]) -> StoreResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn()?;
        let acked = conn
            .execute(
                "DELETE FROM sealed_envelopes WHERE recipient_device = $1 AND id = ANY($2)",
                &[&device.as_bytes(), &ids],
            )
            .map_err(db_err)?;
        Ok(acked)
    }

    /// Retention purge for sealed envelopes (mirrors [`Self::purge_stale_envelopes`]).
    pub fn purge_stale_sealed(
        &self,
        ttl: std::time::Duration,
        batch_size: i64,
        max_batches: u32,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let ttl_secs = ttl.as_secs_f64();
        let mut total: u64 = 0;
        for _ in 0..max_batches {
            let purged = conn
                .execute(
                    "DELETE FROM sealed_envelopes WHERE id IN (
                         SELECT id FROM sealed_envelopes
                         WHERE created_at < now() - make_interval(secs => $1)
                         ORDER BY created_at
                         LIMIT $2)",
                    &[&ttl_secs, &batch_size],
                )
                .map_err(db_err)?;
            total += purged;
            if purged < batch_size as u64 {
                break;
            }
        }
        Ok(total)
    }

    // ----- Device self-group (ADR-0015 option 3) --------------------------------------------------
    //
    // Establishing + using the account's own-devices MLS group over the relay. The relay is MLS-blind
    // throughout: it never sees the self-group's group id or plaintext, only routes opaque ciphertext
    // among ONE account's authenticated devices. Every method here is account-scoped by construction.

    /// Record that `device` (of `account`) has joined its account's self-group. Idempotent — a repeat
    /// is a no-op. The caller authenticates as this device, so no cross-account membership is
    /// representable.
    pub fn register_self_group_member(
        &self,
        account: &AccountId,
        device: &DeviceId,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO self_group_members (account_id, device_id) VALUES ($1, $2)
             ON CONFLICT (account_id, device_id) DO NOTHING",
            &[&account.as_bytes(), &device.as_bytes()],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ----- App Attest (#10) -----------------------------------------------------------------------

    /// Issue (upsert) a short-lived attestation challenge for a device. The client folds it into its
    /// attestation object; the server later matches it (anti-replay).
    pub fn issue_attest_challenge(
        &self,
        device: &DeviceId,
        challenge: &[u8; 32],
        ttl_secs: u64,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO app_attest_challenges (device_id, challenge, expires_at)
             VALUES ($1, $2, now() + make_interval(secs => $3))
             ON CONFLICT (device_id)
             DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at",
            &[
                &device.as_bytes(),
                &challenge.as_slice(),
                &(ttl_secs as f64),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Consume a device's challenge iff `presented` matches the stored, non-expired one. Deletes it
    /// on success (single-use). Returns whether it matched.
    pub fn consume_attest_challenge(
        &self,
        device: &DeviceId,
        presented: &[u8],
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "DELETE FROM app_attest_challenges
                 WHERE device_id = $1 AND challenge = $2 AND expires_at > now()
                 RETURNING 1",
                &[&device.as_bytes(), &presented],
            )
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    /// Store a device's submitted App Attest attestation. `verified` records whether the
    /// attestation object passed cryptographic verification against the pinned Apple root
    /// (`crate::attest`); unconfigured (bootstrap) deployments store `false`. Upsert.
    pub fn store_attestation(
        &self,
        device: &DeviceId,
        key_id: &str,
        attestation: &[u8],
        verified: bool,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO app_attest_keys (device_id, key_id, attestation, verified)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (device_id)
             DO UPDATE SET key_id = EXCLUDED.key_id, attestation = EXCLUDED.attestation,
                           verified = EXCLUDED.verified, created_at = now()",
            &[&device.as_bytes(), &key_id, &attestation, &verified],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// A device's stored attestation `(key_id, verified)`, if any (for status / the future verifier).
    pub fn attestation_for_device(&self, device: &DeviceId) -> StoreResult<Option<(String, bool)>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT key_id, verified FROM app_attest_keys WHERE device_id = $1",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.map(|r| (r.get::<_, String>(0), r.get::<_, bool>(1))))
    }

    // ----- Push notification tokens (#4) ----------------------------------------------------------

    /// Register (or rotate) a device's push token for a platform (`apns`). Upsert — one token per
    /// (device, platform). The token is opaque to the relay; it addresses a contentless wake push.
    pub fn register_push_token(
        &self,
        device: &DeviceId,
        platform: &str,
        token: &str,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        // A push token identifies ONE device. APNs really does reassign a token to a reinstalled
        // app, and the previous owner's row would otherwise keep it: that device then receives
        // wake pushes meant for the new one, leaking "this other account has mail" to whoever now
        // holds the token. Registering therefore TRANSFERS ownership — the old claim is released
        // first, which is also what keeps the `device_push_tokens_one_owner` index satisfied.
        txn.execute(
            "DELETE FROM device_push_tokens
             WHERE platform = $2 AND token = $3 AND device_id <> $1",
            &[&device.as_bytes(), &platform, &token],
        )
        .map_err(db_err)?;
        txn.execute(
            "INSERT INTO device_push_tokens (device_id, platform, token, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (device_id, platform)
             DO UPDATE SET token = EXCLUDED.token, updated_at = now()",
            &[&device.as_bytes(), &platform, &token],
        )
        .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// This device's registered push tokens as `(platform, token)` pairs.
    pub fn push_tokens_for_device(&self, device: &DeviceId) -> StoreResult<Vec<(String, String)>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT platform, token FROM device_push_tokens WHERE device_id = $1",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
            .collect())
    }

    /// Delete all of a device's push tokens (on revocation). Idempotent; returns rows removed.
    pub fn delete_push_tokens(&self, device: &DeviceId) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let removed = conn
            .execute(
                "DELETE FROM device_push_tokens WHERE device_id = $1",
                &[&device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(removed)
    }

    /// Drop a device from its account's self-group membership (housekeeping when the device is
    /// revoked). Idempotent. The *cryptographic* re-key is a client action (an existing device issues
    /// an MLS remove-commit); this just stops the relay routing self-group traffic to it and keeps
    /// the pending-devices view accurate. Returns rows removed.
    pub fn remove_self_group_member(
        &self,
        account: &AccountId,
        device: &DeviceId,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let removed = conn
            .execute(
                "DELETE FROM self_group_members WHERE account_id = $1 AND device_id = $2",
                &[&account.as_bytes(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(removed)
    }

    /// True if `device` is a joined member of `account`'s self-group.
    pub fn is_self_group_member(
        &self,
        account: &AccountId,
        device: &DeviceId,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT 1 FROM self_group_members WHERE account_id = $1 AND device_id = $2",
                &[&account.as_bytes(), &device.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    /// The account's non-revoked devices that are enrolled but NOT yet in its self-group — the
    /// candidates a linking device claims a key package for and adds. Excludes `caller` itself.
    pub fn pending_self_group_devices(
        &self,
        account: &AccountId,
        caller: &DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT d.device_id FROM devices d
                 WHERE d.account_id = $1 AND NOT d.revoked AND d.device_id <> $2
                   AND NOT EXISTS (
                       SELECT 1 FROM self_group_members m
                       WHERE m.account_id = $1 AND m.device_id = d.device_id)
                 ORDER BY d.device_id",
                &[&account.as_bytes(), &caller.as_bytes()],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| id16(r.get::<_, &[u8]>(0)))
            .collect()
    }

    /// Claim (pop) one non-expired key package for a **specific** device (used to add a named sibling
    /// device to the self-group). Like [`Self::claim_key_package`] but scoped to one device rather
    /// than any of the account's devices, so a multi-device link targets each sibling deterministically.
    pub fn claim_key_package_for_device(
        &self,
        device: &DeviceId,
        ttl_secs: u64,
    ) -> StoreResult<Option<ClaimedKeyPackage>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "DELETE FROM key_packages WHERE id = (
                     SELECT id FROM key_packages
                     WHERE device_id = $1 AND created_at > now() - make_interval(secs => $2)
                     ORDER BY id LIMIT 1
                     FOR UPDATE SKIP LOCKED
                 ) RETURNING device_id, key_package",
                &[&device.as_bytes(), &(ttl_secs as f64)],
            )
            .map_err(db_err)?;
        row.map(|r| {
            Ok(ClaimedKeyPackage {
                device_id: id16(r.get::<_, &[u8]>(0))?,
                key_package: r.get::<_, Vec<u8>>(1),
            })
        })
        .transpose()
    }

    /// Deliver a self-group envelope to ONE specific recipient device of `account` (an MLS Welcome to
    /// a device being linked, or a commit to an existing member). Refuses if the recipient is not a
    /// non-revoked device of `account`. Idempotent on `(recipient, sender, idempotency_key)`.
    pub fn deliver_self_group_targeted(
        &self,
        account: &AccountId,
        sender_device: &DeviceId,
        recipient_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SelfGroupSendOutcome> {
        let mut conn = self.conn()?;
        let mut txn = conn.transaction().map_err(db_err)?;
        // The recipient must be a non-revoked device of the SAME account (authorization boundary).
        let ok = txn
            .query_opt(
                "SELECT 1 FROM devices WHERE device_id = $1 AND account_id = $2 AND NOT revoked",
                &[&recipient_device.as_bytes(), &account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some();
        if !ok {
            return Ok(SelfGroupSendOutcome::Forbidden);
        }
        let row = txn
            .query_opt(
                "INSERT INTO self_group_envelopes
                     (recipient_device, sender_device, ciphertext, idempotency_key)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (recipient_device, sender_device, idempotency_key) DO NOTHING
                 RETURNING recipient_device",
                &[
                    &recipient_device.as_bytes(),
                    &sender_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        let newly_queued = match row {
            Some(_) => vec![recipient_device.0],
            None => vec![], // idempotent retry
        };
        Ok(SelfGroupSendOutcome::Delivered { newly_queued })
    }

    /// Fan a self-group envelope out to every OTHER **joined member** of `account`'s self-group (a
    /// `SecretConsumed` control message, or a commit to the whole self-group). Excludes the sender and
    /// any revoked device. Idempotent per key. One statement, mirroring [`Self::fanout_message`].
    pub fn fanout_self_group(
        &self,
        account: &AccountId,
        sender_device: &DeviceId,
        ciphertext: &[u8],
        idempotency_key: &[u8; 16],
    ) -> StoreResult<SelfGroupSendOutcome> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "INSERT INTO self_group_envelopes
                     (recipient_device, sender_device, ciphertext, idempotency_key)
                 SELECT m.device_id, $2, $3, $4
                 FROM self_group_members m
                 JOIN devices d ON d.device_id = m.device_id
                 WHERE m.account_id = $1 AND m.device_id <> $2 AND NOT d.revoked
                 ON CONFLICT (recipient_device, sender_device, idempotency_key) DO NOTHING
                 RETURNING recipient_device",
                &[
                    &account.as_bytes(),
                    &sender_device.as_bytes(),
                    &ciphertext,
                    &idempotency_key.as_slice(),
                ],
            )
            .map_err(db_err)?;
        let newly_queued = rows
            .into_iter()
            .map(|r| id16(r.get::<_, &[u8]>(0)))
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(SelfGroupSendOutcome::Delivered { newly_queued })
    }

    /// Peek a device's undelivered self-group envelopes (at-least-once, like [`Self::peek_inbox`]).
    pub fn peek_self_group_inbox(
        &self,
        device: &DeviceId,
        limit: i64,
    ) -> StoreResult<Vec<SelfGroupEnvelopeOut>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT id, sender_device, ciphertext FROM self_group_envelopes
                 WHERE recipient_device = $1 AND NOT delivered
                 ORDER BY id LIMIT $2",
                &[&device.as_bytes(), &limit],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(SelfGroupEnvelopeOut {
                    id: r.get(0),
                    sender_device: id16(r.get::<_, &[u8]>(1))?,
                    ciphertext: r.get::<_, Vec<u8>>(2),
                })
            })
            .collect()
    }

    /// Acknowledge (delete) self-group envelopes, scoped to the caller's own device.
    pub fn ack_self_group(&self, device: &DeviceId, ids: &[i64]) -> StoreResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn()?;
        let acked = conn
            .execute(
                "DELETE FROM self_group_envelopes WHERE recipient_device = $1 AND id = ANY($2)",
                &[&device.as_bytes(), &ids],
            )
            .map_err(db_err)?;
        Ok(acked)
    }

    /// Retention purge for self-group envelopes (mirrors [`Self::purge_stale_envelopes`]).
    pub fn purge_stale_self_group(
        &self,
        ttl: std::time::Duration,
        batch_size: i64,
        max_batches: u32,
    ) -> StoreResult<u64> {
        let mut conn = self.conn()?;
        let ttl_secs = ttl.as_secs_f64();
        let mut total: u64 = 0;
        for _ in 0..max_batches {
            let purged = conn
                .execute(
                    "DELETE FROM self_group_envelopes WHERE id IN (
                         SELECT id FROM self_group_envelopes
                         WHERE created_at < now() - make_interval(secs => $1)
                         ORDER BY created_at
                         LIMIT $2)",
                    &[&ttl_secs, &batch_size],
                )
                .map_err(db_err)?;
            total += purged;
            if purged < batch_size as u64 {
                break;
            }
        }
        Ok(total)
    }
}

/// True if this sender has already used `idempotency_key` for a DIFFERENT payload or
/// conversation. Runs inside the send transaction, only touching the sender's own rows via the
/// `envelopes_idem` index prefix. A `true` result must abort the send: the key identifies one
/// logical message, and silently deduplicating a *different* message would drop it.
fn idem_key_conflicts(
    txn: &mut postgres::Transaction<'_>,
    conversation_id: &[u8; 16],
    sender_device: &DeviceId,
    ciphertext: &[u8],
    idempotency_key: &[u8; 16],
) -> StoreResult<bool> {
    let row = txn
        .query_opt(
            "SELECT 1 FROM envelopes
             WHERE sender_device = $1 AND idempotency_key = $2
               AND (conversation_id <> $3 OR ciphertext <> $4)
             LIMIT 1",
            &[
                &sender_device.as_bytes(),
                &idempotency_key.as_slice(),
                &conversation_id.as_slice(),
                &ciphertext,
            ],
        )
        .map_err(db_err)?;
    Ok(row.is_some())
}
