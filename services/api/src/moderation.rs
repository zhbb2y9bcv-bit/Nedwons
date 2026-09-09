//! The review team's half of the report pipeline (docs/MODERATION.md): the queue of open
//! reports with their reporter-submitted evidence, the audited resolve action, and account bans.
//!
//! Access model: these stores back `/v1/moderation/*`, which exists ONLY when the deployment
//! configures a moderation token (`NEDWONS_MODERATION_TOKEN`) — an ops-held bearer secret for the
//! review team's tooling, compared in constant time. Reviewers are identified by a handle they
//! send per action, recorded in the audit columns; the token gates access, the handle attributes
//! it. This is deliberately NOT end-user auth: moderation is an operator function.
//!
//! What the server can and cannot do here, stated plainly: it cannot read message content, so a
//! report's evidence is exactly what the reporter decrypted and chose to submit. A ban refuses
//! every authenticated request from the account and blocks new sessions; it does not (cannot)
//! reach into other members' devices, and — with no phone/identity verification — does not stop
//! the person registering a fresh account. Those limits are in MODERATION.md, not hidden.

use auth_core::store::{StoreError, StoreResult};
use auth_core::AccountId;

use crate::pgstore::PgPool;

fn db_err(e: postgres::Error) -> StoreError {
    StoreError(format!("db: {e}"))
}

fn id16(bytes: &[u8]) -> StoreResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError("bad id length".into()))
}

/// One report as the review queue sees it. `evidence_media` is returned only by
/// [`PgModeration::report`] (single fetch), never in the list — the queue stays light.
pub struct ReportRow {
    pub id: i64,
    pub reporter: [u8; 16],
    pub reported: [u8; 16],
    pub category: String,
    pub reason: String,
    pub evidence: Option<String>,
    pub conversation_id: Option<[u8; 16]>,
    pub message_id: Option<[u8; 16]>,
    pub has_media: bool,
    pub status: String,
    pub created_at_unix: i64,
}

/// A full report plus its (bytes, mime) media evidence, when any was submitted.
pub type ReportWithMedia = (ReportRow, Option<(Vec<u8>, String)>);

pub struct BanRow {
    pub account_id: [u8; 16],
    pub reason: String,
    pub banned_by: String,
    pub report_id: Option<i64>,
    pub created_at_unix: i64,
}

pub struct PgModeration {
    pool: PgPool,
}

impl PgModeration {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn conn(
        &self,
    ) -> StoreResult<
        r2d2::PooledConnection<r2d2_postgres::PostgresConnectionManager<postgres::NoTls>>,
    > {
        self.pool
            .get()
            .map_err(|e| StoreError(format!("pool: {e}")))
    }

    /// Record the extended (V28) report fields for a just-created report. Split from
    /// `PgSocial::create_report` so the proven insert path stays untouched; this update is part
    /// of the same request handler.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_report_details(
        &self,
        report_id: i64,
        category: &str,
        conversation_id: Option<&[u8; 16]>,
        message_id: Option<&[u8; 16]>,
        media: Option<&[u8]>,
        media_mime: Option<&str>,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "UPDATE reports SET category = $2, conversation_id = $3, message_id = $4,
                    evidence_media = $5, evidence_media_mime = $6
             WHERE id = $1",
            &[
                &report_id,
                &category,
                &conversation_id.map(|c| c.as_slice()),
                &message_id.map(|m| m.as_slice()),
                &media,
                &media_mime,
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// The review queue: open reports, oldest first (nobody's report waits behind newer ones).
    pub fn open_reports(&self, limit: i64) -> StoreResult<Vec<ReportRow>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT id, reporter, reported, category, reason, evidence, conversation_id,
                        message_id, evidence_media IS NOT NULL, status,
                        extract(epoch FROM created_at)::bigint
                 FROM reports WHERE status = 'open' ORDER BY created_at LIMIT $1",
                &[&limit],
            )
            .map_err(db_err)?;
        rows.into_iter().map(|r| Self::row(&r)).collect()
    }

    /// One report in full (media included).
    pub fn report(&self, id: i64) -> StoreResult<Option<ReportWithMedia>> {
        let mut conn = self.conn()?;
        let row = conn
            .query_opt(
                "SELECT id, reporter, reported, category, reason, evidence, conversation_id,
                        message_id, evidence_media IS NOT NULL, status,
                        extract(epoch FROM created_at)::bigint,
                        evidence_media, evidence_media_mime
                 FROM reports WHERE id = $1",
                &[&id],
            )
            .map_err(db_err)?;
        row.map(|r| {
            let media: Option<Vec<u8>> = r.get(11);
            let mime: Option<String> = r.get(12);
            Ok((
                Self::row(&r)?,
                media.map(|m| (m, mime.unwrap_or_else(|| "application/octet-stream".into()))),
            ))
        })
        .transpose()
    }

    /// Resolve a report with the audit trail filled in. `actioned` says whether the reviewer
    /// took action (typically a ban, recorded separately) or dismissed it. Returns false when
    /// the report was not open (already resolved by another reviewer — first one wins).
    pub fn resolve_report(
        &self,
        id: i64,
        actioned: bool,
        reviewer: &str,
        note: &str,
    ) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let updated = conn
            .execute(
                "UPDATE reports SET status = $2, reviewed_by = $3, reviewed_at = now(),
                        resolution_note = $4
                 WHERE id = $1 AND status = 'open'",
                &[
                    &id,
                    &if actioned { "actioned" } else { "dismissed" },
                    &reviewer,
                    &note,
                ],
            )
            .map_err(db_err)?;
        Ok(updated == 1)
    }

    /// Ban an account (idempotent — a second ban updates the reason/attribution). Enforcement is
    /// at the auth gate; the caller also burns the account's sessions.
    pub fn ban(
        &self,
        account: &AccountId,
        reason: &str,
        banned_by: &str,
        report_id: Option<i64>,
    ) -> StoreResult<()> {
        let mut conn = self.conn()?;
        conn.execute(
            "INSERT INTO bans (account_id, reason, banned_by, report_id)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (account_id)
             DO UPDATE SET reason = EXCLUDED.reason, banned_by = EXCLUDED.banned_by,
                           report_id = EXCLUDED.report_id, created_at = now()",
            &[&account.as_bytes(), &reason, &banned_by, &report_id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Lift a ban. Returns false when the account wasn't banned.
    pub fn unban(&self, account: &AccountId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        let deleted = conn
            .execute(
                "DELETE FROM bans WHERE account_id = $1",
                &[&account.as_bytes()],
            )
            .map_err(db_err)?;
        Ok(deleted == 1)
    }

    /// The auth-gate check. One indexed point read per authenticated request.
    pub fn is_banned(&self, account: &AccountId) -> StoreResult<bool> {
        let mut conn = self.conn()?;
        Ok(conn
            .query_opt(
                "SELECT 1 FROM bans WHERE account_id = $1",
                &[&account.as_bytes()],
            )
            .map_err(db_err)?
            .is_some())
    }

    pub fn bans(&self, limit: i64) -> StoreResult<Vec<BanRow>> {
        let mut conn = self.conn()?;
        let rows = conn
            .query(
                "SELECT account_id, reason, banned_by, report_id,
                        extract(epoch FROM created_at)::bigint
                 FROM bans ORDER BY created_at DESC LIMIT $1",
                &[&limit],
            )
            .map_err(db_err)?;
        rows.into_iter()
            .map(|r| {
                Ok(BanRow {
                    account_id: id16(r.get::<_, &[u8]>(0))?,
                    reason: r.get(1),
                    banned_by: r.get(2),
                    report_id: r.get(3),
                    created_at_unix: r.get(4),
                })
            })
            .collect()
    }

    fn row(r: &postgres::Row) -> StoreResult<ReportRow> {
        Ok(ReportRow {
            id: r.get(0),
            reporter: id16(r.get::<_, &[u8]>(1))?,
            reported: id16(r.get::<_, &[u8]>(2))?,
            category: r.get(3),
            reason: r.get(4),
            evidence: r.get(5),
            conversation_id: r.get::<_, Option<&[u8]>>(6).map(id16).transpose()?,
            message_id: r.get::<_, Option<&[u8]>>(7).map(id16).transpose()?,
            has_media: r.get(8),
            status: r.get(9),
            created_at_unix: r.get(10),
        })
    }
}
