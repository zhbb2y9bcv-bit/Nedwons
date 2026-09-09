/* tslint:disable */
/* eslint-disable */
/**
 * The kind tag on [`InboundResult`]. A Rust enum with payloads cannot cross `wasm_bindgen`, so the
 * tagged union becomes a tag plus nullable payload getters — the standard JS shape.
 */

export type InboundKind = "application" | "state_advanced" | "duplicate" | "secret_sealed" | "secret_consumed_remotely" | "delivery_key_granted" | "history_synced";
/**
 * Mirrors `mls_core::secret::SecretState`.
 */

export type SecretPhase = "sealed" | "countdown" | "visible" | "consumed" | "unknown";

/**
 * Commit fans out to existing members; welcome goes to the new one. Both opaque.
 */
export class AddOutcome {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly commit: Uint8Array;
    readonly welcome: Uint8Array;
}

/**
 * Lets the host assert it links a compatible core and refuse on mismatch (ADR-0007).
 */
export class Capabilities {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly bindingVersion: string;
    readonly ciphersuite: string;
    readonly coreVersion: string;
    readonly maxEnvelope: number;
    readonly maxIdentity: number;
    readonly maxKeyPackage: number;
    readonly maxPlaintext: number;
    readonly maxWelcome: number;
    readonly protocol: string;
    readonly storageFormatVersion: number;
}

/**
 * One past message in a history-sync batch. Secrets are never included.
 */
export class HistoryEntry {
    free(): void;
    [Symbol.dispose](): void;
    constructor(outbound: boolean, body: Uint8Array);
    readonly body: Uint8Array;
    readonly outbound: boolean;
}

export class InboundResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Set only for `history_synced`.
     */
    readonly count: bigint | undefined;
    /**
     * Set only for `delivery_key_granted`.
     */
    readonly keyR: Uint8Array | undefined;
    readonly kind: InboundKind;
    /**
     * Set only for `application`.
     */
    readonly plaintext: Uint8Array | undefined;
    /**
     * Set for `secret_sealed` / `secret_consumed_remotely`.
     */
    readonly secretId: Uint8Array | undefined;
}

/**
 * One identity + one conversation.
 */
export class MlsClient {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Durably processed, so safe to acknowledge to the server.
     */
    ackEligible(): BigUint64Array;
    /**
     * The grown group is durable before returning.
     */
    addMember(key_package: Uint8Array): AddOutcome;
    /**
     * Returns a **wrapped** commit (for existing devices via `processSelfInbound`, which unwraps)
     * plus the **raw** welcome (for the new device via `joinSelfGroup`, which does not).
     */
    addSelfDevice(key_package: Uint8Array): AddOutcome;
    /**
     * **Atomic + fail-closed:** the transition + deadlines are committed before this returns; an
     * invalid transition (double tap, replay) or failed write throws and reveals nothing. `nowMs`
     * is the caller's monotonic clock (`performance.now()`, NOT `Date.now()`).
     */
    beginSecretReveal(secret_id: Uint8Array, now_ms: bigint): void;
    /**
     * Server rejected, or we're rebasing. State unchanged.
     */
    clearStaged(): void;
    /**
     * Erase this device's visible message log when the user deletes the conversation. Protocol
     * state (ratchet, replay watermark, outbox, secret records) is retained, so later messages
     * still decrypt and a replayed secret still cannot be re-revealed. Local only — nothing is
     * sent, and the peer's copy is untouched.
     */
    clearVisibleHistory(): void;
    /**
     * Idempotent. Durable state is untouched — reopen with `open`.
     */
    close(): void;
    confirmAcked(ids: BigUint64Array): void;
    /**
     * Used on an explicit close (or a detected capture, where the platform allows). Idempotent;
     * scrubs the body.
     */
    consumeSecret(secret_id: Uint8Array): void;
    /**
     * This client becomes the group creator/first member. Persists before returning.
     *
     * `journal` is the embedder's synchronous storage host (see `journal.rs` for the atomicity
     * contract it must honour); `atRestKey` is 32 bytes from the caller's key hierarchy.
     */
    static createGroup(identity: Uint8Array, journal: JournalHost, at_rest_key: Uint8Array): MlsClient;
    /**
     * **Volatile**: state lives only for this page's lifetime. For tests and throwaway sessions —
     * never a fallback when the storage host is unavailable, which must surface as an error rather
     * than silently losing the ratchet.
     */
    static createGroupInMemory(identity: Uint8Array): MlsClient;
    /**
     * `wrong_state` if one already exists.
     */
    createSelfGroup(): void;
    /**
     * Produces the versioned opaque envelope (`app-envelope v1`). **Idempotent:** a retry returns
     * the same bytes and never advances the ratchet again — no double-spend of a message key.
     */
    encrypt(local_id: bigint): Uint8Array;
    /**
     * Durable draft; does NOT advance the ratchet.
     */
    enqueue(plaintext: Uint8Array): bigint;
    /**
     * ADR-0014: share `K_r` (exactly 32 bytes) over the E2EE channel — the relay never sees it.
     */
    enqueueDeliveryKeyGrant(key_r: Uint8Array): bigint;
    /**
     * Replicate `entries` over the self-group. `wrong_state` if none is established.
     */
    enqueueHistorySync(entries: HistoryEntry[]): bigint;
    /**
     * The classification + body are encrypted inside the content envelope, so the relay never
     * learns a message is secret. `encrypt`/`markSent` then proceed exactly as for a normal one.
     */
    enqueueSecret(body: Uint8Array): SecretHandle;
    epoch(): bigint;
    hasSelfGroup(): boolean;
    /**
     * Up to `max` recent non-secret messages, for replication to a newly-linked device.
     */
    historyEntries(max: number): HistoryEntry[];
    /**
     * `Pending` → `Active`, persisted. On a bad Welcome the client stays `Pending` (retryable).
     */
    joinGroup(welcome: Uint8Array): void;
    joinSelfGroup(welcome: Uint8Array): void;
    /**
     * A one-time prekey to publish so others can add this client.
     */
    keyPackage(): Uint8Array;
    markSent(local_id: bigint): void;
    /**
     * Server accepted: advance the epoch and persist.
     */
    mergeStaged(): void;
    /**
     * Cheap: no payload crosses the boundary.
     */
    messageCount(): bigint;
    /**
     * Bounded window, oldest first. `limit` is clamped to `MAX_PAGE_MESSAGES` so one call can never
     * marshal an unbounded payload; an offset past the end returns an empty page.
     *
     * There is deliberately no "all messages" call here: the UniFFI surface has one only for tests,
     * and R-105 (whole-history rewrite per commit) bites harder in a browser.
     */
    messagesPage(offset: bigint, limit: number): StoredMessage[];
    /**
     * Create a fresh identity that will JOIN an existing group: publish `keyPackage()`, then
     * `joinGroup(welcome)` once added. The pending identity is not yet durable — if the page dies
     * before joining, request a fresh key package.
     */
    static newJoiner(identity: Uint8Array, journal: JournalHost, at_rest_key: Uint8Array): MlsClient;
    /**
     * Volatile joiner, the counterpart to [`Self::create_group_in_memory`]. Same warning: nothing
     * survives a reload.
     */
    static newJoinerInMemory(identity: Uint8Array): MlsClient;
    /**
     * Reopen the last durably-committed session (reload / crash recovery).
     */
    static open(journal: JournalHost, at_rest_key: Uint8Array): MlsClient;
    /**
     * ADR-0010 recipient path: merges ONLY if the commit's actual effect equals the sender's signed
     * manifest. On mismatch: discarded unmerged, `invalid_message`, state unchanged.
     *
     * `added`/`removed` are arrays of identity byte-arrays taken from that manifest.
     */
    processCommit(envelope: Uint8Array, next_epoch: bigint, added: Array<any>, removed: Array<any>): void;
    /**
     * All effects — advanced ratchet, stored message, dedup marker, ack-eligibility — are durable
     * together before returning. Idempotent per `envelopeId`.
     */
    processInbound(envelope_id: bigint, ciphertext: Uint8Array): InboundResult;
    /**
     * Self-group channel (ADR-0015 option 3): a `SecretConsumed` from another of this account's
     * devices, or a self-group membership commit. Same dedup + ack contract.
     */
    processSelfInbound(envelope_id: bigint, ciphertext: Uint8Array): InboundResult;
    /**
     * Used when that device is revoked. The returned remove-commit advances the epoch, so the
     * removed device cannot decrypt later self-group traffic even if it kept old ratchet state.
     */
    removeSelfDevice(identity: Uint8Array): Uint8Array;
    /**
     * The consumption control message for a secret this device revealed (ADR-0015). `null` if the
     * secret is unknown, the sender's own, or unrevealed here. Idempotent: repeated calls return
     * the same envelope and never double-advance the ratchet.
     */
    secretConsumptionEnvelope(secret_id: Uint8Array): Uint8Array | undefined;
    secretPhase(secret_id: Uint8Array, now_ms: bigint): SecretPhase;
    secretRemaining(secret_id: Uint8Array, now_ms: bigint): SecretRemaining;
    /**
     * The plaintext gate: `null` while sealed/counting down and forever after expiry (which also
     * scrubs + persists).
     */
    secretVisibleBody(secret_id: Uint8Array, now_ms: bigint): Uint8Array | undefined;
    /**
     * Builds commit + welcome WITHOUT advancing the epoch or persisting. Sign a manifest, POST
     * `/commit`, then `mergeStaged()` on success or `clearStaged()` on rejection. Never merge
     * before the server's epoch CAS confirms — that is how a race loser desyncs.
     */
    stageAdd(key_package: Uint8Array): AddOutcome;
    stageRemove(identity: Uint8Array): Uint8Array;
    /**
     * 0 = pre-versioning; a pending client also reports 0.
     */
    storageFormatVersion(): number;
}

export class SecretHandle {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly localId: bigint;
    readonly secretId: Uint8Array;
}

/**
 * Both 0 outside that phase. Drives the UI timer/fade.
 */
export class SecretRemaining {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly countdownMs: bigint;
    readonly viewMs: bigint;
}

/**
 * What the UI renders.
 */
export class StoredMessage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly envelopeId: bigint | undefined;
    readonly localId: bigint;
    /**
     * True if this account sent it. (The UniFFI surface uses a `Direction` enum; a boolean is the
     * idiomatic JS equivalent of a two-variant enum and avoids a needless exported type.)
     */
    readonly outbound: boolean;
    /**
     * EMPTY when `secretId` is set — render the placeholder/tombstone from `secretPhase`, never
     * this.
     */
    readonly plaintext: Uint8Array;
    /**
     * `Some` (16 bytes) for a view-once secret.
     */
    readonly secretId: Uint8Array | undefined;
}

export function bindingVersion(): string;

/**
 * Machine-checkable version compatibility.
 */
export function capabilities(): Capabilities;

/**
 * Bundled system text — never an external resource that could fail at runtime.
 */
export function secretTombstoneText(): string;

/**
 * Route Rust panics to `console.error` with a stack trace. Without this a panic surfaces in JS as
 * an opaque `unreachable executed`. Safe to call more than once; call it first from the host.
 */
export function setPanicHook(): void;
