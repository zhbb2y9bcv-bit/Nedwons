/* @ts-self-types="./mls_wasm.d.ts" */

/**
 * Commit fans out to existing members; welcome goes to the new one. Both opaque.
 */
class AddOutcome {
    static __wrap(ptr) {
        const obj = Object.create(AddOutcome.prototype);
        obj.__wbg_ptr = ptr;
        AddOutcomeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        AddOutcomeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_addoutcome_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get commit() {
        const ret = wasm.addoutcome_commit(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    get welcome() {
        const ret = wasm.addoutcome_welcome(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) AddOutcome.prototype[Symbol.dispose] = AddOutcome.prototype.free;
exports.AddOutcome = AddOutcome;

/**
 * Lets the host assert it links a compatible core and refuse on mismatch (ADR-0007).
 */
class Capabilities {
    static __wrap(ptr) {
        const obj = Object.create(Capabilities.prototype);
        obj.__wbg_ptr = ptr;
        CapabilitiesFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CapabilitiesFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_capabilities_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get bindingVersion() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.capabilities_bindingVersion(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get ciphersuite() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.capabilities_ciphersuite(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get coreVersion() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.capabilities_coreVersion(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {number}
     */
    get maxEnvelope() {
        const ret = wasm.capabilities_maxEnvelope(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    get maxIdentity() {
        const ret = wasm.capabilities_maxIdentity(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    get maxKeyPackage() {
        const ret = wasm.capabilities_maxKeyPackage(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    get maxPlaintext() {
        const ret = wasm.capabilities_maxPlaintext(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    get maxWelcome() {
        const ret = wasm.capabilities_maxWelcome(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {string}
     */
    get protocol() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.capabilities_protocol(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {number}
     */
    get storageFormatVersion() {
        const ret = wasm.capabilities_storageFormatVersion(this.__wbg_ptr);
        return ret >>> 0;
    }
}
if (Symbol.dispose) Capabilities.prototype[Symbol.dispose] = Capabilities.prototype.free;
exports.Capabilities = Capabilities;

/**
 * One past message in a history-sync batch. Secrets are never included.
 */
class HistoryEntry {
    static __wrap(ptr) {
        const obj = Object.create(HistoryEntry.prototype);
        obj.__wbg_ptr = ptr;
        HistoryEntryFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    static __unwrap(jsValue) {
        if (!(jsValue instanceof HistoryEntry)) {
            return 0;
        }
        return jsValue.__destroy_into_raw();
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        HistoryEntryFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_historyentry_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get body() {
        const ret = wasm.historyentry_body(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {boolean} outbound
     * @param {Uint8Array} body
     */
    constructor(outbound, body) {
        const ptr0 = passArray8ToWasm0(body, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.historyentry_new(outbound, ptr0, len0);
        this.__wbg_ptr = ret;
        HistoryEntryFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @returns {boolean}
     */
    get outbound() {
        const ret = wasm.historyentry_outbound(this.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) HistoryEntry.prototype[Symbol.dispose] = HistoryEntry.prototype.free;
exports.HistoryEntry = HistoryEntry;

class InboundResult {
    static __wrap(ptr) {
        const obj = Object.create(InboundResult.prototype);
        obj.__wbg_ptr = ptr;
        InboundResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        InboundResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_inboundresult_free(ptr, 0);
    }
    /**
     * Set only for `history_synced`.
     * @returns {bigint | undefined}
     */
    get count() {
        const ret = wasm.inboundresult_count(this.__wbg_ptr);
        return ret[0] === 0 ? undefined : BigInt.asUintN(64, ret[1]);
    }
    /**
     * Set only for `delivery_key_granted`.
     * @returns {Uint8Array | undefined}
     */
    get keyR() {
        const ret = wasm.inboundresult_keyR(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {InboundKind}
     */
    get kind() {
        const ret = wasm.inboundresult_kind(this.__wbg_ptr);
        return __wbindgen_enum_InboundKind[ret];
    }
    /**
     * Set only for `application`.
     * @returns {Uint8Array | undefined}
     */
    get plaintext() {
        const ret = wasm.inboundresult_plaintext(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Set for `secret_sealed` / `secret_consumed_remotely`.
     * @returns {Uint8Array | undefined}
     */
    get secretId() {
        const ret = wasm.inboundresult_secretId(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
}
if (Symbol.dispose) InboundResult.prototype[Symbol.dispose] = InboundResult.prototype.free;
exports.InboundResult = InboundResult;

/**
 * One identity + one conversation.
 */
class MlsClient {
    static __wrap(ptr) {
        const obj = Object.create(MlsClient.prototype);
        obj.__wbg_ptr = ptr;
        MlsClientFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        MlsClientFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_mlsclient_free(ptr, 0);
    }
    /**
     * Durably processed, so safe to acknowledge to the server.
     * @returns {BigUint64Array}
     */
    ackEligible() {
        const ret = wasm.mlsclient_ackEligible(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU64FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 8, 8);
        return v1;
    }
    /**
     * The grown group is durable before returning.
     * @param {Uint8Array} key_package
     * @returns {AddOutcome}
     */
    addMember(key_package) {
        const ptr0 = passArray8ToWasm0(key_package, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_addMember(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return AddOutcome.__wrap(ret[0]);
    }
    /**
     * Returns a **wrapped** commit (for existing devices via `processSelfInbound`, which unwraps)
     * plus the **raw** welcome (for the new device via `joinSelfGroup`, which does not).
     * @param {Uint8Array} key_package
     * @returns {AddOutcome}
     */
    addSelfDevice(key_package) {
        const ptr0 = passArray8ToWasm0(key_package, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_addSelfDevice(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return AddOutcome.__wrap(ret[0]);
    }
    /**
     * **Atomic + fail-closed:** the transition + deadlines are committed before this returns; an
     * invalid transition (double tap, replay) or failed write throws and reveals nothing. `nowMs`
     * is the caller's monotonic clock (`performance.now()`, NOT `Date.now()`).
     * @param {Uint8Array} secret_id
     * @param {bigint} now_ms
     */
    beginSecretReveal(secret_id, now_ms) {
        const ptr0 = passArray8ToWasm0(secret_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_beginSecretReveal(this.__wbg_ptr, ptr0, len0, now_ms);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Server rejected, or we're rebasing. State unchanged.
     */
    clearStaged() {
        const ret = wasm.mlsclient_clearStaged(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Erase this device's visible message log when the user deletes the conversation. Protocol
     * state (ratchet, replay watermark, outbox, secret records) is retained, so later messages
     * still decrypt and a replayed secret still cannot be re-revealed. Local only — nothing is
     * sent, and the peer's copy is untouched.
     */
    clearVisibleHistory() {
        const ret = wasm.mlsclient_clearVisibleHistory(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Idempotent. Durable state is untouched — reopen with `open`.
     */
    close() {
        wasm.mlsclient_close(this.__wbg_ptr);
    }
    /**
     * @param {BigUint64Array} ids
     */
    confirmAcked(ids) {
        const ptr0 = passArray64ToWasm0(ids, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_confirmAcked(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Used on an explicit close (or a detected capture, where the platform allows). Idempotent;
     * scrubs the body.
     * @param {Uint8Array} secret_id
     */
    consumeSecret(secret_id) {
        const ptr0 = passArray8ToWasm0(secret_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_consumeSecret(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * This client becomes the group creator/first member. Persists before returning.
     *
     * `journal` is the embedder's synchronous storage host (see `journal.rs` for the atomicity
     * contract it must honour); `atRestKey` is 32 bytes from the caller's key hierarchy.
     * @param {Uint8Array} identity
     * @param {JournalHost} journal
     * @param {Uint8Array} at_rest_key
     * @returns {MlsClient}
     */
    static createGroup(identity, journal, at_rest_key) {
        const ptr0 = passArray8ToWasm0(identity, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(at_rest_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_createGroup(ptr0, len0, journal, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return MlsClient.__wrap(ret[0]);
    }
    /**
     * **Volatile**: state lives only for this page's lifetime. For tests and throwaway sessions —
     * never a fallback when the storage host is unavailable, which must surface as an error rather
     * than silently losing the ratchet.
     * @param {Uint8Array} identity
     * @returns {MlsClient}
     */
    static createGroupInMemory(identity) {
        const ptr0 = passArray8ToWasm0(identity, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_createGroupInMemory(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return MlsClient.__wrap(ret[0]);
    }
    /**
     * `wrong_state` if one already exists.
     */
    createSelfGroup() {
        const ret = wasm.mlsclient_createSelfGroup(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Produces the versioned opaque envelope (`app-envelope v1`). **Idempotent:** a retry returns
     * the same bytes and never advances the ratchet again — no double-spend of a message key.
     * @param {bigint} local_id
     * @returns {Uint8Array}
     */
    encrypt(local_id) {
        const ret = wasm.mlsclient_encrypt(this.__wbg_ptr, local_id);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Durable draft; does NOT advance the ratchet.
     * @param {Uint8Array} plaintext
     * @returns {bigint}
     */
    enqueue(plaintext) {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_enqueue(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * ADR-0014: share `K_r` (exactly 32 bytes) over the E2EE channel — the relay never sees it.
     * @param {Uint8Array} key_r
     * @returns {bigint}
     */
    enqueueDeliveryKeyGrant(key_r) {
        const ptr0 = passArray8ToWasm0(key_r, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_enqueueDeliveryKeyGrant(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * Replicate `entries` over the self-group. `wrong_state` if none is established.
     * @param {HistoryEntry[]} entries
     * @returns {bigint}
     */
    enqueueHistorySync(entries) {
        const ptr0 = passArrayJsValueToWasm0(entries, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_enqueueHistorySync(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * The classification + body are encrypted inside the content envelope, so the relay never
     * learns a message is secret. `encrypt`/`markSent` then proceed exactly as for a normal one.
     * @param {Uint8Array} body
     * @returns {SecretHandle}
     */
    enqueueSecret(body) {
        const ptr0 = passArray8ToWasm0(body, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_enqueueSecret(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SecretHandle.__wrap(ret[0]);
    }
    /**
     * @returns {bigint}
     */
    epoch() {
        const ret = wasm.mlsclient_epoch(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * @returns {boolean}
     */
    hasSelfGroup() {
        const ret = wasm.mlsclient_hasSelfGroup(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * Up to `max` recent non-secret messages, for replication to a newly-linked device.
     * @param {number} max
     * @returns {HistoryEntry[]}
     */
    historyEntries(max) {
        const ret = wasm.mlsclient_historyEntries(this.__wbg_ptr, max);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * `Pending` → `Active`, persisted. On a bad Welcome the client stays `Pending` (retryable).
     * @param {Uint8Array} welcome
     */
    joinGroup(welcome) {
        const ptr0 = passArray8ToWasm0(welcome, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_joinGroup(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @param {Uint8Array} welcome
     */
    joinSelfGroup(welcome) {
        const ptr0 = passArray8ToWasm0(welcome, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_joinSelfGroup(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * A one-time prekey to publish so others can add this client.
     * @returns {Uint8Array}
     */
    keyPackage() {
        const ret = wasm.mlsclient_keyPackage(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {bigint} local_id
     */
    markSent(local_id) {
        const ret = wasm.mlsclient_markSent(this.__wbg_ptr, local_id);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Server accepted: advance the epoch and persist.
     */
    mergeStaged() {
        const ret = wasm.mlsclient_mergeStaged(this.__wbg_ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Cheap: no payload crosses the boundary.
     * @returns {bigint}
     */
    messageCount() {
        const ret = wasm.mlsclient_messageCount(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BigInt.asUintN(64, ret[0]);
    }
    /**
     * Bounded window, oldest first. `limit` is clamped to `MAX_PAGE_MESSAGES` so one call can never
     * marshal an unbounded payload; an offset past the end returns an empty page.
     *
     * There is deliberately no "all messages" call here: the UniFFI surface has one only for tests,
     * and R-105 (whole-history rewrite per commit) bites harder in a browser.
     * @param {bigint} offset
     * @param {number} limit
     * @returns {StoredMessage[]}
     */
    messagesPage(offset, limit) {
        const ret = wasm.mlsclient_messagesPage(this.__wbg_ptr, offset, limit);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * Create a fresh identity that will JOIN an existing group: publish `keyPackage()`, then
     * `joinGroup(welcome)` once added. The pending identity is not yet durable — if the page dies
     * before joining, request a fresh key package.
     * @param {Uint8Array} identity
     * @param {JournalHost} journal
     * @param {Uint8Array} at_rest_key
     * @returns {MlsClient}
     */
    static newJoiner(identity, journal, at_rest_key) {
        const ptr0 = passArray8ToWasm0(identity, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(at_rest_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_newJoiner(ptr0, len0, journal, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return MlsClient.__wrap(ret[0]);
    }
    /**
     * Volatile joiner, the counterpart to [`Self::create_group_in_memory`]. Same warning: nothing
     * survives a reload.
     * @param {Uint8Array} identity
     * @returns {MlsClient}
     */
    static newJoinerInMemory(identity) {
        const ptr0 = passArray8ToWasm0(identity, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_newJoinerInMemory(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return MlsClient.__wrap(ret[0]);
    }
    /**
     * Reopen the last durably-committed session (reload / crash recovery).
     * @param {JournalHost} journal
     * @param {Uint8Array} at_rest_key
     * @returns {MlsClient}
     */
    static open(journal, at_rest_key) {
        const ptr0 = passArray8ToWasm0(at_rest_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_open(journal, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return MlsClient.__wrap(ret[0]);
    }
    /**
     * ADR-0010 recipient path: merges ONLY if the commit's actual effect equals the sender's signed
     * manifest. On mismatch: discarded unmerged, `invalid_message`, state unchanged.
     *
     * `added`/`removed` are arrays of identity byte-arrays taken from that manifest.
     * @param {Uint8Array} envelope
     * @param {bigint} next_epoch
     * @param {Array<any>} added
     * @param {Array<any>} removed
     */
    processCommit(envelope, next_epoch, added, removed) {
        const ptr0 = passArray8ToWasm0(envelope, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_processCommit(this.__wbg_ptr, ptr0, len0, next_epoch, added, removed);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * All effects — advanced ratchet, stored message, dedup marker, ack-eligibility — are durable
     * together before returning. Idempotent per `envelopeId`.
     * @param {bigint} envelope_id
     * @param {Uint8Array} ciphertext
     * @returns {InboundResult}
     */
    processInbound(envelope_id, ciphertext) {
        const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_processInbound(this.__wbg_ptr, envelope_id, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return InboundResult.__wrap(ret[0]);
    }
    /**
     * Self-group channel (ADR-0015 option 3): a `SecretConsumed` from another of this account's
     * devices, or a self-group membership commit. Same dedup + ack contract.
     * @param {bigint} envelope_id
     * @param {Uint8Array} ciphertext
     * @returns {InboundResult}
     */
    processSelfInbound(envelope_id, ciphertext) {
        const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_processSelfInbound(this.__wbg_ptr, envelope_id, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return InboundResult.__wrap(ret[0]);
    }
    /**
     * Used when that device is revoked. The returned remove-commit advances the epoch, so the
     * removed device cannot decrypt later self-group traffic even if it kept old ratchet state.
     * @param {Uint8Array} identity
     * @returns {Uint8Array}
     */
    removeSelfDevice(identity) {
        const ptr0 = passArray8ToWasm0(identity, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_removeSelfDevice(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * The consumption control message for a secret this device revealed (ADR-0015). `null` if the
     * secret is unknown, the sender's own, or unrevealed here. Idempotent: repeated calls return
     * the same envelope and never double-advance the ratchet.
     * @param {Uint8Array} secret_id
     * @returns {Uint8Array | undefined}
     */
    secretConsumptionEnvelope(secret_id) {
        const ptr0 = passArray8ToWasm0(secret_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_secretConsumptionEnvelope(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v2;
        if (ret[0] !== 0) {
            v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * @param {Uint8Array} secret_id
     * @param {bigint} now_ms
     * @returns {SecretPhase}
     */
    secretPhase(secret_id, now_ms) {
        const ptr0 = passArray8ToWasm0(secret_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_secretPhase(this.__wbg_ptr, ptr0, len0, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return __wbindgen_enum_SecretPhase[ret[0]];
    }
    /**
     * @param {Uint8Array} secret_id
     * @param {bigint} now_ms
     * @returns {SecretRemaining}
     */
    secretRemaining(secret_id, now_ms) {
        const ptr0 = passArray8ToWasm0(secret_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_secretRemaining(this.__wbg_ptr, ptr0, len0, now_ms);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SecretRemaining.__wrap(ret[0]);
    }
    /**
     * The plaintext gate: `null` while sealed/counting down and forever after expiry (which also
     * scrubs + persists).
     * @param {Uint8Array} secret_id
     * @param {bigint} now_ms
     * @returns {Uint8Array | undefined}
     */
    secretVisibleBody(secret_id, now_ms) {
        const ptr0 = passArray8ToWasm0(secret_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_secretVisibleBody(this.__wbg_ptr, ptr0, len0, now_ms);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v2;
        if (ret[0] !== 0) {
            v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * Builds commit + welcome WITHOUT advancing the epoch or persisting. Sign a manifest, POST
     * `/commit`, then `mergeStaged()` on success or `clearStaged()` on rejection. Never merge
     * before the server's epoch CAS confirms — that is how a race loser desyncs.
     * @param {Uint8Array} key_package
     * @returns {AddOutcome}
     */
    stageAdd(key_package) {
        const ptr0 = passArray8ToWasm0(key_package, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_stageAdd(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return AddOutcome.__wrap(ret[0]);
    }
    /**
     * @param {Uint8Array} identity
     * @returns {Uint8Array}
     */
    stageRemove(identity) {
        const ptr0 = passArray8ToWasm0(identity, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.mlsclient_stageRemove(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * 0 = pre-versioning; a pending client also reports 0.
     * @returns {number}
     */
    storageFormatVersion() {
        const ret = wasm.mlsclient_storageFormatVersion(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
}
if (Symbol.dispose) MlsClient.prototype[Symbol.dispose] = MlsClient.prototype.free;
exports.MlsClient = MlsClient;

class SecretHandle {
    static __wrap(ptr) {
        const obj = Object.create(SecretHandle.prototype);
        obj.__wbg_ptr = ptr;
        SecretHandleFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SecretHandleFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secrethandle_free(ptr, 0);
    }
    /**
     * @returns {bigint}
     */
    get localId() {
        const ret = wasm.secrethandle_localId(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {Uint8Array}
     */
    get secretId() {
        const ret = wasm.secrethandle_secretId(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) SecretHandle.prototype[Symbol.dispose] = SecretHandle.prototype.free;
exports.SecretHandle = SecretHandle;

/**
 * Both 0 outside that phase. Drives the UI timer/fade.
 */
class SecretRemaining {
    static __wrap(ptr) {
        const obj = Object.create(SecretRemaining.prototype);
        obj.__wbg_ptr = ptr;
        SecretRemainingFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SecretRemainingFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_secretremaining_free(ptr, 0);
    }
    /**
     * @returns {bigint}
     */
    get countdownMs() {
        const ret = wasm.secretremaining_countdownMs(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * @returns {bigint}
     */
    get viewMs() {
        const ret = wasm.secretremaining_viewMs(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
}
if (Symbol.dispose) SecretRemaining.prototype[Symbol.dispose] = SecretRemaining.prototype.free;
exports.SecretRemaining = SecretRemaining;

/**
 * What the UI renders.
 */
class StoredMessage {
    static __wrap(ptr) {
        const obj = Object.create(StoredMessage.prototype);
        obj.__wbg_ptr = ptr;
        StoredMessageFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        StoredMessageFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_storedmessage_free(ptr, 0);
    }
    /**
     * @returns {bigint | undefined}
     */
    get envelopeId() {
        const ret = wasm.storedmessage_envelopeId(this.__wbg_ptr);
        return ret[0] === 0 ? undefined : BigInt.asUintN(64, ret[1]);
    }
    /**
     * @returns {bigint}
     */
    get localId() {
        const ret = wasm.storedmessage_localId(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * True if this account sent it. (The UniFFI surface uses a `Direction` enum; a boolean is the
     * idiomatic JS equivalent of a two-variant enum and avoids a needless exported type.)
     * @returns {boolean}
     */
    get outbound() {
        const ret = wasm.storedmessage_outbound(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * EMPTY when `secretId` is set — render the placeholder/tombstone from `secretPhase`, never
     * this.
     * @returns {Uint8Array}
     */
    get plaintext() {
        const ret = wasm.storedmessage_plaintext(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * `Some` (16 bytes) for a view-once secret.
     * @returns {Uint8Array | undefined}
     */
    get secretId() {
        const ret = wasm.storedmessage_secretId(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
}
if (Symbol.dispose) StoredMessage.prototype[Symbol.dispose] = StoredMessage.prototype.free;
exports.StoredMessage = StoredMessage;

/**
 * @returns {string}
 */
function bindingVersion() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.bindingVersion();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
exports.bindingVersion = bindingVersion;

/**
 * Machine-checkable version compatibility.
 * @returns {Capabilities}
 */
function capabilities() {
    const ret = wasm.capabilities();
    return Capabilities.__wrap(ret);
}
exports.capabilities = capabilities;

/**
 * Bundled system text — never an external resource that could fail at runtime.
 * @returns {string}
 */
function secretTombstoneText() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.secretTombstoneText();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
exports.secretTombstoneText = secretTombstoneText;

/**
 * Route Rust panics to `console.error` with a stack trace. Without this a panic surfaces in JS as
 * an opaque `unreachable executed`. Safe to call more than once; call it first from the host.
 */
function setPanicHook() {
    wasm.setPanicHook();
}
exports.setPanicHook = setPanicHook;
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_ea9085d691f535d3: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_a27215656b807791: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_ea5e6cc2e4141dfe: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_a6e5c5dce5018821: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_commit_cb69e204159bddda: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.commit(getArrayU8FromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_error_d7e7b8e4367f0ec5: function(arg0, arg1) {
            console.error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getRandomValues_cc7f052a444bb2ce: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_get_unchecked_6e0ad6d2a41b06f6: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_historyentry_new: function(arg0) {
            const ret = HistoryEntry.__wrap(arg0);
            return ret;
        },
        __wbg_historyentry_unwrap: function(arg0) {
            const ret = HistoryEntry.__unwrap(arg0);
            return ret;
        },
        __wbg_instanceof_Uint8Array_309b927aaf7a3fc7: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_length_1f0964f4a5e2c6d8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_370319915dc99107: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_load_22cf935cc8b3c428: function() { return handleError(function (arg0) {
            const ret = arg0.load();
            return ret;
        }, arguments); },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_b667d279fd5aa943: function(arg0, arg1) {
            const ret = new Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_cd45aabdf6073e84: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_with_length_e6785c33c8e4cce8: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_86c0d4ba3fa605b8: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_146583524fe1469b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_storedmessage_new: function(arg0) {
            const ret = StoredMessage.__wrap(arg0);
            return ret;
        },
        __wbg_subarray_3ed232c8a6baee09: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./mls_wasm_bg.js": import0,
    };
}

const __wbindgen_enum_InboundKind = ["application", "state_advanced", "duplicate", "secret_sealed", "secret_consumed_remotely", "delivery_key_granted", "history_synced"];


const __wbindgen_enum_SecretPhase = ["sealed", "countdown", "visible", "consumed", "unknown"];
const AddOutcomeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_addoutcome_free(ptr, 1));
const CapabilitiesFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_capabilities_free(ptr, 1));
const HistoryEntryFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_historyentry_free(ptr, 1));
const InboundResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_inboundresult_free(ptr, 1));
const MlsClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_mlsclient_free(ptr, 1));
const SecretHandleFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secrethandle_free(ptr, 1));
const SecretRemainingFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_secretremaining_free(ptr, 1));
const StoredMessageFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_storedmessage_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU64FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getBigUint64ArrayMemory0().subarray(ptr / 8, ptr / 8 + len);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedBigUint64ArrayMemory0 = null;
function getBigUint64ArrayMemory0() {
    if (cachedBigUint64ArrayMemory0 === null || cachedBigUint64ArrayMemory0.byteLength === 0) {
        cachedBigUint64ArrayMemory0 = new BigUint64Array(wasm.memory.buffer);
    }
    return cachedBigUint64ArrayMemory0;
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray64ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 8, 8) >>> 0;
    getBigUint64ArrayMemory0().set(arg, ptr / 8);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

const wasmPath = `${__dirname}/mls_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasmInstance = new WebAssembly.Instance(wasmModule, __wbg_get_imports());
let wasm = wasmInstance.exports;
wasm.__wbindgen_start();
