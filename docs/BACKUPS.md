# Encrypted chat backups

Settings → Security → **Chat backup**. One file, sealed under a user passphrase, containing the
message history and the key material that opens it. This document is the honest specification:
what's inside, what protects it, what a restore can and cannot do.

## What a backup contains

- The MLS store directory: `index.json`, every per-conversation encrypted store, and every R-105
  archive file — i.e. the complete local message history, still in its at-rest encryption.
- The **at-rest root key** (the HKDF root the per-store keys derive from). This is the one
  sanctioned way that key leaves the Keychain, and it only ever travels inside the sealed file.

Deliberately **not** included: the device identity key (Secure-Enclave-bound and non-exportable —
by design), the session tokens, and view-once secrets' transient state (they fail closed on any
relaunch anyway).

## The container (`NedwonsKit.Backup`, format v1)

```
"NEDWONSBK" || version(1) || salt(16) || iterations(u32 BE) || nonce(12) || AES-256-GCM ciphertext
```

- KEK = PBKDF2-HMAC-SHA256(passphrase, salt, 600 000 iterations — OWASP's current figure).
  PBKDF2 because it ships in the OS with zero new dependencies; **Argon2id is the tracked
  upgrade** (better GPU resistance) and the version byte exists so v2 can switch KDFs without
  breaking v1 restores. Archives claiming fewer than 100 000 iterations are refused outright.
- A wrong passphrase and a tampered file fail identically (GCM, fail closed). Fresh salt per
  backup, so identical content produces unlinkable files.
- The payload decoder is strict: bounded counts and name lengths, flat file names only (no `/`, no
  `..` — a crafted backup cannot write outside the store directory), no trailing bytes.

## What restore does — scope, stated plainly (v1)

Restore works into an **empty** store (fresh install) and refuses otherwise — no silent merging,
no clobbering the keys guarding existing data (`importRoot` refuses a different live root).

- **Same device** (delete + reinstall, failed migration): the Keychain-held device identity and
  at-rest root survive app deletion on iOS, so the restored ratchets **resume exactly** — new
  messages keep decrypting in both directions. Proven end-to-end in `BackupManagerTests`.
- **A different phone**: not yet. The device key cannot travel (Secure Enclave), so another
  device is a different MLS participant; it joins conversations going forward via account
  recovery + the V27 setup queue, but making backed-up history *readable* there is future work
  (a history-import mode that renders without resuming sessions). The UI says this.

## The two sentences users must actually read

The passphrase seals the file; **nobody — including Nedwons — can open or recover a backup
without it.** Store the file and the passphrase separately and safely; losing the passphrase
loses the backup, which is the price of it being worth having.
