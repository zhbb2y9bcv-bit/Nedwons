# App Store privacy & compliance

What to answer in App Store Connect, and **why** — so the answers can be defended rather than
re-guessed by whoever submits.

Read this alongside `apps/ios/Nedwons/PrivacyInfo.xcprivacy` (the manifest) and `PRIVACY.md` (the
user-facing statement). If the three ever disagree, the software is right and the documents are
wrong; fix the documents.

> **Scope limit, stated up front.** Everything here describes what the software *does*, verified by
> auditing this repository. Whether Apple's **current** rules classify that behaviour this way is a
> separate question. Apple's data-type taxonomy, required-reason API list and reason codes change,
> and export classification is a legal determination. **Verify against Apple's live documentation
> and get counsel before submitting.** Tracked as R-402.

---

## 1. What the audit actually found (2026-09-08)

These are findings, not assumptions. Each was checked against the code, and two of them were
defects that would have reached review:

| Checked | Result |
|---|---|
| Crash/analytics SDKs (Firebase, Crashlytics, Sentry, AppCenter, MetricKit) | **None.** No third-party SwiftPM packages at all — only local ones |
| Required-reason APIs (UserDefaults, file timestamps, disk space, boot time, active keyboard) | **None used**, in Swift or in the Rust core |
| `@AppStorage` / `@SceneStorage` (wrap UserDefaults) | **None** |
| Client IP persisted server-side | **Never.** No column in any migration; the rate limiter holds it in memory only |
| Address-book / phone-number discovery | **No code path exists.** Asserted by a test that probes the router for such endpoints |
| Privacy manifest present in the built `.app` | **Was NOT bundled** — fixed (see §5) |
| Export compliance declared | **Was missing** — fixed (see §6) |

The manifest previously declared crash-data collection that does not happen and two required-reason
API categories that are not used. Over-declaring is not a safe default: it is an inaccurate
statement about the app, and it invites questions that cannot be answered.

---

## 2. Data collection answers

"Collect" is Apple's term: transmitting data off the device where it persists beyond servicing the
request in real time.

| App Store data type | Collect? | What it is | Linked | Tracking |
|---|---|---|---|---|
| User ID | **Yes** | The username. Permanent, user-chosen, and the only discovery mechanism | Yes | No |
| Name | **Yes** | Optional display name shown to others | Yes | No |
| Device ID | **Yes** | Push token + device id, used to route mail to the right device | Yes | No |
| Other User Content | **Yes** | Message content — see §3, this one deserves its own argument | Yes | No |
| Customer Support | **Yes** | Abuse reports: a reason and optional evidence the reporter submits | Yes | No |
| Other Data | **Yes** | Social graph (contacts, requests, blocks) and group membership | Yes | No |
| Contacts | **No** | The device address book is never read. No Contacts permission is requested | — | — |
| Email / Phone | **No** | Never collected. There is no email or phone field anywhere | — | — |
| Location | **No** | Never collected, coarse or precise | — | — |
| Browsing / Search History | **No** | Search queries are used to answer the request and are not stored or logged (the query string is stripped before logging — proven by `log_redaction.rs`) | — | — |
| Crash / Performance Data | **No** | No crash reporter or analytics SDK is integrated | — | — |
| Purchases, Financial, Health, Sensitive Info | **No** | None of these exist in the product | — | — |

**Tracking is `false` across the board**, and this is a strong claim the code supports: there are no
third-party SDKs, no advertising identifiers, no data brokers, and nothing is sold or shared for
advertising.

---

## 3. Message content: why it is declared even though we cannot read it

The tempting answer is "not collected" — the relay stores only MLS ciphertext and holds no key that
opens it, which the relay-blindness tests prove by querying the database directly.

It is declared anyway, for a reason worth stating: the app **does** transmit message content off the
device, and the server **does** store it until delivery. "We cannot read it" is a statement about
our access, not about whether transmission occurred. Under-declaring on the strength of an argument
Apple has not agreed to is exactly the kind of decision that looks like a deliberate omission if it
is ever questioned.

So it is declared, and the encryption is explained in the app description and in `PRIVACY.md`. If
Apple's guidance (or counsel) later says an E2EE provider with no plaintext access should answer
"not collected", that is a defensible change — but it should be made explicitly, with the reasoning
recorded here, not by quietly deleting the entry.

---

## 4. Account deletion (App Store requirement)

An app that lets people create an account must let them delete it **from inside the app** — not via
a website, not by emailing support.

**Status: implemented.** Settings → Delete account.

- The flow requires the password **and** a signature from this device's enrolled key, so a stolen
  session alone cannot destroy an account.
- It states the consequences before the button, including the one users get backwards: deleting is
  **not an unsend**. Messages other people already received stay on their devices.
- Server-side erasure spans every store — only `devices` and `profiles` cascade from `accounts`, so
  deletion is explicit and exhaustive (`services/api/src/account_deletion.rs`).
- Local erasure is the part no server can do: aliases, the MLS store (keys included) and the
  enrolled device key are destroyed on the device.
- Order is deliberate: **server first**, local wipe only after the server confirms. Wiping first
  would leave an account alive that this device could no longer authenticate to delete.

Retained deliberately, and disclosed in `PRIVACY.md`: abuse reports survive deletion in anonymized
form, so a bad actor cannot launder their history by deleting and re-registering; and the
key-transparency log is append-only, because deleting leaves would invalidate other users'
inclusion proofs.

---

## 5. Privacy manifest packaging

The manifest must sit at the **app bundle root**. It previously lived at
`apps/ios/Nedwons/PrivacyInfo.xcprivacy`, outside the target's `sources:`, so it was never copied
into the built app — verified by inspecting the built `.app`, which did not contain it.

That is the worst kind of compliance bug: the file exists, looks maintained, and ships nothing.
Fixed by adding it to the target's resources in `project.yml`, and verified by rebuilding and
confirming it appears in the bundle.

**Outstanding:** the Notification Service Extension is a separate bundle. It uses no required-reason
APIs and collects nothing itself, but whether it needs its own manifest should be confirmed against
Apple's current rules before submission.

---

## 6. Encryption export compliance

`ITSAppUsesNonExemptEncryption` is declared **`true`**.

This is the conservative answer and it is deliberate. The app's core function is end-to-end
encrypted messaging, so claiming one of the exemptions would be a claim we cannot substantiate —
and unlike the privacy questionnaire, this declaration is made to a **regulator**.

Consequence: export documentation (self-classification report / ERN, possibly CCATS) must be filed
before distribution. **This is a legal determination, not an engineering one.** Get counsel. Do not
flip this to `false` to make a submission prompt go away.

---

## 7. Still outstanding before submission

Honest list of what is not done, because a compliance document that only lists successes is not
useful:

| Item | Status |
|---|---|
| Support URL and contact address | **Missing.** Requires a real domain and a monitored inbox; App Store Connect requires a support URL |
| Privacy policy URL | **Missing.** `PRIVACY.md` has the content but is not published at a stable URL |
| Export classification filed | **Not started.** See §6 — needs counsel |
| Apple Developer account, App ID, provisioning | **Not provisioned** (R-502) |
| Re-verify taxonomy and reason codes against Apple's live docs | **Not done** — cannot be done reliably from this environment |
| Notification Service Extension manifest | **Undetermined** — see §5 |
| Age rating questionnaire | **Not answered.** A messaging app with user-generated content and no moderation of message *content* (it cannot be read) needs a considered answer, not a default |
| Data-retention statement matched to backend behaviour | Partially — `DATA_RETENTION.md` exists; the 30-day envelope TTL and quota-window sweeps are implemented and match |
