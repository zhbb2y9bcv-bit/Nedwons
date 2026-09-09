//! Attachment encryption: the file is encrypted on the device with a one-time key, the CIPHERTEXT
//! is uploaded to the relay, and the key travels to the recipients inside the MLS message that
//! references it ([`crate::content::Content::Attachment`]).
//!
//! What the relay gets is a bag of bytes and a random id. It never holds a key, never sees a
//! filename or a media type, and cannot tell a photo from a voice note from a PDF — those all live
//! in the E2EE envelope. This is the same shape as the delivery-access-key grant (ADR-0014): the
//! secret rides the MLS channel, the opaque blob rides the relay.
//!
//! **One key per attachment, never reused.** A fresh 32-byte key is drawn for every file, so the
//! nonce is fixed at zero: AES-GCM's requirement is that a (key, nonce) pair is never reused, and a
//! key used exactly once satisfies it without having to store or transmit a nonce. Re-encrypting
//! the same file produces a different key and different bytes.
//!
//! **Integrity twice over.** GCM authenticates the ciphertext under the key, so tampering fails to
//! decrypt. On top of that the sender includes a SHA-256 of the ciphertext in the message; the
//! recipient checks it *before* decrypting, which is what binds "the blob the relay served" to
//! "the blob the sender meant" — a relay that swaps one stored object for another is caught even
//! though both are undecryptable-by-it ciphertext.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Bytes in an attachment key.
pub const ATTACHMENT_KEY_LEN: usize = 32;
/// Bytes in the ciphertext digest (SHA-256).
pub const ATTACHMENT_DIGEST_LEN: usize = 32;

/// The largest file this version will encrypt or accept, in bytes.
///
/// Bounded because both halves run in memory: the plaintext, the ciphertext, and (across the FFI)
/// a copy of each. Streaming encryption would lift this and is the natural next step; until it
/// exists, an honest cap beats an out-of-memory crash on a large video.
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Carries no key material or plaintext, so logging one leaks nothing.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AttachmentError {
    /// Larger than [`MAX_ATTACHMENT_BYTES`], or empty.
    BadSize,
    /// Wrong key length.
    BadKey,
    /// The served bytes are not the bytes the sender described.
    DigestMismatch,
    /// Authentication failed: wrong key, or the ciphertext was altered.
    Undecryptable,
}

/// Everything a device needs to fetch and open an attachment later, as stored in the message log.
///
/// It includes the KEY, deliberately: the recipient must be able to open the file again after a
/// relaunch without asking the sender. The log lives inside the durable blob, which is encrypted at
/// rest under the device's at-rest key — the same place the message ratchet already sits, so an
/// attachment key is no more exposed than the conversation it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttachmentRef {
    pub blob_id: [u8; 16],
    pub key: [u8; ATTACHMENT_KEY_LEN],
    pub digest: [u8; ATTACHMENT_DIGEST_LEN],
    pub size: u64,
    pub mime: String,
    pub filename: String,
}

/// An encrypted attachment, ready to upload, plus the secrets that must travel over MLS.
pub struct SealedAttachment {
    /// Upload this to the relay. It learns nothing from it.
    pub ciphertext: Vec<u8>,
    /// Send this inside the MLS message. Never let it near the relay.
    pub key: [u8; ATTACHMENT_KEY_LEN],
    /// SHA-256 of `ciphertext`, checked by the recipient before decrypting.
    pub digest: [u8; ATTACHMENT_DIGEST_LEN],
}

/// Encrypt `plaintext` under a fresh one-time key.
pub fn seal(plaintext: &[u8]) -> Result<SealedAttachment, AttachmentError> {
    if plaintext.is_empty() || plaintext.len() > MAX_ATTACHMENT_BYTES {
        return Err(AttachmentError::BadSize);
    }
    let mut key = [0u8; ATTACHMENT_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AttachmentError::BadKey)?;
    let ciphertext = cipher
        .encrypt(zero_nonce(), plaintext)
        // The only realistic cause is an allocation failure on a very large input; there is no
        // partial result to return.
        .map_err(|_| AttachmentError::BadSize)?;
    let digest = digest_of(&ciphertext);
    Ok(SealedAttachment {
        ciphertext,
        key,
        digest,
    })
}

/// Verify the served ciphertext against the sender's digest, then decrypt it.
///
/// The digest is checked first and in full: decrypting bytes that are not the ones the sender
/// described would still fail, but failing on the digest says *which* thing went wrong — the relay
/// served something else — rather than blaming the key.
pub fn open(key: &[u8], digest: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AttachmentError> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_ATTACHMENT_BYTES + 64 {
        return Err(AttachmentError::BadSize);
    }
    if digest.len() != ATTACHMENT_DIGEST_LEN || digest_of(ciphertext).as_slice() != digest {
        return Err(AttachmentError::DigestMismatch);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AttachmentError::BadKey)?;
    cipher
        .decrypt(zero_nonce(), ciphertext)
        .map_err(|_| AttachmentError::Undecryptable)
}

/// SHA-256 of the ciphertext, as both sides compute it.
pub fn digest_of(ciphertext: &[u8]) -> [u8; ATTACHMENT_DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Safe only because a key is used for exactly one attachment — see the module header.
fn zero_nonce() -> &'static Nonce<aes_gcm::aes::cipher::consts::U12> {
    Nonce::from_slice(&[0u8; 12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_never_reuses_a_key() {
        let file = b"a photo, pretend".repeat(64);
        let a = seal(&file).expect("seal");
        let b = seal(&file).expect("seal again");
        assert_ne!(a.key, b.key, "a fresh key per attachment");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "so identical files upload differently"
        );
        assert_ne!(a.ciphertext, file, "the relay never sees the file");
        assert_eq!(open(&a.key, &a.digest, &a.ciphertext).expect("open"), file);
    }

    #[test]
    fn a_substituted_blob_is_caught_before_decryption() {
        let a = seal(b"the real file").expect("seal");
        let b = seal(b"a different file").expect("seal");
        // The relay serves someone else's (perfectly valid) ciphertext under our id.
        assert_eq!(
            open(&a.key, &a.digest, &b.ciphertext),
            Err(AttachmentError::DigestMismatch)
        );
    }

    #[test]
    fn tampering_and_wrong_keys_fail_closed() {
        let a = seal(b"the real file").expect("seal");
        let mut altered = a.ciphertext.clone();
        altered[0] ^= 0xff;
        // Altered bytes fail the digest; if an attacker fixes the digest too, GCM still refuses.
        assert_eq!(
            open(&a.key, &a.digest, &altered),
            Err(AttachmentError::DigestMismatch)
        );
        assert_eq!(
            open(&a.key, &digest_of(&altered), &altered),
            Err(AttachmentError::Undecryptable)
        );
        let wrong = [9u8; ATTACHMENT_KEY_LEN];
        assert_eq!(
            open(&wrong, &a.digest, &a.ciphertext),
            Err(AttachmentError::Undecryptable)
        );
        assert_eq!(
            open(&a.key[..16], &a.digest, &a.ciphertext),
            Err(AttachmentError::BadKey)
        );
    }

    #[test]
    fn sizes_are_bounded_at_both_ends() {
        assert!(matches!(seal(b""), Err(AttachmentError::BadSize)));
        assert!(matches!(
            seal(&vec![0u8; MAX_ATTACHMENT_BYTES + 1]),
            Err(AttachmentError::BadSize)
        ));
        let a = seal(b"x").expect("seal");
        assert_eq!(open(&a.key, &a.digest, b""), Err(AttachmentError::BadSize));
    }
}
