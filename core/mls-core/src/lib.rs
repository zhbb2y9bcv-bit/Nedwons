//! `mls-core` — a narrow, memory-safe wrapper over OpenMLS (RFC 9420) for Nedwons's
//! end-to-end encrypted messaging (ADR-0001). No custom cryptography: every primitive comes
//! from OpenMLS and its RustCrypto provider.
//!
//! Design boundary (THREAT_MODEL.md INV-1): the values that cross the network are the
//! opaque bytes returned by [`Conversation::encrypt`], [`Conversation::add_member`], and
//! friends. The **server never links this crate** — it routes ciphertext without the means
//! to read it.
//!
//! Each [`Member`] owns its own OpenMLS provider (key store); a [`Conversation`] belongs to
//! the member that created or joined it and must be operated with that same member.

#![forbid(unsafe_code)]

pub mod client;
pub mod content;
pub mod envelope;
pub mod secret;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

pub mod durable;

/// The single, explicit ciphersuite for v1 (CRYPTOGRAPHY.md §1). No silent negotiation.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// This crate's version, surfaced across the FFI so the client can assert compatibility.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human-readable ciphersuite name (stable string for the FFI `capabilities()` report).
pub const CIPHERSUITE_NAME: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error("mls library error: {0}")]
    Lib(String),
    #[error("serialization error")]
    Codec,
    #[error("member not found in group")]
    MemberNotFound,
    /// A commit's actual cryptographic effect does not match the sender's signed membership
    /// manifest (ADR-0010 correspondence check). The commit was NOT merged; group state is
    /// unchanged. Treat as a security event: the committer (or the server) lied.
    #[error("commit does not match its membership manifest")]
    ManifestMismatch,
}

type Result<T> = core::result::Result<T, MlsError>;

fn lib<E: std::fmt::Display>(e: E) -> MlsError {
    MlsError::Lib(e.to_string())
}

/// One participant identity: signature key pair, credential, and its own key store.
pub struct Member {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: Vec<u8>,
}

impl Member {
    /// Create a fresh identity. `identity` is the credential's identity bytes (e.g. a device
    /// record id); it is not a secret.
    pub fn new(identity: &[u8]) -> Result<Self> {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(lib)?;
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).map_err(lib)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
            identity: identity.to_vec(),
        })
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Produce a fresh key package others use to add this member asynchronously (the "prekey"
    /// in Signal terms). Serialized bytes are published to the key-directory service.
    pub fn key_package(&self) -> Result<KeyPackage> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(lib)?;
        Ok(bundle.key_package().clone())
    }

    /// Serialize a key package for transport.
    pub fn key_package_bytes(&self) -> Result<Vec<u8>> {
        self.key_package()?
            .tls_serialize_detached()
            .map_err(|_| MlsError::Codec)
    }

    /// Create a new group (conversation) with this member as the sole initial participant.
    pub fn create_group(&self) -> Result<Conversation> {
        let group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true) // welcomes carry the ratchet tree
            .build(&self.provider, &self.signer, self.credential.clone())
            .map_err(lib)?;
        Ok(Conversation { group })
    }

    /// Join a group from a serialized Welcome (produced by [`Conversation::add_member`]).
    pub fn join_from_welcome(&self, mut welcome_bytes: &[u8]) -> Result<Conversation> {
        let message =
            MlsMessageIn::tls_deserialize(&mut welcome_bytes).map_err(|_| MlsError::Codec)?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(MlsError::Codec),
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged =
            StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None).map_err(lib)?;
        let group = staged.into_group(&self.provider).map_err(lib)?;
        Ok(Conversation { group })
    }

    // ----- Durable snapshot/restore (crash-safe client state machine; see `durable`) --------

    /// This member's signature public key — needed to reload the signer from a restored store.
    /// Not a secret.
    pub fn public_key(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    /// Serialize this member's key store, which holds the signature key pair **and the group's
    /// ratchet secrets**. This blob is SENSITIVE: on device it is encrypted under the local
    /// at-rest key hierarchy (CRYPTOGRAPHY.md §5) before it ever touches disk.
    pub fn export_store(&self) -> Result<Vec<u8>> {
        // The provider's KV map (`values`) is public; serialize it as key/value pairs (JSON can't
        // key an object by a byte array). This avoids the storage crate's `test-utils`-gated codec.
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::Codec)?;
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        serde_json::to_vec(&pairs).map_err(|_| MlsError::Codec)
    }

    /// Reconstruct a member from a previously [`export_store`](Member::export_store)d blob plus its
    /// (non-secret) identity and public key. Rebuilds the provider, reloads the signer, and
    /// re-derives the credential; the caller then reloads the group with [`Conversation::reload`].
    pub fn restore(identity: &[u8], store_bytes: &[u8], public_key: &[u8]) -> Result<Self> {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            serde_json::from_slice(store_bytes).map_err(|_| MlsError::Codec)?;
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| MlsError::Codec)?;
            *values = pairs.into_iter().collect();
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            public_key,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or(MlsError::MemberNotFound)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: public_key.to_vec().into(),
        };
        Ok(Self {
            provider,
            signer,
            credential,
            identity: identity.to_vec(),
        })
    }
}

/// Result of adding a member: the commit to fan out to existing members, and the welcome to
/// deliver to the new member. Both are opaque ciphertext to the server.
pub struct AddResult {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// What a processed inbound message yielded.
pub enum Incoming {
    /// Decrypted application plaintext.
    Application(Vec<u8>),
    /// A membership/commit message was processed and merged; group state advanced.
    StateAdvanced,
}

/// A single conversation (MLS group), operated by its owning [`Member`].
pub struct Conversation {
    group: MlsGroup,
}

impl Conversation {
    /// Current epoch — increments on every membership change (INV-9 visibility).
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// This member's leaf index (its own position in the group).
    pub fn own_leaf(&self) -> u32 {
        self.group.own_leaf_index().u32()
    }

    /// Add a member by their serialized key package. Returns the commit (for existing
    /// members) and welcome (for the new member). Caller must deliver both.
    pub fn add_member(&mut self, me: &Member, mut key_package_bytes: &[u8]) -> Result<AddResult> {
        let kp_in =
            KeyPackageIn::tls_deserialize(&mut key_package_bytes).map_err(|_| MlsError::Codec)?;
        let key_package = kp_in
            .validate(me.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(lib)?;

        let (commit, welcome, _group_info) = self
            .group
            .add_members(&me.provider, &me.signer, &[key_package])
            .map_err(lib)?;
        self.group.merge_pending_commit(&me.provider).map_err(lib)?;

        Ok(AddResult {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| MlsError::Codec)?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|_| MlsError::Codec)?,
        })
    }

    /// Remove the member whose credential identity matches `identity`. Returns the commit to
    /// fan out; the epoch advances so the removed member cannot decrypt future messages.
    pub fn remove_member(&mut self, me: &Member, identity: &[u8]) -> Result<Vec<u8>> {
        let leaf = self
            .leaf_for_identity(identity)
            .ok_or(MlsError::MemberNotFound)?;
        let (commit, _welcome, _info) = self
            .group
            .remove_members(&me.provider, &me.signer, &[leaf])
            .map_err(lib)?;
        self.group.merge_pending_commit(&me.provider).map_err(lib)?;
        commit.tls_serialize_detached().map_err(|_| MlsError::Codec)
    }

    // ----- Staged commits (ADR-0010) --------------------------------------------------------
    //
    // For MLS-commit-authoritative membership the proposer must NOT advance its own group state
    // until the server's epoch compare-and-swap confirms its commit won. `stage_*` build a commit
    // but leave it PENDING (epoch unchanged); `merge_staged` applies it (server accepted),
    // `clear_staged` discards it (server rejected / rebase). This prevents a race loser from
    // desyncing by merging a commit the group never accepted.

    /// Stage an add: build the commit + welcome WITHOUT merging. The epoch is unchanged until
    /// [`merge_staged`](Self::merge_staged).
    pub fn stage_add_member(
        &mut self,
        me: &Member,
        mut key_package_bytes: &[u8],
    ) -> Result<AddResult> {
        let kp_in =
            KeyPackageIn::tls_deserialize(&mut key_package_bytes).map_err(|_| MlsError::Codec)?;
        let key_package = kp_in
            .validate(me.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(lib)?;
        let (commit, welcome, _group_info) = self
            .group
            .add_members(&me.provider, &me.signer, &[key_package])
            .map_err(lib)?;
        Ok(AddResult {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| MlsError::Codec)?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|_| MlsError::Codec)?,
        })
    }

    /// Stage a remove: build the commit WITHOUT merging.
    pub fn stage_remove_member(&mut self, me: &Member, identity: &[u8]) -> Result<Vec<u8>> {
        let leaf = self
            .leaf_for_identity(identity)
            .ok_or(MlsError::MemberNotFound)?;
        let (commit, _welcome, _info) = self
            .group
            .remove_members(&me.provider, &me.signer, &[leaf])
            .map_err(lib)?;
        commit.tls_serialize_detached().map_err(|_| MlsError::Codec)
    }

    /// Merge the pending staged commit — the server accepted it (its epoch CAS won). Advances the
    /// epoch. No-op-safe only if a commit is actually pending; otherwise it is a library error.
    pub fn merge_staged(&mut self, me: &Member) -> Result<()> {
        self.group.merge_pending_commit(&me.provider).map_err(lib)
    }

    /// Discard the pending staged commit — the server rejected it (stale epoch / governance), or
    /// the client is rebasing. The epoch is unchanged; the caller rebuilds against fresh state.
    pub fn clear_staged(&mut self, me: &Member) -> Result<()> {
        self.group
            .clear_pending_commit(me.provider.storage())
            .map_err(lib)
    }

    /// Encrypt an application message. The returned bytes are an opaque envelope.
    pub fn encrypt(&mut self, me: &Member, plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .group
            .create_message(&me.provider, &me.signer, plaintext)
            .map_err(lib)?;
        out.tls_serialize_detached().map_err(|_| MlsError::Codec)
    }

    /// Process an inbound envelope: an application message yields plaintext; a commit is
    /// merged and advances group state.
    pub fn process(&mut self, me: &Member, mut envelope: &[u8]) -> Result<Incoming> {
        let message = MlsMessageIn::tls_deserialize(&mut envelope).map_err(|_| MlsError::Codec)?;
        let protocol = message
            .try_into_protocol_message()
            .map_err(|_| MlsError::Codec)?;
        let processed = self
            .group
            .process_message(&me.provider, protocol)
            .map_err(lib)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(Incoming::Application(app.into_bytes()))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&me.provider, *staged)
                    .map_err(lib)?;
                Ok(Incoming::StateAdvanced)
            }
            _ => Ok(Incoming::StateAdvanced),
        }
    }

    /// Process an inbound **commit** with the ADR-0010 correspondence check: the commit's actual
    /// cryptographic effect must equal the sender's signed membership manifest, otherwise the
    /// commit is **discarded without merging** (group state unchanged) and
    /// [`MlsError::ManifestMismatch`] is returned.
    ///
    /// This is the half of membership verification only clients can do — the MLS-blind relay
    /// verified the manifest's *signature/authorization/ordering*; the recipient verifies the
    /// *correspondence* between the routing claim and the cryptographic change.
    ///
    /// `expected_added`/`expected_removed` are the manifest's device identities (credential
    /// identity bytes); `expected_next_epoch` is the manifest's `next_epoch`.
    pub fn process_commit_checked(
        &mut self,
        me: &Member,
        mut envelope: &[u8],
        expected_next_epoch: u64,
        expected_added: &[Vec<u8>],
        expected_removed: &[Vec<u8>],
    ) -> Result<()> {
        // The manifest must describe exactly the next epoch relative to our local state; a
        // stale or skipped epoch is a divergence, not something to merge through.
        if expected_next_epoch != self.epoch() + 1 {
            return Err(MlsError::ManifestMismatch);
        }

        let message = MlsMessageIn::tls_deserialize(&mut envelope).map_err(|_| MlsError::Codec)?;
        let protocol = message
            .try_into_protocol_message()
            .map_err(|_| MlsError::Codec)?;
        let processed = self
            .group
            .process_message(&me.provider, protocol)
            .map_err(lib)?;
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            // Not a commit at all — cannot satisfy a membership manifest.
            _ => return Err(MlsError::ManifestMismatch),
        };

        // What the commit ACTUALLY does, read from the staged (not yet merged) state.
        let mut actual_added: Vec<Vec<u8>> = staged
            .add_proposals()
            .map(|p| {
                p.add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential()
                    .serialized_content()
                    .to_vec()
            })
            .collect();
        // Removed leaves are resolved against the PRE-merge member list.
        let mut actual_removed: Vec<Vec<u8>> = Vec::new();
        for p in staged.remove_proposals() {
            let leaf = p.remove_proposal().removed();
            let identity = self
                .group
                .members()
                .find(|m| m.index == leaf)
                .map(|m| m.credential.serialized_content().to_vec())
                .ok_or(MlsError::ManifestMismatch)?;
            actual_removed.push(identity);
        }

        let mut expected_added = expected_added.to_vec();
        let mut expected_removed = expected_removed.to_vec();
        actual_added.sort();
        actual_removed.sort();
        expected_added.sort();
        expected_removed.sort();
        if actual_added != expected_added || actual_removed != expected_removed {
            // Drop the staged commit unmerged: our cryptographic state must not follow a lie.
            return Err(MlsError::ManifestMismatch);
        }

        self.group
            .merge_staged_commit(&me.provider, *staged)
            .map_err(lib)?;
        debug_assert_eq!(self.epoch(), expected_next_epoch);
        Ok(())
    }

    /// The MLS group id — the key under which this group's state lives in the store. Not a secret.
    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    /// Reload a conversation's group state from a restored [`Member`]'s store (crash recovery).
    pub fn reload(member: &Member, group_id: &[u8]) -> Result<Self> {
        let gid = GroupId::from_slice(group_id);
        let group = MlsGroup::load(member.provider.storage(), &gid)
            .map_err(lib)?
            .ok_or(MlsError::MemberNotFound)?;
        Ok(Self { group })
    }

    fn leaf_for_identity(&self, identity: &[u8]) -> Option<LeafNodeIndex> {
        self.group.members().find_map(|m| {
            if m.credential.serialized_content() == identity {
                Some(m.index)
            } else {
                None
            }
        })
    }
}
