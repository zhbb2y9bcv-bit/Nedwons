//! Narrow wrapper over OpenMLS (RFC 9420). No custom cryptography (ADR-0001).
//!
//! Relay boundary (THREAT_MODEL.md INV-1): only the opaque bytes these methods return cross the
//! network. The **server never links this crate**.
//!
//! Each [`Member`] owns its own provider (key store); a [`Conversation`] must be operated with the
//! member that created or joined it.

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

/// The single pinned ciphersuite (CRYPTOGRAPHY.md §1). No silent negotiation.
///
/// Hybrid post-quantum: the KEM is X-Wing (X25519 **and** ML-KEM-768), so key establishment resists
/// harvest-now-decrypt-later and is never weaker than classical X25519 alone. Signatures stay
/// Ed25519 — authentication is verified live, so it carries no HNDL exposure (ADR-0016).
/// Requires the vendored provider (`core/vendor/openmls_rust_crypto`) for the X-Wing KEM arm.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

/// Surfaced across the FFI so the client can assert compatibility.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stable string for the FFI `capabilities()` report.
pub const CIPHERSUITE_NAME: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";

#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error("mls library error: {0}")]
    Lib(String),
    #[error("serialization error")]
    Codec,
    #[error("member not found in group")]
    MemberNotFound,
    /// Commit's cryptographic effect ≠ the sender's signed manifest (ADR-0010 correspondence
    /// check). NOT merged; state unchanged. A security event: the committer or server lied.
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
    /// `identity` is the credential's identity bytes (e.g. a device record id); not a secret.
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

    /// A fresh prekey others use to add this member asynchronously; published to the directory.
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

    pub fn key_package_bytes(&self) -> Result<Vec<u8>> {
        self.key_package()?
            .tls_serialize_detached()
            .map_err(|_| MlsError::Codec)
    }

    /// New group with this member as the sole initial participant.
    pub fn create_group(&self) -> Result<Conversation> {
        let group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true) // welcomes carry the ratchet tree
            .build(&self.provider, &self.signer, self.credential.clone())
            .map_err(lib)?;
        Ok(Conversation { group })
    }

    /// Join from a serialized Welcome produced by [`Conversation::add_member`].
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

    /// Needed to reload the signer from a restored store. Not a secret.
    pub fn public_key(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    /// Holds the signature key pair **and the group's ratchet secrets**. SENSITIVE: on device this
    /// blob is encrypted under the at-rest key hierarchy (CRYPTOGRAPHY.md §5) before touching disk.
    pub fn export_store(&self) -> Result<Vec<u8>> {
        // Serialized as pairs because JSON can't key an object by a byte array; also avoids the
        // storage crate's `test-utils`-gated codec.
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

    /// Rebuild from an [`export_store`](Member::export_store) blob plus the (non-secret) identity
    /// and public key. Caller then reloads the group with [`Conversation::reload`].
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

/// Commit fans out to existing members, welcome goes to the new one. Both opaque to the server.
pub struct AddResult {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

pub enum Incoming {
    Application(Vec<u8>),
    /// A commit was merged; group state advanced.
    StateAdvanced,
}

/// An MLS group, operated by its owning [`Member`].
pub struct Conversation {
    group: MlsGroup,
}

impl Conversation {
    /// Increments on every membership change (INV-9 visibility).
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn own_leaf(&self) -> u32 {
        self.group.own_leaf_index().u32()
    }

    /// Caller must deliver both returned values.
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

    /// Returns the commit to fan out. The epoch advances, so the removed member cannot decrypt
    /// future messages.
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
    // The proposer must NOT advance its own state until the server's epoch CAS confirms its commit
    // won, or a race loser desyncs by merging a commit the group never accepted. `stage_*` leave
    // the commit pending; `merge_staged` applies it, `clear_staged` discards it.

    /// Epoch unchanged until [`merge_staged`](Self::merge_staged).
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

    /// Server accepted (epoch CAS won): advance the epoch. Errors if no commit is pending.
    pub fn merge_staged(&mut self, me: &Member) -> Result<()> {
        self.group.merge_pending_commit(&me.provider).map_err(lib)
    }

    /// Server rejected, or we're rebasing. Epoch unchanged; caller rebuilds against fresh state.
    pub fn clear_staged(&mut self, me: &Member) -> Result<()> {
        self.group
            .clear_pending_commit(me.provider.storage())
            .map_err(lib)
    }

    /// Returns an opaque envelope.
    pub fn encrypt(&mut self, me: &Member, plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .group
            .create_message(&me.provider, &me.signer, plaintext)
            .map_err(lib)?;
        out.tls_serialize_detached().map_err(|_| MlsError::Codec)
    }

    /// Application messages yield plaintext; commits are merged and advance group state.
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

    /// ADR-0010 correspondence check: the commit's actual cryptographic effect must equal the
    /// sender's signed manifest, or it is discarded unmerged with [`MlsError::ManifestMismatch`].
    ///
    /// The half of membership verification only clients can do — the MLS-blind relay checked the
    /// manifest's signature/authorization/ordering, never its correspondence to the real change.
    ///
    /// `expected_*` are the manifest's device identities (credential identity bytes) and epoch.
    pub fn process_commit_checked(
        &mut self,
        me: &Member,
        mut envelope: &[u8],
        expected_next_epoch: u64,
        expected_added: &[Vec<u8>],
        expected_removed: &[Vec<u8>],
    ) -> Result<()> {
        // A stale or skipped epoch is a divergence, not something to merge through.
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
