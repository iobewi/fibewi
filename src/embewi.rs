//! Embewi OTA application metadata and transaction projection.
//!
//! The serialized `OTM1` record must remain readable by deployed firmware.
//! Targets are opaque names; the platform adapter translates them to slots.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use crate::{Action, ArtifactRecord, BackendOutcome, Digest, TransactionMetadata, TransactionRecord, TransactionState, reconcile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataError { Persistence, Corrupt, TooLarge }

const METADATA_MAGIC: &[u8; 4] = b"OTM1";
const METADATA_HEADER_LEN: usize = 19;
const MAX_SLOT_LEN: usize = 8;
const MAX_DIGEST_LEN: usize = 71;
const MAX_DEPLOYMENT_ID_LEN: usize = 128;
/// Embewi contract §4: `staged.state` ∈ `none | written | activating`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    None,
    Written,
    Activating,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::None => "none",
            Stage::Written => "written",
            Stage::Activating => "activating",
        }
    }

    pub const fn transaction_state(self) -> Option<TransactionState> {
        match self {
            Self::None => None,
            Self::Written => Some(TransactionState::Staged),
            Self::Activating => Some(TransactionState::Activating),
        }
    }
}

/// What's sitting in the inactive slot right now (contrat §4/§6's staged
/// object).
#[derive(Clone, Default)]
pub struct Staged {
    pub stage: Stage,
    pub slot: String,
    pub digest: String,
    pub deployment_id: String,
    pub size: u32,
}

impl Default for Stage {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Default)]
pub struct Metadata {
    pub staged: Staged,
    pub active_digest: String,
    pub active_deployment_id: String,
}

/// Abstract access to the OTA component's atomically published byte space.
/// ConfigSpace, file backed storage and other platforms can provide it.
#[allow(async_fn_in_trait)]
pub trait MetadataStore {
    type Error;
    async fn load_raw(&self) -> Result<Option<Vec<u8>>, Self::Error>;
    async fn commit_raw(&self, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub async fn load_metadata<S: MetadataStore>(store: &S) -> Result<Metadata, MetadataError> {
    match store.load_raw().await.map_err(|_| MetadataError::Persistence)? {
        Some(raw) => Metadata::decode(&raw),
        None => Ok(Metadata::default()),
    }
}

pub async fn save_metadata<S: MetadataStore>(store: &S, metadata: &Metadata) -> Result<(), MetadataError> {
    let bytes = metadata.encode()?;
    store.commit_raw(&bytes).await.map_err(|_| MetadataError::Persistence)
}

pub async fn clear_staged<S: MetadataStore>(store: &S) -> Result<(), MetadataError> {
    let mut metadata = load_metadata(store).await?;
    metadata.set_staged(Staged::default());
    save_metadata(store, &metadata).await
}

pub async fn load_transaction<S: MetadataStore>(store: &S) -> Result<Option<Transaction>, MetadataError> {
    let metadata = load_metadata(store).await?;
    Ok(transaction_from_staged(&metadata.staged))
}

pub async fn commit_transaction<S: MetadataStore>(store: &S, record: Option<&Transaction>) -> Result<(), MetadataError> {
    let mut metadata = load_metadata(store).await?;
    metadata.set_staged(staged_from_transaction(record)?);
    save_metadata(store, &metadata).await
}

pub async fn promote_staged<S: MetadataStore>(store: &S, staged: &Staged) -> Result<(), MetadataError> {
    let mut metadata = load_metadata(store).await?;
    metadata.promote_staged(staged);
    save_metadata(store, &metadata).await
}

impl Metadata {
    /// Matches the existing ConfigSpace allocation for OTA metadata.
    pub const MAX_BYTES: usize = 512;

    pub fn set_staged(&mut self, staged: Staged) {
        self.staged = staged;
    }

    pub fn promote_staged(&mut self, staged: &Staged) {
        self.active_digest = staged.digest.clone();
        self.active_deployment_id = staged.deployment_id.clone();
    }

    pub fn encode(&self) -> Result<alloc::vec::Vec<u8>, MetadataError> {
        let fields = [
            self.staged.slot.as_bytes(),
            self.staged.digest.as_bytes(),
            self.staged.deployment_id.as_bytes(),
            self.active_digest.as_bytes(),
            self.active_deployment_id.as_bytes(),
        ];
        if fields[0].len() > MAX_SLOT_LEN
            || fields[1].len() > MAX_DIGEST_LEN
            || fields[2].len() > MAX_DEPLOYMENT_ID_LEN
            || fields[3].len() > MAX_DIGEST_LEN
            || fields[4].len() > MAX_DEPLOYMENT_ID_LEN
        {
            return Err(MetadataError::TooLarge);
        }

        let total = METADATA_HEADER_LEN
            + fields.iter().map(|field| field.len()).sum::<usize>();
        if total > Self::MAX_BYTES {
            return Err(MetadataError::TooLarge);
        }

        let mut out = alloc::vec::Vec::with_capacity(total);
        out.extend_from_slice(METADATA_MAGIC);
        out.push(self.staged.stage as u8);
        out.extend_from_slice(&self.staged.size.to_le_bytes());
        for field in fields {
            let len = u16::try_from(field.len()).map_err(|_| MetadataError::TooLarge)?;
            out.extend_from_slice(&len.to_le_bytes());
        }
        for field in fields {
            out.extend_from_slice(field);
        }
        Ok(out)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, MetadataError> {
        if raw.len() < METADATA_HEADER_LEN || &raw[..4] != METADATA_MAGIC {
            return Err(MetadataError::Corrupt);
        }
        let stage = match raw[4] {
            0 => Stage::None,
            1 => Stage::Written,
            2 => Stage::Activating,
            _ => return Err(MetadataError::Corrupt),
        };
        let size = u32::from_le_bytes([raw[5], raw[6], raw[7], raw[8]]);
        let mut lens = [0usize; 5];
        for (i, len) in lens.iter_mut().enumerate() {
            let at = 9 + i * 2;
            *len = u16::from_le_bytes([raw[at], raw[at + 1]]) as usize;
        }
        if lens[0] > MAX_SLOT_LEN
            || lens[1] > MAX_DIGEST_LEN
            || lens[2] > MAX_DEPLOYMENT_ID_LEN
            || lens[3] > MAX_DIGEST_LEN
            || lens[4] > MAX_DEPLOYMENT_ID_LEN
        {
            return Err(MetadataError::Corrupt);
        }

        let mut cursor = METADATA_HEADER_LEN;
        let mut next = |len: usize| -> Result<&str, MetadataError> {
            let end = cursor.checked_add(len).ok_or(MetadataError::Corrupt)?;
            let bytes = raw.get(cursor..end).ok_or(MetadataError::Corrupt)?;
            cursor = end;
            core::str::from_utf8(bytes).map_err(|_| MetadataError::Corrupt)
        };
        let slot = String::from(next(lens[0])?);
        let digest = String::from(next(lens[1])?);
        let deployment_id = String::from(next(lens[2])?);
        let active_digest = String::from(next(lens[3])?);
        let active_deployment_id = String::from(next(lens[4])?);
        if cursor != raw.len() {
            return Err(MetadataError::Corrupt);
        }

        Ok(Self {
            staged: Staged { stage, slot, digest, deployment_id, size },
            active_digest,
            active_deployment_id,
        })
    }
}

pub type Transaction = TransactionRecord<String, String, String>;

/// In-memory staging for FiBeWI's synchronous transition API. Its result
/// must be persisted by the caller before switching the physical boot slot.
pub struct MemoryTransactionMetadata {
    pub record: Option<Transaction>,
}

impl TransactionMetadata for MemoryTransactionMetadata {
    type Error = ();
    type Record = Transaction;

    fn load(&mut self) -> Result<Option<Self::Record>, Self::Error> {
        Ok(self.record.clone())
    }

    fn commit(&mut self, record: Option<&Self::Record>) -> Result<(), Self::Error> {
        self.record = record.cloned();
        Ok(())
    }
}

/// Publish one verified firmware artifact as an Embewi transaction. The
/// platform provides only the target name; FiBeWI owns the record shape.
pub fn firmware_record(deployment_id: String, size: u64, digest: Digest, target: String) -> Transaction {
    Transaction::staged(
        deployment_id,
        ArtifactRecord { id: String::from("firmware"), size, digest, target },
    )
}

pub fn parse_digest(value: &str) -> Option<Digest> {
    let hex = value.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(Digest(bytes))
}

pub fn format_digest(digest: &Digest) -> String {
    let mut s = String::from("sha256:");
    for b in digest.0 {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn transaction_from_staged(staged: &Staged) -> Option<Transaction> {
    let state = match staged.stage {
        Stage::None => return None,
        Stage::Written => TransactionState::Staged,
        Stage::Activating => TransactionState::Activating,
    };
    Some(Transaction {
        id: staged.deployment_id.clone(),
        state,
        artifacts: alloc::vec![ArtifactRecord {
            id: String::from("firmware"),
            size: u64::from(staged.size),
            digest: parse_digest(&staged.digest)?,
            target: staged.slot.clone(),
        }],
    })
}

pub fn staged_from_transaction(record: Option<&Transaction>) -> Result<Staged, MetadataError> {
    let Some(record) = record else {
        return Ok(Staged::default());
    };
    let stage = match record.state {
        TransactionState::Staged => Stage::Written,
        TransactionState::Activating => Stage::Activating,
    };
    let [artifact] = record.artifacts.as_slice() else {
        return Err(MetadataError::Corrupt);
    };
    if artifact.id != "firmware" {
        return Err(MetadataError::Corrupt);
    }
    let size = u32::try_from(artifact.size).map_err(|_| MetadataError::TooLarge)?;
    Ok(Staged {
        stage,
        slot: artifact.target.clone(),
        digest: format_digest(&artifact.digest),
        deployment_id: record.id.clone(),
        size,
    })
}

/// A staged image may be superseded; an activation in flight must not.
pub fn can_supersede(record: Option<&Transaction>) -> bool {
    record.is_none_or(|record| record.state == TransactionState::Staged)
}

/// Identity fixed by the first upload request. Later chunks must repeat it.
#[derive(Clone, Debug)]
pub struct SessionParams {
    pub deployment_id: String,
    pub digest: String,
    pub total: u32,
}

impl SessionParams {
    pub fn matches(&self, other: &Self) -> bool {
        self.deployment_id == other.deployment_id
            && self.digest.eq_ignore_ascii_case(&other.digest)
            && self.total == other.total
    }
}

/// Business outcomes for Embewi's prepare request. HTTP rendering belongs
/// to the agent's transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareRefusal {
    ChipMismatch,
    LayoutMismatch,
    Busy,
    SizeTooLarge,
}

impl PrepareRefusal {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ChipMismatch => "chip_mismatch",
            Self::LayoutMismatch => "layout_mismatch",
            Self::Busy => "busy",
            Self::SizeTooLarge => "size_too_large",
        }
    }
}

/// Check compatibility before examining any flash or metadata.
pub fn check_compatibility(chip: &str, layout: &str, platform_chip: &str, platform_layout: &str) -> Result<(), PrepareRefusal> {
    if chip != platform_chip {
        return Err(PrepareRefusal::ChipMismatch);
    }
    if layout != platform_layout {
        return Err(PrepareRefusal::LayoutMismatch);
    }
    Ok(())
}

/// Check size before consulting staged transactions. The platform chooses
/// the target and reports its capacity; FiBeWI decides if a write is safe.
pub fn check_target(size: u64, capacity: Option<u64>) -> Result<(), PrepareRefusal> {
    let capacity = capacity.ok_or(PrepareRefusal::Busy)?;
    if size > capacity {
        return Err(PrepareRefusal::SizeTooLarge);
    }
    Ok(())
}

pub fn check_staged(record: Option<&Transaction>) -> Result<(), PrepareRefusal> {
    if can_supersede(record) { Ok(()) } else { Err(PrepareRefusal::Busy) }
}

/// Reconcile the persisted Embewi record against the platform's boot report.
/// An unknown booted slot stays unknown so no destructive recovery follows
/// from a failed hardware read.
pub fn boot_action(staged: &Staged, image: BackendOutcome, booted_slot: Option<&str>) -> Action {
    let matches_staged = booted_slot.map(|slot| slot == staged.slot);
    reconcile(staged.stage.transaction_state(), image, matches_staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct MemoryStore(RefCell<Option<Vec<u8>>>);

    impl MetadataStore for MemoryStore {
        type Error = ();
        async fn load_raw(&self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.borrow().clone())
        }
        async fn commit_raw(&self, bytes: &[u8]) -> Result<(), Self::Error> {
            *self.0.borrow_mut() = Some(bytes.to_vec());
            Ok(())
        }
    }

    fn ready<F: Future>(future: F) -> F::Output {
        struct Noop;
        impl Wake for Noop { fn wake(self: Arc<Self>) {} }
        let waker = Waker::from(Arc::new(Noop));
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("in-memory store must be immediately ready"),
        }
    }

    #[test]
    fn reads_existing_otm1_record_and_keeps_its_layout() {
        // Existing NVS layout: magic, state, u32 size, five u16 lengths,
        // then slot, staged digest, deployment, active digest and deployment.
        let legacy = b"OTM1\x01\x00\x04\x00\x00\x05\x00\x00\x00\x08\x00\x00\x00\x00\x00ota_1deploy-1";
        let stored = Metadata::decode(legacy).unwrap();
        assert_eq!(stored.staged.stage.as_str(), "written");
        assert_eq!(stored.staged.size, 1024);
        assert_eq!(stored.staged.slot, "ota_1");
        assert_eq!(stored.staged.deployment_id, "deploy-1");
        assert_eq!(stored.encode().unwrap(), legacy);
    }

    #[test]
    fn rejects_trailing_data() {
        let metadata = Metadata {
            staged: Staged { stage: Stage::Written, slot: String::from("ota_1"), digest: format_digest(&Digest([0x42; 32])), deployment_id: String::from("deploy-1"), size: 1024 },
            active_digest: String::from("old"),
            active_deployment_id: String::from("deploy-0"),
        };
        let bytes = metadata.encode().unwrap();
        assert_eq!(&bytes[..4], b"OTM1");
        let restored = Metadata::decode(&bytes).unwrap();
        assert_eq!(restored.staged.slot, "ota_1");
        assert_eq!(restored.staged.size, 1024);
        assert_eq!(restored.active_deployment_id, "deploy-0");
        let mut corrupted = bytes;
        corrupted.push(0);
        assert!(matches!(Metadata::decode(&corrupted), Err(MetadataError::Corrupt)));
    }

    #[test]
    fn transaction_keeps_an_opaque_platform_target() {
        let record = Transaction::staged(
            String::from("deploy"),
            ArtifactRecord { id: String::from("firmware"), size: 10, digest: Digest([0x13; 32]), target: String::from("bank-b") },
        );
        let staged = staged_from_transaction(Some(&record)).unwrap();
        assert_eq!(staged.slot, "bank-b");
        assert_eq!(transaction_from_staged(&staged).unwrap().artifacts[0].target, "bank-b");
        assert!(can_supersede(Some(&record)));
        assert!(!can_supersede(Some(&record.with_state(TransactionState::Activating))));
    }

    #[test]
    fn prepare_refuses_an_activating_transaction_without_erasing_it() {
        let record = Transaction::staged(
            String::from("deploy"),
            ArtifactRecord { id: String::from("firmware"), size: 10, digest: Digest([0x13; 32]), target: String::from("bank-b") },
        ).with_state(TransactionState::Activating);
        assert_eq!(check_staged(Some(&record)), Err(PrepareRefusal::Busy));
        assert_eq!(check_target(11, Some(10)), Err(PrepareRefusal::SizeTooLarge));
        assert_eq!(check_compatibility("RP2350", "v1", "ESP32-S3", "v1"), Err(PrepareRefusal::ChipMismatch));
        assert_eq!(record.state, TransactionState::Activating);
    }

    #[test]
    fn continuing_upload_keeps_identity_and_accepts_uppercase_digest() {
        let session = SessionParams { deployment_id: String::from("deploy"), digest: String::from("sha256:abc"), total: 10 };
        let next = SessionParams { deployment_id: String::from("deploy"), digest: String::from("sha256:ABC"), total: 10 };
        assert!(session.matches(&next));
        assert!(!session.matches(&SessionParams { total: 11, ..next }));
    }

    #[test]
    fn unknown_boot_slot_does_not_trigger_rollback() {
        let staged = Staged {
            stage: Stage::Activating,
            slot: String::from("bank-b"),
            ..Staged::default()
        };
        assert_eq!(boot_action(&staged, BackendOutcome::PendingConfirmation, None), Action::AwaitConfirmation);
        assert_eq!(boot_action(&staged, BackendOutcome::PendingConfirmation, Some("bank-a")), Action::RollbackUnaccounted);
    }

    #[test]
    fn clearing_staged_transaction_preserves_active_identity() {
        let store = MemoryStore(RefCell::new(None));
        let mut metadata = Metadata {
            active_digest: String::from("sha256:active"),
            active_deployment_id: String::from("running"),
            ..Metadata::default()
        };
        metadata.staged = Staged {
            stage: Stage::Written,
            slot: String::from("bank-b"),
            digest: format_digest(&Digest([0x13; 32])),
            deployment_id: String::from("candidate"),
            size: 10,
        };
        ready(save_metadata(&store, &metadata)).unwrap();
        assert!(ready(load_transaction(&store)).unwrap().is_some());
        ready(clear_staged(&store)).unwrap();
        let reloaded = ready(load_metadata(&store)).unwrap();
        assert_eq!(reloaded.staged.stage.as_str(), "none");
        assert_eq!(reloaded.active_digest, "sha256:active");
        assert_eq!(reloaded.active_deployment_id, "running");
    }
}
