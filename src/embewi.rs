//! Embewi OTA application metadata and transaction projection.
//!
//! The serialized `OTM1` record must remain readable by deployed firmware.
//! Targets are opaque names; the platform adapter translates them to slots.

use alloc::string::String;
use core::fmt::Write as _;
use crate::{ArtifactRecord, Digest, TransactionRecord, TransactionState};

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
        _ => return Err(MetadataError::Corrupt),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
