//! A transactional, resumable, A/B-safe OTA engine core.
//!
//! `no_std`, and independent of the ESP32, `esp-hal`, Embassy, HTTP/TLS,
//! Kubernetes/any particular deployment control plane, and any one
//! bootloader's on-flash format. What it owns:
//!
//! * a streaming, resumable artifact write with a digest computed while
//!   writing, never re-read back afterward ([`artifact`]);
//! * a staged-transaction record and its lifecycle: staged -> activating ->
//!   resolved, with every field a multi-artifact transaction will need
//!   already in place, even though v1 only ever stages one ([`transaction`]);
//! * the decision table that reconciles a staged transaction against
//!   whatever the backend reports after a restart, so the outcome of a
//!   power cut at any point is always deterministic
//!   ([`transaction::reconcile`], [`state`]);
//! * two effect boundaries a backend implements ([`storage`]): bulk artifact
//!   bytes (streamed, not read-back-verified here) and a small transaction
//!   record (the one place this crate requires a genuinely atomic publish).
//!
//! # What is deliberately *not* here
//!
//! * `Content-Range` (or any other resume-token wire format) -- transport
//!   detail. [`artifact::resume_plan`]/[`artifact::is_complete`] take the
//!   *decoded* numbers; parsing a header into them is the caller's job.
//! * flash mechanics (sectors, erase/program, alignment/padding) -- backend
//!   detail, behind [`storage::ArtifactStorage`].
//! * concrete bootloader execution, partition lookup, flash I/O, MMU/cache,
//!   watchdogs, or SoC memory geometry -- those belong to the platform layer.
//!   FiBeWI does own the pure EWBT/A-B decision semantics and ESP image-format
//!   validator contracts exposed by [`boot`].
//! * a decision of *what* a "target" is (a flash slot, a container tag, a
//!   block device, ...) -- opaque to this crate, carried as the `Target`
//!   type parameter of [`transaction::TransactionRecord`].
//!
//! # Stability
//!
//! Nothing in this crate is a stable API yet: every public enum is
//! `#[non_exhaustive]` and every signature should be expected to move as
//! the multi-artifact and rollback paths are built out on top of it.
#![no_std]

#[cfg(feature = "engine")]
extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(feature = "engine")]
pub mod artifact;
#[cfg(feature = "boot")]
pub mod boot;
#[cfg(feature = "engine")]
pub mod error;
#[cfg(feature = "engine")]
pub mod embewi;
#[cfg(feature = "engine")]
pub mod state;
#[cfg(feature = "engine")]
pub mod storage;
#[cfg(feature = "engine")]
pub mod transaction;

#[cfg(feature = "engine")]
pub use artifact::{Committed, Digest, ResumePlan, WriteSession, is_complete, resume_plan};
#[cfg(feature = "engine")]
pub use error::Error;
#[cfg(feature = "engine")]
pub use state::{Action, BackendOutcome, TransactionState};
#[cfg(feature = "engine")]
pub use storage::{ArtifactStorage, TransactionMetadata};
#[cfg(feature = "engine")]
pub use transaction::{ArtifactRecord, TransactionRecord, activate, clear_stale, finish, reconcile};
