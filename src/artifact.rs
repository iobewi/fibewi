//! Streaming write of one artifact's bytes: accepts data in any chunking,
//! tracks *received* (accepted into this session) separately from *durable*
//! (the backend's own watermark, from [`crate::storage::ArtifactStorage`]),
//! and hashes exactly the bytes that have become durable -- never bytes
//! merely received, and never by re-reading them back from storage.
//!
//! That distinction is the one invariant this module exists to hold: after
//! a dropped connection, only `durable` bytes are known to still be there,
//! so a resumed stream must continue from `durable`, never from `received`
//! (which can run ahead of it by however much the backend was still
//! holding, unflushed, at the moment things stopped). A [`WriteSession`]
//! itself is never reconstructed from a `durable` watermark alone -- its
//! digest lives only in its own live hasher, so "resuming" only ever means
//! a caller keeping the *same* session across chunks; see
//! [`WriteSession::begin`]'s own doc comment for what that implies about
//! surviving a process restart (it doesn't, by design, same as the proven
//! code this was extracted from).
//!
//! Nothing here knows what a "sector" is: [`crate::storage::ArtifactStorage`]
//! decides, on every call, how much of what it's offered it can make
//! durable right now, and this module keeps whatever it didn't take (the
//! *pending* tail) in RAM until the backend says otherwise.
//!
//! That backend is not trusted on faith to keep its side of this: every
//! `write`/`finish` reply is checked, as a real, non-optimized-out error
//! ([`Error::InvalidDurabilityReport`]), against
//! `old_durable <= new_durable <= old_durable + pending.len()`. A backend
//! that never advances `durable` at all is legal -- `pending` then grows,
//! but only up to `total` (bounded by the same check `append` already
//! makes on `received`), never past it and never without bound.

use alloc::vec::Vec;
use sha2::{Digest as _, Sha256};

use crate::error::Error;
use crate::storage::ArtifactStorage;

/// A SHA-256 digest -- see the crate doc comment for why this crate commits
/// to one concrete algorithm rather than a generic hasher trait: it is
/// reused, proven code, not a speculative abstraction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// [`resume_plan`]'s outcome. Transport-agnostic: the caller derives
/// `claims_progress`/`claimed_offset` from whatever resume header its own
/// protocol uses (`Content-Range`, a resumable-upload token, ...) -- this
/// module has no notion of that format, only of the decision it drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumePlan {
    /// Start a new session (no resume claimed, or the claimed offset is 0).
    Begin,
    /// The claim doesn't match this session's state: no session in
    /// progress, or the claimed offset doesn't equal what's actually
    /// durable. The caller must reject the chunk and report `durable` back.
    Resync,
    /// The claim matches: append the incoming bytes to the session in
    /// progress.
    Continue,
}

/// Ported from `embewi-agent-esp`'s `ota_logic::write_plan` (itself a port
/// of `firmware-c`'s `embewi_ota_plan`), with `Content-Range` genericized
/// into `claims_progress`/`claimed_offset`.
///
/// `session_active` and `durable` describe the *engine's* state, not the
/// backend's -- callers get these from whether a [`WriteSession`] exists and
/// its own `durable()`.
pub fn resume_plan(claims_progress: bool, claimed_offset: u64, session_active: bool, durable: u64) -> ResumePlan {
    if !claims_progress || claimed_offset == 0 {
        return ResumePlan::Begin;
    }
    if !session_active || durable != claimed_offset {
        return ResumePlan::Resync;
    }
    ResumePlan::Continue
}

/// Ported from `ota_logic::write_is_final`. `claimed_end` is inclusive (the
/// last byte offset of the chunk just accepted), as `Content-Range` and
/// similar resumable-upload schemes describe it; the `+ 1` is checked so
/// `claimed_end == u64::MAX` can never wrap and spuriously match `total ==
/// 0`.
pub fn is_complete(claims_range: bool, claimed_end: u64, total: u64) -> bool {
    !claims_range || claimed_end.checked_add(1) == Some(total)
}

/// What [`WriteSession::finish`] returns once every byte is durable and the
/// digest matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    pub size: u64,
    pub digest: Digest,
}

/// One streaming write session. Deliberately **not** generic over, or
/// owning, an [`ArtifactStorage`] backend -- `append`/`finish` take one by
/// `&mut` instead, per call. A backend is very often not a value a caller
/// can hold onto for a whole session's lifetime in the first place: on an
/// embedded target the flash it wraps is commonly behind an async lock
/// shared with unrelated work (config reads, ...), reacquired fresh for
/// each HTTP chunk, which a struct field borrowing it for the session's
/// duration cannot express. Taking the backend per call costs nothing for
/// a backend that *can* be held (a caller just passes the same one every
/// time) and is the only shape that also works for one that can't.
///
/// Buffers, in RAM, only the bytes the backend hasn't yet made durable
/// (`pending`) -- bounded in practice by whatever physical unit the backend
/// batches on, but this type never assumes a size for that; it just keeps
/// growing/draining `pending` as `write`'s watermark moves.
pub struct WriteSession {
    total: u64,
    expected_digest: Digest,
    received: u64,
    durable: u64,
    pending: Vec<u8>,
    hasher: Sha256,
}

impl WriteSession {
    /// Opens a fresh session for an artifact of `total` bytes, whose digest
    /// must match `expected_digest` once every byte is durable.
    ///
    /// There is deliberately no constructor that reconstructs a session
    /// from a `durable` watermark alone (say, after a process restart): the
    /// digest is accumulated in this session's own live hasher as bytes are
    /// appended, never re-derived by re-reading storage, so nothing can
    /// seed a hasher for bytes this session didn't itself hash. "Resuming"
    /// a session therefore only ever means a caller holding on to the same
    /// still-live `WriteSession` across chunks of one upload -- exactly
    /// what [`resume_plan`]'s `session_active` is asking about. A session
    /// that didn't survive (the process restarted) has no resume: the
    /// caller starts over with a new one from offset 0, which is also why
    /// this type carries no on-disk representation of its own.
    pub fn begin(total: u64, expected_digest: Digest) -> Self {
        WriteSession { total, expected_digest, received: 0, durable: 0, pending: Vec::new(), hasher: Sha256::new() }
    }

    /// Bytes accepted into this session so far (`durable` plus whatever is
    /// still buffered, unflushed). This is what an *uninterrupted* stream's
    /// next chunk continues from -- see [`resume_plan`]'s own doc comment
    /// for why that's a different number from `durable`.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Whether another chunk fits the declared image length. Backends can
    /// check this before erasing a block for a chunk that would be refused.
    pub fn can_append(&self, len: usize) -> bool {
        u64::try_from(len)
            .ok()
            .and_then(|len| self.received.checked_add(len))
            .is_some_and(|end| end <= self.total)
    }

    /// Bytes the backend has confirmed durable. The point it's safe to
    /// resume from after an interruption.
    pub fn durable(&self) -> u64 {
        self.durable
    }

    /// Appends `data`, offering the accumulated undurable tail to `storage`
    /// and hashing exactly whatever portion of it `storage` just made
    /// durable. `storage` need not be the same value/reference across
    /// calls (see this type's own doc comment) -- only the same *target*.
    ///
    /// A backend that never advances `durable` at all is not rejected here
    /// -- it is a legitimate (if pathological) way to answer `write` -- but
    /// note what that costs: `pending` keeps every byte offered and never
    /// durable, so it grows up to `total` in the worst case. This crate
    /// bounds that growth by `total` (via the `TooLarge` check below, which
    /// still applies) rather than by anything smaller; a backend that wants
    /// a tighter bound enforces its own (a real flash backend durables at
    /// least every physical unit, keeping `pending` far under `total` in
    /// practice) -- seeing `write` called at all is not a promise of
    /// progress on its own.
    pub fn append<S: ArtifactStorage>(&mut self, storage: &mut S, data: &[u8]) -> Result<(), Error<S::Error>> {
        if !self.can_append(data.len()) {
            return Err(Error::TooLarge);
        }
        let end = self.received + data.len() as u64;
        self.pending.extend_from_slice(data);
        self.received = end;

        let new_durable = storage.write(self.durable, &self.pending).map_err(Error::Backend)?;
        self.advance(new_durable)?;
        Ok(())
    }

    /// Closes the session: flushes whatever is left buffered (a backend's
    /// final, possibly short-of-a-full-unit write), then checks completeness
    /// and the digest. Both checks happen here, together, so a caller can't
    /// observe "complete" without also "digest verified" -- see the crate
    /// doc comment's invariant on never activating an unverified artifact.
    pub fn finish<S: ArtifactStorage>(mut self, storage: &mut S) -> Result<Committed, Error<S::Error>> {
        if !self.pending.is_empty() {
            let expected = self.durable + self.pending.len() as u64;
            let new_durable = storage.finish(self.durable, &self.pending).map_err(Error::Backend)?;
            self.advance(new_durable)?;
            if self.durable != expected {
                // `advance` already refused a `new_durable` past `expected`
                // (that's `InvalidDurabilityReport`); reaching here means it
                // was short of it, i.e. `finish` didn't actually consume
                // everything it was handed.
                return Err(Error::Incomplete { durable: self.durable });
            }
        }
        if self.durable != self.total {
            return Err(Error::Incomplete { durable: self.durable });
        }
        let digest = Digest(self.hasher.finalize().into());
        if digest != self.expected_digest {
            return Err(Error::DigestMismatch(digest));
        }
        Ok(Committed { size: self.durable, digest })
    }

    /// Hashes the newly-durable prefix of `pending` and drains it, moving
    /// `durable` forward to `new_durable` -- after checking, as a real
    /// error and not a `debug_assert` (see [`Error::InvalidDurabilityReport`]),
    /// that the backend's claim actually fits what it was offered:
    /// `self.durable <= new_durable <= self.durable + self.pending.len()`.
    fn advance<E>(&mut self, new_durable: u64) -> Result<(), Error<E>> {
        if new_durable < self.durable {
            return Err(Error::InvalidDurabilityReport);
        }
        let consumed = new_durable - self.durable;
        if consumed > self.pending.len() as u64 {
            return Err(Error::InvalidDurabilityReport);
        }
        let consumed = consumed as usize;
        self.hasher.update(&self.pending[..consumed]);
        self.pending.drain(..consumed);
        self.durable = new_durable;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn plan_no_progress_claimed_always_begins() {
        assert_eq!(resume_plan(false, 0, false, 0), ResumePlan::Begin);
        assert_eq!(resume_plan(false, 42, true, 42), ResumePlan::Begin);
    }

    #[test]
    fn plan_offset_zero_always_begins() {
        assert_eq!(resume_plan(true, 0, true, 1234), ResumePlan::Begin);
        assert_eq!(resume_plan(true, 0, false, 0), ResumePlan::Begin);
    }

    #[test]
    fn plan_resyncs_when_nothing_in_progress() {
        assert_eq!(resume_plan(true, 100, false, 0), ResumePlan::Resync);
    }

    #[test]
    fn plan_resyncs_on_offset_mismatch() {
        assert_eq!(resume_plan(true, 100, true, 50), ResumePlan::Resync);
        assert_eq!(resume_plan(true, 100, true, 200), ResumePlan::Resync);
    }

    #[test]
    fn plan_continues_when_aligned() {
        assert_eq!(resume_plan(true, 100, true, 100), ResumePlan::Continue);
    }

    #[test]
    fn is_complete_without_a_range_is_always_complete() {
        // Legacy monolithic write: one call is the whole artifact.
        assert!(is_complete(false, 0, 0));
        assert!(is_complete(false, 999, 1));
    }

    #[test]
    fn is_complete_with_a_range_checks_the_last_byte() {
        assert!(is_complete(true, 999, 1000));
        assert!(!is_complete(true, 499, 1000));
    }

    #[test]
    fn is_complete_off_by_one_boundaries() {
        assert!(is_complete(true, 0, 1));
        assert!(!is_complete(true, 0, 2));
    }

    #[test]
    fn is_complete_u64_max_end_cannot_wrap() {
        assert!(!is_complete(true, u64::MAX, 0));
        assert!(is_complete(true, u64::MAX - 1, u64::MAX));
    }

    /// A backend that only ever makes a whole `unit`-sized run of bytes
    /// durable at a time -- standing in for "a flash sector", without this
    /// test (or [`WriteSession`]) ever naming one. `finish` is the only
    /// place a short-of-a-full-unit tail is accepted.
    struct UnitBackend {
        unit: usize,
        committed: alloc::vec::Vec<u8>,
    }

    impl ArtifactStorage for UnitBackend {
        type Error = &'static str;

        fn write(&mut self, durable_offset: u64, pending: &[u8]) -> Result<u64, Self::Error> {
            assert_eq!(durable_offset, self.committed.len() as u64, "engine's offset must track the backend's own durability");
            let take = (pending.len() / self.unit) * self.unit;
            self.committed.extend_from_slice(&pending[..take]);
            Ok(self.committed.len() as u64)
        }

        fn finish(&mut self, durable_offset: u64, pending: &[u8]) -> Result<u64, Self::Error> {
            assert_eq!(durable_offset, self.committed.len() as u64);
            self.committed.extend_from_slice(pending);
            Ok(self.committed.len() as u64)
        }
    }

    fn digest_of(data: &[u8]) -> Digest {
        use sha2::{Digest as _, Sha256};
        Digest(Sha256::digest(data).into())
    }

    #[test]
    fn streams_in_odd_chunks_and_matches_a_plain_digest() {
        let data: alloc::vec::Vec<u8> = (0u8..=255).cycle().take(10_007).collect();
        let expected = digest_of(&data);
        let mut backend = UnitBackend { unit: 64, committed: vec![] };
        let mut session = WriteSession::begin(data.len() as u64, expected);

        // Deliberately not a multiple of `unit`, and not of the data length either.
        for chunk in data.chunks(37) {
            session.append(&mut backend, chunk).unwrap();
        }
        let committed = session.finish(&mut backend).unwrap();
        assert_eq!(committed.size, data.len() as u64);
        assert_eq!(committed.digest, expected);
    }

    #[test]
    fn received_can_run_ahead_of_durable_but_digest_only_ever_covers_durable() {
        let mut backend = UnitBackend { unit: 8, committed: vec![] };
        let mut session = WriteSession::begin(20, digest_of(&[0u8; 20]));
        session.append(&mut backend, &[0u8; 5]).unwrap();
        // 5 bytes received, but nothing is a whole 8-byte unit yet.
        assert_eq!(session.received(), 5);
        assert_eq!(session.durable(), 0);
        session.append(&mut backend, &[0u8; 5]).unwrap();
        // 10 received; one 8-byte unit durable, 2 bytes still only pending.
        assert_eq!(session.received(), 10);
        assert_eq!(session.durable(), 8);
    }

    #[test]
    fn refuses_more_than_the_declared_total() {
        let mut backend = UnitBackend { unit: 4, committed: vec![] };
        let mut session = WriteSession::begin(10, digest_of(&[0u8; 10]));
        assert_eq!(session.append(&mut backend, &[0u8; 11]), Err(Error::TooLarge));
    }

    #[test]
    fn finish_short_of_the_total_is_incomplete() {
        let mut backend = UnitBackend { unit: 4, committed: vec![] };
        let mut session = WriteSession::begin(10, digest_of(&[0u8; 10]));
        session.append(&mut backend, &[0u8; 5]).unwrap();
        // 4 bytes durable from `append` (one whole unit), `finish` flushes
        // the last 1 -- 5 of 10 declared, reported back exactly.
        assert_eq!(session.finish(&mut backend), Err(Error::Incomplete { durable: 5 }));
    }

    #[test]
    fn finish_with_a_wrong_digest_is_rejected_even_once_complete() {
        let mut backend = UnitBackend { unit: 4, committed: vec![] };
        let wrong = digest_of(b"not what actually gets written");
        let mut session = WriteSession::begin(4, wrong);
        session.append(&mut backend, &[1, 2, 3, 4]).unwrap();
        // The error carries what was *actually* computed, not the expected
        // one the caller already has -- proves it's the real digest of
        // `[1,2,3,4]`, not e.g. `wrong` echoed back or a placeholder.
        assert_eq!(session.finish(&mut backend), Err(Error::DigestMismatch(digest_of(&[1, 2, 3, 4]))));
    }

    /// A backend that answers `write`/`finish` with whatever watermark the
    /// test tells it to, regardless of what it was actually offered --
    /// standing in for a buggy or adversarial implementation of the trait,
    /// to prove the *engine* -- not backend goodwill -- is what keeps
    /// `old_durable <= new_durable <= old_durable + pending.len()`.
    struct LyingBackend {
        next_durable: u64,
    }

    impl ArtifactStorage for LyingBackend {
        type Error = ();
        fn write(&mut self, _durable_offset: u64, _pending: &[u8]) -> Result<u64, Self::Error> {
            Ok(self.next_durable)
        }
        fn finish(&mut self, _durable_offset: u64, _pending: &[u8]) -> Result<u64, Self::Error> {
            Ok(self.next_durable)
        }
    }

    #[test]
    fn a_backend_claiming_more_durable_than_it_was_offered_is_rejected() {
        let mut backend = LyingBackend { next_durable: 1_000_000 };
        let mut session = WriteSession::begin(100, digest_of(&[0u8; 100]));
        assert_eq!(session.append(&mut backend, &[0u8; 10]), Err(Error::InvalidDurabilityReport));
    }

    #[test]
    fn a_backend_reporting_durability_moving_backward_is_rejected() {
        let mut backend = LyingBackend { next_durable: 8 };
        let mut session = WriteSession::begin(100, digest_of(&[0u8; 100]));
        // Legitimately advances durable to 8 (offered 8, claims exactly 8)...
        session.append(&mut backend, &[0u8; 8]).unwrap();
        assert_eq!(session.durable(), 8);
        // ... then the backend lies and claims durability *regressed*.
        backend.next_durable = 4;
        assert_eq!(session.append(&mut backend, &[0u8; 8]), Err(Error::InvalidDurabilityReport));
    }

    /// A backend that never durables a single byte until `finish`: legal
    /// (nothing requires progress on every call), and bounded -- `pending`
    /// grows only up to `total`, never past it, because `append` itself
    /// refuses to accept more than `total` regardless of what the backend
    /// does with it.
    struct NeverProgressesUntilFinish {
        committed: alloc::vec::Vec<u8>,
    }

    impl ArtifactStorage for NeverProgressesUntilFinish {
        type Error = &'static str;
        fn write(&mut self, durable_offset: u64, _pending: &[u8]) -> Result<u64, Self::Error> {
            Ok(durable_offset) // no progress, ever, until finish
        }
        fn finish(&mut self, durable_offset: u64, pending: &[u8]) -> Result<u64, Self::Error> {
            assert_eq!(durable_offset, self.committed.len() as u64);
            self.committed.extend_from_slice(pending);
            Ok(self.committed.len() as u64)
        }
    }

    #[test]
    fn a_backend_that_never_progresses_still_completes_correctly_at_finish() {
        let data: alloc::vec::Vec<u8> = (0u8..=200).collect();
        let expected = digest_of(&data);
        let mut backend = NeverProgressesUntilFinish { committed: vec![] };
        let mut session = WriteSession::begin(data.len() as u64, expected);
        for chunk in data.chunks(17) {
            session.append(&mut backend, chunk).unwrap();
            // Never durable early: RAM usage is bounded by `total`, not
            // unbounded, but it does grow -- exactly what a caller building
            // a tighter-than-`total` bound has to do with its own backend,
            // not something this crate silently assumes for it.
            assert_eq!(session.durable(), 0);
        }
        assert_eq!(session.received(), data.len() as u64);
        let committed = session.finish(&mut backend).unwrap();
        assert_eq!(committed.digest, expected);
        assert_eq!(committed.size, data.len() as u64);
    }
}
