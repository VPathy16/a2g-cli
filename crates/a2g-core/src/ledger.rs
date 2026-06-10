//! Ledger trait — abstract persistence interface for the enforcement engine.
//!
//! The core crate depends only on this trait. Concrete implementations
//! (SQLite, in-memory) live in the consumer crate and are wired in at the
//! call site. This keeps a2g-core free of any I/O or database dependency.

use crate::error::A2gError;

/// Minimal ledger interface required by the enforcement pipeline.
///
/// The enforcement engine needs two queries:
///   1. Has a given mandate been explicitly revoked?
///   2. How many decisions has an agent produced in the last N seconds?
///
/// Everything else (appending receipts, audit queries, authority log) is the
/// responsibility of the concrete ledger implementation in the CLI crate.
pub trait EnforceLedger {
    fn is_revoked(&self, agent_did: &str, mandate_hash: &str) -> Result<bool, A2gError>;

    fn count_recent(&self, agent_did: &str, seconds: i64) -> Result<u64, A2gError>;
}

/// A no-op ledger that never revokes mandates and has no rate limiting.
///
/// Intended for embedded and FFI use cases where mandate management and rate
/// limiting are implemented by the host process. Records no decisions and
/// persists nothing.
///
/// **Note**: a2g-ffi uses this exclusively. Host processes that need real
/// revocation or rate-limit enforcement must supply their own `EnforceLedger`.
pub struct NoopLedger;

impl EnforceLedger for NoopLedger {
    fn is_revoked(&self, _agent_did: &str, _mandate_hash: &str) -> Result<bool, A2gError> {
        Ok(false)
    }

    fn count_recent(&self, _agent_did: &str, _seconds: i64) -> Result<u64, A2gError> {
        Ok(0)
    }
}
