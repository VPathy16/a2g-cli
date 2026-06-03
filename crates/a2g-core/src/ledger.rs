//! Ledger trait — abstract persistence interface for the enforcement engine.
//!
//! The core crate depends only on this trait. Concrete implementations
//! (SQLite, in-memory) live in the consumer crate and are wired in at the
//! call site. This keeps a2g-core free of any I/O or database dependency.

/// Minimal ledger interface required by the enforcement pipeline.
///
/// The enforcement engine needs two queries:
///   1. Has a given mandate been explicitly revoked?
///   2. How many decisions has an agent produced in the last N seconds?
///
/// Everything else (appending receipts, audit queries, authority log) is the
/// responsibility of the concrete ledger implementation in the CLI crate.
pub trait EnforceLedger {
    fn is_revoked(
        &self,
        agent_did: &str,
        mandate_hash: &str,
    ) -> Result<bool, Box<dyn std::error::Error>>;

    fn count_recent(
        &self,
        agent_did: &str,
        seconds: i64,
    ) -> Result<u64, Box<dyn std::error::Error>>;
}
