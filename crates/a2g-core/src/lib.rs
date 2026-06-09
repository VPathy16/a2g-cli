// Panic-freedom enforcement for a2g-core (ISO 26262 / safety-island context).
//
// The decision path (decide() and every function it calls) MUST NOT panic on
// any input. Failures MUST return Err(…) so the caller can resolve them to a
// fail-safe DENY verdict. These lints are crate-wide; test modules are
// individually opted out with #[allow] on their mod blocks.
//
// See docs/PANIC_FREEDOM.md for the policy rationale, fail-safe DENY contract,
// fuzz/property-test coverage, and honest residuals.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::unreachable,
    clippy::todo,
    clippy::panicking_unwrap
)]

pub mod authority;
pub mod enforce;
pub mod hitl;
pub mod identity;
pub mod ledger;
pub mod mandate;
pub mod output_gov;
pub mod proposal;
pub mod receipt;
pub mod vehicle;
