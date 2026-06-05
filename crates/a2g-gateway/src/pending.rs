//! Pending-approval queue and nonce ring buffer (ADR-0010 §HITL Pending Queue).
//!
//! The gateway is the sole owner of the HITL pending queue (closes ADR-0008's deferral).
//! Entries are in-memory only; a gateway restart drops all pending bindings (documented
//! limitation in ADR-0010 §Residual Limitations).

use a2g_core::hitl::{ApprovalGrant, PendingApprovalBinding};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};

/// Maximum number of nonces retained for anti-replay (ring buffer capacity).
const NONCE_RING_CAPACITY: usize = 4096;

/// A queued pending-approval entry.
pub struct PendingEntry {
    /// MAC-protected binding JSON signed by the gateway's binding key.
    pub signed_json: String,
    /// The raw binding (for TTL checks and binding_id lookup).
    pub binding: PendingApprovalBinding,
    /// True once a valid `ApprovalGrant` has been submitted and verified.
    pub approved: bool,
    /// The grant that approved this binding (set when `approved == true`).
    pub grant: Option<ApprovalGrant>,
}

/// In-memory pending queue + nonce anti-replay ring.
pub struct PendingQueue {
    entries: HashMap<String, PendingEntry>,
    nonce_ring: VecDeque<String>,
}

impl Default for PendingQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingQueue {
    pub fn new() -> Self {
        PendingQueue {
            entries: HashMap::new(),
            nonce_ring: VecDeque::with_capacity(NONCE_RING_CAPACITY),
        }
    }

    /// Insert a newly signed binding into the queue.
    pub fn insert(&mut self, signed_json: String, binding: PendingApprovalBinding) {
        self.entries.insert(
            binding.binding_id.clone(),
            PendingEntry {
                signed_json,
                binding,
                approved: false,
                grant: None,
            },
        );
    }

    /// Look up an entry by binding_id (immutable).
    pub fn get(&self, binding_id: &str) -> Option<&PendingEntry> {
        self.entries.get(binding_id)
    }

    /// Mark a pending entry as approved, storing the grant.
    /// Returns false if the binding_id is not in the queue.
    pub fn approve(&mut self, binding_id: &str, grant: ApprovalGrant) -> bool {
        if let Some(entry) = self.entries.get_mut(binding_id) {
            entry.approved = true;
            entry.grant = Some(grant);
            true
        } else {
            false
        }
    }

    /// Remove a consumed (Phase-2-enforced) entry from the queue.
    pub fn remove(&mut self, binding_id: &str) {
        self.entries.remove(binding_id);
    }

    /// Expire entries whose TTL has elapsed.
    pub fn expire(&mut self, now: DateTime<Utc>) {
        self.entries.retain(|_, e| now < e.binding.ttl_expires_at);
    }

    // ── Nonce ring ──────────────────────────────────────────────────────────────

    /// Returns `true` if this nonce has been seen before (replay attempt).
    pub fn nonce_seen(&self, nonce: &str) -> bool {
        self.nonce_ring.iter().any(|n| n == nonce)
    }

    /// Record a nonce as seen.  Evicts the oldest entry if the ring is full.
    pub fn record_nonce(&mut self, nonce: String) {
        if self.nonce_ring.len() >= NONCE_RING_CAPACITY {
            self.nonce_ring.pop_front();
        }
        self.nonce_ring.push_back(nonce);
    }
}
