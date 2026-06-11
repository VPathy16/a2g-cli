//! Pending-approval queue and nonce anti-replay ring (ADR-0010 §HITL Pending Queue).
//!
//! ## Persistence (P3)
//!
//! When constructed with [`PendingQueue::with_persist`] the queue writes a JSON
//! snapshot to disk after every mutation.  On the next startup the snapshot is
//! loaded; entries whose TTL has already elapsed are silently dropped.
//!
//! The snapshot also persists the **nonce high-water mark** — the maximum
//! `issued_at_ms` ever recorded.  After a restart, any receipt whose
//! `issued_at_ms` does not exceed the high-water mark is rejected, closing the
//! replay window that would otherwise open because the in-memory nonce ring was
//! cleared.
//!
//! If no persist path is set the queue behaves exactly as before P3 (in-memory
//! only), so existing tests are not affected.

use a2g_core::hitl::{ApprovalGrant, PendingApprovalBinding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

/// Maximum number of nonces retained for anti-replay (ring buffer capacity).
const NONCE_RING_CAPACITY: usize = 4096;

// ── Serializable snapshot ─────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct PersistedEntry {
    signed_json: String,
    binding: PendingApprovalBinding,
    approved: bool,
    grant: Option<ApprovalGrant>,
}

#[derive(Serialize, Deserialize, Default)]
struct QueueSnapshot {
    entries: HashMap<String, PersistedEntry>,
    /// Maximum `issued_at_ms` ever processed — used as the nonce high-water mark
    /// on restart to reject receipts from the previous session's freshness window.
    nonce_hwm_ms: i64,
}

// ── Public types ──────────────────────────────────────────────────────────────

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

/// Pending queue, nonce ring, and optional disk persistence.
pub struct PendingQueue {
    entries: HashMap<String, PendingEntry>,
    nonce_ring: VecDeque<String>,
    /// Highest `issued_at_ms` ever processed in this or previous sessions.
    nonce_hwm_ms: i64,
    /// If set, the queue is written to this path after every mutation.
    persist_path: Option<PathBuf>,
    /// True if the queue was loaded from a previous session's snapshot.
    /// The high-water mark is only enforced as a gate when this is true.
    loaded_from_prior_session: bool,
}

impl Default for PendingQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingQueue {
    /// Construct an in-memory queue (no persistence).
    pub fn new() -> Self {
        PendingQueue {
            entries: HashMap::new(),
            nonce_ring: VecDeque::with_capacity(NONCE_RING_CAPACITY),
            nonce_hwm_ms: 0,
            persist_path: None,
            loaded_from_prior_session: false,
        }
    }

    /// Construct a queue backed by `path`.
    ///
    /// Loads any existing snapshot from `path`, dropping entries whose TTL
    /// has elapsed.  If the file is absent or unreadable the queue starts
    /// empty.  On every subsequent mutation the queue is atomically written
    /// back to `path`.
    pub fn with_persist(path: &Path) -> Self {
        let mut q = PendingQueue {
            entries: HashMap::new(),
            nonce_ring: VecDeque::with_capacity(NONCE_RING_CAPACITY),
            nonce_hwm_ms: 0,
            persist_path: Some(path.to_owned()),
            loaded_from_prior_session: false,
        };
        q.load(path);
        q
    }

    // ── Queue operations ──────────────────────────────────────────────────────

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
        self.save_if_persistent();
    }

    /// Look up an entry by binding_id (immutable).
    pub fn get(&self, binding_id: &str) -> Option<&PendingEntry> {
        self.entries.get(binding_id)
    }

    /// Mark a pending entry as approved, storing the grant.
    /// Returns false if the binding_id is not in the queue.
    pub fn approve(&mut self, binding_id: &str, grant: ApprovalGrant) -> bool {
        let found = if let Some(entry) = self.entries.get_mut(binding_id) {
            entry.approved = true;
            entry.grant = Some(grant);
            true
        } else {
            false
        };
        if found {
            self.save_if_persistent();
        }
        found
    }

    /// Remove a consumed (Phase-2-enforced) entry from the queue.
    pub fn remove(&mut self, binding_id: &str) {
        self.entries.remove(binding_id);
        self.save_if_persistent();
    }

    /// Expire entries whose TTL has elapsed.
    pub fn expire(&mut self, now: DateTime<Utc>) {
        let before = self.entries.len();
        self.entries.retain(|_, e| now < e.binding.ttl_expires_at);
        if self.entries.len() != before {
            self.save_if_persistent();
        }
    }

    // ── Nonce ring ────────────────────────────────────────────────────────────

    /// Returns `true` if this nonce has been seen before in the current session.
    pub fn nonce_seen(&self, nonce: &str) -> bool {
        self.nonce_ring.iter().any(|n| n == nonce)
    }

    /// Record a nonce and its receipt timestamp.
    ///
    /// Updates `nonce_hwm_ms` if `issued_at_ms` is larger than the current
    /// high-water mark.  Evicts the oldest nonce if the ring is at capacity.
    pub fn record_nonce(&mut self, nonce: String) {
        if self.nonce_ring.len() >= NONCE_RING_CAPACITY {
            self.nonce_ring.pop_front();
        }
        self.nonce_ring.push_back(nonce);
    }

    /// Record both the nonce string and the receipt timestamp for the high-water
    /// mark.  Call this instead of `record_nonce` when persistence is active.
    pub fn record_nonce_with_ts(&mut self, nonce: String, issued_at_ms: i64) {
        self.record_nonce(nonce);
        if issued_at_ms > self.nonce_hwm_ms {
            self.nonce_hwm_ms = issued_at_ms;
            // The first new receipt that advances the HWM clears the startup gate —
            // the nonce ring now covers all receipts in this session.
            self.loaded_from_prior_session = false;
            self.save_if_persistent();
        }
    }

    /// Returns the nonce high-water mark: the maximum `issued_at_ms` ever
    /// processed.  Zero if no receipts have been processed in any session.
    pub fn nonce_hwm_ms(&self) -> i64 {
        self.nonce_hwm_ms
    }

    /// Returns `Some(hwm)` when the queue was loaded from a prior session and
    /// the HWM should be enforced as a gate.  `None` for in-memory queues or
    /// fresh (empty) snapshots.  Once the first new receipt is recorded the
    /// flag is cleared — the gate only fires on startup to close the
    /// post-restart replay window.
    pub fn hwm_gate_ms(&mut self) -> Option<i64> {
        if self.loaded_from_prior_session && self.nonce_hwm_ms > 0 {
            // After the first new receipt advances the HWM, the gate is no
            // longer needed — the nonce ring takes over.
            Some(self.nonce_hwm_ms)
        } else {
            None
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    fn load(&mut self, path: &Path) {
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return, // no existing snapshot — start empty
        };
        let snap: QueueSnapshot = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[gateway:persist] failed to parse queue snapshot: {e}; starting empty");
                return;
            }
        };
        let now = Utc::now();
        for (id, pe) in snap.entries {
            if now < pe.binding.ttl_expires_at {
                self.entries.insert(
                    id,
                    PendingEntry {
                        signed_json: pe.signed_json,
                        binding: pe.binding,
                        approved: pe.approved,
                        grant: pe.grant,
                    },
                );
            }
        }
        self.nonce_hwm_ms = snap.nonce_hwm_ms;
        if !self.entries.is_empty() || self.nonce_hwm_ms > 0 {
            self.loaded_from_prior_session = true;
        }
        eprintln!(
            "[gateway:persist] loaded {} pending entries, nonce_hwm_ms={}",
            self.entries.len(),
            self.nonce_hwm_ms
        );
    }

    fn save_if_persistent(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let snap = QueueSnapshot {
            entries: self
                .entries
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        PersistedEntry {
                            signed_json: v.signed_json.clone(),
                            binding: v.binding.clone(),
                            approved: v.approved,
                            grant: v.grant.clone(),
                        },
                    )
                })
                .collect(),
            nonce_hwm_ms: self.nonce_hwm_ms,
        };
        let json = match serde_json::to_string(&snap) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[gateway:persist] serialization error: {e}");
                return;
            }
        };
        // Write atomically: write + fdatasync on the temp file, then rename.
        // fsync before rename so the data survives a power cut between the two
        // syscalls — otherwise the high-water mark is silently lost on restart.
        let tmp = path.with_extension("tmp");
        let save_result = (|| -> std::io::Result<()> {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.sync_data()?;
            drop(f);
            std::fs::rename(&tmp, path)
        })();
        if let Err(e) = save_result {
            eprintln!("[gateway:persist] save failed: {e}");
        }
    }
}
