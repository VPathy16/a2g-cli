//! Enforcement Engine — Deterministic policy evaluation
//!
//! ## Architecture
//!
//! - `decide()`: Pure decision function. No wall-clock reads, no filesystem I/O.
//!   Takes an explicit `now: DateTime<Utc>` for TTL and jurisdiction checks.
//!   Ledger calls (`is_revoked`, `count_recent`) are read-only — no writes.
//!   Generic over `L: EnforceLedger` (static dispatch, vtable-free).
//! - `enforce()`: Public API wrapper. Injects `Utc::now()`, delegates to `decide()`.
//!   Same external signature as before except `&dyn` → `<L: EnforceLedger>`.
//! - `decide_with_approval()`: Phase 2 of the HITL state machine (ADR-0008).
//!   Validates a signed `ApprovalGrant` against a `PendingApprovalBinding`, then
//!   runs the full pipeline with the escalation trigger removed.
//!
//! ## Allocation notes — non-removable on the current path
//!
//! - TOML parse (`toml::from_str`): creates owned `String` for every `Mandate` field.
//!   Blocked on a zero-copy TOML deserializer (none available for no_std).
//! - `serde_json::to_string(params)`: serialises params to compute hash. One transient String.
//! - `hex::encode(Sha256::...)`: two 64-byte `String`s per call (params_hash, mandate_hash).
//! - `Verdict` struct: ~10 owned `String` fields; empty fields use `String::new()` (stack
//!   allocation for the pointer/len/cap triple, no heap until first push).
//! - `uuid::Uuid::new_v4()`: one OsRng read (std-only); candidate replacement: caller-supplied ID.
//! - `canonicalize_path_logical`: one `Vec<&str>` + `join()` per path check.
//! - `format!()` calls in policy-rule strings: unavoidable until policy rules are static strs.

use crate::hitl::{
    self, compute_request_hash, PendingApprovalBinding, PENDING_APPROVAL_TTL_MINUTES,
};
use crate::ledger::EnforceLedger;
use crate::mandate::{self, Mandate};
use crate::vehicle::VerifiedVehicleState;
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
    Expired,
    /// Phase 1 of the HITL state machine (ADR-0008): escalation is required.
    /// `decide()` returns immediately with this verdict and a
    /// `PendingApprovalBinding` in `Verdict.pending_approval`. No waiting occurs.
    /// Phase 2 (`decide_with_approval()`) evaluates the human's signed grant.
    PendingApproval,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Deny => write!(f, "DENY"),
            Decision::Expired => write!(f, "EXPIRED"),
            Decision::PendingApproval => write!(f, "PENDING_APPROVAL"),
        }
    }
}

#[derive(Debug)]
pub struct Verdict {
    pub verdict_id: String,
    pub agent_did: String,
    pub agent_name: String,
    pub tool: String,
    pub params_hash: String,
    pub decision: Decision,
    pub policy_rule: String,
    pub evaluated_at: DateTime<Utc>,
    pub mandate_hash: String,
    pub proposal_hash: String,
    pub delegation_chain_hash: String,
    pub issuer_did: String,
    pub authority_level: String,
    pub scope_hash: String,
    pub correlation_id: String,
    pub parent_receipt_hash: String,
    /// Populated when `decision == PendingApproval` (ADR-0008 Phase 1).
    /// Contains the binding that the Phase 2 `ApprovalGrant` must match.
    pub pending_approval: Option<PendingApprovalBinding>,
    /// Trust basis of the vehicle state used in this decision (ADR-0007).
    /// Values: "attested" | "operator_trusted" | "none"
    /// Recorded in the ledger; auditors can distinguish cryptographically-attested
    /// decisions from operator-typed ones.
    pub state_trust: String,
}

/// Pure enforcement decision — runs the full 8-step pipeline with no I/O.
///
/// # Clock injection
/// `now` is the evaluation timestamp used for TTL (step 2) and jurisdiction
/// operating-hours (step 5) checks. Callers must supply it explicitly so the
/// function is deterministic and testable without mocking the system clock.
///
/// # Vehicle state (ADR-0007)
/// `verified_state` is the attested vehicle state for Sensitive-domain gating (step 4.5).
/// Passing `None` causes the fail-safe default (`999 km/h, Drive`) to be used,
/// which denies all Sensitive operations. Raw `VehicleState` cannot reach gating
/// directly — callers must produce `VerifiedVehicleState` via
/// `AttestedVehicleState::verify()` (gateway path) or
/// `VerifiedVehicleState::from_operator_trusted()` (interim CLI path, ADR-0007 §4).
///
/// # HITL (ADR-0008)
/// When a tool is in `escalate_tools`, `decide()` returns `PendingApproval`
/// **immediately** — it never waits. The binding in `Verdict.pending_approval`
/// identifies the request. Phase 2 is handled by `decide_with_approval()`.
///
/// # Ledger reads
/// `ledger.is_revoked()` (step 0) and `ledger.count_recent()` (step 7) are
/// read-only queries. No writes occur inside `decide()`.
///
/// # Path canonicalization
/// Uses logical normalization only — no filesystem access, no symlink resolution.
/// When called through `enforce()`, the `path` param has already been resolved to
/// a canonical real path before this function runs.
pub fn decide<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
    now: DateTime<Utc>,
    verified_state: Option<&VerifiedVehicleState>,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    decide_core(
        mandate_str,
        tool,
        params,
        ledger,
        now,
        verified_state,
        false,
    )
}

/// Phase 2 of the HITL state machine (ADR-0008).
///
/// Validates a signed `ApprovalGrant` against the `PendingApprovalBinding` produced
/// in Phase 1, then runs the full enforcement pipeline with the escalation trigger
/// removed for this tool.
///
/// ## Ordering
///
/// 1. **Forbidden pre-check fires first** — unconditionally, before grant validation.
///    A Forbidden tool is denied even with a cryptographically valid grant.
///    This ordering is intentional and tested (test `test_phase2_forbidden_denied_even_with_valid_grant`).
/// 2. Grant validation: binding match, request-hash match, TTL, ed25519 signature.
/// 3. Pending binding TTL: the Phase 1 request must not be expired.
/// 4. Full pipeline (steps 0–7) with escalation skipped.
///
/// On success, `Verdict.parent_receipt_hash` is set to `grant.parent_receipt_hash`
/// so the ledger chain links Phase 1 and Phase 2 receipts.
#[allow(clippy::too_many_arguments)]
pub fn decide_with_approval<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
    now: DateTime<Utc>,
    verified_state: Option<&VerifiedVehicleState>,
    pending: &PendingApprovalBinding,
    grant: &hitl::ApprovalGrant,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    // We need the core fields for make_verdict before calling decide_core.
    let params_hash = hex::encode(Sha256::digest(serde_json::to_string(params)?.as_bytes()));
    let m: Mandate = toml::from_str(mandate_str)?;
    let agent_did = m.mandate.agent_did.clone();
    let agent_name = m.mandate.agent_name.clone();
    let mandate_hash = hex::encode(Sha256::digest(mandate_str.as_bytes()));
    let proposal_hash = m.mandate.proposal_hash.clone();

    let early_deny_state_trust = verified_state
        .map(|vs| vs.trust_basis().as_str().to_string())
        .unwrap_or_else(|| crate::vehicle::StateTrust::None.as_str().to_string());

    let make_early_deny = |rule: &str| -> Verdict {
        Verdict {
            verdict_id: uuid::Uuid::new_v4().to_string(),
            agent_did: agent_did.clone(),
            agent_name: agent_name.clone(),
            tool: tool.to_string(),
            params_hash: params_hash.clone(),
            decision: Decision::Deny,
            policy_rule: rule.to_string(),
            evaluated_at: now,
            mandate_hash: mandate_hash.clone(),
            proposal_hash: proposal_hash.clone(),
            delegation_chain_hash: String::new(),
            issuer_did: String::new(),
            authority_level: String::new(),
            scope_hash: String::new(),
            correlation_id: String::new(),
            parent_receipt_hash: String::new(),
            pending_approval: None,
            state_trust: early_deny_state_trust.clone(),
        }
    };

    // ── Step 0 (Phase 2): Forbidden domain — unconditional, before grant check ──
    // An approval grant cannot resurrect a Forbidden action.
    if crate::vehicle::classify_vehicle_tool(tool) == crate::vehicle::VehicleDomain::Forbidden {
        return Ok(make_early_deny(&format!(
            "vehicle_forbidden_domain: '{}' is in the safety-critical domain \
             and cannot be granted by any mandate or approval",
            tool
        )));
    }

    // ── Step 1 (Phase 2): Validate approval grant ──
    use hitl::ApprovalGrantError;
    if let Err(e) = grant.verify_against_binding(pending, now) {
        let rule = match e {
            ApprovalGrantError::BindingMismatch { field } => {
                format!("approval_grant_invalid: {} mismatch", field)
            }
            ApprovalGrantError::Expired => "approval_grant_expired".to_string(),
            ApprovalGrantError::InvalidSignature | ApprovalGrantError::InvalidPubkey => {
                format!("approval_grant_invalid: {}", e)
            }
        };
        return Ok(make_early_deny(&rule));
    }

    // ── Step 2 (Phase 2): Pending binding must not be expired ──
    if now >= pending.ttl_expires_at {
        return Ok(make_early_deny("pending_approval_expired"));
    }

    // ── Run the normal pipeline, skipping Step 6 (escalation already resolved) ──
    let mut verdict = decide_core(mandate_str, tool, params, ledger, now, verified_state, true)?;

    // Link Phase 2 receipt to Phase 1 receipt via parent_receipt_hash.
    if verdict.decision == Decision::Allow && !grant.parent_receipt_hash.is_empty() {
        verdict.parent_receipt_hash = grant.parent_receipt_hash.clone();
        verdict.correlation_id = pending.binding_id.clone();
    }

    Ok(verdict)
}

/// Internal pipeline implementation shared by `decide()` and `decide_with_approval()`.
///
/// `skip_escalation`: when `true`, Step 6 (escalation check) is bypassed.
/// Set by `decide_with_approval()` after validating a grant.
fn decide_core<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
    now: DateTime<Utc>,
    verified_state: Option<&VerifiedVehicleState>,
    skip_escalation: bool,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    let params_hash = hex::encode(Sha256::digest(serde_json::to_string(params)?.as_bytes()));

    let m: Mandate = toml::from_str(mandate_str)?;

    let agent_did = m.mandate.agent_did.clone();
    let agent_name = m.mandate.agent_name.clone();

    let mandate_hash = hex::encode(Sha256::digest(mandate_str.as_bytes()));
    let proposal_hash = m.mandate.proposal_hash.clone();

    // Compute state trust basis for audit trail (ADR-0007 follow-up).
    let state_trust = verified_state
        .map(|vs| vs.trust_basis().as_str().to_string())
        .unwrap_or_else(|| crate::vehicle::StateTrust::None.as_str().to_string());

    let make_verdict = |decision: Decision, rule: &str| -> Verdict {
        Verdict {
            verdict_id: uuid::Uuid::new_v4().to_string(),
            agent_did: agent_did.clone(),
            agent_name: agent_name.clone(),
            tool: tool.to_string(),
            params_hash: params_hash.clone(),
            decision,
            policy_rule: rule.to_string(),
            evaluated_at: now,
            mandate_hash: mandate_hash.clone(),
            proposal_hash: proposal_hash.clone(),
            delegation_chain_hash: String::new(),
            issuer_did: String::new(),
            authority_level: String::new(),
            scope_hash: String::new(),
            correlation_id: String::new(),
            parent_receipt_hash: String::new(),
            pending_approval: None,
            state_trust: state_trust.clone(),
        }
    };

    // ── Pre-check: Empty tool name ──
    if tool.is_empty() {
        return Ok(make_verdict(
            Decision::Deny,
            "invalid_request: tool name must not be empty",
        ));
    }

    // ── Pre-check: Vehicle Forbidden Domain ──
    // Hard DENY before any mandate evaluation. No mandate permission, escalation,
    // or vehicle state can override this — checked before Step 0 (revocation).
    if crate::vehicle::classify_vehicle_tool(tool) == crate::vehicle::VehicleDomain::Forbidden {
        return Ok(make_verdict(
            Decision::Deny,
            &format!(
                "vehicle_forbidden_domain: '{}' is in the safety-critical domain \
                 and cannot be granted by any mandate",
                tool
            ),
        ));
    }

    // ── Step 0: Revocation Check ──
    if ledger.is_revoked(&m.mandate.agent_did, &mandate_hash)? {
        return Ok(make_verdict(
            Decision::Deny,
            "mandate_revoked: this mandate has been explicitly revoked",
        ));
    }

    // ── Step 1: Mandate Signature Check (no TTL; TTL handled in step 2) ──
    if let Err(e) = mandate::verify_signature(mandate_str) {
        return Ok(make_verdict(
            Decision::Deny,
            &format!("mandate_invalid: {}", e),
        ));
    }

    // ── Step 2: TTL Check (uses injected `now`) ──
    if !m.mandate.expires_at.is_empty() {
        if let Ok(expires) = m.mandate.expires_at.parse::<DateTime<Utc>>() {
            if now >= expires {
                return Ok(make_verdict(Decision::Expired, "mandate_ttl_exceeded"));
            }
        }
    }

    // ── Step 3: Tool Authorization ──
    if !m.capabilities.tools.contains(&tool.to_string()) {
        return Ok(make_verdict(
            Decision::Deny,
            &format!("tool_not_authorized: '{}' not in capabilities.tools", tool),
        ));
    }

    // ── Workspace Root Resolution ──
    let workspace_root = if !m.mandate.workspace_root.is_empty() {
        Some(canonicalize_path_logical(&m.mandate.workspace_root))
    } else {
        None
    };

    // ── Step 4: Boundary Check ──
    if let Some(raw_path) = params.get("path").and_then(|p| p.as_str()) {
        let full_path = canonicalize_path_logical(raw_path);

        let path = if let Some(ref root) = workspace_root {
            full_path
                .strip_prefix(root)
                .map(|p| p.trim_start_matches('/'))
                .unwrap_or(&full_path)
                .to_string()
        } else {
            full_path.clone()
        };
        let path = &path;

        // 4a: deny wins
        for pattern in &m.boundaries.fs_deny {
            if glob_matches(pattern, path) {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: path '{}' matches fs_deny '{}'",
                        path, pattern
                    ),
                ));
            }
        }

        // 4b: read boundaries
        if (tool == "read_file" || tool == "read") && !m.boundaries.fs_read.is_empty() {
            let allowed = m.boundaries.fs_read.iter().any(|p| glob_matches(p, path));
            if !allowed {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: path '{}' not in fs_read boundaries",
                        path
                    ),
                ));
            }
        }

        // 4c: write boundaries
        if (tool == "write_file" || tool == "write") && !m.boundaries.fs_write.is_empty() {
            let allowed = m.boundaries.fs_write.iter().any(|p| glob_matches(p, path));
            if !allowed {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: path '{}' not in fs_write boundaries",
                        path
                    ),
                ));
            }
        }
    }

    // 4d: Network boundaries
    if let Some(target) = params.get("url").and_then(|u| u.as_str()) {
        let host = extract_host(target);
        for pattern in &m.boundaries.net_deny {
            if pattern == "*" || glob_matches(pattern, &host) {
                let allowed = m
                    .boundaries
                    .net_allow
                    .iter()
                    .any(|p| glob_matches(p, &host));
                if !allowed {
                    return Ok(make_verdict(
                        Decision::Deny,
                        &format!("boundary_violation: host '{}' blocked by net_deny", host),
                    ));
                }
            }
        }
    }

    // 4e: Command boundaries
    if let Some(cmd) = params.get("command").and_then(|c| c.as_str()) {
        for pattern in &m.boundaries.cmd_deny {
            if cmd.contains(pattern) || glob_matches(pattern, cmd) {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: command '{}' matches cmd_deny '{}'",
                        cmd, pattern
                    ),
                ));
            }
        }
        if !m.boundaries.cmd_allow.is_empty() {
            let cmd_base = cmd.split_whitespace().next().unwrap_or(cmd);
            let allowed = m.boundaries.cmd_allow.iter().any(|p| p == cmd_base);
            if !allowed {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: command base '{}' not in cmd_allow",
                        cmd_base
                    ),
                ));
            }
        }
    }

    // ── Step 4.5: Vehicle State Gating (ADR-0007) ──
    // Requires `Option<&VerifiedVehicleState>` — raw `VehicleState` cannot reach
    // this path. `None` → `VehicleState::fail_safe()` → Sensitive DENY (safe default).
    // Comfort, Convenience, and Forbidden are not evaluated here.
    if crate::vehicle::classify_vehicle_tool(tool) == crate::vehicle::VehicleDomain::Sensitive {
        let state = verified_state
            .map(|vs| vs.as_vehicle_state().clone())
            .unwrap_or_else(crate::vehicle::VehicleState::fail_safe);
        if let crate::vehicle::StateVerdict::Deny(reason) =
            crate::vehicle::evaluate_vehicle_state(tool, &state)
        {
            return Ok(make_verdict(Decision::Deny, reason));
        }
    }

    // ── Step 5: Jurisdiction Check (uses injected `now`) ──
    if !m.jurisdiction.operating_hours.is_empty() {
        let (start_hour, start_min, end_hour, end_min) =
            validate_operating_hours(&m.jurisdiction.operating_hours)?;
        let current_hour = now.hour();
        let current_min = now.minute();
        let current_total = current_hour.saturating_mul(60).saturating_add(current_min);
        let start_total = start_hour.saturating_mul(60).saturating_add(start_min);
        let end_total = end_hour.saturating_mul(60).saturating_add(end_min);

        if current_total < start_total || current_total > end_total {
            return Ok(make_verdict(
                Decision::Deny,
                &format!(
                    "jurisdiction_violation: current time {:02}:{:02} outside operating hours {}",
                    current_hour, current_min, m.jurisdiction.operating_hours
                ),
            ));
        }
    }

    // ── Step 6: Escalation Check (skipped in Phase 2 when grant is valid) ──
    if !skip_escalation {
        if m.escalation.escalate_tools.contains(&tool.to_string()) {
            let timestamp = now.to_rfc3339();
            let request_hash = compute_request_hash(&mandate_hash, tool, &params_hash, &timestamp);
            let binding_id = uuid::Uuid::new_v4().to_string();
            // Adding 5 minutes cannot overflow for any realistic timestamp; None only if now > year 262143.
            let ttl_expires_at = now
                .checked_add_signed(Duration::minutes(PENDING_APPROVAL_TTL_MINUTES))
                .unwrap_or(now);
            let pending = PendingApprovalBinding {
                binding_id,
                request_hash,
                escalate_to: m.escalation.escalate_to.clone(),
                ttl_expires_at,
            };
            let mut v = make_verdict(
                Decision::PendingApproval,
                &format!(
                    "escalation_required: tool '{}' requires approval from {}",
                    tool,
                    if m.escalation.escalate_to.is_empty() {
                        "higher authority"
                    } else {
                        &m.escalation.escalate_to
                    }
                ),
            );
            v.pending_approval = Some(pending);
            return Ok(v);
        }

        if let Some(raw_path) = params.get("path").and_then(|p| p.as_str()) {
            let full_epath = canonicalize_path_logical(raw_path);
            let epath = if let Some(ref root) = workspace_root {
                full_epath
                    .strip_prefix(root)
                    .map(|p| p.trim_start_matches('/'))
                    .unwrap_or(&full_epath)
                    .to_string()
            } else {
                full_epath.clone()
            };
            let epath = &epath;
            for pattern in &m.escalation.escalate_paths {
                if glob_matches(pattern, epath) {
                    let timestamp = now.to_rfc3339();
                    let request_hash =
                        compute_request_hash(&mandate_hash, tool, &params_hash, &timestamp);
                    let binding_id = uuid::Uuid::new_v4().to_string();
                    let pending = PendingApprovalBinding {
                        binding_id,
                        request_hash,
                        escalate_to: m.escalation.escalate_to.clone(),
                        // Adding 5 minutes cannot overflow for any realistic timestamp; None only if now > year 262143.
                        ttl_expires_at: now
                            .checked_add_signed(Duration::minutes(PENDING_APPROVAL_TTL_MINUTES))
                            .unwrap_or(now),
                    };
                    let mut v = make_verdict(
                        Decision::PendingApproval,
                        &format!(
                            "escalation_required: path '{}' matches escalate_paths '{}'",
                            epath, pattern
                        ),
                    );
                    v.pending_approval = Some(pending);
                    return Ok(v);
                }
            }
        }

        if let Some(target) = params.get("url").and_then(|u| u.as_str()) {
            let ehost = extract_host(target);
            for pattern in &m.escalation.escalate_hosts {
                if glob_matches(pattern, &ehost) {
                    let timestamp = now.to_rfc3339();
                    let request_hash =
                        compute_request_hash(&mandate_hash, tool, &params_hash, &timestamp);
                    let binding_id = uuid::Uuid::new_v4().to_string();
                    let pending = PendingApprovalBinding {
                        binding_id,
                        request_hash,
                        escalate_to: m.escalation.escalate_to.clone(),
                        // Adding 5 minutes cannot overflow for any realistic timestamp; None only if now > year 262143.
                        ttl_expires_at: now
                            .checked_add_signed(Duration::minutes(PENDING_APPROVAL_TTL_MINUTES))
                            .unwrap_or(now),
                    };
                    let mut v = make_verdict(
                        Decision::PendingApproval,
                        &format!(
                            "escalation_required: host '{}' matches escalate_hosts '{}'",
                            ehost, pattern
                        ),
                    );
                    v.pending_approval = Some(pending);
                    return Ok(v);
                }
            }
        }
    }

    // ── Step 7: Rate Limit Check ──
    let recent_count = ledger.count_recent(&m.mandate.agent_did, 60)?;
    if recent_count >= m.limits.max_calls_per_minute {
        return Ok(make_verdict(
            Decision::Deny,
            &format!(
                "rate_limit_exceeded: {} calls in last 60s (max: {})",
                recent_count, m.limits.max_calls_per_minute
            ),
        ));
    }

    // ── All checks passed ──
    Ok(make_verdict(Decision::Allow, "all_checks_passed"))
}

/// Run the deterministic enforcement pipeline.
///
/// **I/O boundary**: before delegating to `decide()`, this function resolves the
/// `path` parameter (if present) to its canonical real form via
/// `std::fs::canonicalize`. This prevents symlink-based boundary escapes where a
/// symlink inside an allowed boundary points to a target outside it.
///
/// **Vehicle state (ADR-0007 interim posture)**: until the Secure Gateway is deployed,
/// vehicle state supplied via `--vehicle-state` (in `params["vehicle_state"]`) is
/// treated as operator-trusted. `enforce()` wraps it in
/// `VerifiedVehicleState::from_operator_trusted()` and passes it to `decide()`.
/// This is the documented interim path; the gateway will replace it with attested state.
pub fn enforce<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    let resolved_params = if let Some(raw_path) = params.get("path").and_then(|p| p.as_str()) {
        let resolved = resolve_path_for_enforce(raw_path)?;
        let mut p = params.clone();
        p.as_object_mut()
            .ok_or("params is not a JSON object")?
            .insert("path".to_string(), serde_json::Value::String(resolved));
        p
    } else {
        params.clone()
    };

    // Interim operator-trusted state from params (ADR-0007 §4).
    let operator_state = crate::vehicle::extract_vehicle_state(&resolved_params);
    let verified = VerifiedVehicleState::from_operator_trusted(operator_state);
    decide(
        mandate_str,
        tool,
        &resolved_params,
        ledger,
        Utc::now(),
        Some(&verified),
    )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Validate jurisdiction operating_hours format (HH:MM-HH:MM)
fn validate_operating_hours(
    hours_str: &str,
) -> Result<(u32, u32, u32, u32), Box<dyn std::error::Error>> {
    let mut range = hours_str.splitn(2, '-');
    let start = range
        .next()
        .ok_or_else(|| {
            format!(
                "invalid operating_hours format '{}': expected HH:MM-HH:MM",
                hours_str
            )
        })?
        .trim();
    let end = range
        .next()
        .ok_or_else(|| {
            format!(
                "invalid operating_hours format '{}': expected HH:MM-HH:MM",
                hours_str
            )
        })?
        .trim();

    let parse_time = |time_str: &str| -> Result<(u32, u32), Box<dyn std::error::Error>> {
        let mut tp = time_str.splitn(2, ':');
        let hour_str = tp
            .next()
            .ok_or_else(|| format!("invalid time '{}': expected HH:MM", time_str))?;
        let min_str = tp
            .next()
            .ok_or_else(|| format!("invalid time '{}': expected HH:MM", time_str))?;
        let hour: u32 = hour_str
            .parse()
            .map_err(|_| format!("invalid hour in '{}'", time_str))?;
        let minute: u32 = min_str
            .parse()
            .map_err(|_| format!("invalid minute in '{}'", time_str))?;
        if hour > 23 {
            return Err(format!("hour {} exceeds 23 in '{}'", hour, time_str).into());
        }
        if minute > 59 {
            return Err(format!("minute {} exceeds 59 in '{}'", minute, time_str).into());
        }
        Ok((hour, minute))
    };

    let (sh, sm) = parse_time(start)?;
    let (eh, em) = parse_time(end)?;

    // Values are bounded: hour 0-23, minute 0-59; saturating arithmetic is exact here.
    let start_total = sh.saturating_mul(60).saturating_add(sm);
    let end_total = eh.saturating_mul(60).saturating_add(em);
    if start_total >= end_total {
        return Err(format!(
            "operating_hours start '{}' must be before end '{}'",
            start, end
        )
        .into());
    }

    Ok((sh, sm, eh, em))
}

/// Logical path canonicalization — pure, no filesystem access.
pub(crate) fn canonicalize_path_logical(raw: &str) -> String {
    let is_absolute = raw.starts_with('/');
    let mut components: Vec<&str> = Vec::new();

    for part in raw.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if !components.is_empty() && (is_absolute || components.last() != Some(&"..")) {
                    components.pop();
                } else if !is_absolute {
                    components.push("..");
                }
            }
            _ => components.push(part),
        }
    }

    let joined = components.join("/");
    if is_absolute {
        format!("/{}", joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

#[cfg(feature = "std")]
#[allow(dead_code)]
fn canonicalize_path(raw: &str) -> String {
    if let Ok(canonical) = std::fs::canonicalize(raw) {
        return canonical.to_string_lossy().to_string();
    }
    canonicalize_path_logical(raw)
}

#[cfg(feature = "std")]
fn resolve_path_for_enforce(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    let logical = canonicalize_path_logical(raw);
    if let Ok(resolved) = std::fs::canonicalize(&logical) {
        return Ok(resolved.to_string_lossy().into_owned());
    }
    let path_obj = std::path::Path::new(&logical);
    let leaf = path_obj.file_name().ok_or_else(|| {
        format!(
            "path '{}' has no filename component; refusing to pass unresolved path to policy engine",
            logical
        )
    })?;
    let parent = match path_obj.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_owned(),
        _ => std::path::PathBuf::from("."),
    };

    std::fs::canonicalize(&parent)
        .map(|p| p.join(leaf).to_string_lossy().into_owned())
        .map_err(|_| {
            format!(
                "path '{}' does not exist and parent '{}' cannot be resolved; \
                 refusing to pass unresolved path to policy engine",
                logical,
                parent.display()
            )
            .into()
        })
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    if pattern.contains("**") {
        let mut double_star = pattern.splitn(2, "**");
        if let (Some(prefix_raw), Some(suffix_raw)) = (double_star.next(), double_star.next()) {
            let prefix = prefix_raw.trim_end_matches('/');
            let suffix = suffix_raw.trim_start_matches('/');
            if !prefix.is_empty() && !path.starts_with(prefix) {
                return false;
            }
            if suffix.is_empty() {
                return true;
            }
            if suffix.contains('*') {
                let filename = path.rsplit('/').next().unwrap_or(path);
                return simple_wildcard_match(suffix, filename);
            } else {
                return path.ends_with(suffix);
            }
        }
    }
    if pattern.contains('*') {
        return simple_wildcard_match(pattern, path);
    }
    pattern == path
}

fn simple_wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    match parts.as_slice() {
        [] => true,
        [only] => *only == text,
        [prefix, suffix] => {
            text.starts_with(*prefix)
                && text.ends_with(*suffix)
                && text.len() >= prefix.len().saturating_add(suffix.len())
        }
        [first, rest @ ..] => {
            if !text.starts_with(*first) {
                return false;
            }
            let Some(after_first) = text.get(first.len()..) else {
                return false;
            };
            let mut remaining = after_first;
            let Some((last, middle)) = rest.split_last() else {
                return false;
            };
            for part in middle {
                let Some(pos) = remaining.find(*part) else {
                    return false;
                };
                let new_start = pos.saturating_add(part.len());
                let Some(new_remaining) = remaining.get(new_start..) else {
                    return false;
                };
                remaining = new_remaining;
            }
            remaining.ends_with(*last)
        }
    }
}

fn extract_host(url: &str) -> String {
    url.replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::panic
)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    struct TestLedger;

    impl EnforceLedger for TestLedger {
        fn is_revoked(
            &self,
            _agent_did: &str,
            _mandate_hash: &str,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(false)
        }

        fn count_recent(
            &self,
            _agent_did: &str,
            _seconds: i64,
        ) -> Result<u64, Box<dyn std::error::Error>> {
            Ok(0)
        }
    }

    fn signed_mandate() -> String {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let template = crate::mandate::generate_template("test-agent", &did);
        crate::mandate::sign_mandate(&template, &secret, 24).unwrap()
    }

    /// Build a signed mandate with specific tools listed.
    fn cabin_mandate(tools: &[&str]) -> String {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("cabin-agent", &did);
        let tools_toml = tools
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect::<Vec<_>>()
            .join(", ");
        template = template.replace(
            r#"tools = ["read_file", "write_file"]"#,
            &format!("tools = [{}]", tools_toml),
        );
        crate::mandate::sign_mandate(&template, &secret, 24).unwrap()
    }

    /// Build a signed mandate with specific tools AND escalate_tools.
    fn cabin_escalate_mandate(tools: &[&str], escalate_tools: &[&str]) -> String {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("cabin-agent", &did);
        let tools_toml = tools
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect::<Vec<_>>()
            .join(", ");
        let escl_toml = escalate_tools
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect::<Vec<_>>()
            .join(", ");
        template = template.replace(
            r#"tools = ["read_file", "write_file"]"#,
            &format!("tools = [{}]", tools_toml),
        );
        template = template.replace(
            "escalate_tools = []",
            &format!("escalate_tools = [{}]", escl_toml),
        );
        crate::mandate::sign_mandate(&template, &secret, 24).unwrap()
    }

    /// Decode a hex secret key into a SigningKey for use in tests.
    fn signing_key_from_hex(secret_hex: &str) -> ed25519_dalek::SigningKey {
        let bytes = hex::decode(secret_hex).unwrap();
        let arr: [u8; 32] = bytes.try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&arr)
    }

    // ── Existing tests ────────────────────────────────────────────────────────

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("/etc/**", "/etc/passwd"));
        assert!(glob_matches("/etc/**", "/etc/ssh/sshd_config"));
        assert!(!glob_matches("/etc/**", "/home/user/file.txt"));
        assert!(glob_matches("**/*.env", "/home/user/.env"));
        assert!(glob_matches("**/*secret*", "/app/secret_keys.json"));
        assert!(glob_matches("*.wikipedia.org", "en.wikipedia.org"));
    }

    #[test]
    fn test_canonicalize_path() {
        assert_eq!(
            canonicalize_path_logical("/home/user/../../etc/passwd"),
            "/etc/passwd"
        );
        assert_eq!(
            canonicalize_path_logical("/../../../etc/shadow"),
            "/etc/shadow"
        );
        assert_eq!(
            canonicalize_path_logical("/home/./user/./file.txt"),
            "/home/user/file.txt"
        );
        assert_eq!(
            canonicalize_path_logical("/home//user///file.txt"),
            "/home/user/file.txt"
        );
        assert_eq!(
            canonicalize_path_logical("workspace/../../../etc/passwd"),
            "../../etc/passwd"
        );
        assert_eq!(
            canonicalize_path_logical("/home/user/file.txt"),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://api.openai.com/v1/chat"),
            "api.openai.com"
        );
        assert_eq!(extract_host("http://localhost:8080/test"), "localhost");
    }

    #[test]
    fn test_validate_operating_hours() {
        assert!(validate_operating_hours("09:00-17:00").is_ok());
        assert!(validate_operating_hours("00:00-23:59").is_ok());
        let (sh, sm, eh, em) = validate_operating_hours("09:00-17:00").unwrap();
        assert_eq!((sh, sm, eh, em), (9, 0, 17, 0));
        assert!(validate_operating_hours("25:00-17:00").is_err());
        assert!(validate_operating_hours("09:00").is_err());
        assert!(validate_operating_hours("17:00-09:00").is_err());
        assert!(validate_operating_hours("09:60-17:00").is_err());
    }

    #[test]
    fn test_tampered_mandate_denied() {
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let template = crate::mandate::generate_template("tamper-test", &agent_did);
        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let tampered = signed.replace("read_file", "execute");
        let db = TestLedger;
        let params: serde_json::Value = serde_json::from_str("{}").unwrap();
        let result = enforce(&tampered, "execute", &params, &db).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("mandate_invalid"));
    }

    #[test]
    fn test_workspace_root_relative_match() {
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("workspace-test", &agent_did);
        template = template.replace(
            "workspace_root = \"\"",
            "workspace_root = \"/home/agent/workspace\"",
        );
        template = template.replace("fs_read = [\"workspace/**\"]", "fs_read = [\"**/*.txt\"]");
        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = TestLedger;
        let params = serde_json::json!({"path": "/home/agent/workspace/data/test.txt"});
        let result = decide(&signed, "read_file", &params, &db, Utc::now(), None).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_workspace_root_empty_fallback() {
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("empty-workspace", &agent_did);
        template = template.replace(
            "fs_read = [\"workspace/**\"]",
            "fs_read = [\"/home/agent/workspace/**\"]",
        );
        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = TestLedger;
        let params = serde_json::json!({"path": "/home/agent/workspace/data/test.txt"});
        let result = decide(&signed, "read_file", &params, &db, Utc::now(), None).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_workspace_root_deny_still_works() {
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("deny-test", &agent_did);
        template = template.replace(
            "workspace_root = \"\"",
            "workspace_root = \"/home/agent/workspace\"",
        );
        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = TestLedger;
        let params = serde_json::json!({"path": "/etc/passwd"});
        let result = enforce(&signed, "read_file", &params, &db).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("boundary_violation"));
    }

    #[test]
    fn test_ttl_just_before_expiry_allows() {
        let signed = signed_mandate();
        let m: crate::mandate::Mandate = toml::from_str(&signed).unwrap();
        let expires: DateTime<Utc> = m.mandate.expires_at.parse().unwrap();
        let just_before = expires - chrono::Duration::seconds(1);
        let db = TestLedger;
        let params = serde_json::json!({"path": "workspace/file.txt"});
        let result = decide(&signed, "read_file", &params, &db, just_before, None).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ttl_at_expiry_denies() {
        let signed = signed_mandate();
        let m: crate::mandate::Mandate = toml::from_str(&signed).unwrap();
        let expires: DateTime<Utc> = m.mandate.expires_at.parse().unwrap();
        let db = TestLedger;
        let params = serde_json::json!({});
        let result = decide(&signed, "read_file", &params, &db, expires, None).unwrap();
        assert_eq!(result.decision, Decision::Expired);
    }

    #[test]
    fn test_ttl_past_expiry_denies() {
        let signed = signed_mandate();
        let m: crate::mandate::Mandate = toml::from_str(&signed).unwrap();
        let expires: DateTime<Utc> = m.mandate.expires_at.parse().unwrap();
        let db = TestLedger;
        let params = serde_json::json!({});
        let one_hour_late = expires + chrono::Duration::hours(1);
        let result = decide(&signed, "read_file", &params, &db, one_hour_late, None).unwrap();
        assert_eq!(result.decision, Decision::Expired);
        assert_eq!(result.policy_rule, "mandate_ttl_exceeded");
    }

    #[test]
    fn test_jurisdiction_inside_hours_allows() {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("jur-test", &did);
        template = template.replace(
            "operating_hours = \"\"",
            "operating_hours = \"09:00-17:00\"",
        );
        let signed = crate::mandate::sign_mandate(&template, &secret, 876_000).unwrap();
        let db = TestLedger;
        let params = serde_json::json!({});
        let noon = Utc.with_ymd_and_hms(2030, 6, 1, 12, 0, 0).unwrap();
        let result = decide(&signed, "read_file", &params, &db, noon, None).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_jurisdiction_outside_hours_denies() {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("jur-test2", &did);
        template = template.replace(
            "operating_hours = \"\"",
            "operating_hours = \"09:00-17:00\"",
        );
        let signed = crate::mandate::sign_mandate(&template, &secret, 876_000).unwrap();
        let db = TestLedger;
        let params = serde_json::json!({});
        let night = Utc.with_ymd_and_hms(2030, 6, 1, 2, 0, 0).unwrap();
        let result = decide(&signed, "read_file", &params, &db, night, None).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("jurisdiction_violation"));
    }

    #[test]
    fn test_jurisdiction_at_end_boundary_denies() {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("jur-boundary", &did);
        template = template.replace(
            "operating_hours = \"\"",
            "operating_hours = \"09:00-17:00\"",
        );
        let signed = crate::mandate::sign_mandate(&template, &secret, 876_000).unwrap();
        let db = TestLedger;
        let params = serde_json::json!({});
        let just_after = Utc.with_ymd_and_hms(2030, 6, 1, 17, 1, 0).unwrap();
        let result = decide(&signed, "read_file", &params, &db, just_after, None).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("jurisdiction_violation"));
    }

    // ── Vehicle capability tests ──────────────────────────────────────────────

    /// Forbidden domain is denied even when the mandate lists the tool.
    #[test]
    fn test_forbidden_domain_denied_despite_mandate() {
        let signed = cabin_mandate(&["vehicle.powertrain.start_engine"]);
        let db = TestLedger;
        let params = serde_json::json!({});
        let result = decide(
            &signed,
            "vehicle.powertrain.start_engine",
            &params,
            &db,
            Utc::now(),
            None,
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("vehicle_forbidden_domain"));
    }

    /// Sensitive tool (window) is allowed when state is Park and speed < 5.
    #[test]
    fn test_window_allowed_when_parked() {
        let signed = cabin_mandate(&["vehicle.window.set_position"]);
        let db = TestLedger;
        let parked =
            crate::vehicle::VerifiedVehicleState::new_for_test(crate::vehicle::VehicleState {
                speed_mmps: 0,
                gear: crate::vehicle::Gear::Park,
                actor: crate::vehicle::Actor::Driver,
            });
        let params = serde_json::json!({"position": 50});
        let result = decide(
            &signed,
            "vehicle.window.set_position",
            &params,
            &db,
            Utc::now(),
            Some(&parked),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    /// Sensitive tool (window) is denied when vehicle is moving.
    #[test]
    fn test_window_denied_when_moving() {
        let signed = cabin_mandate(&["vehicle.window.set_position"]);
        let db = TestLedger;
        let moving =
            crate::vehicle::VerifiedVehicleState::new_for_test(crate::vehicle::VehicleState {
                speed_mmps: 16_667, // 60.0 km/h
                gear: crate::vehicle::Gear::Drive,
                actor: crate::vehicle::Actor::Driver,
            });
        let params = serde_json::json!({"position": 50});
        let result = decide(
            &signed,
            "vehicle.window.set_position",
            &params,
            &db,
            Utc::now(),
            Some(&moving),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("vehicle_state_violation"));
    }

    /// Comfort tool (climate) is allowed regardless of vehicle state.
    #[test]
    fn test_comfort_allowed_while_moving() {
        let signed = cabin_mandate(&["vehicle.climate.set_temperature"]);
        let db = TestLedger;
        let params = serde_json::json!({"target_temp_c": 22});
        let result = decide(
            &signed,
            "vehicle.climate.set_temperature",
            &params,
            &db,
            Utc::now(),
            None, // Comfort: no state gating
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    /// Sensitive tool with no verified state (None) → fail-safe (999 km/h, Drive) → DENY.
    #[test]
    fn test_sensitive_no_state_denied_by_failsafe() {
        let signed = cabin_mandate(&["vehicle.window.set_position"]);
        let db = TestLedger;
        let params = serde_json::json!({"position": 50});
        let result = decide(
            &signed,
            "vehicle.window.set_position",
            &params,
            &db,
            Utc::now(),
            None, // No verified state → fail_safe() → DENY
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("vehicle_state_violation"));
    }

    /// Read-only VHAL telemetry (NonVehicle domain) passes all checks.
    #[test]
    fn test_vhal_speed_read_permitted() {
        let signed = cabin_mandate(&["PERF_VEHICLE_SPEED"]);
        let db = TestLedger;
        let params = serde_json::json!({});
        let result = decide(
            &signed,
            "PERF_VEHICLE_SPEED",
            &params,
            &db,
            Utc::now(),
            None,
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    /// Forbidden VHAL write (ADAS) is hard-denied even when listed in the mandate.
    #[test]
    fn test_vhal_adas_write_denied_despite_mandate() {
        let signed = cabin_mandate(&["CRUISE_CONTROL_COMMAND"]);
        let db = TestLedger;
        let params = serde_json::json!({});
        let result = decide(
            &signed,
            "CRUISE_CONTROL_COMMAND",
            &params,
            &db,
            Utc::now(),
            None,
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("vehicle_forbidden_domain"));
    }

    /// decide() and enforce() produce the same decision for the same mandate.
    #[test]
    fn test_enforce_wraps_decide_consistently() {
        let signed = signed_mandate();
        let db = TestLedger;
        let params = serde_json::json!({"path": "/etc/passwd"});

        let via_enforce = enforce(&signed, "read_file", &params, &db).unwrap();
        let via_decide = decide(&signed, "read_file", &params, &db, Utc::now(), None).unwrap();

        assert_eq!(via_enforce.decision, Decision::Deny);
        assert_eq!(via_decide.decision, Decision::Deny);
        assert_eq!(via_enforce.policy_rule, via_decide.policy_rule);
    }

    #[cfg(unix)]
    #[test]
    fn test_enforce_denies_symlink_file_escape() {
        let tmpdir = std::env::temp_dir().join(format!("a2g_symtest_{}", std::process::id()));
        let workspace = tmpdir.join("workspace");
        let outside = tmpdir.join("outside");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let outside_file = outside.join("data.txt");
        std::fs::write(&outside_file, "out of bounds").unwrap();
        std::os::unix::fs::symlink(&outside_file, workspace.join("evil_link")).unwrap();

        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("symlink-test", &agent_did);
        template = template.replace(
            "workspace_root = \"\"",
            &format!(
                "workspace_root = \"{}\"",
                tmpdir.to_str().unwrap().replace('\\', "\\\\")
            ),
        );
        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = TestLedger;

        let symlink_path = workspace.join("evil_link").to_str().unwrap().to_string();
        let params = serde_json::json!({"path": symlink_path});

        let result = enforce(&signed, "read_file", &params, &db).unwrap();
        assert_eq!(result.decision, Decision::Deny);

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[cfg(unix)]
    #[test]
    fn test_enforce_denies_symlink_dir_escape() {
        let tmpdir = std::env::temp_dir().join(format!("a2g_symtest_dir_{}", std::process::id()));
        let workspace = tmpdir.join("workspace");
        let outside_dir = tmpdir.join("outside_dir");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("report.csv"), "restricted").unwrap();
        std::os::unix::fs::symlink(&outside_dir, workspace.join("outsidedir")).unwrap();

        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("symlink-dir-test", &agent_did);
        template = template.replace(
            "workspace_root = \"\"",
            &format!(
                "workspace_root = \"{}\"",
                tmpdir.to_str().unwrap().replace('\\', "\\\\")
            ),
        );
        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = TestLedger;

        let path_through_symdir = workspace
            .join("outsidedir")
            .join("report.csv")
            .to_str()
            .unwrap()
            .to_string();
        let params = serde_json::json!({"path": path_through_symdir});

        let result = enforce(&signed, "read_file", &params, &db).unwrap();
        assert_eq!(result.decision, Decision::Deny);

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    // ── ADR-0008: HITL two-phase approval tests ───────────────────────────────

    /// (a) Sensitive tool in escalate_tools → PendingApproval with correct binding.
    ///     The binding_id and request_hash must be non-empty; ttl_expires_at must be
    ///     in the future. This is Phase 1 of the ADR-0008 state machine.
    #[test]
    fn test_sensitive_escalate_returns_pending_approval() {
        let signed = cabin_escalate_mandate(&["WINDOW_POS"], &["WINDOW_POS"]);
        let db = TestLedger;
        let parked =
            crate::vehicle::VerifiedVehicleState::new_for_test(crate::vehicle::VehicleState {
                speed_mmps: 0,
                gear: crate::vehicle::Gear::Park,
                actor: crate::vehicle::Actor::Driver,
            });
        let now = Utc::now();
        let result = decide(
            &signed,
            "WINDOW_POS",
            &serde_json::json!({}),
            &db,
            now,
            Some(&parked),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::PendingApproval);
        let pending = result
            .pending_approval
            .expect("PendingApproval must carry a binding");
        assert!(
            !pending.binding_id.is_empty(),
            "binding_id must not be empty"
        );
        assert!(
            !pending.request_hash.is_empty(),
            "request_hash must not be empty"
        );
        assert!(
            pending.ttl_expires_at > now,
            "ttl_expires_at must be in the future"
        );
    }

    /// (b) Valid unexpired grant bound to the correct Phase 1 binding → ALLOW.
    #[test]
    fn test_phase2_valid_grant_allows() {
        let signed = cabin_escalate_mandate(&["WINDOW_POS"], &["WINDOW_POS"]);
        let db = TestLedger;
        let parked =
            crate::vehicle::VerifiedVehicleState::new_for_test(crate::vehicle::VehicleState {
                speed_mmps: 0,
                gear: crate::vehicle::Gear::Park,
                actor: crate::vehicle::Actor::Driver,
            });
        let now = Utc::now();

        // Phase 1
        let v1 = decide(
            &signed,
            "WINDOW_POS",
            &serde_json::json!({}),
            &db,
            now,
            Some(&parked),
        )
        .unwrap();
        assert_eq!(v1.decision, Decision::PendingApproval);
        let pending = v1.pending_approval.unwrap();

        // Create a valid signed grant for this binding
        let (approver_did, approver_secret, _) = crate::identity::generate_agent_keypair();
        let approver_key = signing_key_from_hex(&approver_secret);
        let grant_time = now + chrono::Duration::seconds(1);
        let grant = crate::hitl::ApprovalGrant::new_signed(
            &pending.binding_id,
            &pending.request_hash,
            &approver_did,
            &approver_key,
            300,
            grant_time,
            "",
        );

        // Phase 2
        let v2 = decide_with_approval(
            &signed,
            "WINDOW_POS",
            &serde_json::json!({}),
            &db,
            grant_time + chrono::Duration::seconds(1),
            Some(&parked),
            &pending,
            &grant,
        )
        .unwrap();
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "valid grant should produce ALLOW: {}",
            v2.policy_rule
        );
    }

    /// (c) Grant whose request_hash was signed for a different action → DENY.
    ///     Prevents cross-request replay: approving action A cannot authorise action B.
    #[test]
    fn test_phase2_mismatched_request_hash_denies() {
        let signed = cabin_escalate_mandate(&["WINDOW_POS"], &["WINDOW_POS"]);
        let db = TestLedger;
        let parked =
            crate::vehicle::VerifiedVehicleState::new_for_test(crate::vehicle::VehicleState {
                speed_mmps: 0,
                gear: crate::vehicle::Gear::Park,
                actor: crate::vehicle::Actor::Driver,
            });
        let now = Utc::now();

        let v1 = decide(
            &signed,
            "WINDOW_POS",
            &serde_json::json!({}),
            &db,
            now,
            Some(&parked),
        )
        .unwrap();
        let pending = v1.pending_approval.unwrap();

        // Grant signed for a different request_hash (cross-request replay attempt)
        let (approver_did, approver_secret, _) = crate::identity::generate_agent_keypair();
        let approver_key = signing_key_from_hex(&approver_secret);
        let wrong_hash = "0".repeat(64);
        let grant = crate::hitl::ApprovalGrant::new_signed(
            &pending.binding_id,
            &wrong_hash,
            &approver_did,
            &approver_key,
            300,
            now + chrono::Duration::seconds(1),
            "",
        );

        let v2 = decide_with_approval(
            &signed,
            "WINDOW_POS",
            &serde_json::json!({}),
            &db,
            now + chrono::Duration::seconds(2),
            Some(&parked),
            &pending,
            &grant,
        )
        .unwrap();
        assert_eq!(v2.decision, Decision::Deny);
        assert!(
            v2.policy_rule.contains("request_hash"),
            "policy rule should identify request_hash mismatch, got: {}",
            v2.policy_rule
        );
    }

    /// (d) Expired grant → DENY (replay-via-time prevention).
    #[test]
    fn test_phase2_expired_grant_denies() {
        let signed = cabin_escalate_mandate(&["WINDOW_POS"], &["WINDOW_POS"]);
        let db = TestLedger;
        let parked =
            crate::vehicle::VerifiedVehicleState::new_for_test(crate::vehicle::VehicleState {
                speed_mmps: 0,
                gear: crate::vehicle::Gear::Park,
                actor: crate::vehicle::Actor::Driver,
            });
        let now = Utc::now();

        let v1 = decide(
            &signed,
            "WINDOW_POS",
            &serde_json::json!({}),
            &db,
            now,
            Some(&parked),
        )
        .unwrap();
        let pending = v1.pending_approval.unwrap();

        // Grant issued 1 hour ago with 30-second TTL → already expired
        let (approver_did, approver_secret, _) = crate::identity::generate_agent_keypair();
        let approver_key = signing_key_from_hex(&approver_secret);
        let past = now - chrono::Duration::hours(1);
        let grant = crate::hitl::ApprovalGrant::new_signed(
            &pending.binding_id,
            &pending.request_hash,
            &approver_did,
            &approver_key,
            30, // 30s TTL — expired 3570s ago
            past,
            "",
        );

        // Evaluate at `now` — grant is long expired
        let v2 = decide_with_approval(
            &signed,
            "WINDOW_POS",
            &serde_json::json!({}),
            &db,
            now,
            Some(&parked),
            &pending,
            &grant,
        )
        .unwrap();
        assert_eq!(v2.decision, Decision::Deny);
        assert!(
            v2.policy_rule.contains("approval_grant_expired"),
            "expected approval_grant_expired, got: {}",
            v2.policy_rule
        );
    }

    /// (e) AttestedVehicleState::verify() rejects:
    ///     - bad signature (tampered bytes)
    ///     - stale nonce (wrong challenge)
    ///     - stale timestamp (too old)
    ///     and accepts a valid attestation.
    #[test]
    fn test_attested_state_verify() {
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let key = signing_key_from_hex(&secret);
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        let nonce = "challenge-abc-123";
        let now = Utc::now();
        let state = crate::vehicle::VehicleState {
            speed_mmps: 0,
            gear: crate::vehicle::Gear::Park,
            actor: crate::vehicle::Actor::Driver,
        };
        let attested = crate::vehicle::AttestedVehicleState::sign(state, &key, nonce, now);

        let freshness = crate::vehicle::ATTESTATION_FRESHNESS_MS;

        // Valid attestation with correct nonce → Ok
        assert!(
            attested
                .verify(&pubkey_hex, now, freshness, Some(nonce))
                .is_ok(),
            "valid attestation must verify"
        );

        // Bad signature
        let mut bad_sig = attested.clone();
        bad_sig.signature = "00".repeat(64);
        assert_eq!(
            bad_sig
                .verify(&pubkey_hex, now, freshness, Some(nonce))
                .unwrap_err(),
            crate::vehicle::AttestationError::BadSignature
        );

        // Wrong nonce (stale nonce / replay)
        assert_eq!(
            attested
                .verify(&pubkey_hex, now, freshness, Some("wrong-nonce"))
                .unwrap_err(),
            crate::vehicle::AttestationError::StaleNonce
        );

        // Stale timestamp: age = 1000ms > ATTESTATION_FRESHNESS_MS (500ms)
        let stale_now = now + chrono::Duration::milliseconds(1000);
        assert_eq!(
            attested
                .verify(&pubkey_hex, stale_now, freshness, None)
                .unwrap_err(),
            crate::vehicle::AttestationError::Stale
        );

        // Custom freshness override: 2000ms window accepts the 1000ms-old state
        assert!(
            attested.verify(&pubkey_hex, stale_now, 2000, None).is_ok(),
            "custom freshness_ms=2000 must accept 1000ms-old state"
        );
    }

    /// (f) Forbidden tool is denied even when a fully valid ApprovalGrant is supplied.
    ///     The Forbidden pre-check fires unconditionally before grant evaluation.
    ///     This ordering is critical: no approval can resurrect a Forbidden action.
    #[test]
    fn test_phase2_forbidden_denied_even_with_valid_grant() {
        // Create a plausible (but irrelevant) pending binding and grant for a Forbidden tool.
        // The Forbidden check fires before grant validation, so the grant is never inspected.
        let signed = cabin_mandate(&["CRUISE_CONTROL_COMMAND"]);
        let db = TestLedger;
        let now = Utc::now();

        let binding = crate::hitl::PendingApprovalBinding {
            binding_id: uuid::Uuid::new_v4().to_string(),
            request_hash: "a".repeat(64),
            escalate_to: "did:a2g:approver".to_string(),
            ttl_expires_at: now + chrono::Duration::minutes(5),
        };

        let (approver_did, approver_secret, _) = crate::identity::generate_agent_keypair();
        let approver_key = signing_key_from_hex(&approver_secret);
        let grant = crate::hitl::ApprovalGrant::new_signed(
            &binding.binding_id,
            &binding.request_hash,
            &approver_did,
            &approver_key,
            300,
            now,
            "",
        );

        let v = decide_with_approval(
            &signed,
            "CRUISE_CONTROL_COMMAND",
            &serde_json::json!({}),
            &db,
            now + chrono::Duration::seconds(1),
            None,
            &binding,
            &grant,
        )
        .unwrap();
        assert_eq!(
            v.decision,
            Decision::Deny,
            "Forbidden tool must be denied even with a valid grant"
        );
        assert!(
            v.policy_rule.contains("vehicle_forbidden_domain"),
            "policy rule must identify vehicle_forbidden_domain, got: {}",
            v.policy_rule
        );
    }

    // ── Part 1 follow-ups ─────────────────────────────────────────────────────

    /// Phase 2 uses the `request_hash` carried in the `PendingApprovalBinding` (Phase 1
    /// timestamp), not a freshly-computed hash from the Phase 2 clock.
    /// Evaluating Phase 2 minutes after Phase 1 must still succeed — the async gap
    /// between human approval and Phase 2 resolution must not break hash matching.
    #[test]
    fn test_phase2_async_gap_matches_carried_binding() {
        let signed = cabin_escalate_mandate(&["WINDOW_POS"], &["WINDOW_POS"]);
        let db = TestLedger;
        let parked =
            crate::vehicle::VerifiedVehicleState::new_for_test(crate::vehicle::VehicleState {
                speed_mmps: 0,
                gear: crate::vehicle::Gear::Park,
                actor: crate::vehicle::Actor::Driver,
            });
        let params = serde_json::json!({});

        // Phase 1 at t1: anchored to mandate validity window (mandate has 24-h TTL from real now)
        let m: crate::mandate::Mandate = toml::from_str(&signed).unwrap();
        let expires: DateTime<Utc> = m.mandate.expires_at.parse().unwrap();
        let t1 = expires - chrono::Duration::hours(1);
        let v1 = decide(&signed, "WINDOW_POS", &params, &db, t1, Some(&parked)).unwrap();
        assert_eq!(v1.decision, Decision::PendingApproval);
        let pending = v1.pending_approval.clone().unwrap();

        // Phase 2 at t2 = t1 + 3 min (within 5-min TTL, but different from t1).
        // The grant carries the SAME request_hash as the binding from Phase 1.
        // If Phase 2 recomputed request_hash from t2, matching would fail.
        let t2 = t1 + chrono::Duration::minutes(3);
        let approver_key = signing_key_from_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let grant = crate::hitl::ApprovalGrant::new_signed(
            &pending.binding_id,
            &pending.request_hash, // carried from Phase 1, NOT recomputed from t2
            "did:a2g:approver",
            &approver_key,
            600,
            t2,
            "phase1-receipt",
        );

        let v2 = decide_with_approval(
            &signed,
            "WINDOW_POS",
            &params,
            &db,
            t2,
            Some(&parked),
            &pending,
            &grant,
        )
        .unwrap();
        assert_eq!(
            v2.decision,
            Decision::Allow,
            "Phase 2 must succeed 3 min after Phase 1 — hash matching uses carried binding value"
        );
    }

    /// state_trust = "attested" when VerifiedVehicleState was produced by AttestedVehicleState::verify().
    #[test]
    fn test_state_trust_attested_recorded() {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("trust-test-attested", &did);
        template = template.replace(
            r#"tools = ["read_file", "write_file"]"#,
            r#"tools = ["HVAC_TEMPERATURE_SET"]"#,
        );
        let signed = crate::mandate::sign_mandate(&template, &secret, 876_000).unwrap();
        let (_, attester_secret, _) = crate::identity::generate_agent_keypair();
        let attester_key = signing_key_from_hex(&attester_secret);
        let pubkey_hex = hex::encode(attester_key.verifying_key().to_bytes());
        let nonce = "test-nonce-attest";
        let now = Utc::now();
        let state = crate::vehicle::VehicleState {
            speed_mmps: 0,
            gear: crate::vehicle::Gear::Park,
            actor: crate::vehicle::Actor::Driver,
        };
        let attested = crate::vehicle::AttestedVehicleState::sign(state, &attester_key, nonce, now);
        let verified = attested
            .verify(
                &pubkey_hex,
                now,
                crate::vehicle::ATTESTATION_FRESHNESS_MS,
                Some(nonce),
            )
            .unwrap();
        let db = TestLedger;
        let v = decide(
            &signed,
            "HVAC_TEMPERATURE_SET",
            &serde_json::json!({}),
            &db,
            now,
            Some(&verified),
        )
        .unwrap();
        assert_eq!(
            v.state_trust, "attested",
            "VerifiedVehicleState from verify() must record state_trust=attested"
        );
    }

    /// state_trust = "operator_trusted" when VerifiedVehicleState came from from_operator_trusted().
    #[test]
    fn test_state_trust_operator_trusted_recorded() {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("trust-test-operator", &did);
        template = template.replace(
            r#"tools = ["read_file", "write_file"]"#,
            r#"tools = ["HVAC_TEMPERATURE_SET"]"#,
        );
        let signed = crate::mandate::sign_mandate(&template, &secret, 876_000).unwrap();
        let state = crate::vehicle::VehicleState {
            speed_mmps: 0,
            gear: crate::vehicle::Gear::Park,
            actor: crate::vehicle::Actor::Driver,
        };
        let verified = crate::vehicle::VerifiedVehicleState::from_operator_trusted(state);
        let db = TestLedger;
        let now = Utc::now();
        let v = decide(
            &signed,
            "HVAC_TEMPERATURE_SET",
            &serde_json::json!({}),
            &db,
            now,
            Some(&verified),
        )
        .unwrap();
        assert_eq!(
            v.state_trust, "operator_trusted",
            "from_operator_trusted() must record state_trust=operator_trusted"
        );
    }

    /// state_trust = "none" when no verified state is passed (non-vehicle tool, or omission).
    #[test]
    fn test_state_trust_none_when_no_state() {
        let signed = signed_mandate();
        let db = TestLedger;
        let v = decide(
            &signed,
            "read_file",
            &serde_json::json!({"path": "workspace/file.txt"}),
            &db,
            Utc::now(),
            None,
        )
        .unwrap();
        assert_eq!(
            v.state_trust, "none",
            "None verified_state must record state_trust=none"
        );
    }
}
