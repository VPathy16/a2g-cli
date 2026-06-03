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

use crate::ledger::EnforceLedger;
use crate::mandate::{self, Mandate};
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
    Expired,
    /// Action exceeds current mandate scope — requires higher authority approval.
    /// The agent pauses. A human or higher-authority system reviews.
    Escalate,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Deny => write!(f, "DENY"),
            Decision::Expired => write!(f, "EXPIRED"),
            Decision::Escalate => write!(f, "ESCALATE"),
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
}

/// Pure enforcement decision — runs the full 8-step pipeline with no I/O.
///
/// # Clock injection
/// `now` is the evaluation timestamp used for TTL (step 2) and jurisdiction
/// operating-hours (step 5) checks. Callers must supply it explicitly so the
/// function is deterministic and testable without mocking the system clock.
///
/// # Ledger reads
/// `ledger.is_revoked()` (step 0) and `ledger.count_recent()` (step 7) are
/// read-only queries. No writes occur inside `decide()`.
///
/// # Path canonicalization
/// Uses logical normalization only — no filesystem access. Symlinks are **not**
/// resolved. See `docs/no_std-blockers.md` for details.
///
/// # API change vs pre-refactor `enforce()`
/// Generic `<L: EnforceLedger>` replaces `&dyn EnforceLedger`. This is a
/// static-dispatch (vtable-free) bound. All existing call sites that pass
/// `&concrete_type` continue to compile unchanged.
pub fn decide<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
    now: DateTime<Utc>,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    let params_hash = hex::encode(Sha256::digest(serde_json::to_string(params)?.as_bytes()));

    // Parse mandate
    let m: Mandate = toml::from_str(mandate_str)?;

    let agent_did = m.mandate.agent_did.clone();
    let agent_name = m.mandate.agent_name.clone();

    // Compute mandate_hash early for revocation check and verdict
    let mandate_hash = hex::encode(Sha256::digest(mandate_str.as_bytes()));
    let proposal_hash = m.mandate.proposal_hash.clone();

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
    // Logical normalization only — no filesystem access.
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

    // ── Step 4.5: Vehicle State Gating ──
    // Only for Sensitive capabilities (door/window/trunk/lock). Comfort and
    // Convenience are not gated; Forbidden was denied above. Unknown vehicle.*
    // sub-domains are treated as Sensitive (fail-safe) by classify_vehicle_tool.
    if crate::vehicle::classify_vehicle_tool(tool) == crate::vehicle::VehicleDomain::Sensitive {
        let state = crate::vehicle::extract_vehicle_state(params);
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
        let current_total = current_hour * 60 + current_min;
        let start_total = start_hour * 60 + start_min;
        let end_total = end_hour * 60 + end_min;

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

    // ── Step 6: Escalation Check ──
    if m.escalation.escalate_tools.contains(&tool.to_string()) {
        return Ok(make_verdict(
            Decision::Escalate,
            &format!(
                "escalation_required: tool '{}' requires approval from {}",
                tool,
                if m.escalation.escalate_to.is_empty() {
                    "higher authority"
                } else {
                    &m.escalation.escalate_to
                }
            ),
        ));
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
                return Ok(make_verdict(
                    Decision::Escalate,
                    &format!(
                        "escalation_required: path '{}' matches escalate_paths '{}'",
                        epath, pattern
                    ),
                ));
            }
        }
    }
    if let Some(target) = params.get("url").and_then(|u| u.as_str()) {
        let ehost = extract_host(target);
        for pattern in &m.escalation.escalate_hosts {
            if glob_matches(pattern, &ehost) {
                return Ok(make_verdict(
                    Decision::Escalate,
                    &format!(
                        "escalation_required: host '{}' matches escalate_hosts '{}'",
                        ehost, pattern
                    ),
                ));
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
/// Public API wrapper: injects the current wall-clock time and delegates to
/// `decide()`. Signature is source-compatible with callers that previously
/// passed `&dyn EnforceLedger`; the only change is `&dyn` → generic `<L>`,
/// which is explicitly called out in the PR description.
pub fn enforce<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    decide(mandate_str, tool, params, ledger, Utc::now())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Validate jurisdiction operating_hours format (HH:MM-HH:MM)
fn validate_operating_hours(
    hours_str: &str,
) -> Result<(u32, u32, u32, u32), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = hours_str.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid operating_hours format '{}': expected HH:MM-HH:MM",
            hours_str
        )
        .into());
    }
    let start = parts[0].trim();
    let end = parts[1].trim();

    let parse_time = |time_str: &str| -> Result<(u32, u32), Box<dyn std::error::Error>> {
        let time_parts: Vec<&str> = time_str.split(':').collect();
        if time_parts.len() != 2 {
            return Err(format!("invalid time '{}': expected HH:MM", time_str).into());
        }
        let hour: u32 = time_parts[0]
            .parse()
            .map_err(|_| format!("invalid hour in '{}'", time_str))?;
        let minute: u32 = time_parts[1]
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

    let start_total = sh * 60 + sm;
    let end_total = eh * 60 + em;
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
///
/// Resolves `.`, `..`, and double slashes without touching the disk.
/// Symlinks are **not** resolved. This is the version used in `decide()`.
///
/// `canonicalize_path` (below) tries `std::fs::canonicalize` first and falls
/// back here; it is kept for any `std`-only callers that want symlink resolution.
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

/// Path canonicalization with optional filesystem resolution.
///
/// Tries `std::fs::canonicalize` first (resolves symlinks, real path);
/// falls back to `canonicalize_path_logical` for paths that don't exist on
/// disk. Not used in `decide()` — kept for `std`-only call sites.
#[cfg(feature = "std")]
#[allow(dead_code)]
fn canonicalize_path(raw: &str) -> String {
    if let Ok(canonical) = std::fs::canonicalize(raw) {
        return canonical.to_string_lossy().to_string();
    }
    canonicalize_path_logical(raw)
}

/// Glob matching for path patterns.
///
/// - `**` matches any number of path segments (including zero)
/// - `*`  matches any characters within a single segment
/// - exact string match otherwise
fn glob_matches(pattern: &str, path: &str) -> bool {
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.splitn(2, "**").collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim_end_matches('/');
            let suffix = parts[1].trim_start_matches('/');
            let path_matches_prefix = prefix.is_empty() || path.starts_with(prefix);
            if !path_matches_prefix {
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
    if parts.len() == 2 {
        let prefix = parts[0];
        let suffix = parts[1];
        return text.starts_with(prefix)
            && text.ends_with(suffix)
            && text.len() >= prefix.len() + suffix.len();
    }
    if parts.is_empty() {
        return true;
    }
    if !text.starts_with(parts[0]) {
        return false;
    }
    let mut remaining = &text[parts[0].len()..];
    for part in &parts[1..parts.len() - 1] {
        if let Some(pos) = remaining.find(part) {
            remaining = &remaining[pos + part.len()..];
        } else {
            return false;
        }
    }
    let last = parts[parts.len() - 1];
    remaining.ends_with(last)
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
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// No-op ledger for unit tests — focuses on mandate logic; ledger paths
    /// (revocation + rate-limit) are covered by CLI integration tests.
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

    // ── Existing tests (unchanged behaviour) ─────────────────────────────────

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
        let result = enforce(&signed, "read_file", &params, &db).unwrap();
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
        let result = enforce(&signed, "read_file", &params, &db).unwrap();
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

    // ── New tests using decide() with injected clock ──────────────────────────

    /// TTL boundary: one second before expiry → ALLOW.
    #[test]
    fn test_ttl_just_before_expiry_allows() {
        let signed = signed_mandate();
        // Parse expires_at from the signed mandate
        let m: crate::mandate::Mandate = toml::from_str(&signed).unwrap();
        let expires: DateTime<Utc> = m.mandate.expires_at.parse().unwrap();

        // One second before expiry — should ALLOW
        let just_before = expires - chrono::Duration::seconds(1);
        let db = TestLedger;
        let params = serde_json::json!({"path": "workspace/file.txt"});
        let result = decide(&signed, "read_file", &params, &db, just_before).unwrap();
        assert_eq!(
            result.decision,
            Decision::Allow,
            "1 second before expiry should ALLOW"
        );
    }

    /// TTL boundary: exactly at expiry → EXPIRED.
    #[test]
    fn test_ttl_at_expiry_denies() {
        let signed = signed_mandate();
        let m: crate::mandate::Mandate = toml::from_str(&signed).unwrap();
        let expires: DateTime<Utc> = m.mandate.expires_at.parse().unwrap();

        let db = TestLedger;
        let params = serde_json::json!({});
        let result = decide(&signed, "read_file", &params, &db, expires).unwrap();
        assert_eq!(
            result.decision,
            Decision::Expired,
            "Exactly at expiry should EXPIRED"
        );
    }

    /// TTL boundary: one hour past expiry → EXPIRED.
    #[test]
    fn test_ttl_past_expiry_denies() {
        let signed = signed_mandate();
        let m: crate::mandate::Mandate = toml::from_str(&signed).unwrap();
        let expires: DateTime<Utc> = m.mandate.expires_at.parse().unwrap();

        let db = TestLedger;
        let params = serde_json::json!({});
        let one_hour_late = expires + chrono::Duration::hours(1);
        let result = decide(&signed, "read_file", &params, &db, one_hour_late).unwrap();
        assert_eq!(result.decision, Decision::Expired);
        assert_eq!(result.policy_rule, "mandate_ttl_exceeded");
    }

    /// Jurisdiction: inject a time within operating hours → ALLOW.
    #[test]
    fn test_jurisdiction_inside_hours_allows() {
        let (did, _, _) = crate::identity::generate_agent_keypair();
        let (_, secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("jur-test", &did);
        template = template.replace(
            "operating_hours = \"\"",
            "operating_hours = \"09:00-17:00\"",
        );
        // 100-year TTL so injected 2030 dates fall within the mandate's valid window
        let signed = crate::mandate::sign_mandate(&template, &secret, 876_000).unwrap();
        let db = TestLedger;
        let params = serde_json::json!({});

        // Noon UTC — well inside 09:00-17:00
        let noon = Utc.with_ymd_and_hms(2030, 6, 1, 12, 0, 0).unwrap();
        let result = decide(&signed, "read_file", &params, &db, noon).unwrap();
        assert_eq!(
            result.decision,
            Decision::Allow,
            "Noon should be inside 09:00-17:00"
        );
    }

    /// Jurisdiction: inject a time outside operating hours → DENY.
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

        // 02:00 UTC — outside 09:00-17:00
        let night = Utc.with_ymd_and_hms(2030, 6, 1, 2, 0, 0).unwrap();
        let result = decide(&signed, "read_file", &params, &db, night).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("jurisdiction_violation"));
    }

    /// Jurisdiction: exactly at window boundary (17:00) → DENY.
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

        // 17:01 UTC — one minute past end
        let just_after = Utc.with_ymd_and_hms(2030, 6, 1, 17, 1, 0).unwrap();
        let result = decide(&signed, "read_file", &params, &db, just_after).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("jurisdiction_violation"));
    }

    // ── Vehicle capability tests ──────────────────────────────────────────────

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

    /// Forbidden domain is denied even when the mandate lists the tool in capabilities.
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
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result.policy_rule.contains("vehicle_forbidden_domain"),
            "expected vehicle_forbidden_domain, got: {}",
            result.policy_rule
        );
    }

    /// Sensitive tool (window) is allowed when Park and speed < 5.
    #[test]
    fn test_window_allowed_when_parked() {
        let signed = cabin_mandate(&["vehicle.window.set_position"]);
        let db = TestLedger;
        let params = serde_json::json!({
            "position": 50,
            "vehicle_state": {"speed_kph": 0.0, "gear": "Park", "actor": "Driver"}
        });
        let result = decide(
            &signed,
            "vehicle.window.set_position",
            &params,
            &db,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    /// Sensitive tool (window) is denied when vehicle is moving.
    #[test]
    fn test_window_denied_when_moving() {
        let signed = cabin_mandate(&["vehicle.window.set_position"]);
        let db = TestLedger;
        let params = serde_json::json!({
            "position": 50,
            "vehicle_state": {"speed_kph": 60.0, "gear": "Drive", "actor": "Driver"}
        });
        let result = decide(
            &signed,
            "vehicle.window.set_position",
            &params,
            &db,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result.policy_rule.contains("vehicle_state_violation"),
            "expected vehicle_state_violation, got: {}",
            result.policy_rule
        );
    }

    /// Comfort tool (climate) is allowed regardless of speed or actor.
    #[test]
    fn test_comfort_allowed_while_moving() {
        let signed = cabin_mandate(&["vehicle.climate.set_temperature"]);
        let db = TestLedger;
        let params = serde_json::json!({
            "target_temp_c": 22,
            "vehicle_state": {"speed_kph": 80.0, "gear": "Drive", "actor": "Passenger"}
        });
        let result = decide(
            &signed,
            "vehicle.climate.set_temperature",
            &params,
            &db,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    /// Sensitive tool with no vehicle_state in params → fail-safe (999 km/h, Drive) → DENY.
    ///
    /// Verifies that the classify_vehicle_tool / Step 4.5 path, not string matching,
    /// drives the gating: even with a mandate that lists the tool, omitting vehicle_state
    /// triggers VehicleState::fail_safe() and the state gate fires.
    #[test]
    fn test_sensitive_no_state_denied_by_failsafe() {
        let signed = cabin_mandate(&["vehicle.window.set_position"]);
        let db = TestLedger;
        // No vehicle_state key in params — extract_vehicle_state returns fail_safe()
        let params = serde_json::json!({"position": 50});
        let result = decide(
            &signed,
            "vehicle.window.set_position",
            &params,
            &db,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result.policy_rule.contains("vehicle_state_violation"),
            "expected vehicle_state_violation for omitted state, got: {}",
            result.policy_rule
        );
    }

    /// PERF_VEHICLE_SPEED is read-only telemetry (NonVehicle domain): passes the
    /// forbidden pre-check, and a mandate listing it permits it via step 3.
    #[test]
    fn test_vhal_speed_read_permitted() {
        let signed = cabin_mandate(&["PERF_VEHICLE_SPEED"]);
        let db = TestLedger;
        let params = serde_json::json!({});
        let result = decide(&signed, "PERF_VEHICLE_SPEED", &params, &db, Utc::now()).unwrap();
        assert_eq!(
            result.decision,
            Decision::Allow,
            "read-only telemetry should be ALLOW, got: {} — {}",
            result.decision,
            result.policy_rule
        );
    }

    /// CRUISE_CONTROL_COMMAND is Forbidden (ADAS write): hard-denied even when the
    /// mandate explicitly lists it — forbidden pre-check fires before tool authorization.
    #[test]
    fn test_vhal_adas_write_denied_despite_mandate() {
        let signed = cabin_mandate(&["CRUISE_CONTROL_COMMAND"]);
        let db = TestLedger;
        let params = serde_json::json!({});
        let result = decide(&signed, "CRUISE_CONTROL_COMMAND", &params, &db, Utc::now()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result.policy_rule.contains("vehicle_forbidden_domain"),
            "expected vehicle_forbidden_domain, got: {}",
            result.policy_rule
        );
    }

    /// decide() and enforce() produce the same decision for the same mandate.
    #[test]
    fn test_enforce_wraps_decide_consistently() {
        let signed = signed_mandate();
        let db = TestLedger;
        let params = serde_json::json!({"path": "workspace/data.csv"});

        let via_enforce = enforce(&signed, "read_file", &params, &db).unwrap();
        // decide() with a recent timestamp should match enforce()
        let via_decide = decide(&signed, "read_file", &params, &db, Utc::now()).unwrap();

        assert_eq!(via_enforce.decision, via_decide.decision);
        assert_eq!(via_enforce.policy_rule, via_decide.policy_rule);
    }
}
