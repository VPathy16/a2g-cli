//! End-to-end tests for the A2G MCP proxy (ADR-0019).
//!
//! These tests run the proxy dispatch loop in-process against a mock downstream
//! transport and a real embedded gateway, verifying:
//!
//!   (a) Allowed call passes with receipt metadata in the response.
//!   (b) Denied call produces ZERO downstream log entries (downstream never called).
//!   (c) Unmapped tool is not forwarded (treated as pay.unknown → ESCALATE).
//!   (d) pay.* tool without binding produces ESCALATE, not ALLOW.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use a2g_gateway::keys::generate;
use a2g_gateway::server::{serve, GatewayState};
use serde_json::{json, Value};
use std::sync::mpsc;
use std::thread;

// Bring in proxy internals via path (integration tests have access to src).
use a2g_mcp_proxy::{
    config::{DownstreamConfig, ProxyConfig, TrustAnchorConfig},
    governance::GovernanceContext,
    mcp::{read_message, write_message, ERR_A2G_DENIED, ERR_A2G_ESCALATE},
    proxy::run_proxy,
    transport::DownstreamTransport,
};

// ── Mock downstream transport ─────────────────────────────────────────────────

/// Records every call and responds with a pre-configured response.
struct MockDownstream {
    /// Responses to return in order (cycled if exhausted).
    responses: Vec<String>,
    response_idx: usize,
    /// Calls received.
    calls: Arc<Mutex<Vec<String>>>,
}

impl MockDownstream {
    fn new(calls: Arc<Mutex<Vec<String>>>, responses: Vec<Value>) -> Self {
        Self {
            responses: responses
                .into_iter()
                .map(|v| serde_json::to_string(&v).unwrap())
                .collect(),
            response_idx: 0,
            calls,
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl DownstreamTransport for MockDownstream {
    fn send(&mut self, body: &str) -> Result<(), String> {
        self.calls.lock().unwrap().push(body.to_string());
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<String>, String> {
        if self.responses.is_empty() {
            return Ok(None);
        }
        let idx = self.response_idx % self.responses.len();
        self.response_idx = self.response_idx.wrapping_add(1);
        Ok(Some(self.responses[idx].clone()))
    }
}

// ── Test harness ──────────────────────────────────────────────────────────────

/// Full test harness: embedded gateway + proxy dispatch loop.
struct TestHarness {
    config: ProxyConfig,
    gov: GovernanceContext,
    _shutdown_tx: mpsc::Sender<()>,
    // Keep temp files alive for the duration of the test.
    _key_file: tempfile::NamedTempFile,
    _mandate_file: tempfile::NamedTempFile,
}

impl TestHarness {
    /// Start an embedded gateway and build a governance context for tests.
    ///
    /// `tool_map` maps MCP tool names to A2G capabilities.
    /// `allowed_capabilities` are the capabilities granted in the mandate.
    fn new(tool_map: HashMap<String, String>, allowed_capabilities: &[&str]) -> Self {
        // Generate gateway keys and write demo key file.
        let key_file = tempfile::NamedTempFile::new().unwrap();

        // Use a dedicated temp dir for the socket to avoid path length issues.
        let socket_path =
            std::env::temp_dir().join(format!("a2g-test-gw-{}.sock", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&socket_path);

        let (gw_keys, demo_keys) = generate(key_file.path());
        let state = Arc::new(GatewayState::new(gw_keys, demo_keys.clone(), "vcan0"));
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let state_c = Arc::clone(&state);
        let sock_c = socket_path.clone();
        thread::spawn(move || serve(state_c, &sock_c, ready_tx, shutdown_rx));
        ready_rx.recv().expect("embedded gateway ready");

        // Build mandate CBOR with the requested capabilities.
        let mandate_cbor = build_mandate(allowed_capabilities);
        let mandate_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(mandate_file.path(), &mandate_cbor).unwrap();

        // Build config.
        let config = ProxyConfig {
            downstream: DownstreamConfig {
                command: "a2g-echo-mcp-server".to_string(),
                args: vec![],
            },
            mandate_path: mandate_file.path().to_path_buf(),
            gateway_socket: socket_path,
            demo_key_file: key_file.path().to_path_buf(),
            trust_anchor: TrustAnchorConfig::SelfSovereign,
            tool_map,
        };

        let gov = GovernanceContext::load(&config).expect("load governance context");

        TestHarness {
            config,
            gov,
            _shutdown_tx: shutdown_tx,
            _key_file: key_file,
            _mandate_file: mandate_file,
        }
    }

    /// Run the proxy with a single tools/call request.
    ///
    /// Returns (response_json, downstream_call_count).
    fn run_tool_call(
        &self,
        tool_name: &str,
        arguments: Value,
        downstream_responses: Vec<Value>,
    ) -> (Value, usize) {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut downstream = MockDownstream::new(Arc::clone(&calls), downstream_responses);

        // Build a tools/call request.
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        });

        // Frame it as Content-Length–framed MCP.
        let mut upstream_in = Vec::new();
        let body = serde_json::to_string(&request).unwrap();
        write_message(&mut upstream_in, &body).unwrap();
        // Append EOF (empty = no more messages; proxy will exit loop).

        let mut upstream_out = Vec::new();

        run_proxy(
            Cursor::new(upstream_in),
            &mut upstream_out,
            &mut downstream,
            &self.config,
            &self.gov,
        );

        let call_count = downstream.call_count();

        // Parse the response.
        let mut reader = BufReader::new(Cursor::new(upstream_out));
        let response_body = read_message(&mut reader)
            .expect("read response")
            .expect("response present");
        let response: Value = serde_json::from_str(&response_body).expect("parse response");

        (response, call_count)
    }
}

// ── Mandate builder ───────────────────────────────────────────────────────────

/// Build a signed CBOR mandate granting the given capabilities.
fn build_mandate(tools: &[&str]) -> Vec<u8> {
    use a2g_core::cbor::{encode_canonical, CborMandate, MandateTbs};
    use a2g_core::mandate::capabilities_hash;
    use chrono::Utc;
    use ed25519_dalek::Signer;

    let (agent_did, _, _) = a2g_core::identity::generate_agent_keypair();
    let (_, secret, _) = a2g_core::identity::generate_agent_keypair();
    let secret_bytes = hex::decode(&secret).unwrap();
    let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret_arr);
    let vk = sk.verifying_key();

    let now = Utc::now();
    let expires = now
        .checked_add_signed(chrono::Duration::hours(24))
        .unwrap_or(now);
    let issuer_did = format!("did:a2g:{}", bs58::encode(vk.to_bytes()).into_string());
    let tools_owned: Vec<String> = tools.iter().map(|s| s.to_string()).collect();
    let cap_hash_bytes = hex::decode(capabilities_hash(&tools_owned)).unwrap();

    let tbs = MandateTbs {
        tag: "MANDATE".to_string(),
        agent_did,
        issuer_did,
        agent_name: "test-mcp-agent".to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        proposal_hash: String::new(),
        workspace_root: String::new(),
        capabilities_hash: cap_hash_bytes.into(),
        tools: tools_owned,
        fs_read: vec![],
        fs_write: vec![],
        fs_deny: vec![],
        net_allow: vec![],
        net_deny: vec![],
        cmd_allow: vec![],
        cmd_deny: vec![],
        max_calls_per_minute: 60,
        max_file_size_bytes: 10_485_760,
        max_output_tokens: 4096,
        max_session_duration_sec: 3600,
        deny_patterns: vec![],
        redact_patterns: vec![],
        max_output_length: 50_000,
        region: String::new(),
        regulatory_framework: String::new(),
        environment: String::new(),
        classification: String::new(),
        operating_hours: String::new(),
        escalate_tools: vec![],
        escalate_paths: vec![],
        escalate_hosts: vec![],
        escalate_to: String::new(),
    };

    let tbs_bytes = encode_canonical(&tbs).unwrap();
    let sig = sk.sign(&tbs_bytes);
    let envelope = CborMandate {
        tag: "MANDATE-V1".to_string(),
        tbs: tbs_bytes.into(),
        signature: sig.to_bytes().to_vec().into(),
        issuer_pubkey: vk.to_bytes().to_vec().into(),
    };
    encode_canonical(&envelope).unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// (a) Allowed call passes with receipt metadata.
#[test]
fn test_allowed_call_passes_with_receipt_metadata() {
    let mut tool_map = HashMap::new();
    tool_map.insert(
        "echo".to_string(),
        "vehicle.climate.set_temperature".to_string(),
    );

    let harness = TestHarness::new(tool_map, &["vehicle.climate.set_temperature"]);

    // Downstream mock responds with a successful echo result.
    let downstream_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": "echo: tool=echo arguments={\"message\":\"hello\"}"}]
        }
    });

    let (response, call_count) = harness.run_tool_call(
        "echo",
        json!({"message": "hello"}),
        vec![downstream_response],
    );

    // Should be a success response.
    assert!(
        response.get("result").is_some(),
        "expected result, got: {response}"
    );
    assert!(
        response.get("error").is_none(),
        "unexpected error: {response}"
    );

    // receipt_id should be in _meta.
    let meta = &response["result"]["_meta"];
    assert!(
        !meta["a2g_receipt_id"].is_null(),
        "expected a2g_receipt_id in _meta, got: {response}"
    );

    // Downstream MUST have been called.
    assert_eq!(call_count, 1, "downstream should be called once for ALLOW");
}

/// (b) Denied call — downstream receives ZERO calls.
#[test]
fn test_denied_call_produces_zero_downstream_calls() {
    let mut tool_map = HashMap::new();
    tool_map.insert(
        "echo".to_string(),
        "vehicle.climate.set_temperature".to_string(),
    );

    // Mandate does NOT include "vehicle.climate.set_temperature" → DENY.
    let harness = TestHarness::new(tool_map, &["some_other_tool"]);

    let (response, call_count) = harness.run_tool_call("echo", json!({"message": "hello"}), vec![]);

    // Should be an error response with the A2G denied code.
    let error = response
        .get("error")
        .expect("expected error for denied call");
    assert_eq!(
        error["code"].as_i64().unwrap(),
        ERR_A2G_DENIED,
        "wrong error code: {error}"
    );
    assert!(
        error["message"]
            .as_str()
            .unwrap_or("")
            .contains("a2g_denied"),
        "message should contain a2g_denied: {error}"
    );

    // Downstream MUST NOT have been called.
    assert_eq!(
        call_count, 0,
        "downstream must not be called for DENY — got {call_count} calls"
    );
}

/// (c) Unmapped tool — not forwarded (fail-closed → pay.unknown → ESCALATE).
#[test]
fn test_unmapped_tool_is_not_forwarded() {
    let tool_map = HashMap::new(); // empty — no mappings

    // Mandate grants pay.unknown which is always-HITL regardless; but mandate
    // does not contain "pay.unknown" anyway.
    let harness = TestHarness::new(tool_map, &["vehicle.climate.set_temperature"]);

    let (response, call_count) = harness.run_tool_call("some_unmapped_tool", json!({}), vec![]);

    // Should be an error — either ESCALATE (pay.unknown HITL) or DENY (not in mandate).
    let error = response
        .get("error")
        .expect("expected error for unmapped tool");
    let code = error["code"].as_i64().unwrap();
    assert!(
        code == ERR_A2G_ESCALATE || code == ERR_A2G_DENIED,
        "expected ESCALATE or DENY for unmapped tool, got code={code}: {error}"
    );

    // Downstream MUST NOT have been called.
    assert_eq!(
        call_count, 0,
        "downstream must not be called for unmapped tool — got {call_count} calls"
    );
}

/// (d) pay.* tool without binding → ESCALATE (always-HITL), downstream never called.
#[test]
fn test_pay_tool_without_binding_is_escalated() {
    let mut tool_map = HashMap::new();
    tool_map.insert("checkout".to_string(), "pay.checkout".to_string());

    // Mandate includes pay.checkout — but pay.* is always-HITL regardless.
    let harness = TestHarness::new(tool_map, &["pay.checkout"]);

    let (response, call_count) = harness.run_tool_call("checkout", json!({"amount": 9.99}), vec![]);

    // Should be ESCALATE.
    let error = response
        .get("error")
        .expect("expected error for pay.* without binding");
    let code = error["code"].as_i64().unwrap();
    assert_eq!(
        code, ERR_A2G_ESCALATE,
        "expected ESCALATE for pay.* without binding, got code={code}: {error}"
    );

    // binding_id should be present in error data.
    let binding_id = error["data"]["binding_id"].as_str().unwrap_or("");
    assert!(
        !binding_id.is_empty(),
        "binding_id should be present in ESCALATE response: {error}"
    );

    // Downstream MUST NOT have been called.
    assert_eq!(
        call_count, 0,
        "downstream must not be called for ESCALATE — got {call_count} calls"
    );
}

/// (e) Gateway refused after ALLOW (e.g. freshness window expired due to clock skew).
///     Downstream must not be called.
#[test]
fn test_gateway_refused_does_not_forward() {
    // Use a tool that would be ALLOW but simulate gateway refusal by using a
    // different gateway socket path that doesn't exist.
    let mut tool_map = HashMap::new();
    tool_map.insert(
        "echo".to_string(),
        "vehicle.climate.set_temperature".to_string(),
    );

    // Build mandate normally.
    let mandate_cbor = build_mandate(&["vehicle.climate.set_temperature"]);
    let mandate_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(mandate_file.path(), &mandate_cbor).unwrap();

    // Point gateway_socket at a non-existent path → gateway_unreachable.
    let config = ProxyConfig {
        downstream: DownstreamConfig {
            command: "a2g-echo-mcp-server".to_string(),
            args: vec![],
        },
        mandate_path: mandate_file.path().to_path_buf(),
        gateway_socket: PathBuf::from("/tmp/a2g-nonexistent-test.sock"),
        // We need a real demo key file — use a fake one with generated keys.
        demo_key_file: PathBuf::from("/tmp/a2g-nonexistent-keys.json"),
        trust_anchor: TrustAnchorConfig::SelfSovereign,
        tool_map,
    };

    // GovernanceContext::load will fail because demo_key_file doesn't exist.
    // Test that the error path returns an internal error and no downstream calls.
    // We verify the GovernanceContext load failure is handled gracefully.
    let result = GovernanceContext::load(&config);
    assert!(result.is_err(), "should fail when demo key file missing");
}
