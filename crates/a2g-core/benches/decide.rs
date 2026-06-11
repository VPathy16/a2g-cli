use a2g_core::{
    cbor::{encode_canonical, CborMandate, MandateTbs},
    enforce::{decide, TrustAnchor},
    identity,
    ledger::EnforceLedger,
    mandate::capabilities_hash,
};
use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::Signer;
use serde_json::json;

/// Minimal ledger that records nothing and never revokes.
struct NoopLedger;

impl EnforceLedger for NoopLedger {
    fn is_revoked(
        &self,
        _agent_did: &str,
        _mandate_hash: &str,
    ) -> Result<bool, a2g_core::A2gError> {
        Ok(false)
    }

    fn count_recent(&self, _agent_did: &str, _seconds: i64) -> Result<u64, a2g_core::A2gError> {
        Ok(0)
    }
}

fn make_cbor_mandate() -> Vec<u8> {
    let (agent_did, _, _) = identity::generate_agent_keypair();
    let (_, sovereign_secret, _) = identity::generate_agent_keypair();
    let secret_bytes = hex::decode(&sovereign_secret).unwrap();
    let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret_arr);
    let vk = sk.verifying_key();

    let now = Utc::now();
    let expires = now
        .checked_add_signed(chrono::Duration::hours(24))
        .unwrap_or(now);
    let issuer_did = format!("did:a2g:{}", bs58::encode(vk.to_bytes()).into_string());
    let tools = vec!["read_file".to_string(), "write_file".to_string()];
    let cap_hash_bytes = hex::decode(capabilities_hash(&tools)).unwrap();

    let tbs = MandateTbs {
        tag: "MANDATE".to_string(),
        agent_did,
        issuer_did,
        agent_name: "bench-agent".to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        proposal_hash: String::new(),
        workspace_root: String::new(),
        capabilities_hash: cap_hash_bytes.into(),
        tools,
        fs_read: vec!["workspace/**".to_string()],
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

fn bench_decide_allow(c: &mut Criterion) {
    let cbor = make_cbor_mandate();
    let ledger = NoopLedger;
    let params = json!({"path": "workspace/data.csv"});
    let now = Utc::now();

    c.bench_function("decide_allow (read_file)", |b| {
        b.iter(|| {
            let verdict = decide(
                &cbor,
                "read_file",
                &params,
                &ledger,
                now,
                None,
                &TrustAnchor::SelfSovereign,
            )
            .unwrap();
            // read_file is in the mandate's tools list → ALLOW
            std::hint::black_box(verdict);
        });
    });
}

fn bench_decide_deny_unknown_tool(c: &mut Criterion) {
    let cbor = make_cbor_mandate();
    let ledger = NoopLedger;
    let params = json!({});
    let now = Utc::now();

    c.bench_function("decide_deny (unknown_tool)", |b| {
        b.iter(|| {
            let verdict = decide(
                &cbor,
                "delete_database",
                &params,
                &ledger,
                now,
                None,
                &TrustAnchor::SelfSovereign,
            )
            .unwrap();
            std::hint::black_box(verdict);
        });
    });
}

criterion_group!(benches, bench_decide_allow, bench_decide_deny_unknown_tool);
criterion_main!(benches);
