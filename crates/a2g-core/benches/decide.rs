use a2g_core::{
    enforce::decide,
    identity,
    ledger::EnforceLedger,
    mandate::{generate_template, sign_mandate},
};
use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;

/// Minimal ledger that records nothing and never revokes.
struct NoopLedger;

impl EnforceLedger for NoopLedger {
    fn is_revoked(&self, _agent_did: &str, _mandate_hash: &str) -> Result<bool, a2g_core::A2gError> {
        Ok(false)
    }

    fn count_recent(&self, _agent_did: &str, _seconds: i64) -> Result<u64, a2g_core::A2gError> {
        Ok(0)
    }
}

fn make_signed_mandate() -> (String, String) {
    let (did, _, _) = identity::generate_agent_keypair();
    let (_, sovereign_secret, _) = identity::generate_agent_keypair();
    let template = generate_template("bench-agent", &did);
    let signed = sign_mandate(&template, &sovereign_secret, 24).unwrap();
    (signed, did)
}

fn bench_decide_allow(c: &mut Criterion) {
    let (signed, _) = make_signed_mandate();
    let ledger = NoopLedger;
    let params = json!({"path": "workspace/data.csv"});
    let now = Utc::now();

    c.bench_function("decide_allow (read_file)", |b| {
        b.iter(|| {
            let verdict = decide(&signed, "read_file", &params, &ledger, now, None).unwrap();
            // read_file is in the template's tools list → ALLOW
            std::hint::black_box(verdict);
        });
    });
}

fn bench_decide_deny_unknown_tool(c: &mut Criterion) {
    let (signed, _) = make_signed_mandate();
    let ledger = NoopLedger;
    let params = json!({});
    let now = Utc::now();

    c.bench_function("decide_deny (unknown_tool)", |b| {
        b.iter(|| {
            let verdict = decide(&signed, "delete_database", &params, &ledger, now, None).unwrap();
            std::hint::black_box(verdict);
        });
    });
}

criterion_group!(benches, bench_decide_allow, bench_decide_deny_unknown_tool);
criterion_main!(benches);
