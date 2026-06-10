//! Round-trip and determinism tests for CBOR-encoded signed payloads (ADR-0011).
//!
//! Contract:
//!   1. `encode_canonical` is deterministic: identical inputs produce identical bytes.
//!   2. `decode_canonical` round-trips: decode(encode(x)) equals x field-by-field.
//!   3. Malformed CBOR bytes do not panic — `decode_canonical` returns `Err`.
//!
//! Running:
//!   cargo test -p a2g-core --test cbor_canonical

use a2g_core::cbor::{decode_canonical, encode_canonical, BindingPayload, GrantPayload};
use proptest::prelude::*;

// ── Determinism tests ─────────────────────────────────────────────────────────

#[test]
fn binding_payload_is_deterministic() {
    let hash = vec![0xab_u8; 32];
    let a = BindingPayload {
        tag: "BINDING".to_string(),
        binding_id: "uuid-a".to_string(),
        request_hash: hash.clone().into(),
        escalate_to: "did:a2g:approver".to_string(),
        ttl_unix_secs: 1_700_000_000,
    };
    let b = BindingPayload {
        tag: "BINDING".to_string(),
        binding_id: "uuid-a".to_string(),
        request_hash: hash.into(),
        escalate_to: "did:a2g:approver".to_string(),
        ttl_unix_secs: 1_700_000_000,
    };
    assert_eq!(
        encode_canonical(&a).unwrap(),
        encode_canonical(&b).unwrap(),
        "identical BindingPayload inputs must produce identical CBOR bytes"
    );
}

#[test]
fn grant_payload_is_deterministic() {
    let hash = vec![0xcd_u8; 32];
    let a = GrantPayload {
        tag: "APPROVAL".to_string(),
        binding_id: "uuid-b".to_string(),
        request_hash: hash.clone().into(),
        expires_at: "2025-01-01T00:00:00Z".to_string(),
    };
    let b = GrantPayload {
        tag: "APPROVAL".to_string(),
        binding_id: "uuid-b".to_string(),
        request_hash: hash.into(),
        expires_at: "2025-01-01T00:00:00Z".to_string(),
    };
    assert_eq!(
        encode_canonical(&a).unwrap(),
        encode_canonical(&b).unwrap(),
        "identical GrantPayload inputs must produce identical CBOR bytes"
    );
}

// ── Round-trip tests ──────────────────────────────────────────────────────────

#[test]
fn binding_payload_round_trips() {
    let hash: Vec<u8> = (0u8..32).collect();
    let orig = BindingPayload {
        tag: "BINDING".to_string(),
        binding_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        request_hash: hash.into(),
        escalate_to: "did:a2g:human".to_string(),
        ttl_unix_secs: 9_999_999_999,
    };
    let bytes = encode_canonical(&orig).expect("encode");
    let decoded: BindingPayload = decode_canonical(&bytes).expect("decode");
    assert_eq!(orig.tag, decoded.tag);
    assert_eq!(orig.binding_id, decoded.binding_id);
    assert_eq!(&orig.request_hash as &[u8], &decoded.request_hash as &[u8]);
    assert_eq!(orig.escalate_to, decoded.escalate_to);
    assert_eq!(orig.ttl_unix_secs, decoded.ttl_unix_secs);
}

#[test]
fn grant_payload_round_trips() {
    let hash: Vec<u8> = (100u8..132).collect();
    let orig = GrantPayload {
        tag: "APPROVAL".to_string(),
        binding_id: "binding-xyz".to_string(),
        request_hash: hash.into(),
        expires_at: "2030-06-15T12:00:00Z".to_string(),
    };
    let bytes = encode_canonical(&orig).expect("encode");
    let decoded: GrantPayload = decode_canonical(&bytes).expect("decode");
    assert_eq!(orig.tag, decoded.tag);
    assert_eq!(orig.binding_id, decoded.binding_id);
    assert_eq!(&orig.request_hash as &[u8], &decoded.request_hash as &[u8]);
    assert_eq!(orig.expires_at, decoded.expires_at);
}

// ── Field-order sensitivity ───────────────────────────────────────────────────

#[test]
fn binding_payload_field_order_affects_bytes() {
    let hash = vec![0xff_u8; 32];
    let a = BindingPayload {
        tag: "BINDING".to_string(),
        binding_id: "id-a".to_string(),
        request_hash: hash.clone().into(),
        escalate_to: "did:a2g:x".to_string(),
        ttl_unix_secs: 1_000,
    };
    let b = BindingPayload {
        tag: "BINDING".to_string(),
        binding_id: "id-b".to_string(), // different binding_id
        request_hash: hash.into(),
        escalate_to: "did:a2g:x".to_string(),
        ttl_unix_secs: 1_000,
    };
    assert_ne!(
        encode_canonical(&a).unwrap(),
        encode_canonical(&b).unwrap(),
        "different binding_id must produce different CBOR bytes"
    );
}

// ── Malformed CBOR rejection ──────────────────────────────────────────────────

#[test]
fn malformed_cbor_binding_decode_returns_err() {
    let garbage = b"\x82\x43\xab\xcd"; // truncated CBOR
    let result: Result<BindingPayload, _> = decode_canonical(garbage);
    assert!(result.is_err(), "malformed CBOR must return Err, not panic");
}

#[test]
fn empty_bytes_decode_returns_err() {
    let result: Result<GrantPayload, _> = decode_canonical(b"");
    assert!(result.is_err(), "empty bytes must return Err");
}

#[test]
fn json_bytes_decode_returns_err() {
    let json = br#"{"tag":"BINDING","binding_id":"x"}"#;
    let result: Result<BindingPayload, _> = decode_canonical(json);
    assert!(result.is_err(), "JSON bytes must not decode as CBOR");
}

// ── Property tests ────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary bytes must not cause decode_canonical to panic.
    #[test]
    fn prop_arbitrary_bytes_decode_never_panics_binding(
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _: Result<BindingPayload, _> = decode_canonical(&data);
    }

    #[test]
    fn prop_arbitrary_bytes_decode_never_panics_grant(
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _: Result<GrantPayload, _> = decode_canonical(&data);
    }

    /// Valid BindingPayload encodes and decodes without error.
    #[test]
    fn prop_binding_encode_decode_roundtrip(
        binding_id in "[a-z0-9-]{1,36}",
        escalate_to in "[a-z:]{5,40}",
        ttl in i64::MIN..=i64::MAX,
    ) {
        let hash = vec![0u8; 32];
        let orig = BindingPayload {
            tag: "BINDING".to_string(),
            binding_id: binding_id.clone(),
            request_hash: hash.into(),
            escalate_to: escalate_to.clone(),
            ttl_unix_secs: ttl,
        };
        let bytes = encode_canonical(&orig).expect("encode");
        let decoded: BindingPayload = decode_canonical(&bytes).expect("decode");
        prop_assert_eq!(orig.binding_id, decoded.binding_id);
        prop_assert_eq!(orig.escalate_to, decoded.escalate_to);
        prop_assert_eq!(orig.ttl_unix_secs, decoded.ttl_unix_secs);
    }
}
