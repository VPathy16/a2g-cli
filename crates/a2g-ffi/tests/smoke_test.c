/*
 * A2G FFI C smoke test.
 *
 * Exercises three paths through the ABI:
 *   1. Comfort-domain ALLOW (read_file, no vehicle state required)
 *   2. Forbidden hard-deny (delete_all_data)
 *   3. Operator-trusted vehicle state — state_trust field on verdict
 *
 * This test links against liba2g_ffi.so / liba2g_ffi.a and uses only the
 * public ABI defined in include/a2g.h. It intentionally exercises
 * buffer-ownership rules (all handles freed explicitly).
 *
 * Build:
 *   cc -I../../crates/a2g-ffi/include smoke_test.c -la2g_ffi -L<lib_dir> -o smoke_test
 *
 * The CI workflow compiles and runs this via the Makefile in this directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "a2g.h"

/* Use the built-in test mandate helper to obtain signed CBOR bytes. */

static void test_comfort_allow(const uint8_t *cbor, uintptr_t cbor_len,
                               A2gTrustAnchorHandle *trust) {
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(cbor, cbor_len, "read_file", "{}", NULL, trust, &verdict);

    assert(d == A2G_DECISION_ALLOW && "Comfort tool read_file must be ALLOW");
    assert(verdict != NULL);
    assert(a2g_verdict_decision(verdict) == A2G_DECISION_ALLOW);

    const char *rule = a2g_verdict_policy_rule(verdict);
    assert(rule != NULL);

    printf("  [PASS] comfort ALLOW: policy_rule=%s\n", rule);
    a2g_verdict_free(verdict);
}

static void test_forbidden_deny(const uint8_t *cbor, uintptr_t cbor_len,
                                A2gTrustAnchorHandle *trust) {
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(cbor, cbor_len, "delete_all_data", "{}", NULL, trust, &verdict);

    assert(d == A2G_DECISION_DENY && "Unknown tool delete_all_data must be DENY");
    assert(verdict != NULL);
    assert(a2g_verdict_decision(verdict) == A2G_DECISION_DENY);

    printf("  [PASS] deny (unknown tool)\n");
    a2g_verdict_free(verdict);
}

static void test_operator_trusted_state_trust(const uint8_t *cbor, uintptr_t cbor_len,
                                              A2gTrustAnchorHandle *trust) {
    /* Parked (gear=0), Driver (actor=0), 0 km/h — operator trusted. */
    A2gVerifiedStateHandle *state = a2g_verified_state_operator_trusted(0.0, 0, 0);
    assert(state != NULL && "operator_trusted state creation must succeed");

    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(cbor, cbor_len, "read_file", "{}", state, trust, &verdict);

    assert(d == A2G_DECISION_ALLOW);
    const char *state_trust = a2g_verdict_state_trust(verdict);
    assert(state_trust != NULL);
    assert(strcmp(state_trust, "operator_trusted") == 0 && "state_trust must be operator_trusted");

    printf("  [PASS] operator_trusted state_trust=%s\n", state_trust);
    a2g_verdict_free(verdict);
    a2g_verified_state_free(state);
}

static void test_null_trust_returns_error(const uint8_t *cbor, uintptr_t cbor_len) {
    /* NULL trust → A2G_DECISION_ERROR (fail-explicit, ADR-0014). */
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(cbor, cbor_len, "read_file", "{}", NULL, NULL, &verdict);
    assert(d == A2G_DECISION_ERROR && "NULL trust must return ERROR (fail-explicit)");
    assert(verdict != NULL);
    a2g_verdict_free(verdict);
    printf("  [PASS] NULL trust → ERROR (fail-explicit)\n");
}

static void test_null_mandate_returns_error(A2gTrustAnchorHandle *trust) {
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(NULL, 0, "read_file", "{}", NULL, trust, &verdict);
    assert(d == A2G_DECISION_ERROR && "NULL mandate must return ERROR");
    assert(verdict != NULL);
    a2g_verdict_free(verdict);
    printf("  [PASS] NULL mandate → ERROR\n");
}

static void test_invalid_gear_returns_null(void) {
    A2gVerifiedStateHandle *h = a2g_verified_state_operator_trusted(0.0, 99, 0);
    assert(h == NULL && "out-of-range gear must return NULL");
    a2g_verified_state_free(h); /* NULL is safe to pass */
    printf("  [PASS] invalid gear → NULL\n");
}

int main(void) {
    printf("A2G FFI smoke test\n");

    uint8_t *cbor = NULL;
    uintptr_t cbor_len = 0;
    if (a2g_test_mandate_cbor(&cbor, &cbor_len) != 0 || cbor == NULL) {
        fprintf(stderr, "FATAL: a2g_test_mandate_cbor() failed\n");
        return 1;
    }
    printf("  mandate obtained (%zu bytes)\n", (size_t)cbor_len);

    /* Explicit SelfSovereign trust anchor (ADR-0014). */
    A2gTrustAnchorHandle *trust = a2g_trust_anchor_self_sovereign();
    assert(trust != NULL && "a2g_trust_anchor_self_sovereign must return non-NULL");
    printf("  trust anchor created (SelfSovereign)\n");

    test_comfort_allow(cbor, cbor_len, trust);
    test_forbidden_deny(cbor, cbor_len, trust);
    test_operator_trusted_state_trust(cbor, cbor_len, trust);
    test_null_trust_returns_error(cbor, cbor_len);
    test_null_mandate_returns_error(trust);
    test_invalid_gear_returns_null();

    a2g_trust_anchor_free(trust);
    a2g_cbor_free(cbor, cbor_len);

    printf("All smoke tests passed.\n");
    return 0;
}
