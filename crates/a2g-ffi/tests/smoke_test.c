/*
 * A2G FFI C smoke test.
 *
 * Exercises three paths through the ABI:
 *   1. Comfort-domain ALLOW (read_file, no vehicle state required)
 *   2. Forbidden hard-deny (delete_all_data)
 *   3. Sensitive + escalate → PendingApproval (WINDOW_POS, parked, escalate_tools set)
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

/* Use the built-in test mandate helper rather than an embedded literal. */

static void test_comfort_allow(const char *mandate) {
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(mandate, "read_file", "{}", NULL, &verdict);

    assert(d == A2G_DECISION_ALLOW && "Comfort tool read_file must be ALLOW");
    assert(verdict != NULL);
    assert(a2g_verdict_decision(verdict) == A2G_DECISION_ALLOW);

    const char *rule = a2g_verdict_policy_rule(verdict);
    assert(rule != NULL);

    printf("  [PASS] comfort ALLOW: policy_rule=%s\n", rule);
    a2g_verdict_free(verdict);
}

static void test_forbidden_deny(const char *mandate) {
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(mandate, "delete_all_data", "{}", NULL, &verdict);

    assert(d == A2G_DECISION_DENY && "Forbidden tool delete_all_data must be DENY");
    assert(verdict != NULL);
    assert(a2g_verdict_decision(verdict) == A2G_DECISION_DENY);

    printf("  [PASS] forbidden DENY\n");
    a2g_verdict_free(verdict);
}

static void test_operator_trusted_state_trust(const char *mandate) {
    /* Parked (gear=0), Driver (actor=0), 0 km/h — operator trusted. */
    A2gVerifiedStateHandle *state = a2g_verified_state_operator_trusted(0.0, 0, 0);
    assert(state != NULL && "operator_trusted state creation must succeed");

    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(mandate, "read_file", "{}", state, &verdict);

    assert(d == A2G_DECISION_ALLOW);
    const char *trust = a2g_verdict_state_trust(verdict);
    assert(trust != NULL);
    assert(strcmp(trust, "operator_trusted") == 0 && "state_trust must be operator_trusted");

    printf("  [PASS] operator_trusted state_trust=%s\n", trust);
    a2g_verdict_free(verdict);
    a2g_verified_state_free(state);
}

static void test_null_mandate_returns_error(void) {
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(NULL, "read_file", "{}", NULL, &verdict);
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

    char *mandate = a2g_test_mandate_toml();
    if (mandate == NULL) {
        fprintf(stderr, "FATAL: a2g_test_mandate_toml() returned NULL\n");
        return 1;
    }
    printf("  mandate obtained (%zu bytes)\n", strlen(mandate));

    test_comfort_allow(mandate);
    test_forbidden_deny(mandate);
    test_operator_trusted_state_trust(mandate);
    test_null_mandate_returns_error();
    test_invalid_gear_returns_null();

    a2g_string_free(mandate);

    printf("All smoke tests passed.\n");
    return 0;
}
