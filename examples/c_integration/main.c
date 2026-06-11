/*
 * A2G C Integration Example
 * ==========================
 * Demonstrates the three verdict paths through the a2g-ffi ABI:
 *
 *   ALLOW            — Comfort-domain tool, returns immediately.
 *   DENY             — Forbidden-domain tool, hard-denied before mandate check.
 *   PENDING_APPROVAL — Human-in-the-loop path (Phase 1 → Phase 2 code shown).
 *
 * Audience: Platform engineers integrating a2g-ffi into ECU firmware or
 * infotainment middleware with a C or C++ toolchain.
 *
 * Build:
 *   make A2G_LIB_DIR=../../target/release
 *   ./a2g_integration
 *
 * For aarch64:
 *   make CC=aarch64-linux-gnu-gcc A2G_LIB_DIR=/path/to/aarch64/release
 *
 * See docs/INTEGRATION.md for the full three-zone architecture, cross-compile
 * instructions, and safety posture.
 *
 * Compile requirements: C99 or later.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "a2g_integration.h"  /* includes a2g.h + contract docs */

/* ── Forward declarations ─────────────────────────────────────────────────── */
static const char *decision_name(A2gDecision d);

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static const char *decision_name(A2gDecision d) {
    switch (d) {
    case A2G_DECISION_ALLOW:            return "ALLOW";
    case A2G_DECISION_DENY:             return "DENY";
    case A2G_DECISION_EXPIRED:          return "EXPIRED";
    case A2G_DECISION_PENDING_APPROVAL: return "PENDING_APPROVAL";
    default:                            return "ERROR";
    }
}

static void print_verdict(const A2gVerdictHandle *h) {
    printf("    decision    : %s\n", decision_name(a2g_verdict_decision(h)));
    printf("    verdict_id  : %s\n", a2g_verdict_id(h));
    printf("    agent_did   : %s\n", a2g_verdict_agent_did(h));
    printf("    tool        : %s\n", a2g_verdict_tool(h));
    printf("    policy_rule : %s\n", a2g_verdict_policy_rule(h));
    printf("    state_trust : %s\n", a2g_verdict_state_trust(h));
}

/* ── Demo 1: ALLOW ────────────────────────────────────────────────────────── */

/*
 * Demonstrates A2G_DECISION_ALLOW for a Comfort-domain tool.
 *
 * read_file is in the default [capabilities].tools list and is not in
 * [escalation].escalate_tools, so it returns ALLOW immediately regardless of
 * vehicle state.  We pass operator-trusted vehicle state here to show that the
 * state_trust field is populated on the verdict.
 */
static void demo_allow(const uint8_t *cbor, uintptr_t cbor_len,
                       A2gTrustAnchorHandle *trust) {
    printf("\n=== Demo 1: ALLOW (read_file, parked, driver) ===\n");

    /* Create an operator-trusted vehicle state: parked (gear=0), 0 km/h, driver (actor=0).
     * speed_kph is a double at the C ABI, validated and converted to mm/s internally.
     * NaN, infinity, negative, subnormal, or >1000.0 values return NULL (fail-safe DENY). */
    A2gVerifiedStateHandle *state =
        a2g_verified_state_operator_trusted(0.0 /* speed_kph — converted to 0 mm/s */,
                                            0   /* gear: Park */,
                                            0   /* actor: Driver */);
    if (state == NULL) {
        fprintf(stderr, "FATAL: a2g_verified_state_operator_trusted returned NULL\n");
        exit(1);
    }

    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(cbor, cbor_len, "read_file", "{}", state, trust, &verdict);

    assert(verdict != NULL);
    print_verdict(verdict);

    if (d != A2G_DECISION_ALLOW) {
        fprintf(stderr, "FAIL: expected ALLOW, got %s\n", decision_name(d));
        a2g_verdict_free(verdict);
        a2g_verified_state_free(state);
        exit(1);
    }

    assert(strcmp(a2g_verdict_state_trust(verdict), "operator_trusted") == 0);
    printf("  [PASS] ALLOW path verified\n");

    /* Free in any order — the string pointers from accessors are owned by the
     * handle and are invalidated by a2g_verdict_free. */
    a2g_verdict_free(verdict);
    a2g_verified_state_free(state);
}

/* ── Demo 2: DENY ─────────────────────────────────────────────────────────── */

/*
 * Demonstrates A2G_DECISION_DENY for a Forbidden-domain tool.
 *
 * delete_all_data is hard-denied before any mandate check — no mandate content
 * can override a Forbidden-domain classification.  No vehicle state is needed.
 */
static void demo_deny(const uint8_t *cbor, uintptr_t cbor_len,
                      A2gTrustAnchorHandle *trust) {
    printf("\n=== Demo 2: DENY (delete_all_data, not authorized) ===\n");

    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(cbor, cbor_len, "delete_all_data", "{}", NULL, trust, &verdict);

    assert(verdict != NULL);
    print_verdict(verdict);

    if (d != A2G_DECISION_DENY) {
        fprintf(stderr, "FAIL: expected DENY, got %s\n", decision_name(d));
        a2g_verdict_free(verdict);
        exit(1);
    }

    printf("  [PASS] DENY path verified\n");
    a2g_verdict_free(verdict);
}

/* ── Demo 3: Complete dispatch showing all four verdict types ─────────────── */

/*
 * demo_dispatch — production-style dispatch pattern.
 *
 * Always switch over all four A2gDecision values.  New decision codes will not
 * be added without a major ABI revision, but treating unknown values as errors
 * is good defensive practice.
 *
 * For the PENDING_APPROVAL case: the code below shows the full Phase 1 →
 * Phase 2 flow.  With the test mandate (escalate_tools = []), this branch is
 * never reached at demo runtime — the tool just returns ALLOW.  In production,
 * use a mandate where the target tool appears in BOTH [capabilities].tools and
 * [escalation].escalate_tools to trigger this path.
 *
 * See docs/INTEGRATION.md §Phase 1 → Phase 2 for the full sequence.
 */
static int demo_dispatch(const uint8_t *cbor,
                         uintptr_t cbor_len,
                         const char *tool,
                         const char *params_json,
                         A2gVerifiedStateHandle *state,
                         A2gTrustAnchorHandle *trust) {
    A2gVerdictHandle *verdict = NULL;
    A2gDecision d = a2g_decide(cbor, cbor_len, tool, params_json, state, trust, &verdict);

    assert(verdict != NULL);  /* always written, even on error */

    printf("  %-28s → %s  (rule: %s)\n",
           tool, decision_name(d), a2g_verdict_policy_rule(verdict));

    switch (d) {
    case A2G_DECISION_ALLOW:
        /*
         * Tool call is permitted.  Forward the ALLOW verdict (verdict_id +
         * policy_rule) to the Enforcing Writer, which is the sole HAL writer.
         * The writer appends a signed receipt to the hash-chained ledger before
         * executing any hardware action.
         */
        break;

    case A2G_DECISION_DENY:
        /* Tool call is refused.  Log the denial; do not execute. */
        break;

    case A2G_DECISION_EXPIRED:
        /* Mandate TTL has elapsed.  Reject the mandate; request a new one. */
        break;

    case A2G_DECISION_PENDING_APPROVAL:
        /*
         * PHASE 1 SUCCEEDED — Human approval is required before execution.
         *
         * Steps:
         *   1. Retrieve the MAC-protected binding JSON.  Do NOT modify any
         *      field — a tampered MAC causes Phase 2 to return ERROR.
         *
         *   2. Retrieve binding_id, request_hash, and the escalate_to DID from
         *      the binding JSON.  Forward these to your approval backend
         *      (operator console, mobile push notification, etc.).
         *
         *   3. When the human approver returns a signed ApprovalGrant JSON
         *      (grant_json), call a2g_decide_with_approval() with:
         *        - the same cbor/cbor_len, tool, params_json, state as Phase 1
         *        - the unmodified binding_json from step 1
         *        - the grant_json from the approver
         *
         *   4. Phase 2 returns A2G_DECISION_ALLOW on success.  Free both
         *      the Phase 1 and Phase 2 handles separately.
         *
         * Example Phase 2 call:
         *
         *   const char *binding_json = a2g_verdict_binding_json(verdict);
         *   A2gVerdictHandle *verdict2 = NULL;
         *   A2gDecision d2 = a2g_decide_with_approval(
         *       cbor, cbor_len, tool, params_json, state,
         *       binding_json, grant_json, trust, &verdict2);
         *   if (d2 == A2G_DECISION_ALLOW) { forward_to_enforcing_writer(); }
         *   a2g_verdict_free(verdict2);
         *
         * The Pending Approval TTL is 5 minutes.  If the approver does not
         * respond within this window, Phase 2 will return A2G_DECISION_ERROR.
         */
        printf("    binding_id  : %s\n", a2g_verdict_binding_id(verdict));
        printf("    request_hash: %s\n", a2g_verdict_request_hash(verdict));
        break;

    default:
        /* A2G_DECISION_ERROR — invalid input, internal error, or tampered MAC. */
        fprintf(stderr, "    ERROR: rule=%s\n", a2g_verdict_policy_rule(verdict));
        a2g_verdict_free(verdict);
        return -1;
    }

    a2g_verdict_free(verdict);
    return 0;
}

/* ── Demo 4: Error handling (NULL mandate, NULL trust, invalid state params) ── */

static void demo_error_paths(A2gTrustAnchorHandle *trust) {
    printf("\n=== Demo 4: Error handling ===\n");

    /* NULL trust → A2G_DECISION_ERROR (fail-explicit, ADR-0014) */
    {
        A2gVerdictHandle *verdict = NULL;
        A2gDecision d = a2g_decide(NULL, 0, "read_file", "{}", NULL, NULL, &verdict);
        assert(d == A2G_DECISION_ERROR && verdict != NULL);
        printf("  NULL trust              → %s  [PASS] (fail-explicit)\n", decision_name(d));
        a2g_verdict_free(verdict);
    }

    /* NULL mandate bytes → A2G_DECISION_ERROR (never crashes, returns error verdict) */
    {
        A2gVerdictHandle *verdict = NULL;
        A2gDecision d = a2g_decide(NULL, 0, "read_file", "{}", NULL, trust, &verdict);
        assert(d == A2G_DECISION_ERROR && verdict != NULL);
        printf("  NULL mandate            → %s  [PASS]\n", decision_name(d));
        a2g_verdict_free(verdict);
    }

    /* Out-of-range gear → NULL state handle (not a crash) */
    {
        A2gVerifiedStateHandle *h = a2g_verified_state_operator_trusted(0.0, 99, 0);
        assert(h == NULL);
        a2g_verified_state_free(h);  /* NULL is safe to pass */
        printf("  gear=99 (invalid)       → NULL state handle  [PASS]\n");
    }

    /* Out-of-range actor → NULL state handle */
    {
        A2gVerifiedStateHandle *h = a2g_verified_state_operator_trusted(0.0, 0, 5);
        assert(h == NULL);
        a2g_verified_state_free(h);
        printf("  actor=5 (invalid)       → NULL state handle  [PASS]\n");
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void) {
    printf("A2G C Integration Example\n");
    printf("=========================\n");

    /* Obtain a test mandate compiled to signed CBOR bytes (ADR-0013).
     * In production, mandates are issued by your trust root (issuer DID),
     * compiled from TOML authoring format to CBOR by `a2g sign`, and loaded
     * from a secure store at agent startup.
     * Free the buffer with a2g_cbor_free(cbor, cbor_len) when done. */
    uint8_t *cbor = NULL;
    uintptr_t cbor_len = 0;
    if (a2g_test_mandate_cbor(&cbor, &cbor_len) != 0 || cbor == NULL) {
        fprintf(stderr, "FATAL: a2g_test_mandate_cbor() failed\n");
        return 1;
    }
    printf("Mandate obtained (%zu bytes)\n", (size_t)cbor_len);

    /* Create a SelfSovereign trust anchor (ADR-0014).
     * In production, use a2g_trust_anchor_roots() with your issuer pubkeys.
     * SelfSovereign is an explicit opt-in for local testing only. */
    A2gTrustAnchorHandle *trust = a2g_trust_anchor_self_sovereign();
    if (trust == NULL) {
        fprintf(stderr, "FATAL: a2g_trust_anchor_self_sovereign() returned NULL\n");
        return 1;
    }
    printf("Trust anchor created (SelfSovereign)\n");

    /* Demo 1: ALLOW */
    demo_allow(cbor, cbor_len, trust);

    /* Demo 2: DENY */
    demo_deny(cbor, cbor_len, trust);

    /* Demo 3: Full dispatch showing all four verdict types.
     *
     * read_file and write_file are both in the standard test mandate's
     * [capabilities].tools, with escalate_tools = [].  All calls below
     * return ALLOW.  For a tool in escalate_tools a real deployment would
     * see PENDING_APPROVAL on the first call (Phase 1), then ALLOW on
     * the Phase 2 call with the approved grant. */
    printf("\n=== Demo 3: Full dispatch pattern ===\n");
    {
        A2gVerifiedStateHandle *state =
            a2g_verified_state_operator_trusted(0.0, 0, 0);
        assert(state != NULL);

        demo_dispatch(cbor, cbor_len, "read_file",  "{}", state, trust);
        demo_dispatch(cbor, cbor_len, "write_file", "{\"path\":\"workspace/output/log.txt\"}", state, trust);

        /* Unauthorized tool — DENY because it is not in the capabilities list. */
        demo_dispatch(cbor, cbor_len, "delete_all_data", "{}", state, trust);

        a2g_verified_state_free(state);
    }

    /* Demo 4: Error paths */
    demo_error_paths(trust);

    /* Free handles in any order. */
    a2g_trust_anchor_free(trust);
    a2g_cbor_free(cbor, cbor_len);

    printf("\nAll demos completed successfully.\n");
    printf("\nNOTE: PENDING_APPROVAL is not triggered in this demo because the\n");
    printf("test mandate has escalate_tools = [].  In production, configure a\n");
    printf("mandate with a tool in both [capabilities].tools and\n");
    printf("[escalation].escalate_tools to exercise the two-phase code path\n");
    printf("shown in demo_dispatch() above.\n");

    return 0;
}
