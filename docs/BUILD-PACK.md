# A2G Product Sprint — Build Pack v2.1

Repo-resident edition. Commit this file as `docs/BUILD-PACK.md`.

**Status at time of writing:** `main` carries v0.2.0 (frozen protocol) + S1
(cockpit domains, ADR-0018). S2 (MCP proxy) and S5 (QNX build) are launched
in parallel sessions. Remaining tasks in this pack: S3, S4, S6, S7.

## Operating model (proven over PR #29/#30)

- **One task per Claude Code session, one PR per task, base branch `main`.**
- The session prompt is one line:
  `Read docs/BUILD-PACK.md. Execute task S<N> only, with the standing preamble. Do not stop until every acceptance criterion passes. Open one PR against main. Do not start any other task.`
- The human review gate between sessions is non-negotiable. Review asymmetry:
  line-by-line for anything touching `decide()`, the classifiers, the FFI,
  or gateway verification (S3); skim-level for docs and packaging (S6, S7).
- Claude Code's commit messages and checklists are claims, not evidence.
  The five standard commands are run by the human before any box is ticked.
- No release tags inside feature PRs. Merge → CI green on main → tag later.
- Deviations from a task spec are allowed only in the fail-closed direction,
  and must be recorded in the task's ADR as an open question (precedent:
  ADR-0018 items 4 and 5).

---

## Standing preamble (prepend to every task prompt)

```text
You are working on a2g-cli (Rust workspace: a2g-core, a2g-cli, a2g-ffi,
a2g-gateway, a2g-demo, a2g-conformance), at v0.2.0 + S1 with a FROZEN
protocol: canonical CBOR signed payloads (ADR-0011/0013), A2gError
(ADR-0012), issuer TrustAnchor (ADR-0014), gateway binding-key custody
(ADR-0015), gateway-side SocketCAN state ingestion with fail-closed
staleness (ADR-0016), actor-zone Comfort gating (ADR-0017), cockpit
domains comms.*/pay.*/pii.* with the pii.grant reserved sentinel
(ADR-0018, SPEC §3.6), length-prefixed CBOR transport (64 KiB max),
persisted pending queue + nonce high-water mark, 77+ deterministic
conformance vectors (now_ms injected-clock schema), and a 15+-attack
adversarial CI suite. Later ADRs may exist — read the ADR index and
CHANGELOG [Unreleased] to learn the true current state before assuming
this paragraph is complete.

Before writing code: read SPEC.md (normative), CHANGELOG.md, and every
ADR your task touches. Where code and spec conflict, the spec wins.

HARD RULES:
- decide() stays pure: no I/O, no wall clock, no floats, deny-by-default.
- The Forbidden pre-checks (vehicle + cockpit) stay structurally first.
  Never reorder them.
- The protocol is FROZEN: existing signed payload layouts, the CBOR frame
  format, and existing verdict semantics MUST NOT change. New capability
  namespaces and message types are ADDED via the documented extension
  mechanisms only. If a task seems to require breaking the freeze, STOP
  and write the trade-off into the ADR for human decision.
- Fail-closed on every ambiguity: unknown namespace, unmapped tool,
  missing data, unrecognized field => DENY or Sensitive-with-HITL,
  never warn-and-proceed.
- No new a2g-core dependencies without written justification (no_std goal).
- Every behavioral change ships with: tests, conformance vectors where
  verdict behavior is affected, a CHANGELOG entry, and an ADR for any
  design decision.
- Done means, run locally with output shown:
  cargo test --workspace
  cargo clippy --all-targets -- -D warnings
  cargo fmt --check --all
  cargo run -p a2g-conformance
  cargo test -p a2g-gateway --test adversarial
- Base branch: main. Branch from fresh main. Open the PR against main.
```

---

## S2 — MCP governance proxy  [LAUNCHED — recorded for reference]

```text
[standing preamble]

SCOPE: Execute task S2 ONLY, on branch feat/s2-mcp-proxy. One PR.

TASK S2 — New crate a2g-mcp-proxy: a Model Context Protocol server that
wraps any downstream MCP tool server and forces every tool call through
A2G governance. Write the ADR first (next free number).

1. Config (TOML, authoring-side only — never signed): downstream server
   command/args, mandate CBOR path, gateway socket path, TrustAnchor
   source, and a tool-name => capability mapping table. Default rule:
   any UNMAPPED tool => Sensitive-with-HITL, fail-closed. Mapping may
   target VHAL names or cockpit namespaces (comms./pay./pii.).
2. Flow per MCP tool call: map tool => capability; a2g-core decide()
   with mandate + TrustAnchor; on ALLOW, present the receipt to the
   gateway ENFORCE over the CBOR-framed socket; ONLY on gateway accept,
   forward downstream and return the result with the receipt id in
   response metadata. On DENY/ESCALATE return a structured MCP error
   with the machine reason code and human-readable text. The downstream
   server must never see a denied call.
3. ESCALATE => MCP error instructing retry-after-approval, including
   the binding id. No approval UI in this task.
4. Transport: stdio MCP only; trait seam for HTTP/SSE later, unimplemented.
5. Ship with: demo config wrapping a trivial echo MCP server that logs
   every call; e2e tests proving (a) allowed call passes with receipt
   metadata, (b) denied call and unapproved pay.* call produce ZERO
   downstream log entries, (c) unmapped tool is not forwarded; README
   with a 10-minute quickstart.
6. The proxy runs rich-domain — state that in the ADR trust notes (it
   can lie; the gateway remains the enforcement point).
7. CHANGELOG (Added). No changes to existing crates except justified
   pub re-exports.

DONE: five standard commands green, e2e tests green, quickstart works
from a clean clone, outputs pasted into an honestly ticked test plan.
```

## S5 — QNX gateway build  [LAUNCHED — recorded for reference]

```text
[standing preamble]

SCOPE: Execute task S5 ONLY, on branch feat/s5-qnx-build. One PR.

TASK S5 — Make a2g-gateway and a2g-core compile cleanly for QNX 8.0
(target aarch64-unknown-nto-qnx800 or nearest available — document
which), behind cfg gates, zero Linux regressions. ADR first.

1. Dependency audit table in the ADR. SocketCAN isolated behind the
   platform seam; QNX stub reader reports permanently-stale =>
   FAIL-CLOSED (reader_active semantics preserved). Trait-impl skeleton
   for real QNX CAN drivers (dev-can-*), doc-commented.
2. Unix-socket transport: verify QNX portability or cfg-gate with a
   loopback-only TCP dev-tier listener, OFF by default, documented.
3. docs/qnx-integration.md: toolchain setup, what compiles, what is
   stubbed and why, hypervisor attachment notes (guest<->host
   vdev/vsock). Honest about anything untested on real hardware.
4. CI: QNX build/check job; if SDP licensing prevents real builds,
   cargo check with the public toolchain and document the limitation —
   never fake a green badge.
5. Linux behavior byte-identical: full suite passes, adversarial
   untouched.

DONE: five standard commands green on Linux; QNX check clean for
a2g-core + non-Linux-gated gateway modules; ADR + doc complete;
honestly ticked test plan.
```

---

## S3 — Kotlin SDK over the FFI (the AAOS developer surface)

```text
[standing preamble]

SCOPE: Execute task S3 ONLY, on branch feat/s3-kotlin-sdk. One PR.
Review note for the human: this task touches the FFI trust boundary —
it receives the line-by-line review tier.

TASK S3 — Create sdk/android/: a Kotlin library wrapping a2g-ffi for
AAOS app developers, plus a GovernedCarClient sample. ADR first.

1. Gradle module (AGP, Kotlin, minSdk 29, AAOS-compatible) packaging
   aarch64 + x86_64 builds of a2g-ffi via cargo-ndk. Build documented
   in sdk/android/README.md; CI cross-build job added.
2. API surface (idiomatic Kotlin, no leaked C types):
   A2g.init(mandateCbor: ByteArray, trustAnchor: TrustAnchor)
   A2g.decide(tool: String, paramsJson: String): Verdict
   Verdict sealed class: Allow(receipt) / Deny(reasonCode, humanText) /
   Escalate(binding) — reason codes as an enum mirroring the Rust side,
   generated or asserted-in-sync by a test so they cannot drift.
   GatewayClient over the CBOR-framed Unix socket, behind a pluggable
   transport interface (vsock later).
3. Sample module: GovernedCarClient wrapping CarPropertyManager so
   calls like setHvacTemperature() run decide()+enforce internally and
   on Deny return the human text suitable for assistant speech. Demo
   activity with three buttons (climate / window-at-speed / cruise)
   showing ALLOW / DENY / structurally-REFUSED visually, plus one
   cockpit button (send SMS => Escalate path).
4. Verdict reason code => user-facing string map in strings.xml; the
   code=>string contract documented for OEM localization.
5. Tests: host (x86_64) JNI round-trip unit tests; instrumentation
   stubs. DO NOT weaken the FFI: ADR-0015 NULL-pubkey fail-explicit
   behavior must surface as a thrown exception, never a default. The
   pii.grant reserved-name rule (SPEC §3.6.3) must hold through the
   SDK: a test proves A2g.decide("pii.grant", ...) is refused.

DONE: five standard Rust commands green (workspace untouched except
justified ffi additions); ./gradlew :sdk:assemble + sample build in CI;
host unit tests green; README quickstart takes an AAOS dev from clone
to first DENY on the emulator in under 30 minutes.
```

## S4 — The HMI demo (record THIS, not the terminal)

```text
[standing preamble]
Depends on S3 — read sdk/android/ first. If S3 is not yet on main, STOP.

SCOPE: Execute task S4 ONLY, on branch feat/s4-cockpit-demo. One PR.

TASK S4 — Build demo/aaos-cockpit/: an AAOS-emulator demo app that
makes governance visible and emotionally legible.

1. A scripted in-cabin assistant screen (text input + canned replies,
   no real LLM): "set temperature to 22", "open my window" (sim at
   60 km/h), "disable cruise control", "text my wife I'm late",
   "pay for parking".
2. Each intent runs through the S3 SDK. UI behavior:
   ALLOW => action animates + green receipt chip.
   DENY => assistant SPEAKS the human reason via TTS ("I can't open
   the window while we're moving") + amber chip with reason code.
   ESCALATE => approval bottom-sheet, clearly watermarked DEMO-TIER UI
   with a comment referencing the trusted-UI production requirement.
   Forbidden => red chip "structurally refused — not even verified".
3. Receipt viewer screen: live list of signed verdicts (id, tool,
   decision, reason, chain position); tapping shows the canonical
   payload fields. This is the explainable-refusal money shot.
4. Vehicle-state banner bound to the state simulator: shows the
   gateway-believed speed/gear, with a control to change sim speed so
   the SAME request flips ALLOW<->DENY live.
5. demo/aaos-cockpit/DEMO-SCRIPT.md: a 4-minute recording script —
   climate allow -> window denied with spoken reason -> cruise
   structurally refused -> SMS escalate + approve -> payment HITL ->
   receipt viewer finale.

DONE: runs on the public AAOS emulator image; the script executes end
to end; a stranger can reproduce the recording from the README; five
standard Rust commands untouched-green.
```

## S6 — Commercial hygiene bundle

```text
[standing preamble]

SCOPE: Execute task S6 ONLY, on branch feat/s6-commercial-hygiene.
One PR. No behavior changes anywhere — the test suite must pass
byte-identically.

TASK S6 — Productize the repo surface.

1. SECURITY.md: coordinated disclosure policy, contact, 90-day window,
   scope (trust-property breaks, payload forgery, gate bypasses).
2. Benchmark harness: benches/ measuring (a) decide() p50/p99,
   (b) the full governance hop decide+gateway-verify over the socket,
   on x86, with a documented procedure for the Raspberry Pi as the
   SA8155-class stand-in. Output a markdown report; commit
   docs/BENCHMARKS.md with methodology + first numbers. Claim format:
   "governance hop p99 < X ms — Y% of a 250 ms voice budget".
3. README rewrite for buyer personas: four entry doors at the top
   (AAOS dev -> sdk/android, AI team -> a2g-mcp-proxy, platform
   integrator -> QNX/Pi docs, safety manager -> assurance kit). Move
   protocol internals below the fold.
4. Apply the LICENSE decision recorded in this pack's founder
   checklist (headers, LICENSE, NOTICE); CONTRIBUTING.md gets a
   DCO note consistent with open-core.
5. docs/adopter-notes/ index: one-pagers for each deferred-to-adopter
   item (hypervisor bring-up, HSM provisioning, trusted approval UI,
   real AUTOSAR E2E profiles) — what, why deferred, integration contract.

DONE: repo reads as a product in 90 seconds; benchmarks reproducible
via one command; zero behavioral diffs; five standard commands green.
```

## S7 — Assurance Kit v1 (SKU #2)

```text
[standing preamble]
Documentation task. Read SPEC.md, ALL ADRs, the adversarial test file,
and the conformance vector layout before writing anything.

SCOPE: Execute task S7 ONLY, on branch feat/s7-assurance-kit. One PR.
Every file carries a "DRAFT — REQUIRES DOMAIN REVIEW" banner.

TASK S7 — Assemble assurance-kit/:

1. threat-model.md: STRIDE over the receipt protocol, key lifecycle,
   HITL channel, state ingestion, and the cockpit extension; each
   threat mapped to its mitigating mechanism AND its adversarial test
   id or vector id; residual risks stated honestly (including the
   ADR-0018 pii-gated-reads residual) — structured to feed an
   ISO 21434 TARA.
2. safety-concept-template.md: the domain model (vehicle four-domain +
   cockpit namespaces) as a derivable template with placeholders for
   an OEM item definition and HARA; the forbidden-independence
   argument written out; explicit assumptions-of-use (the SEooC seed).
3. conformance-statement.md: what Level 1/2/3 mean, current level with
   evidence pointers (vector counts, attack count, CI links).
4. evidence-map.md: a table from every claim A2G makes (deny-by-default,
   replay-proof, fail-closed staleness, forbidden-first, always-HITL
   payments, reserved-sentinel enforcement...) to the exact test,
   vector, or ADR that substantiates it. This table IS the product.
5. A 2-page executive brief (pdf-able markdown): the chief-engineer-
   meeting answer — what breaks without governance, what A2G
   guarantees, what remains the OEM's job.

DONE: internally consistent with SPEC/ADRs — no claim without an
evidence pointer; DRAFT banners everywhere; an index README sequencing
the kit for a safety-manager reader; five standard commands green
(nothing executable changed).
```

---

## Founder checklist (human-only, ~1 hour total)

1. **Name** — decide before S6 applies it. Candidates: keep **A2G** as
   protocol name with Vanaras as vendor brand (Kubernetes pattern);
   **Veto** as the product-name alternative. Check collisions.
2. **License** — recommendation: **Apache-2.0** for core, spec,
   conformance, SDK, proxy (patent grant matters to automotive legal).
   Assurance Kit and QNX/hypervisor hardening guides stay commercial.
   Record the decision here when made: ____________
3. **Publishing cadence** — 1 hr/week, non-negotiable: (a) v0.2.0 tag +
   changelog post, (b) terminal adversarial demo recording
   (state_authority_mismatch on screen), (c) S4 cockpit recording,
   (d) benchmark page, (e) assurance-kit executive brief. One artifact
   per fortnight, posted once. Inbound replies are the only metric.

## Sequence and dependencies

S2 + S5 in flight now (parallel-safe). Then S3 (after S2/S5 merge, from
fresh main) → S4 (hard-depends on S3) → S6 + S7 (parallel-safe, S7 best
last so it documents everything). Review gate between every pair. The
90-day exit state: four entry doors, two recorded demos, a benchmark
number, a draft assurance kit — and a repo that reads like a vendor.
