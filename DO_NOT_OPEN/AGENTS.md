# Network AI Platform Instructions

## 2026-08-15 — Initial project baseline

- Treat this project as a defensive network-security platform. Start with local, synthetic, or explicitly authorized telemetry only.
- Separate collection, detection, evidence storage, analyst review, and any response action. Do not enable automated network enforcement without explicit, scoped approval.
- Keep integrations with Suricata, Zeek, and MikroTik read-only by default; redact credentials and retain provenance for all alerts.
- Validate changes locally and distinguish observed evidence from inferred conclusions.
- Preserve unrelated working-tree changes and avoid destructive commands.

## 2026-08-16 — Authoritative workspace

- `/home/aj/network_ai` is the default and authoritative workspace for this project. Do not update the mirrored `/mnt/c/Users/ajswa/Documents/ChatGPT/network_ai` checkout unless the user explicitly asks.

## 2026-08-16 — Deterministic correlation hardening

- Before introducing ML, prioritize deterministic, fixture-only correlation tests for exact, no-match, ambiguous, insufficient-evidence, duplicate/reordered, clock-quality, malformed/unsupported, and identifying-field-conflict cases. Ambiguous results must retain every eligible evidence reference in a stable order and must never select the first candidate arbitrarily.
- Treat a correlation as evidence linkage only. Do not claim a packet, subscriber, compromise, or causal relationship until a separately implemented and validated identity-correlation phase exists.

## 2026-08-16 — Fixture-only session association

- Phase 2b may use only synthetic, opaque MikroTik session bindings with a declared IP and bounded validity interval. A result may state only that a source IP matched a declared binding at an event time; it must not claim subscriber ownership, identity, causation, or compromise.
- Preserve existing Phase 2a evidence compatibility, keep traffic and session outcomes separate, retain all bounded ambiguous candidates, and require verified fixture coverage before emitting session `no_match`. No live MikroTik reader, credentials, or response path is in scope.

## 2026-08-16 — Temporal session-resolution hardening

- Treat session eligibility as inclusive declared validity bounds at the alert event time. `observed_at` is bounded provenance for a declared synthetic binding and may be later than the anchor; it does not establish a contemporaneous attribution.
- Exercise handover endpoints, gaps, full-window coverage, replay, clock uncertainty, and explicit sensor-map isolation before adding further contextual or ML work. Two or more eligible bindings must remain `ambiguous` with every bounded evidence ID in stable order; never resolve by ingestion order.

## 2026-08-16 — Explicit terminal outcomes

- Every implemented processing attempt must surface a versioned terminal outcome, reason code, evidence reference set, and truthful audit state. Unknown evidence must not become false, and ambiguity must not become a match.
- Keep the data plane fail-visible: retain/quarantine evidence when a durable audit append succeeds; report `persistence_failed` when it cannot be confirmed. Keep authority/enforcement fail-conservative: their vocabularies are contract-only until separately authorized; no executor or router path is in scope.

## 2026-08-16 — Read-only replay traces

- Replay must read one bounded, verified ledger snapshot without recovery, truncation, or source mutation. It may report only durable ledgered outcomes and must name non-durable attempts as an explicit limitation.
- Keep semantic trace identity independent of ledger append order while retaining a distinct checkpoint/index-bound derivation identity. Trace projections may expose opaque evidence IDs, but never raw data, normalized observations, candidate-reference objects, or opaque subscriber/session values.

## 2026-08-16 — Explicit read-only live-flow collection

- The earlier v5/v9/IPFIX wording is superseded because the implemented, validated parser supports NetFlow v9 and IPFIX v10 only. Implement and validate a local, read-only UDP v9/IPFIX receiver with an explicit exporter allowlist and durable, bounded evidence handling; reject v5 visibly rather than claiming support.
- This does not authorize router configuration changes, RouterOS API/SSH access, credentials, public web exposure, Suricata/Zeek live readers, subscriber attribution, ML, or any enforcement/action path. Keep the flow receiver opt-in, default-loopback, rate-bounded, and fail-visible.

## 2026-08-16 09:15 UTC — Deterministic periodic live-flow review

- `periodic-flow.v1` may analyse only bounded, already-persisted NetFlow v9/IPFIX metadata and may emit analyst-review candidates with immutable flow evidence IDs and exporter-reported timing provenance.
- Keep all candidate derivation and persistence deterministic, bounded, and all-or-fail. A capacity or audit failure is an explicit incomplete/unknown result; it must not truncate, silently reuse stale candidates as current, or imply an incident.
- This detector does not authorize ML, attribution, router access, live sensor readers, action, or enforcement. A candidate is not proof of periodic traffic, causation, compromise, identity, or network state.

## 2026-08-16 11:23 UTC — Live-flow snapshot provenance

- A completed live-flow analysis must derive from one explicit, bounded retained-flow snapshot with a persisted source-generation boundary and canonical normalized-input hash. New inserts must not silently change that snapshot; source eviction between derivation and persistence must fail visibly.
- Keep completed analysis snapshots, candidate facts, and their references invalidated atomically whenever pruning removes source-flow evidence. Candidate references and public basis material remain bounded; fan-out summaries may use deterministic representative references only when they carry a full supplied-group digest and say that they are not exhaustive.

## 2026-08-16 11:42 UTC — Completed analysis integrity

- A completed live-flow analysis, including a zero-candidate result, is valid only when the persisted source-generation snapshot and every emitted candidate can be recomputed from retained flow metadata inside the commit transaction. A failed analysis must retain a complete captured snapshot when one exists; otherwise it must state that input is unavailable.
- On storage migration or read, demote an unverifiable completed result to an explicit failed legacy/unknown state rather than displaying it as clean. Do not trust a candidate ID, count, or claimed basis without source-bound validation.
