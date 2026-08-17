# AI Network Security Platform

## Status

Phase 1 is implemented and locally validated with synthetic fixtures. It does not contact a network, store router credentials, deploy rules, load models, or change a MikroTik device.

## Run the working Phase 1 demo

Python 3.10+ is sufficient; the runtime uses only the standard library.

```bash
PYTHONPATH=src python -m network_ai.demo --store /tmp/network-ai-phase1-demo
PYTHONPATH=src python -m unittest discover -v
```

The demo ingests one synthetic Suricata alert, Zeek connection record, and MikroTik telemetry snapshot. The supplied storage path holds restricted raw artefacts and a hash-chained local ledger. On POSIX, the store applies owner-only file modes; Windows deployments need equivalent OS-level ACLs. Re-running the same demo records duplicate deliveries rather than manufacturing new events.

`verify()` detects ledger/raw-artifact inconsistency. For tamper evidence across restarts, persist its `AuditCheckpoint` outside the evidence-store directory and supply it during verification; this local store does not claim WORM storage or protection from an owner who can replace both the store and the external checkpoint.

## Purpose

Combine network telemetry from Suricata, Zeek, and explicitly authorized MikroTik inventory/telemetry into analyst-reviewable evidence. Detection should enrich analyst judgment; it must not turn a score or correlation into a claim of compromise or an automatic network action.

## Reference-project boundary

The supplied repositories are design references only until their licences, maintenance, provenance, and security posture have been separately reviewed.

| Reference                   | Useful lesson                                                 | Explicit exclusion from this platform baseline                                                         |
| --------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `network-anomaly-detection` | Reproducible train/evaluate/predict stages                    | Its dataset, artefacts, pickles, model, and evaluation design are not a production telemetry contract. |
| `suritik`                   | Suricata EVE alert ingestion is a useful adapter shape        | Do not write firewall address lists, hold router credentials, or bypass human approval.                |
| `ProbeManager_Suricata`     | Operations and rule-management workflows can inform future UX | No remote installation, rule deployment, blacklist enforcement, or arbitrary script execution.         |

`Geek` is assumed to mean **Zeek**; confirm this before source-specific adapters are built.

## Architecture

```text
Suricata EVE JSON ─┐
Zeek logs ─────────┼─> bounded adapters ─> immutable evidence store ─>
MikroTik telemetry ┘   (fixture-only)      normalized observations
                                                    │
                                                    v
                                  deterministic correlation + anomaly scoring
                                                    │
                                                    v
                                      analyst cases, decisions, and audit log
                                                    │
                                                    v
                          separate, future response workflow requiring approval
```

Each layer has a distinct responsibility:

- **Evidence** preserves the source record and its acquisition context.
- **Observation** is a versioned, schema-validated normalization of one source record.
- **Correlation** links observations and records rationale, confidence, and uncertainty; it is a hypothesis, not causation.
- **Score** is model output with its model/feature/threshold versions; it is not an alert or enforcement command.
- **Case decision** is an attributable analyst disposition and may provide a governed label later. It is not automatic training truth.

## Mandatory evidence contract

Every observation must retain:

- Stable observation and source-event identifiers.
- Original raw record, or a governed immutable reference, plus SHA-256 hash.
- Source/sensor identity; source, adapter, parser, and schema versions; and acquisition/configuration hash.
- `event_time`, `observed_time`, and `ingested_time`, including timezone, clock quality/skew, and uncertainty/error state.
- A data-classification and redaction status, retention policy, and payload-access policy.

Adapters accept only allowlisted fields and versions. They must impose record-size and rate bounds, validate schemas, handle duplicate/replayed/out-of-order data idempotently, and quarantine malformed or unsupported records. Test fixtures must cover each failure mode.

For MikroTik, the first contract permits only an allowlisted, read-only inventory/telemetry view. Arbitrary configuration exports, secrets, tokens, private keys, and unrelated configuration are out of scope.

## Explicit terminal-outcome invariant

Every implemented processing attempt returns a closed, versioned `stage-outcome.v1` record with a stage, terminal outcome, fixed reason code, sorted evidence references, and an audit-state declaration. It contains no raw payload or exception text. Unknown data never becomes false, and ambiguity never becomes a match.

- **Ingestion:** `accepted`, `duplicate_delivery`, `quarantined`, `unsupported_version`, `malformed`, `rejected`, or `persistence_failed`. A duplicate points to its existing evidence and prior ledger entry. Malformed/unsupported/policy-rejected records are still retained only when a new quarantine ledger entry is confirmed. `persistence_failed` means an audit commit could not be confirmed—not that no partial write exists.
- **Correlation:** `match` (reserved), `probable_match`, `ambiguous`, `no_match`, or `insufficient_evidence`. The current five-tuple/session logic never emits definitive `match`.
- **Analysis, authority, and enforcement:** their closed vocabularies are defined as data contracts only. No model runner, authority evaluator, router request, or enforcement executor exists in this release. A future enforcement `applied` result is valid only with `network_state: confirmed_applied`; `execution_failed` retains `unknown` unless a resulting non-applied state is independently confirmed.

The data/intelligence plane is fail-visible: it preserves durable evidence and makes uncertainty observable. The authority/enforcement plane is fail-conservative: uncertainty about authorization, scope, target state, execution, or rollback must prevent a state transition. Batch ingestion now consumes at most `MAX_BATCH_RECORDS + 1` iterator values; batch-limit and iterator failures return explicit rejected outcomes for only that inspected prefix, and do not persist it. This intentionally replaces the older batch-limit `ValueError` behavior.

`replay-trace.v1` can reconstruct a bounded, read-only outcome trace from one verified local ledger snapshot. Its stable semantic ID ignores append order; its distinct derivation ID binds original ledger indices and checkpoint. The trace projects only fixed outcome metadata, rationales, configuration hashes, and opaque evidence IDs—never source manifests, raw data, normalized observations, full candidate-reference objects, or opaque session/subscriber values. It deliberately covers durable accepted/quarantined ledger entries only: duplicate deliveries, invalid API/batch input rejections, and unconfirmed persistence failures have no durable audit record and are named limitations rather than silently reconstructed. An artifact above the explicit replay artifact cap also returns a visible error while remaining preserved in the source ledger. Replay rejects corruption without ledger recovery or truncation.

## Detection and evaluation rules

1. Establish deterministic correlation and rule-only baselines before ML.
2. Use source- and time-separated, frozen fixtures/data for evaluation. Freeze record and label hashes, feature contract, fitting boundary, seed, model and dependency versions, thresholds, and promotion criteria before looking at held-out results.
3. Report precision at analyst capacity, recall by labelled scenario, false alerts per unit time, PR-AUC, calibration, confidence intervals, and source-ablation results. Do not rely on accuracy or ROC alone.
4. Keep scoring explainable and reversible. A high score creates an analyst candidate only.
5. Never load an untrusted serialized model artefact. Model drift/retraining stays disabled until a later approved governance design exists.

## Delivery sequence

1. **Foundation — complete:** Python package, typed event envelope, synthetic Suricata/Zeek/MikroTik fixtures, strict schema validation, byte- and canonical-hash provenance, owner-only tamper-evident local storage, quarantine, and test suite. No network clients.
2. **Phase 2a — complete:** fixture-only, deterministic Suricata-alert to Zeek-connection correlation. For TCP, UDP, and SCTP it uses a validated exact five-tuple plus an inclusive event-time window, producing evidence-linked `probable_match`, `ambiguous`, `no_match`, or `insufficient_evidence` results from a verified local ledger snapshot. `ambiguous` retains every eligible candidate in stable evidence-ID order; it never selects the first record. An exact five-tuple/time-window result is never proof of traffic identity, compromise, or causation. ICMP/ICMPv6 are intentionally `insufficient_evidence` until a separately versioned identifier/type-code contract exists.

   Phase 2a records a stable `semantic_correlation_id` from sorted evidence and fixed configuration, plus a distinct `derivation_id` bound to the source-ledger checkpoint. Therefore reversing ingestion order preserves the correlation conclusion and semantic ID, while the audit derivation changes to reflect the distinct append history. `no_match` means only that no eligible observation was present in supplied, verified declared-complete fixture coverage; it does not describe all network activity. Input EVE/Zeek format profiles remain `v1`, while new normalized evidence is `observation-schema.v2`; correlate a fresh v2 evidence store rather than mixing it with v1 observations, which are rejected safely. Subscriber ownership identity, DNS/TLS relationships, ML, and all live readers remain pending.

3. **Phase 2b — complete:** fixture-only, deterministic session association. A separate `mikrotik-session-binding.v1` profile accepts only opaque subscriber/session references, an assigned IP, and a bounded declared validity interval. It records a separate session component beside the traffic component: one synchronized, declared IP/time binding is `probable_match`; overlapping bindings are `ambiguous`; `no_match` requires verified complete fixture coverage. The result exposes only session evidence IDs, never the opaque subscriber or session references. It means “source IP matched a retrospectively declared session binding at the alert event time,” not a contemporaneous subscriber attribution, ownership, identity, causation, or compromise. Existing v2 traffic evidence remains valid; the session profile has its own adapter/schema versions.

   Session eligibility is exactly `valid_from <= Suricata anchor event_time <= valid_until`, including both endpoints. A binding's `observed_at` is bounded acquisition provenance and may be later than an older anchor in these synthetic fixtures; it is not an alternate join key or a claim that the association was known in real time. More than one eligible binding is always `ambiguous`, with all eligible evidence IDs retained in stable order. A `no_match` says only that the supplied, verified fixture coverage contained no eligible declared binding for the full traffic window. It does not rule out network activity, pre/post-NAT differences, dynamic-IP reuse outside the supplied evidence, or real subscriber ownership. DNS/TLS, asset/subscriber context, historical behaviour, ML, live readers, and enforcement remain pending.

Run the synthetic Phase 2a/2b demo against a fresh directory:

```bash
PYTHONPATH=src python -m network_ai.demo --store /tmp/network-ai-phase2b-v3-demo
```
4. **Experiment:** sealed anomaly-detection evaluation alongside rule-only baseline; preserve raw trajectories and negative results.
5. **Analyst experience:** the ReactPy-Django app under `user_interfac/` is a read-only Kibana-style shell. It queries already-persisted local evidence, derived correlations, process health, and an optional local flow store. It does not tail live Suricata/Zeek logs, open MikroTik, start a collector, or deploy signatures.
6. **Later, separately authorized integration:** read-only collectors for named, owned sources. Any response connector needs its own authority decision, credentials boundary, monitoring, stop conditions, and rollback plan.

## Acceptance gates for the first implementation

- Golden schema/normalization tests and hostile-input fixtures pass.
- Re-ingestion, reordering, and duplicate tests are deterministic.
- Provenance hashes and redaction/access-control behaviour are verified.
- CI proves fixture-only operation and absence of network/router client use.
- The experiment is reproducible from frozen inputs and does not claim real-world detection without validation evidence.

## Authority record

- **Approved:** this planning artifact, the local-only foundation, and an explicitly configured, read-only NetFlow v9/IPFIX listener for authorized router exports.
- **Not approved:** router access/configuration changes, credentials/secrets, Suricata rule deployment, automated or manual router change execution, or claims about real incident detection.
- **Rollback:** delete only generated local development artefacts under a later explicitly approved change; this baseline itself makes no external changes.

## Flow-analysis POC authority record

The NetFlow v9/IPFIX POC is a separate, read-only capability. Its `demo` mode uses only synthetic binary datagrams. Its UDP listener defaults to literal loopback (`127.0.0.1`) for local testing; it is not started automatically.

Non-loopback collection is code-gated and must be an explicitly authorized operator action. It requires a literal bind address and port, `--allow-nonloopback`, a host-only exporter CIDR (`/32` or `/128`), and finite duration/datagram caps. Wildcard and DNS binds are rejected. UDP source allowlisting is traffic filtering, not cryptographic exporter authentication.

### Run the POC

```bash
PYTHONPATH=src python -m network_ai.flow_poc demo --database /tmp/network-ai-flow-poc
PYTHONPATH=src python -m network_ai.flow_poc dashboard --database /tmp/network-ai-flow-poc
```

For the authorized MikroTik v9 export already targeting this collector, start the listener in one terminal:

```bash
PYTHONPATH=src python -m network_ai.flow_poc listen \
  --database /tmp/network-ai-router \
  --host 192.168.22.100 --port 2055 \
  --allow-nonloopback \
  --exporter-allowlist 192.168.22.250/32 \
  --duration-seconds 300 --max-datagrams 3000
```

Then, in a second terminal, view the local-only dashboard:

```bash
PYTHONPATH=src python -m network_ai.flow_poc dashboard --database /tmp/network-ai-router
```

The collector supports NetFlow v9 and IPFIX v10 only; NetFlow v5 is explicitly unsupported. It validates templates before flow data, accepts bounded options-template metadata, ignores matching options data as an explicit completeness warning, and never turns options data into a flow or detector input. The dashboard binds to `127.0.0.1` only and reads the local SQLite store; it is not a direct traffic feed. Its Start/Stop collector controls own one bounded local collector lifecycle and accept the same literal bind, host-only exporter allowlist, duration, and datagram limits enforced by the CLI; stopping the dashboard also stops its collector. It displays candidates only while an active collector has persisted flow data within two minutes and analysis has caught up to that latest flow; it hides historical stored analyses rather than presenting snapshots as live. Its local signature catalog supports add, edit, remove, enable/disable, JSON import updates, and JSON download, but it does not deploy a signature to Suricata or any network device. The exact profile is in `flow_poc_profile.json`; enterprise fields, variable-length fields, malformed/unknown options data, packet payloads, router actions, and automatic response are rejected or absent.

Run an explicit bounded detector pass when needed:

```bash
PYTHONPATH=src python -m network_ai.flow_poc analyze --database /tmp/network-ai-router
```

Both automatic and explicit analysis write a bounded local analysis-run record when storage is available. The record may be associated with the collection run that triggered it, but its input is the bounded retained-flow snapshot and can include evidence from earlier retained collections. The dashboard never borrows an older or unbound analysis result to describe a newer run, and labels the snapshot scope accordingly. When bounded collection retention removes an old run, its dependent analysis records are removed in the same local transaction. A failed detector pass, an unavailable analysis audit, or an unconfirmed collection terminal state is shown as degraded/unknown; it is never presented as a clean zero-candidate result. A listener exits successfully only after its collection-run terminal state is durably written and its automatic analysis has no visible failure.

The current detector set is deterministic and analyst-review only. Alongside threshold candidates, `flow-rate-baseline.v1` compares a source/session/protocol five-minute window against the three immediately preceding contiguous retained windows. It emits a candidate only when the current window contains at least ten supplied flows and meets or exceeds three times the median prior-window count; a gap in the required history produces no candidate rather than a stale baseline. It retains up to 64 deterministic current-window references plus a digest of the full supplied group. `periodic-flow.v1` evaluates every contiguous, exporter-reported four-flow window for the same allowlisted exporter session, source IP, destination IP, destination port, and TCP/UDP/SCTP protocol. Source ports must be valid but are intentionally excluded from the grouping key so ordinary ephemeral-port churn does not hide a cadence. It uses only strictly increasing `flow_end_time` values, a bounded 30-second to one-hour interval policy, and inclusive integer-microsecond tolerance; missing, invalid, unordered, non-port-bearing, or unsupported-protocol records are ineligible. A completed analysis covers the complete retained repository up to the hard 100,000-flow limit, rather than silently choosing a partial recent slice. Its versioned input manifest records a source-generation boundary, row count, and canonical normalized-input hash; commit revalidates that exact boundary so concurrent inserts are excluded and concurrent pruning fails visibly. A successful snapshot may persist up to 5,000 immutable candidate facts; exceeding that capacity is a visible incomplete analysis, never a truncated result. A candidate retains bounded evidence references and a deterministic timing or baseline basis. It is evidence for analyst review, not proof of anomalous network activity, causation, compromise, subscriber identity, or network state.

Successful detector outputs are represented as immutable candidate facts mapped to one bounded analysis snapshot. A completed result, including a zero-candidate result, is committed only after its input manifest and every candidate fact are recomputed from the retained source-flow metadata in the same write transaction. Fan-out candidates retain at most 64 deterministic representative references (one per destination) plus a full supplied-group digest and count; they never imply that the displayed references enumerate every contributor. The dashboard and `/api/candidates` expose candidates only when the active collector is fresh and analysis has caught up; stored historical candidates remain hidden from the live view. A failed or unavailable pass leaves the current state explicitly unknown rather than displaying retained historical facts as a clean result. On open, an old, malformed, or unverifiable completed snapshot is demoted to an explicit legacy/unknown failure. Pruning source evidence invalidates completed snapshots and candidate facts atomically. Manual `analyze` binds its snapshot to the latest recorded collection run when one exists; an unconfirmed collection terminal state remains visibly unhealthy. No ML, live Suricata/Zeek ingestion, MikroTik session attribution, router action, or enforcement is included.
