# Network Intelligence Abstraction and Closed-Loop Control Framework Specification

**Version:** 0.2
**Status:** Architecture and implementation-boundary specification
**Current authority:** Local deterministic intelligence foundation plus separately authorized bounded read-only NetFlow/IPFIX proof of concept
**Future authority:** Explicitly not granted by this specification

---

# 1. Purpose

Modern networks generate more raw telemetry than a general-purpose AI model can use efficiently or reliably.

At one extreme, raw packet and flow telemetry is:

* extremely high volume;
* repetitive;
* fragmented across sensors;
* time-sensitive;
* low-level;
* expensive to place into model context.

At the other extreme, conventional IDS alerts are often too narrow:

```text
ET MALWARE Possible C2
```

Such an alert may indicate something important but usually does not independently establish:

* which network session was involved;
* whether multiple sensors observed the same or related activity;
* whether the behaviour is historically unusual;
* whether the destination is new;
* whether similar behaviour exists elsewhere;
* whether identity evidence is ambiguous;
* what uncertainty remains.

The purpose of the **Network Intelligence Abstraction Layer** is to convert raw observations into compact, deterministic, evidence-linked network intelligence before probabilistic AI reasoning is introduced.

The central principle is:

> **Raw telemetry is optimized for measuring networks. Structured intelligence is optimized for reasoning about networks.**

---

# 2. Mandatory Scope Separation

This specification deliberately separates:

1. **implemented and authorized capability now;**
2. **next gated development capability;**
3. **future architecture requiring separate authorization.**

Conceptual future architecture must never be interpreted as permission to implement or deploy it.

---

# 3. Implemented and Authorized Now

The currently implemented and authorized project boundary is intentionally narrow.

## 3.1 Local deterministic foundation

Currently permitted:

* synthetic Suricata fixtures;
* synthetic Zeek fixtures;
* synthetic MikroTik/session fixtures;
* typed evidence contracts;
* schema validation;
* deterministic normalization;
* immutable/canonical evidence hashing;
* local evidence persistence;
* duplicate-delivery detection;
* replay/idempotency testing;
* explicit stage outcomes;
* five-tuple evidence correlation;
* temporal session-association logic;
* ambiguity preservation;
* no-match outcomes;
* insufficient-evidence outcomes;
* provenance and audit validation;
* local deterministic tests.

---

## 3.2 Separately authorized NetFlow/IPFIX proof of concept

A bounded read-only NetFlow/IPFIX proof of concept may operate only according to its explicit authorization boundary.

It must remain:

* read-only;
* bounded;
* explicitly configured;
* non-enforcing;
* non-authoritative;
* incapable of router changes.

Any broader live telemetry collection requires separate authorization.

---

# 4. Explicitly Not Implemented or Authorized

The following capabilities are **not authorized by this specification**:

* live Suricata collection;
* live Zeek collection;
* live RADIUS collection;
* live subscriber-database access;
* arbitrary MikroTik telemetry access;
* MikroTik credentials;
* RouterOS write access;
* automated router changes;
* manual router changes through this platform;
* production firewall-rule deployment;
* Suricata rule deployment;
* ML-based production classification;
* AI reasoning in production;
* model-driven authority evaluation;
* automatic model retraining;
* automatic rule generation and deployment;
* subscriber quarantine;
* address-list modification;
* rate-limit modification;
* PPPoE session termination;
* route modification;
* path optimization;
* AI-SDN;
* self-healing execution;
* autonomous production changes.

These may appear later in this document only as **future conceptual capabilities**.

Their presence does not grant implementation authority.

---

# 5. Current System Model

The currently authorized operating model is:

```text
Synthetic / explicitly authorized
read-only observations
          │
          ▼
      Validation
          │
          ▼
       Evidence
          │
          ▼
Deterministic correlation
          │
          ▼
Explicit relationship outcome
          │
          ▼
Analyst-readable intelligence
```

There is currently no authorized path from derived intelligence to network modification.

---

# 6. Architectural Philosophy

The intended long-term architecture separates six responsibilities:

```text
Sensors
   ↓
Evidence
   ↓
Intelligence
   ↓
Reasoning
   ↓
Authority
   ↓
Execution
```

However, only the upper portion is currently authorized.

```text
CURRENT PROGRAM
──────────────────────────

Sensors / fixtures
        ↓
Evidence
        ↓
Deterministic intelligence


FUTURE PROGRAM
SEPARATE AUTHORIZATION REQUIRED
══════════════════════════════════

AI reasoning
        ↓
Authority
        ↓
Execution
        ↓
Network feedback
```

---

# 7. Sensors

Sensors observe network state.

Potential sensor classes include:

* NetFlow/IPFIX;
* Suricata;
* Zeek;
* RADIUS;
* DHCP;
* MikroTik telemetry;
* SNMP;
* LLDP;
* RF telemetry;
* power telemetry.

Only explicitly authorized sources may be connected.

No source becomes authorized merely because it is listed here.

---

# 8. Evidence

Evidence preserves what was actually observed.

Evidence must remain separate from interpretation.

Every accepted evidence object should retain, where applicable:

* stable evidence ID;
* source-event ID;
* source type;
* sensor identity;
* event timestamp;
* observed timestamp;
* ingestion timestamp;
* timezone;
* clock-quality state;
* clock uncertainty;
* parser version;
* adapter version;
* schema version;
* acquisition/configuration hash;
* immutable raw record or governed reference;
* SHA-256;
* classification;
* redaction state;
* retention policy.

Evidence does not silently change.

Derived interpretations may evolve.

---

# 9. Intelligence

The intelligence layer converts evidence into explicit relationships and state abstractions.

It may perform:

* normalization;
* five-tuple extraction;
* temporal alignment;
* session association;
* relationship derivation;
* aggregation;
* feature calculation;
* ambiguity detection;
* state summarization.

This layer should remain deterministic wherever practical.

---

# 10. Reasoning

Future AI reasoning will consume structured intelligence rather than uncontrolled raw telemetry.

The reasoning layer may eventually:

* compare explanations;
* rank hypotheses;
* identify missing observations;
* propose additional analysis;
* propose candidate rules;
* propose operational changes.

It must not silently convert a hypothesis into network authority.

---

# 11. Authority

Future consequential actions require a separate authority subsystem.

The authority subsystem does not currently exist.

When eventually authorized, its job will be to determine:

> **What proposed action is permitted?**

rather than:

> **What does the model want to do?**

---

# 12. Execution

Execution is a future capability inspired conceptually by previous controlled network-response work.

Execution currently exists only as vocabulary and architectural intent.

No current executor may:

* log into routers;
* store production router credentials;
* create firewall rules;
* remove firewall rules;
* alter routes;
* terminate sessions;
* change queues;
* modify customer state.

---

# 13. Information Reduction Principle

The intelligence layer acts as a controlled information bottleneck.

Its goal is to transform:

```text
millions of low-level observations
```

into:

```text
a smaller set of meaningful state changes
and evidence-linked relationships
```

without destroying traceability.

The reduction may discard:

* duplicated observations;
* repeated stable state;
* serialization differences;
* irrelevant formatting;
* redundant packet-level detail.

It must preserve:

* timing;
* identity references;
* relationships;
* behavioural changes;
* uncertainty;
* disagreements between sensors;
* evidence provenance.

---

# 14. Raw Telemetry Is Not the AI Interface

The AI reasoning layer should not normally receive thousands of raw flows or packet records.

For example, instead of:

```text
40,000 flow records
```

the intelligence layer may eventually produce:

```text
subject_ref: sub_7f2a
window: 19:20–19:25

flow_count: 4812
baseline_flow_count: 310 ± 84
new_destinations: 147
new_asns: 24
egress_dominant_flows: 96%
periodic_flow_candidate: present
period_estimate: 59.8s
unseen_ja4_count: 3
suricata_relationships: 4
zeek_relationships: 11

session_relationship: probable_match
payload_visibility: unavailable
application_attribution: insufficient_evidence
```

The original evidence remains separately retrievable under appropriate authorization.

---

# 15. Explicit Stage Outcome Contract

Every stage must terminate in a defined, observable outcome.

No silent failure is permitted.

Possible outcome classes include:

```text
accepted
duplicate_delivery
quarantined
malformed
unsupported_version
rejected
persistence_failed

probable_match
ambiguous
no_match
insufficient_evidence

analysis_failed
```

Future stages may introduce additional outcomes only through a versioned contract.

---

# 16. Failure Philosophy

The platform follows two distinct failure principles.

## Intelligence/data plane

**Fail visible.**

If evidence is incomplete:

* preserve what is valid;
* represent uncertainty;
* expose the failure;
* do not invent missing information.

## Future authority/execution plane

**Fail conservative.**

If authorization, target identity, resulting state, or rollback is uncertain:

* do not expand authority;
* do not silently proceed.

---

# 17. Unknown Must Remain Unknown

The system must never silently transform missing information into a negative fact.

Example:

```text
timestamp missing
      ↓
insufficient_evidence
```

not:

```text
timestamp missing
      ↓
assume current time
```

Likewise:

```text
no Zeek evidence available
```

must not automatically mean:

```text
Zeek confirms nothing happened
```

---

# 18. Ambiguity Must Remain Ambiguity

The system must never select a candidate solely because it appears first.

Example:

```text
two valid session bindings
         ↓
      ambiguous
```

not:

```text
two valid session bindings
         ↓
choose first record
```

Record ordering must never become an undocumented decision rule.

---

# 19. Correlation Contract

Correlation links evidence.

Correlation does not establish causation.

A relationship may terminate as:

* `probable_match`;
* `ambiguous`;
* `no_match`;
* `insufficient_evidence`.

The objective is **deterministic relationship evaluation**, not forced convergence.

---

# 20. Multi-Source Relationship Model

The next multi-source objective must not be described as:

```text
SAME NETWORK EVENT
```

Instead:

```text
NetFlow ───┐
Suricata ──┤
Zeek ──────┼─► evidence-linked relationship evaluation
Session ───┘
                    │
                    ▼
           probable_match
           ambiguous
           no_match
           insufficient_evidence
```

The deterministic property is:

> **The same evidence and versions must reproduce the same relationship outcome.**

It is not:

> **All sources must collapse into a single event.**

---

# 21. Correlation Identity and Derivation Identity

Derived relationships should distinguish:

## Correlation identity

Represents the semantic relationship being evaluated.

## Derivation identity

Represents how that relationship was produced from:

* evidence set;
* rule version;
* configuration;
* timing contract;
* derivation logic.

This permits future derivation logic to change without rewriting evidence history.

---

# 22. Temporal Session Association

Session association must be based on explicitly declared temporal validity.

The system must distinguish:

```text
observed_at
```

from:

```text
valid_from / valid_until
```

`observed_at` is provenance.

The validity interval defines when the supplied binding claims to have applied.

Retrospective association is permitted in fixtures.

It must not be described as contemporaneous knowledge.

---

# 23. Temporal Uncertainty

Clock quality must affect interpretation.

Example policy classes may include:

```text
good
degraded
unknown
```

If uncertainty produces multiple valid candidates:

```text
ambiguous
```

If uncertainty prevents useful resolution:

```text
insufficient_evidence
```

The system must not use hidden nearest-time heuristics to manufacture certainty.

---

# 24. Replay and Idempotency

Repeated delivery of identical evidence must not create a new logical world state.

Expected progression:

```text
first delivery
      ↓
accepted
      ↓
audit written


repeat delivery
      ↓
duplicate_delivery
      ↓
preexisting evidence referenced
```

Repeated replay should reproduce the same semantic relationships.

---

# 25. Deterministic Replay Requirement

For a frozen evidence set:

```text
same evidence
+
same schema versions
+
same adapter versions
+
same correlation contract
+
same configuration
        ↓
same deterministic outcome
```

This requirement applies to all deterministic stages.

---

# 26. NetFlow/IPFIX Intelligence

NetFlow/IPFIX provides a useful behavioural representation.

Typical information includes:

```text
source
destination
source port
destination port
protocol
start/end time
packets
bytes
direction
```

Derived deterministic features may include:

* destination fan-out;
* source fan-in;
* byte ratio;
* packet ratio;
* connection rate;
* duration;
* periodicity;
* new destination count;
* new port usage;
* flow asymmetry.

A derived feature remains an observation, not a malware verdict.

---

# 27. Behavioural Asymmetry

Example:

```text
outbound_bytes = 800 MB
inbound_bytes  = 10 MB
```

may derive:

```text
egress_ratio = 80:1
```

Possible interpretations include:

* CCTV;
* backup;
* upload;
* proxyware;
* spam;
* exfiltration;
* malware.

The deterministic layer should represent:

> **high-egress / low-return behaviour**

not:

> **malware**

unless stronger evidence exists under a future validated classifier.

---

# 28. Future Suricata Integration

Live Suricata ingestion is not currently authorized.

When separately approved, it should begin as:

* read-only;
* bounded;
* named sensor only;
* explicit EVE schema versions;
* no rule deployment;
* no IPS action;
* no remote installation;
* no router interaction.

Suricata observations may eventually add:

* alerts;
* protocol metadata;
* TLS metadata;
* JA4;
* DNS;
* file metadata;
* flow context.

---

# 29. Future Zeek Integration

Live Zeek ingestion is not currently authorized.

When separately approved, it should begin as:

* read-only;
* named sensor only;
* bounded;
* explicit log schema;
* explicit retention;
* no remote script deployment.

Zeek may eventually provide:

* connection relationships;
* DNS;
* TLS;
* certificates;
* HTTP metadata;
* file metadata;
* protocol behaviour.

---

# 30. Identity Data Boundary

Live identity data is not authorized by the current project.

Before live RADIUS, subscriber-database, DHCP, or equivalent identity sources are introduced, an explicit **Identity Data Contract** must be approved.

---

# 31. Identity Data Contract Requirements

The future identity contract must define:

* allowed source systems;
* allowed fields;
* prohibited fields;
* minimization rules;
* pseudonymization;
* retention by source;
* deletion policy;
* role-scoped access;
* raw-record access policy;
* audit requirements;
* identity-reveal procedure;
* reasoning-layer exposure restrictions.

No broad identity-source integration may occur before this contract exists.

---

# 32. Pseudonymous Intelligence Objects

Derived intelligence should use opaque identifiers where human identity is unnecessary.

Example:

```text
subject_ref: sub_7f2af014
session_ref: ses_21cc45
nas_ref: nas_pop04
```

rather than:

```text
customer name
email address
phone number
billing account
```

The reasoning layer normally does not need real customer identity.

---

# 33. Reasoning-Layer Privacy Boundary

AI-facing packages must contain only information necessary for the reasoning task.

The default AI package must not contain:

* customer names;
* email addresses;
* phone numbers;
* billing information;
* passwords;
* authentication secrets;
* raw RADIUS credentials;
* unnecessary raw subscriber records.

Use:

* opaque subject references;
* aggregate statistics;
* bounded behavioural summaries;
* evidence references.

---

# 34. Raw Evidence Access

Raw evidence must not automatically be supplied to the reasoning layer.

Future raw-evidence access should require:

* analyst authorization;
* role permission;
* explicit reason;
* audit entry;
* bounded scope.

The system should support:

```text
intelligence object
      ↓
evidence reference
```

without automatically exposing the raw record.

---

# 35. Historical Intelligence

Historical behavioural context is not yet authorized as unrestricted live subscriber profiling.

The next historical capability should first use bounded synthetic or explicitly approved data.

Possible derived values include:

* usual flow count;
* normal protocol mix;
* expected destination range;
* typical active periods;
* common JA4 set;
* normal ingress/egress ratio.

Historical context should state:

```text
unusual relative to baseline
```

not:

```text
malicious
```

---

# 36. Reasoning Layer Boundary

The AI reasoning layer is a future gated capability.

It should be introduced only after:

* deterministic evidence contracts are stable;
* multi-source ambiguity handling is reproducible;
* replay is deterministic;
* historical summaries are bounded;
* AI-facing privacy contracts exist.

The first reasoning implementation must be **analyst-only**.

It must have no execution authority.

---

# 37. AI Reasoning Output

Initial AI outputs should be limited to:

* hypothesis;
* explanation;
* prioritization;
* missing-evidence request;
* suggested next observation;
* analyst summary.

Example:

```text
Hypothesis:
possible periodic C2 activity

Alternative:
legitimate persistent cloud application

Missing evidence:
destination history unavailable

Suggested next step:
collect an additional bounded five-minute metadata window
```

No action should be executed from this output.

---

# 38. Model Independence

The intelligence substrate must not depend on one model.

```text
Structured intelligence
        │
   ┌────┼────┐
   ▼    ▼    ▼
Model A B    C
```

Different models should be testable against identical evidence packages.

---

# 39. Future Authority Program

Authority does not currently exist.

Before an authority subsystem may be implemented, a separate authorization record must define:

* permitted action vocabulary;
* target inventory;
* approver identity;
* approval mechanism;
* policy versioning;
* action expiry;
* rollback requirements;
* state-verification requirements;
* stop conditions.

---

# 40. Future Execution Program

Any future execution adapter requires separate authorization.

Before any real network action is permitted, all of the following must exist:

* explicitly named target devices;
* credential isolation;
* dedicated least-privilege credentials;
* allowlisted operations;
* dry-run mode;
* explicit approval identity;
* expiry;
* rollback definition;
* rollback verification;
* resulting-state verification;
* action audit trail;
* emergency stop mechanism.

---

# 41. Enforcement Vocabulary Is Contract-Only

The following terms may exist in schemas before real implementation:

```text
quarantine
temporary_block
rate_limit
session_termination
route_adjustment
additional_observation
```

Their existence in a schema does not authorize execution.

---

# 42. Independent Result Verification

Future execution must never assume:

```text
command accepted
=
desired state achieved
```

A resulting state must be confirmed by an independent observation path.

Example:

```text
requested:
temporary quarantine
        ↓
executor reports success
        ↓
independent telemetry confirms
expected traffic restriction
        ↓
confirmed_changed
```

If confirmation is unavailable:

```text
network_state = unknown
```

---

# 43. Future Execution Failure Contract

Potential future execution outcomes should explicitly distinguish:

```text
denied
not_authorized
dry_run_only
applied
execution_failed
verification_failed
rolled_back
rollback_failed
network_state_unknown
```

A timeout must never be reported as:

```text
probably unchanged
```

---

# 44. Management Layer

The future management layer is conceptually informed by ProbeManager-style systems.

Its eventual responsibilities may include:

* sensor inventory;
* sensor health;
* parser versions;
* ruleset versions;
* service state;
* telemetry delay;
* dropped-event count;
* deployment status.

Management information is itself intelligence.

For example:

```text
no Zeek events
```

may mean:

```text
no relevant activity
```

or:

```text
Zeek sensor unavailable
```

The system must preserve that distinction.

---

# 45. Incremental Development Gates

Development must progress through explicit gates.

No gate automatically authorizes the next one.

---

# 46. Gate 1 — Synthetic Deterministic Intelligence

**Current focus**

Requirements:

* synthetic Suricata evidence;
* synthetic Zeek evidence;
* synthetic MikroTik/session evidence;
* schema validation;
* five-tuple correlation;
* temporal association;
* replay;
* duplicate handling;
* explicit ambiguity;
* explicit no-match;
* explicit insufficient-evidence;
* provenance;
* audit validation.

Promotion condition:

> deterministic reproduction of all supported terminal outcomes.

---

# 47. Gate 2 — Authorized Read-Only Telemetry

Introduced source-by-source.

Current separately authorized example:

* bounded NetFlow/IPFIX POC.

Future sources require separate approval:

* Suricata;
* Zeek;
* MikroTik telemetry;
* RADIUS.

Requirements:

* named sensor/source;
* bounded fields;
* bounded rates;
* no credentials beyond minimum read-only requirements;
* no action channel;
* explicit stop condition.

---

# 48. Gate 3 — Bounded Historical Context

Requirements:

* approved retention window;
* bounded feature set;
* deterministic baselines;
* pseudonymous subject references;
* no unrestricted identity data;
* reproducible feature generation.

No ML required.

---

# 49. Gate 4 — Analyst-Only AI Reasoning

Requirements:

* structured intelligence input only;
* privacy/minimization contract;
* no router access;
* no execution tools;
* no autonomous retraining;
* recorded hypotheses;
* evidence references;
* analyst review.

---

# 50. Gate 5 — Reasoning Evaluation

Requirements:

* frozen intelligence packages;
* multiple model comparison where useful;
* preserved negative outcomes;
* reproducible evaluation;
* analyst-utility measurement;
* hallucination/error review;
* calibration where applicable.

Promotion must be evidence-driven.

---

# 51. Future Gate 6 — Authority Prototype

**Separate program authorization required**

Initially:

* synthetic actions only;
* no real router;
* deterministic policy evaluation;
* denied/approved simulation;
* rollback simulation;
* full audit trail.

---

# 52. Future Gate 7 — Dry-Run Execution Adapter

**Separate authorization required**

Requirements:

* named target inventory;
* credentials isolated;
* no actual write execution;
* command generation validated;
* resulting state simulated;
* rollback plan tested.

---

# 53. Future Gate 8 — Controlled Enforcement Pilot

**Separate authorization required**

Initial actions should be:

* narrow;
* temporary;
* reversible;
* independently verified.

No unrestricted automation.

---

# 54. Future Gate 9 — Closed-Loop Research

Only after earlier gates are validated may research consider:

* AI-assisted SDN;
* automatic fault remediation;
* path optimization;
* self-healing;
* controlled recursive system improvement.

This remains outside the current project authority.

---

# 55. Vertical Before Horizontal Scaling

The project should reach deterministic reproducibility within each authorized vertical capability before replication.

The current vertical target is not:

```text
everything from sensors to enforcement
```

It is:

```text
bounded observations
      ↓
evidence
      ↓
deterministic intelligence
      ↓
reproducible outcomes
```

Only validated functionality should expand horizontally.

---

# 56. Horizontal Promotion Criterion

The criterion for horizontal replication is:

> **Functionality can be deterministically reproduced under the same evidence, contract versions, and configuration.**

Horizontal scale must not multiply unresolved ambiguity or unstable logic.

---

# 57. Network-Wide Intelligence

Once a capability has been safely replicated, horizontal context may create additional intelligence.

Example:

```text
POP A → 4 subjects contact destination X
POP B → 7 subjects contact destination X
POP C → 9 subjects contact destination X
```

may provide a stronger network-level pattern.

Conversely:

```text
800 subjects contact the same CDN
```

may explain a local anomaly as a benign software update.

Horizontal scale therefore adds context rather than merely volume.

---

# 58. Observation and Promotion Asymmetry

Observation should be broad.

Promotion should be narrow.

## Observation layer

Encourage:

* unusual signals;
* negative results;
* ambiguous cases;
* competing interpretations;
* failed hypotheses;
* new candidate features.

## Promotion layer

Require:

* frozen evidence;
* deterministic reproduction;
* explicit versions;
* regression tests;
* measurable value;
* approval;
* rollback where consequential.

---

# 59. Every Outcome Is Signal

The platform should preserve:

* successful detections;
* false positives;
* false negatives;
* no-match results;
* ambiguity;
* insufficient evidence;
* parser failures;
* timing uncertainty;
* replay events;
* rejected proposals.

But:

> **Every outcome is useful information; not every outcome is a positive label.**

---

# 60. Feedback Safety

The system must never automatically treat its own prediction as training truth.

Unsafe:

```text
model flags X
     ↓
X becomes malicious label
     ↓
model retrains on X
```

Required:

```text
model flags X
     ↓
hypothesis
     ↓
independent evidence / analyst outcome
     ↓
governed label
```

---

# 61. Future Recursive Improvement

A future improvement loop may eventually look like:

```text
observe
   ↓
derive intelligence
   ↓
reason
   ↓
propose improvement
   ↓
test against frozen evidence
   ↓
reproduce
   ↓
approve
   ↓
promote
   ↓
observe new outcome
   ↺
```

The system may expand what it proposes.

It may not automatically expand what it is trusted to execute.

---

# 62. Pivot Capabilities

The long-term intelligence substrate could support multiple applications from the same evidence model.

These are architectural possibilities, not currently authorized deployments.

## Observation

> What is happening?

## Inventory

> What exists and how is it related?

## Monitoring

> What changed?

## Security

> Is this change suspicious?

## Prediction

> What is likely to happen next?

## AI-SDN

> What alternate state might improve network operation?

## Self-healing

> What bounded corrective action could restore a desired state?

---

# 63. Inventory as a Future Projection

A future inventory projection may derive relationships from:

* flow data;
* sessions;
* RADIUS;
* DHCP;
* ARP;
* LLDP;
* routing information.

Example:

```text
opaque subject
    ↓
session
    ↓
IP
    ↓
NAS
    ↓
POP
```

This does not authorize collection of those live sources.

---

# 64. Monitoring as a Future Projection

Monitoring may eventually reason over state transitions rather than only device reachability.

Example:

```text
backhaul traffic disappears
+
route changes
+
subscriber traffic moves
+
alternate path utilization increases
```

may derive:

```text
probable failover event
```

Such interpretation remains evidence-linked and uncertainty-aware.

---

# 65. Future AI-SDN Boundary

AI-SDN is explicitly outside the current authority.

Before any route or network-state optimization can be implemented, it requires:

* separate project approval;
* topology authority;
* configuration isolation;
* deterministic policy constraints;
* simulation;
* blast-radius limits;
* rollback;
* independent verification.

---

# 66. Future Self-Healing Boundary

Self-healing is explicitly outside the current authority.

A future self-healing system must follow:

```text
desired state
     ↓
observed state
     ↓
difference
     ↓
diagnosis
     ↓
proposed correction
     ↓
authority
     ↓
bounded action
     ↓
independent verification
```

Failure at any stage must terminate explicitly.

---

# 67. Current Next Milestone

The next safe vertical milestone is:

> **Deterministically evaluate evidence-linked relationships across synthetic multi-source observations while preserving all valid terminal outcomes.**

Example:

```text
synthetic NetFlow
synthetic Suricata
synthetic Zeek
synthetic session binding
        │
        ▼
relationship evaluation
        │
        ├── probable_match
        ├── ambiguous
        ├── no_match
        └── insufficient_evidence
```

No forced unified event is required.

---

# 68. Next Milestone Acceptance Tests

Acceptance must include deterministic replay of:

* unique five-tuple relationship;
* same tuple outside time window;
* multiple candidates;
* no candidate;
* missing required field;
* degraded clock;
* unknown clock;
* overlapping session bindings;
* dynamic IP reuse;
* reordered delivery;
* duplicate delivery;
* replay;
* malformed evidence;
* unsupported schema.

The same frozen input must reproduce the same outcome.

---

# 69. Subsequent Safe Milestone

After synthetic multi-source relationship handling is stable:

> introduce one separately authorized read-only source at a time.

The progression should be incremental.

Example:

```text
synthetic intelligence
      ↓
bounded NetFlow/IPFIX
      ↓
separately authorized Suricata reader
      ↓
separately authorized Zeek reader
      ↓
bounded historical context
      ↓
analyst-only reasoning
```

Authority and execution remain outside this progression.

---

# 70. Security Invariants

The following are mandatory.

### Invariant 1

Current authorization and future architecture must remain explicitly separated.

### Invariant 2

A conceptual future diagram is not an implementation authorization.

### Invariant 3

Raw telemetry is not the preferred AI reasoning representation.

### Invariant 4

Evidence remains immutable.

### Invariant 5

Derived intelligence must reference its evidence.

### Invariant 6

Unknown never silently becomes false.

### Invariant 7

Ambiguity never silently becomes certainty.

### Invariant 8

Record ordering is not a hidden tie-breaker.

### Invariant 9

Correlation is not causation.

### Invariant 10

Session association is not human ownership or causation.

### Invariant 11

Reasoning output is not authority.

### Invariant 12

Enforcement vocabulary does not authorize enforcement.

### Invariant 13

Identity data must be minimized and pseudonymized before model exposure.

### Invariant 14

Raw subscriber evidence is not supplied to AI by default.

### Invariant 15

All failures must terminate explicitly.

### Invariant 16

Current data/intelligence processing fails visibly.

### Invariant 17

Future authority must fail conservatively.

### Invariant 18

Consequential execution requires independent resulting-state verification.

### Invariant 19

Negative and inconclusive outcomes are preserved.

### Invariant 20

Horizontal scale follows deterministic vertical validation.

### Invariant 21

No AI model is required for deterministic intelligence operation.

### Invariant 22

Normal network forwarding must never depend on the AI reasoning layer.

---

# 71. Current Authority Record

## Approved

* this architecture specification;
* local deterministic intelligence development;
* synthetic fixtures;
* local evidence/correlation testing;
* explicit replay/idempotency testing;
* bounded read-only NetFlow/IPFIX work only where separately authorized.

## Not approved

* live Suricata collection;
* live Zeek collection;
* live subscriber identity ingestion;
* live RADIUS;
* production MikroTik access beyond separately authorized read-only scope;
* credentials/secrets;
* router modification;
* rule deployment;
* AI production reasoning;
* ML-based enforcement;
* authority evaluator;
* execution adapter;
* AI-SDN;
* self-healing;
* autonomous retraining;
* autonomous promotion.

---

# 72. Future Authorization Record Requirement

Every future capability expansion must receive its own authority record describing:

* purpose;
* data sources;
* named targets;
* allowed fields;
* credentials boundary;
* permitted operations;
* prohibited operations;
* rate/resource bounds;
* retention;
* privacy controls;
* monitoring;
* stop conditions;
* rollback;
* acceptance criteria.

No previous approval is inherited automatically.

---

# 73. Final Current System Model

The current project should be understood as:

```text
Authorized observations / fixtures
             │
             ▼
          Evidence
             │
             ▼
Deterministic intelligence
             │
             ▼
Explicit relationship outcomes
             │
             ▼
Analyst / engineering evaluation
```

That is the current system.

---

# 74. Future Target Architecture

The long-term conceptual architecture, requiring separate authorization at each boundary, is:

```text
                     NETWORK
                        │
                        ▼
                     SENSORS
                        │
                        ▼
                     EVIDENCE
                        │
                        ▼
                  INTELLIGENCE
                        │
                        ▼
                 AI REASONING
                        │
                        ▼
                    AUTHORITY
                        │
                        ▼
                    EXECUTION
                        │
                        ▼
                     NETWORK
                        │
                        ▼
                     FEEDBACK
                        │
                        └──────────↺
```

The model operates inside the proposed future loop.

It does not own the loop.

---

# 75. Core Engineering Principle

The framework is based on the following decomposition:

> **Sensors create observations.
> Evidence creates trustworthy knowledge.
> Deterministic correlation and abstraction create network intelligence.
> AI may later reason over that intelligence.
> Authority may later constrain which proposals are permissible.
> Execution may later apply explicitly approved changes.
> Feedback may later verify whether those changes produced the intended result.**

The project should increase utility only after the preceding capability becomes:

* explicit;
* bounded;
* reproducible;
* auditable;
* appropriately authorized.

The development rule is therefore:

> **Observe broadly. Represent uncertainty explicitly. Reproduce deterministically. Promote conservatively. Expand authority only through a separate approved boundary.**
