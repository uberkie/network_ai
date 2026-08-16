# AI-Assisted WISP Network Security Framework Specification

**Version:** 0.1
**Status:** Architecture and implementation baseline
**Deployment model:** Out-of-band general inspection with narrow inline inspection and controlled enforcement

## 1. Purpose

This platform provides a scalable network-security framework for a WISP environment by combining:

* Suricata network detection
* Zeek network telemetry
* MikroTik routing, subscriber, and firewall telemetry
* Deterministic protocol controls
* Behavioural and anomaly detection
* Evidence correlation
* Controlled network enforcement
* Selective inline inspection of suitable protocols

The platform is based on a simple security principle:

> It is not always possible to prevent malicious software from entering a network, but the network can substantially restrict what compromised software is capable of doing once inside.

The system therefore focuses on both **ingress detection** and **post-compromise containment**.

The network should act as a controlled capability environment in which endpoints may communicate only through explicitly permitted channels.

---

# 2. Core Architectural Principle

The platform separates traffic into two security paths:

### General traffic

General subscriber traffic remains on the normal WISP forwarding path.

Security inspection is primarily performed **out of band** through traffic mirroring, telemetry, flow information, and protocol metadata.

### Selected high-risk protocols

Protocols for which deep inspection is practical and operationally safe may be passed through **narrow inline inspection services**.

Email is the first intended use case.

The resulting design principle is:

> **Out-of-band by default. Inline only where inspection is deterministic, valuable, and operationally containable.**

---

# 3. High-Level Architecture

```text
                         INTERNET
                            │
                            ▼
                       EDGE ROUTER
                            │
               Normal production traffic
                            │
                            ▼
                  DISTRIBUTION ROUTER
                            │
                            ▼
                       SUBSCRIBERS


                  OUT-OF-BAND SECURITY PLANE

Edge / Distribution Router
             │
             │ mirror / telemetry
             ▼
       Suricata + Zeek
             │
             ▼
     Evidence Normalization
             │
             ▼
       Correlation Engine
             │
             ├── deterministic rules
             ├── anomaly detection
             ├── historical behaviour
             └── asset/subscriber context
             │
             ▼
          Case Engine
             │
             ▼
      Policy / Authority Gate
             │
             ▼
       MikroTik Adapter
             │
             ▼
    MikroTik Enforcement Point
```

The security system must not be required for normal packet forwarding.

Loss of the analytics platform should cause:

**loss of visibility**

rather than:

**loss of Internet connectivity**

---

# 4. Security Model

The framework uses three types of control.

## 4.1 Hard Constraints

Protocols with predictable behaviour should be controlled through deterministic network rules.

Examples:

```text
DNS
    → approved resolvers only

SMTP
    → approved relays only

NTP
    → approved servers only

SSH
    → restricted according to policy

SMB
    → blocked between unrelated subscriber networks

SNMP
    → management networks only

Direct arbitrary TCP/UDP
    → deny unless explicitly required
```

These decisions should not require AI.

If a network rule can determine the answer reliably, a deterministic rule should be used.

---

# 4.2 Guarded General-Purpose Protocols

Protocols such as HTTPS cannot realistically be fully constrained without severely affecting legitimate Internet use.

HTTPS therefore operates under **guardrails rather than full hard constraints**.

Inspection may use:

* Source and destination
* DNS relationships
* ASN
* TLS metadata
* JA3/JA4 fingerprints
* Certificates
* Session duration
* Connection frequency
* Packet sizes
* Upload/download ratios
* Destination history
* New-domain behaviour
* Flow periodicity
* Connection fan-out
* Historical subscriber behaviour

HTTPS payloads are not decrypted by default.

---

# 4.3 Narrow Inline Inspection

Inline inspection is reserved for protocols where:

1. inspection provides significant security value;
2. buffering is operationally acceptable;
3. traffic does not need wire-speed forwarding;
4. the protocol naturally supports intermediary processing;
5. failure can be isolated from general Internet connectivity.

Email is the primary initial candidate.

---

# 5. Email Security Architecture

Email is treated as a store-and-forward workload rather than real-time network traffic.

The platform should therefore favour a **secure mail gateway** rather than generic full-network TLS interception.

Typical mail-related ports include:

| Protocol        |    Port |
| --------------- | ------: |
| SMTP            |  25/TCP |
| SMTP Submission | 587/TCP |
| SMTPS           | 465/TCP |
| IMAP            | 143/TCP |
| IMAPS           | 993/TCP |
| POP3            | 110/TCP |
| POP3S           | 995/TCP |

Port 2525 may additionally be monitored because some providers use it as an alternate SMTP submission port.

---

# 6. Mail Processing Pipeline

Where mail flow is explicitly controlled and authorized:

```text
Internet
    │
    ▼
SMTP Gateway
    │
    ▼
Receive message
    │
    ▼
Durable spool
    │
    ▼
Bounded inspection queue
    │
    ▼
Analysis workers
    │
    ├── MIME parsing
    ├── attachment extraction
    ├── true file-type detection
    ├── SHA-256 generation
    ├── archive inspection
    ├── nested archive handling
    ├── extension/MIME mismatch detection
    ├── YARA/static rules
    ├── antivirus engines
    ├── script analysis
    ├── document/macro analysis
    └── optional future sandbox analysis
             │
             ▼
        Policy decision
        /      |       \
       /       |        \
   deliver    hold    quarantine
```

The message must not be delivered to the user's mail system until required inspection stages are complete.

---

# 7. Bounded Mail Processing

Inspection concurrency must never directly follow incoming message concurrency.

The platform should use:

```text
Incoming mail
      │
      ▼
Durable queue
      │
      ▼
N scanner workers
      │
      ▼
Decision
      │
      ▼
Delivery
```

The worker count must be configurable according to available CPU, memory, and storage.

For example:

```text
200 queued messages
        │
        ▼
8 analysis workers
        │
        ▼
CPU remains bounded
```

If processing capacity is temporarily exhausted, mail should queue.

The preferred failure mode is:

> **Delayed email**

rather than:

> **Overloaded network infrastructure**

---

# 8. Progressive Inspection

Not every message should receive the same computational workload.

Analysis should proceed from inexpensive checks toward expensive checks.

```text
Message
   │
   ▼
Basic parsing
   │
   ▼
File classification
   │
   ├── no attachment
   │       ↓
   │    low-cost policy
   │
   └── attachment
           │
           ▼
      static analysis
           │
     suspicious?
       /       \
     no         yes
     │           │
 deliver      deep analysis
                  │
                  ├── archive recursion
                  ├── script analysis
                  ├── document inspection
                  └── optional sandbox
```

This protects CPU resources while allowing high-risk objects to receive deeper inspection.

---

# 9. Email Threat Objective

The initial email-security objective is:

> **Prevent executable, exploit-bearing, structurally suspicious, or clearly malicious email content from reaching native mail clients without prior inspection and policy evaluation.**

Examples include:

* JavaScript
* VBScript
* PowerShell scripts
* executable binaries
* SCR files
* shortcut files
* disk images
* suspicious Office documents
* macro-enabled documents
* malicious PDFs
* nested archives
* unusual executable content inside archives
* extension spoofing
* MIME mismatches
* heavily obfuscated scripts
* known malware hashes

This system does not attempt to eliminate all social engineering.

Users may still voluntarily:

* follow malicious links;
* provide credentials;
* authorize OAuth access;
* install software;
* bypass warnings.

Those risks may be detected or mitigated elsewhere but are not the primary responsibility of the mail-content gateway.

---

# 10. HTTPS Policy

General HTTPS traffic should not undergo network-wide TLS interception.

Reasons include:

* certificate pinning;
* unmanaged subscriber devices;
* applications with private trust stores;
* banking applications;
* mobile applications;
* QUIC/HTTP3;
* certificate lifecycle complexity;
* privacy implications;
* high CPU requirements;
* increased operational support burden;
* creation of a critical single point of failure.

HTTPS should instead be monitored through metadata and behaviour.

---

# 11. HTTPS Behavioural Guardrails

The analytics platform may evaluate:

```text
Subscriber
    │
    ├── destination never previously contacted
    ├── new ASN
    ├── unusual JA4
    ├── unusual connection frequency
    ├── periodic beaconing
    ├── continuous upstream traffic
    ├── abnormal upload ratio
    ├── unusual session duration
    ├── rapid destination fan-out
    ├── sudden behavioural change
    └── correlated preceding security events
```

Example:

```text
Previous behaviour:

40–100 normal HTTPS destinations
interactive traffic
mostly downstream
variable connection timing


New behaviour:

one persistent TLS destination
connection every 60 seconds
same packet pattern
new JA4
new ASN
continuous upstream transfer
24-hour activity
```

This should produce an analyst candidate, not automatically establish compromise.

---

# 12. QUIC and Encrypted DNS

The platform must explicitly account for protocols that can bypass traditional TCP-based analysis.

## QUIC / HTTP3

UDP/443 must be separately observed and governed.

Options may include:

* permit with telemetry;
* selectively restrict;
* force fallback to TCP/HTTPS where justified;
* perform behavioural analysis.

## DNS-over-TLS

TCP/853 may be restricted to approved infrastructure or blocked where policy requires central DNS visibility.

## DNS-over-HTTPS

DoH cannot reliably be identified solely by port because it operates over HTTPS.

It should therefore be handled through:

* known provider intelligence;
* DNS destination correlation;
* TLS metadata;
* behavioural detection;
* policy controls where practical.

---

# 13. Subscriber Isolation

A compromised subscriber must not automatically gain useful lateral access.

The architecture should enforce:

```text
Subscriber A ──X── Subscriber B

Subscriber A ──X── infrastructure management

Subscriber A ──X── tower management devices

Subscriber A ──X── NAS management

Subscriber A ──X── unrelated customer LANs
```

Subscriber-facing infrastructure should be routed and segmented wherever possible rather than placed inside large shared Layer-2 domains.

---

# 14. Post-Compromise Containment Model

The system assumes malware may occasionally execute successfully.

The objective then becomes limiting its network utility.

Example:

```text
malware.exe
    │
    ▼
executes successfully
    │
    ├── external DNS ────────────── DROP
    │
    ├── arbitrary SMTP ──────────── DROP
    │
    ├── SSH reverse connection ──── DROP
    │
    ├── random TCP C2 ───────────── DROP
    │
    ├── subscriber scanning ─────── DROP
    │
    └── HTTPS C2
           │
           ▼
       monitored
           │
       anomaly
           │
           ▼
       correlation
           │
           ▼
       containment
```

This creates a **network capability sandbox**.

The endpoint itself is not sandboxed, but its ability to communicate through the network is constrained.

---

# 15. Security Funnel

Restricting unnecessary protocols forces malicious software toward fewer usable communication methods.

```text
             POSSIBLE MALWARE C2
                     │
       ┌─────────────┼─────────────┐
       │             │             │
      DNS           SMTP       random TCP
       X             X             X

      SSH           DoT        random UDP
       X             X             X

                     │
                     ▼
                  HTTPS
                     │
                     ▼
           Guarded communication
                     │
                     ▼
            behavioural analysis
```

The purpose is not to guarantee that C2 becomes impossible.

The purpose is to reduce the attacker's available communication space and make abnormal behaviour easier to detect.

---

# 16. Suricata Responsibilities

Suricata should initially operate as an IDS rather than as an inline IPS.

Responsibilities include:

* network signature detection;
* protocol parsing;
* EVE JSON output;
* TLS metadata;
* JA3/JA4 information;
* file metadata where available;
* HTTP inspection where visible;
* flow events;
* DNS events;
* suspicious network patterns;
* known C2 signatures;
* exploit signatures.

Suricata detection should provide evidence to the correlation layer.

A Suricata alert is not by itself an enforcement command.

---

# 17. Zeek Responsibilities

Zeek should provide high-context behavioural telemetry.

Useful data includes:

* connection logs;
* DNS logs;
* TLS logs;
* HTTP metadata;
* file metadata;
* certificate information;
* session timing;
* protocol behaviour;
* destination relationships;
* connection history.

Suricata primarily answers:

> **Did something match a known suspicious pattern?**

Zeek helps answer:

> **What was this system doing around that event?**

---

# 18. MikroTik Responsibilities

MikroTik devices remain the network forwarding and enforcement authority.

Read-only telemetry may include:

* subscriber identity;
* IP allocation;
* PPPoE session information;
* interface traffic;
* connection information;
* routing context;
* ARP where appropriate;
* firewall counters;
* queue statistics;
* interface state;
* NAS identity.

The security analytics system should not require arbitrary RouterOS configuration access.

---

# 19. MikroTik Adapter

A separate adapter must exist between analytics and RouterOS.

The analytics system must never directly construct and execute unrestricted RouterOS commands.

```text
Analytics
    │
    ▼
Policy / Authority Gate
    │
    ▼
MikroTik Adapter
    │
    ├── validate request
    ├── verify scope
    ├── enforce allowed action
    ├── apply expiry
    ├── log request
    ├── log result
    └── support rollback
            │
            ▼
         RouterOS
```

Possible future permitted actions include:

* temporary quarantine;
* address-list insertion;
* connection blocking;
* destination blocking;
* rate limitation;
* restricted subscriber profile;
* session termination.

Each action must be explicitly allowlisted.

---

# 20. Authority Model

The platform must maintain strict separation between:

**Detection**

and

**Authority**

A model score must never automatically become a firewall command.

Required chain:

```text
Observation
    ↓
Evidence
    ↓
Correlation
    ↓
Risk candidate
    ↓
Policy decision
    ↓
Authority
    ↓
Enforcement
```

At the initial deployment stage, enforcement should require analyst approval.

Future automation may only be introduced for highly deterministic and separately authorized conditions.

---

# 21. Evidence Model

Every event entering the correlation system should preserve:

* observation ID;
* original source event ID;
* source system;
* sensor identity;
* event timestamp;
* observed timestamp;
* ingestion timestamp;
* timezone;
* clock-quality information;
* parser version;
* adapter version;
* schema version;
* raw record or immutable reference;
* SHA-256 hash;
* acquisition/configuration hash;
* redaction state;
* data classification;
* retention policy.

Evidence must remain separable from interpretation.

---

# 22. Observation Model

An observation is a normalized representation of one source record.

Examples:

```text
SURICATA_ALERT
ZEEK_CONNECTION
DNS_QUERY
TLS_SESSION
MIKROTIK_SESSION
MIKROTIK_FLOW
MAIL_ATTACHMENT
FILE_ANALYSIS
ANOMALY_SCORE
```

Schemas must be versioned.

Adapters must reject or quarantine unsupported records rather than silently reinterpret them.

---

# 23. Correlation

Correlation links evidence but does not establish causation.

Example:

```text
Mail attachment
      │
      ├── SHA-256
      │
      ▼
Suricata observation
      │
      ▼
subscriber IP
      │
      ▼
MikroTik PPPoE session
      │
      ▼
Zeek TLS event
      │
      ▼
new external destination
      │
      ▼
anomaly score
```

Possible correlation outcomes must include:

* match;
* probable match;
* ambiguous;
* no match;
* insufficient evidence.

The engine must not force every event into a case.

---

# 24. Anomaly Detection

Machine learning is an additional evidence source.

It is not the primary authority mechanism.

Development sequence:

1. deterministic baselines;
2. rule-only detection;
3. historical statistics;
4. anomaly model;
5. comparison against rule-only baseline.

An anomaly result should include:

* model version;
* feature version;
* threshold version;
* score;
* contributing features;
* uncertainty;
* evaluation provenance.

Example:

```text
Anomaly score: 0.94

Contributors:
+ outbound connections increased 11.8×
+ new ASN
+ new JA4
+ 60-second periodicity
+ upload ratio changed from 0.08 to 4.7
```

The output means:

> behaviour is unusual

not:

> malware is confirmed.

---

# 25. Evaluation Requirements

Models should be evaluated using:

* precision at analyst capacity;
* recall by scenario;
* false alerts per hour/day;
* PR-AUC;
* calibration;
* confidence intervals;
* source ablation;
* threshold sensitivity.

Accuracy alone is insufficient.

ROC-AUC alone is insufficient.

Evaluation datasets must be frozen before held-out results are examined.

---

# 26. Input Safety

All adapters must implement:

* schema validation;
* maximum record size;
* maximum event rate;
* duplicate handling;
* replay handling;
* out-of-order event handling;
* malformed-record quarantine;
* unsupported-version quarantine;
* timestamp sanity checking;
* idempotent ingestion.

No parser should receive unlimited or unconstrained input.

---

# 27. Credential Boundaries

The evidence system must not store:

* RouterOS passwords;
* private keys;
* SMTP authentication credentials;
* IMAP authentication credentials;
* OAuth refresh tokens;
* unrelated configuration secrets.

Where inline mail inspection terminates TLS, authentication material must be explicitly excluded from long-term evidence storage.

Only security-relevant metadata should be retained.

---

# 28. Failure Domains

The system should intentionally separate failure impact.

## Analytics failure

Effect:

> Loss or degradation of security visibility.

Internet forwarding remains operational.

## Suricata/Zeek failure

Effect:

> Reduced detection capability.

Customer forwarding remains operational.

## Mail inspection overload

Effect:

> Mail queues and delivery is delayed.

Internet access remains operational.

## MikroTik adapter failure

Effect:

> Automated/assisted response becomes unavailable.

Routing remains operational.

## Mail gateway failure

Effect:

> Mail delivery is affected.

General customer Internet service remains operational.

---

# 29. Performance Philosophy

The framework should prioritize predictable bounded resource use.

For passive inspection:

* bounded capture buffers;
* sampling where required;
* flow aggregation;
* event filtering;
* asynchronous processing;
* prioritization of security-relevant telemetry.

For mail:

* durable disk-backed queues;
* configurable worker pools;
* CPU limits;
* memory limits;
* attachment-size limits;
* archive recursion limits;
* processing timeouts.

No untrusted object should be capable of consuming unlimited processing resources.

---

# 30. Initial Implementation Boundary

The first implementation remains **local and fixture-based**.

It may contain:

* Python package;
* typed event models;
* synthetic Suricata EVE events;
* synthetic Zeek logs;
* synthetic MikroTik telemetry;
* synthetic mail messages;
* safe test attachments;
* correlation engine;
* anomaly experiment;
* evidence store;
* analyst case model;
* policy model;
* test suite.

It must not initially:

* capture production traffic;
* connect to a MikroTik;
* contain RouterOS credentials;
* modify a router;
* deploy firewall rules;
* intercept real mail;
* intercept HTTPS;
* block subscribers;
* claim validated malware detection.

---

# 31. Development Phases

## Phase 1 — Foundation

Implement:

* Python project;
* evidence envelope;
* schemas;
* provenance;
* synthetic fixtures;
* redaction;
* hashing;
* timestamps;
* validation;
* tests.

No network clients.

---

## Phase 2 — Deterministic Correlation

Implement:

* asset identity;
* subscriber identity;
* Suricata ↔ Zeek correlation;
* MikroTik session correlation;
* DNS/TLS relationship tracking;
* deterministic rules;
* explicit no-match handling.

---

## Phase 3 — Anomaly Experiment

Implement:

* baseline features;
* frozen training/test fixtures;
* anomaly scoring;
* reproducible evaluation;
* rule-only comparison;
* negative-result preservation.

No automated response.

---

## Phase 4 — Analyst Platform

Implement:

* cases;
* evidence timeline;
* confidence display;
* analyst dispositions;
* audit history;
* retention;
* access controls;
* feedback governance.

---

## Phase 5 — Passive Production Sensor

After separate authorization:

```text
Port mirror
    │
    ▼
Suricata + Zeek
    │
    ▼
Production evidence pipeline
```

Initially read-only.

No enforcement.

---

## Phase 6 — Read-Only MikroTik Integration

After separate authorization:

* named routers only;
* dedicated restricted account;
* read-only access;
* explicit telemetry allowlist;
* connection monitoring;
* rate limits;
* audit records.

---

## Phase 7 — Mail Gateway Pilot

Deploy selective inline email inspection.

Initially:

* one controlled domain;
* limited users;
* durable queue;
* attachment inspection;
* quarantine;
* monitoring;
* manual release.

Measure:

* processing latency;
* queue depth;
* CPU usage;
* false positives;
* attachment rates;
* detection quality.

---

## Phase 8 — Controlled Enforcement

Introduce the MikroTik enforcement adapter.

Initial actions should be temporary and reversible.

Example:

```text
Subscriber
     │
     ▼
High-confidence case
     │
     ▼
Analyst approval
     │
     ▼
Quarantine address-list
     │
     ▼
15-minute expiry
```

Permanent rules should not be the first automated action.

---

# 32. Initial Acceptance Criteria

The first implementation is accepted only when:

* schemas have golden tests;
* hostile-input tests pass;
* duplicate ingestion is deterministic;
* reordered events produce deterministic results;
* replayed events do not generate duplicate evidence;
* provenance hashes are reproducible;
* redaction tests pass;
* unsupported schema versions are quarantined;
* no network-access library is used by fixture tests;
* no RouterOS credentials exist;
* no router modification path exists;
* anomaly experiments reproduce from frozen input;
* rule-only baselines are available;
* ML results do not claim compromise;
* negative and inconclusive results are preserved.

---

# 33. Security Invariants

The following rules are architectural invariants.

### Invariant 1

**Production forwarding must not depend on the AI platform.**

### Invariant 2

**A score is not an enforcement command.**

### Invariant 3

**Correlation is not causation.**

### Invariant 4

**No unrestricted RouterOS command execution may originate from analytics.**

### Invariant 5

**Hard constraints should be implemented deterministically rather than delegated to AI.**

### Invariant 6

**Encrypted general-purpose protocols should use guardrails unless a separately authorized inline inspection use case exists.**

### Invariant 7

**Inline processing must have bounded queues, resources, and failure domains.**

### Invariant 8

**Security tooling must not become a WISP-wide single point of failure.**

### Invariant 9

**Compromise of one subscriber must not imply lateral access to another subscriber or network infrastructure.**

### Invariant 10

**Evidence must remain traceable to its original source.**

---

# 34. Overall Security Strategy

The framework assumes four distinct security opportunities:

```text
            MALICIOUS CONTENT

                  │
                  ▼
            1. INGRESS
       detect/block where practical
                  │
                  ▼
            2. EXECUTION
        endpoint security / AV
                  │
                  ▼
         3. NETWORK CAPABILITY
     restrict what endpoint may do
                  │
                  ▼
          4. POST-COMPROMISE
      detect C2 / exfil / scanning
                  │
                  ▼
             CONTAINMENT
```

No single layer is expected to provide complete protection.

Instead, failure at one layer should expose the attacker to another.

---

# 35. Design Philosophy

The framework does not assume:

> Nothing malicious will ever enter the subscriber network.

It assumes:

> Something malicious eventually will.

The objective is therefore to ensure that successful ingress does not automatically provide unrestricted network capability.

A compromised endpoint should operate inside a constrained network environment where:

* unnecessary protocols are unavailable;
* arbitrary DNS is restricted;
* arbitrary SMTP is restricted;
* subscriber-to-subscriber movement is restricted;
* management infrastructure is isolated;
* unusual communications are observable;
* HTTPS remains usable but behaviourally monitored;
* security evidence is correlated across multiple sources;
* suspicious systems can eventually be quarantined through controlled, reversible enforcement.

The resulting model is:

> **Prevent where practical. Constrain by default. Observe broadly. Inspect deeply only at suitable choke points. Correlate evidence. Authorize before enforcement. Contain what gets through.**

This is the baseline architecture for the AI-assisted WISP security framework.
