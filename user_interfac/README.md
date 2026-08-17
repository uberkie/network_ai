# ReactPy-Django analyst UI

Read-only Kibana-style shell for already-persisted Suricata, Zeek, and MikroTik evidence.

This app does **not** tail live EVE/Zeek logs, open RouterOS, start a NetFlow collector, or deploy signatures. Live sensor readers remain unauthorized. A running Suricata process is shown as host health only.

## Run

From this directory, with the project virtualenv:

```bash
uv run manage.py runserver 127.0.0.1:7070
```

Open `/`. Overview, Discover, Relationships, Flows, and Sensors query one bounded local snapshot.

## Read-only sources

| Setting / env              | Default                      | Used for                                          |
| -------------------------- | ---------------------------- | ------------------------------------------------- |
| `NETWORK_AI_EVIDENCE_ROOT` | `/tmp/network_ai_test_store` | Existing evidence ledger and derived correlations |
| `NETWORK_AI_FLOW_ROOT`     | `/tmp/network-ai-router`     | Optional existing NetFlow/IPFIX SQLite store      |

Missing paths stay visible as unavailable. The UI never creates those directories.

Load the synthetic ledger first if needed:

```bash
PYTHONPATH=../src python -m network_ai.demo --store /tmp/network_ai_test_store
```
