# NetDiff Architecture

NetDiff follows a strict pipeline to evaluate and explain why a target connection functions in one environment while failing in another.

```
Target (host:port)
       │
       ▼
 Probe Planner
       │
   ┌───┴───────────┬──────────────┐
   ▼               ▼              ▼
  DNS            Route           TCP
Collector      Collector        Probe
   │               │              │
   └───┬───────────┴──────────────┘
       ▼
 Raw State Snapshot
       │
       ▼
 Semantic Normalizer
       │
       ▼
 Normalized Snapshot (.ndiff)
       │
       ▼
  Diff Engine
       │
       ▼
 Relevance Engine & Evidence DAG
       │
       ▼
 Deterministic Output / Bounded Gemini Reasoner
```

## Key Principles

1. **Target-Bounded State Gathering**: NetDiff never performs indiscriminate system dumps. Every collector extracts only state relevant to the requested destination.
2. **Semantic Normalization**: Machine-specific artifacts (interface indices, temporary IPv6 addresses, resolver order) are normalized to avoid spurious diffs.
3. **Deterministic-First Engine**: All diffing, causal scoring, and explanations function offline through explicit rule matching and dependency DAG analysis.
4. **Bounded AI Reasoning**: When `--ai` is enabled, Gemini acts strictly as a high-level synthesizer and probe recommender over structured evidence bundles—never executing arbitrary commands.
