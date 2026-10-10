# NetDiff

> **“It works on my machine. Why?”**

NetDiff explains why a network connection works in one environment and fails in another.

Instead of manually comparing route tables, DNS resolvers, interface indices, VPN state, proxy variables, MTU, and TCP behavior across dozens of commands, NetDiff captures only the target-relevant network state and isolates the differences capable of explaining the failure.

---

## The Workflow

```bash
# 1. On the working environment:
netdiff capture api.internal.corp:443 -o good.ndiff

# 2. On the failing environment:
netdiff capture api.internal.corp:443 -o bad.ndiff

# 3. Compare them anywhere:
netdiff compare good.ndiff bad.ndiff
```

Output:

```text
=== NetDiff Target Analysis ===
Target: api.internal.company:443

DEVELOPER-LAPTOP-WORKING DEVELOPER-WORKSTATION-FAILING
------------------------------------------------------------
DNS
10.40.8.21               10.40.8.21              
✓ same

Route Table & Egress
tun0 (table 200)         eth0 (main)             
⚠ different

Source Address
10.8.0.14                192.168.1.84            
⚠ different

TCP Connection
connected (27ms)         timeout                 
✗ different

=== HIGH-RELEVANCE DIFFERENCE ===
[Route] Failing host uses a different routing table (policy routing divergence).
  Working: table 200 (table 200)
  Failing: table 254 (main)

[Route] Failing environment routes destination out eth0 instead of tun0.
  Working: tun0
  Failing: eth0

[Interface] Working uses a tunnel interface while failing uses a physical interface.
  Working: tunnel
  Failing: physical
```

---

## Synthesis & Validation Probe (`explain`)

```bash
netdiff explain good.ndiff bad.ndiff --ai
```

Produces:

```text
=== Deterministic Diagnostic Engine ===
Routing divergence is the strongest current explanation. The working environment routes through table 200 (table 200) while the failing environment routes through table 254 (main). Since the failing connection experienced timeout, this divergence directly accounts for the path failure.

Diagnostic Hypotheses:
  1. VPN/Policy Route Bypass [STRONG Support]
     Traffic in failing environment is routed via table 254 (main) instead of expected table 200 (table 200) interface.
  2. MTU or Path Blackhole [WEAK Support]
     Path MTU issues usually establish TCP handshake before dropping larger data packets.

Recommended Validation Probe:
  Action: TEST_TCP_BIND_INTERFACE(tun0)
  Why:    Binding TCP socket explicitly to tun0 on the failing host will verify if reachability succeeds over that link.
```

---

## Architecture

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
 Normalized Semantic Snapshot (.ndiff)
       │
       ▼
  Diff Engine
       │
       ▼
 Relevance Engine & Evidence Graph (DAG)
       │
       ▼
 Deterministic Output / Bounded Gemini Reasoner
```

1. **Target-Bounded Probing**: Only gathers network state relevant to the requested `host:port`.
2. **Semantic Normalization**: Filters out noise such as dynamic interface indices, loopback variations, or temporary IPs.
3. **Causal Relevance Graph**: Distinguishes between root causes (e.g. routing table mismatch) and symptoms (e.g. TCP timeout vs connection refused).
4. **Deterministic First**: Runs completely offline without any external services or LLMs. Gemini is an optional top-layer synthesizer.

---

## CLI Usage

| Command | Description |
| :--- | :--- |
| `netdiff capture <target> [-o file.ndiff]` | Captures target network path to console or file |
| `netdiff compare <good> <bad>` | Compares two `.ndiff` snapshots and highlights high-relevance diffs |
| `netdiff compare <good> <bad> --json` | Emits structured JSON comparison report |
| `netdiff compare <good> <bad> --verbose` | Displays medium and low priority differences |
| `netdiff explain <good> <bad> [--ai]` | Generates hypotheses and recommends bounded validation probe |

---

## Building & Testing

```bash
go test -v ./...
go build -o netdiff ./cmd/netdiff
```
