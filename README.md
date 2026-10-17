# NetDiff

> **“It works on my machine. Why?”**

NetDiff explains why a network connection works in one environment and fails in another.

Instead of manually comparing route tables, DNS resolvers, interface indices, VPN state, policy routing rules, proxy variables, MTU, and TCP behavior across dozens of ad-hoc terminal commands, NetDiff captures only the target-relevant network state and isolates the differences capable of explaining the failure.

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

Policy Rule
from all to 10.40.0.0/16 lookup 200 main                    
⚠ different

Route Table & Egress
tun0 (table 200)         eth0 (main)             
⚠ different

Source Address
10.8.0.14                192.168.1.84            
⚠ different

TCP Connection
connected (27ms)         timeout                 
✗ different

>>> ROOT CAUSE: EARLIEST PATH DIVERGENCE <<<
Policy Rule: from all to 10.40.0.0/16 lookup 200 != default main

=== HIGH-RELEVANCE DIFFERENCE ===
[Policy] Policy routing rules diverge before route table lookup occurs.
  Working: from all to 10.40.0.0/16 lookup 200
  Failing: missing / lookup main

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

## Synthesis & Active Validation (`explain`)

NetDiff synthesizes root cause hypotheses and selects the next-best diagnostic probe from a safe, bounded catalog:

```bash
netdiff explain good.ndiff bad.ndiff --validate
```

```text
=== Deterministic Diagnostic Engine ===
Policy routing rule divergence is the primary root cause. The working environment routes target traffic through tun0 via rule 'from all to 10.40.0.0/16 lookup 200', while the failing environment is missing this policy rule and falls back to eth0. Because the failing host routes traffic out eth0, the connection encountered timeout.

Diagnostic Hypotheses:
  1. Missing or Misordered Policy Routing Rule (ip rule) [STRONG Support]
     Traffic to destination is not captured by policy routing rules on the failing host, dropping into the main table and physical egress eth0 instead of tun0.
  2. Inactive Tunnel Interface or VPN Disconnect [MODERATE Support]
     If the VPN daemon or tunnel failed to initialize, route rules for tun0 may not be active.

Recommended Validation Probe:
  Action: TEST_TCP_BIND_INTERFACE(tun0)
  Why:    Binding TCP socket explicitly to tun0 on the failing host bypasses policy routing evaluation and tests if the underlying tunnel link is functional.

=== Executing Active Validation Probe: TEST_TCP_BIND_INTERFACE(tun0) ===
Testing against api.internal.company:443...

=== Probe Result: ✓ VALIDATION SUCCESS ===
Connected to 10.40.8.21:443 bound to device tun0 in 18ms.

Assessment: Confirms hypothesis — route/interface bypass establishes connection successfully.
```

When `--ai` is enabled and `GEMINI_API_KEY` is set, NetDiff passes structured evidence to Google Gemini Flash to synthesize incident explanations, while strictly constraining recommendations to the safe probe catalog.

---

## Incident Report Generation (`report`)

Generate markdown incident post-mortems ready to paste into Slack, Jira, GitHub issues, or network escalation tickets:

```bash
netdiff report good.ndiff bad.ndiff -o incident.md
```

Includes executive summaries, root cause DAG nodes, side-by-side component tables, ranked differences, and remediation actions.

---

## 30-Second Namespace Demo (Docker)

To run the complete isolated Linux network namespace demonstration on any machine (macOS, Windows, or Linux with Docker):

```bash
docker compose run --rm demo
```

This sets up:
1. `ndiff-server`: Mock internal API service on `10.40.8.21:8080`.
2. `ndiff-good`: Working host with VPN tunnel `vpn0` and policy routing table `200`.
3. `ndiff-bad`: Broken host missing the policy routing rule.
4. Executes real NetDiff captures, semantic diffing, explanation, and report generation in real time.

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
3. **Causal Relevance Graph**: Traces `Hostname → DNS → DestIP → Policy Rule → Route Table → Gateway/Src/Iface → MTU → TCP` to pinpoint earliest divergence.
4. **Deterministic First**: Runs completely offline without external APIs. Gemini is an optional top-layer synthesizer.
5. **Bounded Safety**: Active probes are strictly validated against a safe whitelist catalog (`TEST_TCP_BIND_INTERFACE`, `TEST_DNS_WITH_RESOLVER`, `TEST_PROXY_DISABLED`, `TEST_DIRECT_IP`).

---

## CLI Reference

| Command | Description |
| :--- | :--- |
| `netdiff capture <target> [-o file.ndiff]` | Captures target network path to console or `.ndiff` file |
| `netdiff compare <good> <bad>` | Compares two `.ndiff` snapshots and highlights high-relevance diffs |
| `netdiff compare <good> <bad> --json` | Emits structured JSON comparison report |
| `netdiff compare <good> <bad> --verbose` | Displays medium and low priority differences |
| `netdiff explain <good> <bad> [--ai]` | Synthesizes hypotheses and recommends next validation probe |
| `netdiff explain <good> <bad> --validate` | Automatically executes recommended validation probe |
| `netdiff report <good> <bad> [-o file.md]` | Generates structured Markdown incident post-mortem |
| `netdiff ui <good> <bad> [-p 8080]` | Launches interactive browser visualizer comparing dual dependency DAGs |
| `netdiff probe <name> [param] -t <target>` | Executes a bounded validation probe from the catalog |

---

## Building & Testing

```bash
# Run all unit tests
go test -v ./...

# Build binary
go build -o netdiff ./cmd/netdiff
```
