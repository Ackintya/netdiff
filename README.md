# NetDiff

> Explain why a network connection works in one environment and fails in another.

NetDiff is a Linux network troubleshooting tool designed to isolate the root cause of connection failures across environments. 

Instead of manually running dozens of disconnected commands (`ip route`, `ip rule`, `iptables`, `resolvectl`, `ss`, `ip link`) and guessing which difference matters, NetDiff captures target-specific network state into portable `.ndiff` snapshots, models the connection as a dependency graph, and isolates the earliest divergence responsible for the failure.

---

## Workflow

### Single-Command Diagnosis (Recommended)

Diagnose target connectivity against an automatically managed baseline:

```bash
# First run records baseline snapshot (when network is working):
netdiff diagnose 10.10.0.2:8080

# Subsequent run compares against baseline and provides immediate diagnosis:
netdiff diagnose 10.10.0.2:8080

# Fast reachability check with one-line status:
netdiff check 10.10.0.2:8080
```

### Manual Snapshot Workflow

Capture and compare discrete snapshots across hosts or time:

```bash
# 1. Capture target network state in the working environment:
netdiff capture 10.10.0.2:8080 -o good.ndiff

# 2. Capture target network state in the failing environment:
netdiff capture 10.10.0.2:8080 -o bad.ndiff

# 3. Compare snapshots:
netdiff compare good.ndiff bad.ndiff

# 4. Synthesize diagnostic explanation and recommended probe:
netdiff explain good.ndiff bad.ndiff

# 5. Run the validation probe in the failing environment:
netdiff probe TEST_INTERFACE_STATE veth-client

# 6. (Optional) Generate an incident report or launch the UI:
netdiff report good.ndiff bad.ndiff -o incident.md
netdiff ui good.ndiff bad.ndiff -p 8080
```

---

## How It Works

```text
Target (host:port)
       │
 Probe Planner
       │
 ┌─────┴───────────┬──────────────┐
 ▼                 ▼              ▼
DNS              Route           TCP
Collector      Collector        Probe
 │                 │              │
 └─────┬───────────┴──────────────┘
       ▼
 Portable Snapshot (.ndiff)
       │
 Snapshot Diff Engine
       │
 Evidence Dependency Graph (DAG)
       │
 Relevance Classification
       │
 ┌─────┴────────────────────────┐
 ▼                              ▼
Deterministic Reasoning     Optional Gemini AI
 │                              │
 └─────┬────────────────────────┘
       ▼
 Diagnostic Explanation & Next-Best Probe
       │
 ┌─────┴───────────┬──────────────┐
 ▼                 ▼              ▼
CLI Output    Web Dashboard    Markdown Report
```

1. **Target-Bounded State Collection**: Rather than dumping entire system configurations, NetDiff only queries the state relevant to the specified destination: kernel FIB route lookup (`ip route get`), matching policy routing rules (`ip rule`), egress link state, MTU, ARP neighbor entries, and TCP dial results.
2. **Semantic Normalization**: Eliminates dynamic noise such as ephemeral ports, interface index numbers, and loopback variations across hosts.
3. **Evidence Dependency Graph (DAG)**: NetDiff models the packet path as a sequence:
   $$\text{Hostname} \rightarrow \text{DNS} \rightarrow \text{Destination IP} \rightarrow \text{Policy Rule} \rightarrow \text{Route Table} \rightarrow \text{Route Lookup} \rightarrow \text{Gateway/Src/Iface} \rightarrow \text{MTU} \rightarrow \text{TCP}$$
   The earliest divergent node along this dependency chain represents the primary path divergence.
4. **Relevance Scoring**: Differences are ranked by causal probability. For instance, if a TCP connection encounters `ECONNREFUSED` (TCP RST), the path is fully reachable, and routing differences are downgraded in relevance.
5. **Deterministic Diagnostics**: Explanations operate completely offline without external API dependencies. Optional LLM synthesis (`--ai`) is bounded by the same structured evidence.
6. **Closed-Loop Validation**: Recommended follow-up tests are selected strictly from a fixed catalog of safe validation probes.

---

## Diagnosed Failure Scenarios

NetDiff is designed to accurately identify and distinguish between common network failure modes:

| Scenario | Symptom Observed | NetDiff Diagnostic Finding | Recommended Probe |
|---|---|---|---|
| **Interface Disabled** | `RTNETLINK: Network is unreachable`; TCP unreachable | Route lookup failure; identifies disabled interface | `TEST_INTERFACE_STATE` (returns DOWN) |
| **Missing Route** | `RTNETLINK: Network is unreachable`; interface is UP | Route lookup failure; verifies interface is UP, isolating missing route | `TEST_INTERFACE_STATE` (returns UP) |
| **Firewall Packet Drop** | TCP connect timeout; route & interface functional | Active packet filtering (`iptables`/`nftables`) identified during timeout | `TEST_DIRECT_IP` |
| **DNS Misconfiguration** | Resolution failure; transport unattempted | DNS resolution failure isolated upstream of IP routing | `TEST_DNS_WITH_RESOLVER` |
| **TCP Port Closed** | TCP connection refused (`ECONNREFUSED` / RST) | Full network reachability confirmed; endpoint service is down | `TEST_DIRECT_IP` |

---

## Validation Probe Catalog

| Probe Name | Parameter | Requires Target | Description |
|---|---|:---:|---|
| `TEST_INTERFACE_STATE` | Interface name (e.g. `eth0`) | No | Inspects interface existence, administrative state (`UP`), and operational state (`operstate`) |
| `TEST_TCP_BIND_INTERFACE` | Interface name (e.g. `tun0`) | Yes | Binds socket to interface via `SO_BINDTODEVICE` to test bypass |
| `TEST_TCP_BIND_SOURCE` | Source IP (e.g. `10.8.0.14`) | Yes | Binds socket to specific local source address |
| `TEST_DNS_WITH_RESOLVER` | Resolver IP (e.g. `10.10.0.2`) | Yes | Queries specified DNS server directly to test record presence |
| `TEST_PROXY_DISABLED` | (none) | Yes | Bypasses `HTTP(S)_PROXY` environment variables to test direct egress |
| `TEST_DIRECT_IP` | Destination IP | Yes | Connects directly to IP to isolate transport drops from DNS |

---

## CLI Reference

| Command | Description |
|---|---|
| `netdiff diagnose <target> [-b file.ndiff] [-u] [--validate]` | Single-command diagnosis comparing against saved baseline |
| `netdiff check <target>` | Fast reachability probe with one-line status summary |
| `netdiff capture <target> [-o file.ndiff]` | Capture target network state to console or `.ndiff` snapshot |
| `netdiff compare <good> <bad> [-v] [-j]` | Compare two snapshots and highlight causal differences |
| `netdiff explain <good> <bad> [--ai] [--validate]` | Synthesize diagnostic explanation and recommended validation probe |
| `netdiff report <good> <bad> [-o file.md]` | Generate Markdown incident report for Slack or Jira |
| `netdiff ui <good> <bad> [-p 8080]` | Launch interactive browser visualizer comparing dual dependency DAGs |
| `netdiff probe <name> [param] [-t <target>]` | Execute a bounded diagnostic validation probe |
| `netdiff version` | Display version information |

---

## Testing & Laboratory

### Unprivileged Unit Tests
Runs the test suite across all platforms without root permissions:
```bash
go test -v ./...
```

### Reproducible Network Laboratory (`scripts/lab/`)
NetDiff includes an isolated Linux network namespace laboratory (`nd-client` and `nd-server` connected via `veth` pair):

```bash
# Run all five scenarios automatically:
sudo ./scripts/lab/lab.sh run-all

# Or run individual steps:
sudo ./scripts/lab/lab.sh setup              # Set up namespaces and mock servers
sudo ./scripts/lab/lab.sh baseline           # Capture good.ndiff
sudo ./scripts/lab/lab.sh inject iface-down  # Inject a fault
sudo ./scripts/lab/lab.sh capture bad        # Capture failing snapshot
sudo ./scripts/lab/lab.sh verify iface-down  # Compare and execute validation probe
sudo ./scripts/lab/lab.sh cleanup            # Tear down namespaces
```

---

## Building

```bash
# Build local binary
go build -o netdiff ./cmd/netdiff

# Cross-compile for Linux AMD64
GOOS=linux GOARCH=amd64 go build -o netdiff ./cmd/netdiff
```
