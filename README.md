# NetDiff (v0.4.0)

> **“It works on my machine. Why?”**

NetDiff is a deterministic, evidence-based Linux network diagnostic tool. It compares a working network environment against a failing environment, identifies structural path differences, and provides causal diagnostic explanations and recommended validation probes.

Instead of manually running dozens of ad-hoc commands (`ip route`, `ip rule`, `iptables`, `resolvectl`, `netstat`, `ethtool`) and guessing which difference matters, NetDiff captures target-specific network state into portable `.ndiff` snapshots and systematically isolates the failure.

---

## Key Capabilities (v0.4 Milestone)

- **Reproducible Fault Diagnosis**: Distinguishes five common network failure modes:
  1. **Interface disabled** (administrative DOWN vs link down vs missing)
  2. **Missing or incorrect route** (route lookup failure with interface UP)
  3. **Firewall blocks TCP** (packet filtering drop symptoms vs route issues)
  4. **DNS misconfiguration** (name resolution failure isolated from transport)
  5. **TCP port closed** (active TCP RST refused vs unreachability or timeout)
- **Causal Evidence DAG**: Traces `Hostname → DNS → DestIP → Policy Rule → Route Table → Route Lookup → Gateway/Src/Iface → MTU → TCP` to pinpoint the earliest path divergence.
- **Closed-Loop Validation Probes**: Fixed, safe validation probes (`TEST_INTERFACE_STATE`, `TEST_TCP_BIND_INTERFACE`, `TEST_TCP_BIND_SOURCE`, `TEST_DNS_WITH_RESOLVER`, `TEST_PROXY_DISABLED`, `TEST_DIRECT_IP`) to confirm or refute diagnostic hypotheses.
- **Evidence Before Explanation**: Refuses to fabricate assumed interfaces, gateways, or fallbacks when data is missing.
- **Deterministic First**: Full diagnostic reasoning operates entirely offline without external API dependencies. Optional Gemini synthesis is available via `--ai`.
- **Interactive UI & Markdown Reports**: Interactive browser dashboard (`netdiff ui`) visualizing dual dependency graphs, and incident markdown reports (`netdiff report`) ready for Slack, Jira, or post-mortems.

---

## Architecture Overview

```text
Target Endpoint (e.g., api.corp:443 or 10.10.0.2:8080)
                     │
              Probe Planner
                     │
    ┌────────────────┼────────────────┬──────────────┐
    ▼                ▼                ▼              ▼
   DNS             Route          Interface         TCP
Collector        Collector        Collector        Probe
(Resolver/IPs)  (FIB / ip rule) (Flags/Operstate) (Connect/RST)
    │                │                │              │
    └────────────────┼────────────────┴──────────────┘
                     ▼
       Portable Snapshot File (.ndiff)
                     │
              Snapshot Diff Engine
                     │
         Evidence Dependency Graph (DAG)
                     │
         Relevance Classification Engine
                     │
     ┌───────────────┴───────────────┐
     ▼                               ▼
Deterministic Engine         Optional Gemini AI Layer
(Evidence Synthesis)          (Structured Synthesis)
     │                               │
     └───────────────┬───────────────┘
                     ▼
          Diagnostic Explanation
                     │
     ┌───────────────┼───────────────┐
     ▼               ▼               ▼
CLI Output      Interactive UI    Markdown Incident
(Console Diffs)  Dashboard (DAG)   Report Generator
                     │
                     ▼
         Follow-Up Validation Probe
        (e.g., TEST_INTERFACE_STATE)
```

---

## Quickstart Workflow

```bash
# 1. Capture target network state in the working environment:
netdiff capture 10.10.0.2:8080 -o good.ndiff

# 2. Capture target network state in the failing environment:
netdiff capture 10.10.0.2:8080 -o bad.ndiff

# 3. Compare snapshots anywhere:
netdiff compare good.ndiff bad.ndiff

# 4. Generate deterministic diagnostic explanation & recommended probe:
netdiff explain good.ndiff bad.ndiff

# 5. Execute recommended validation probe in the failing environment:
netdiff probe TEST_INTERFACE_STATE veth-client

# 6. Generate an incident report for Jira/Slack:
netdiff report good.ndiff bad.ndiff -o incident.md
```

---

## The Five Acceptance Scenarios

NetDiff v0.4 accurately characterizes and distinguishes five common Linux network failure modes:

| Failure Scenario | Injected Fault | Observed Symptom | NetDiff Diagnosis | Recommended Probe |
|---|---|---|---|---|
| **1. Interface Disabled** | `ip link set veth-client down` | `RTNETLINK: Network is unreachable`; TCP unreachable | Route lookup failure; identifies previously working interface | `TEST_INTERFACE_STATE` (returns DOWN) |
| **2. Missing Route** | `ip route del 10.10.0.0/24` | `RTNETLINK: Network is unreachable`; interface is UP | Route lookup failure; verifies interface is UP, isolating missing route | `TEST_INTERFACE_STATE` (returns UP) |
| **3. Firewall Blocks TCP** | `iptables -A OUTPUT -p tcp --dport 8080 -j DROP` | TCP connect timeout; route & interface intact | Identifies active packet filtering (`nftables`/`iptables`) during timeout | `TEST_DIRECT_IP` |
| **4. DNS Misconfiguration** | Unreachable nameserver or bad resolver | DNS lookup error; transport unattempted | DNS resolution failure upstream of IP routing | `TEST_DNS_WITH_RESOLVER` |
| **5. TCP Port Closed** | Service not listening on target port | TCP connection refused (`ECONNREFUSED` / RST) | Full network reachability confirmed; service down | `TEST_DIRECT_IP` |

---

## Automated Linux Network Laboratory (`scripts/lab/`)

NetDiff includes a reproducible fault-injection laboratory using Linux network namespaces and virtual Ethernet (`veth`) pairs:

```text
nd-client (10.10.0.1/24) <======== veth pair ========> nd-server (10.10.0.2/24)
   veth-client                                             veth-server
                                                        Mock HTTP (8080)
                                                        Mock DNS  (53)
```

The laboratory is fully isolated from host Wi-Fi, Ethernet, and default routes. Mock HTTP servers run from a dedicated temporary directory (`/tmp/netdiff-lab/www`) rather than the repository root.

### Laboratory Commands

```bash
# Run all five scenarios end-to-end automatically:
sudo ./scripts/lab/lab.sh run-all

# Or run individual steps manually:
sudo ./scripts/lab/lab.sh setup              # Set up namespaces and mock servers
sudo ./scripts/lab/lab.sh baseline           # Capture good.ndiff
sudo ./scripts/lab/lab.sh inject iface-down  # Inject a fault (or route-missing, firewall-drop, dns-failure, port-closed)
sudo ./scripts/lab/lab.sh capture bad        # Capture failing snapshot
sudo ./scripts/lab/lab.sh verify iface-down  # Run compare, explain, and validation probe
sudo ./scripts/lab/lab.sh restore            # Restore to clean baseline
sudo ./scripts/lab/lab.sh cleanup            # Tear down namespaces and servers
```

---

## Validation Probe Catalog

Probes execute bounded, safe follow-up actions to test diagnostic hypotheses:

| Probe Name | Parameter | Target Required | Purpose |
|---|---|:---:|---|
| `TEST_INTERFACE_STATE` | Interface name (e.g. `eth0`) | No | Inspects interface existence, administrative state (`UP`), and operational state (`operstate`) |
| `TEST_TCP_BIND_INTERFACE` | Interface name (e.g. `tun0`) | Yes | Binds socket to interface via `SO_BINDTODEVICE` to bypass policy routing |
| `TEST_TCP_BIND_SOURCE` | Source IP (e.g. `10.8.0.14`) | Yes | Binds socket to specific local source address |
| `TEST_DNS_WITH_RESOLVER` | Resolver IP (e.g. `10.10.0.2`) | Yes | Queries specified DNS server directly to test zone record presence |
| `TEST_PROXY_DISABLED` | (none) | Yes | Bypasses `HTTP(S)_PROXY` environment variables to test direct egress |
| `TEST_DIRECT_IP` | Destination IP | Yes | Connects directly to IP to isolate transport drops from DNS |

---

## Interactive UI (`netdiff ui`)

Launch the visual dashboard comparing working and failing dependency DAGs:

```bash
netdiff ui good.ndiff bad.ndiff -p 8080
```

Opens a dual dependency graph rendering each stage (`DNS`, `Policy Rule`, `Route Table`, `Route Lookup`, `Gateway`, `Source Address`, `Egress Interface`, `MTU`, `TCP`), highlighting the earliest divergence and providing interactive inspection.

---

## Building & Testing

### Prerequisites
- Go 1.22+ (tested with Go 1.26+)
- Linux (for network namespaces and FIB routing) or WSL2 on Windows
- `ip`, `iptables`, `python3` (for the automated laboratory)

### Unprivileged Unit Tests
Normal unit tests run on any platform (Linux, macOS, Windows) without root privileges:
```bash
go test -v ./...
```

### Privileged Linux Integration Tests
Integration tests verifying namespace isolation and fault injection:
```bash
sudo ./scripts/lab/lab.sh run-all
# Or via Go test tag:
sudo go test -v -tags integration ./test/integration/...
```

### Building Binary
```bash
go build -o netdiff ./cmd/netdiff
```

---

## Troubleshooting & FAQ

**Q: Why does `netdiff capture` fail with permission denied on raw sockets or iptables?**  
A: Packet capture and netfilter rule inspection (`iptables -S`) require elevated network privileges (`CAP_NET_ADMIN` or `sudo`). Route lookups and TCP connectivity probes run as normal users.

**Q: Can I compare snapshots captured on different operating systems?**  
A: Yes. `.ndiff` snapshots are portable JSON documents. You can capture a snapshot on a remote Linux server and compare it on your local developer machine.

**Q: Does NetDiff modify host network configuration?**  
A: Never. NetDiff CLI commands (`capture`, `compare`, `explain`, `report`, `probe`) only read network state and perform standard user-space dial tests. The laboratory harness (`scripts/lab/lab.sh`) creates isolated network namespaces and never touches host default routes.

---

## Known Limitations

1. **Kernel FIB Queries**: Kernel FIB route queries (`ip route get`) and socket interface binding (`SO_BINDTODEVICE`) are Linux-specific kernel features. On macOS and Windows, NetDiff falls back to standard routing table information without FIB policy evaluation.
2. **Local vs. Remote Probe Execution**: Validation probes run in the execution environment where the CLI is invoked. If snapshots were captured inside remote servers or network namespaces, validation probes should be executed within that target namespace (e.g. `ip netns exec <ns> netdiff probe ...`).
3. **Encrypted Overlay Tunnels**: NetDiff inspects kernel interface flags, MTU, and routing tables, but does not inspect inner VXLAN or Geneve encapsulated payloads.
