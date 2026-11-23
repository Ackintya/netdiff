# NetDiff — LinkedIn Launch & Multimedia Presentation Playbook

This playbook provides turnkey, high-converting social media posts, carousel decks, and multimedia assets designed to showcase **NetDiff** to DevOps, SRE, Network Engineers, Platform Engineers, and Software Engineers on LinkedIn, Twitter/X, and technical forums.

---

## 🎨 Multimedia Asset Inventory

All graphics are designed in vector SVG for resolution-independent scaling (sharp on Retina/4K displays):

| Asset | File Path | Aspect Ratio | Recommended Usage |
|---|---|---|---|
| **Causal DAG Terminal Simulation** | [`assets/causal_dag_terminal.svg`](causal_dag_terminal.svg) | 1200 × 860 (4:3) | **Primary Hero Image** for Post 1; showcases the ASCII tree, root cause isolation, and guarded remediation commands. |
| **8-Layer Causal Architecture Infographic** | [`assets/architecture_infographic.svg`](architecture_infographic.svg) | 1200 × 780 (16:10) | **Systems Architecture Image** for Post 2; diagrams the 8-layer flow, dual deterministic/Gemini core, and SRE automation. |
| **Hero Brand Banner** | [`assets/banner.svg`](banner.svg) | 1200 × 340 (3.5:1) | **GitHub Hero Header**, LinkedIn article cover, or profile header. |
| **Vector Emblem Logo** | [`assets/logo.svg`](logo.svg) | Square (1:1) | Project avatar, favicon, or carousel watermark. |

> **Pro-Tip for LinkedIn**: LinkedIn accepts SVG natively in markdown articles, or you can export these SVGs directly to crisp PNG/JPEG using `inkscape`, `rsvg-convert`, or an online SVG converter (e.g. at 2400 × 1720 for ultra-sharp Retina rendering).

---

## 🚀 Post 1: The Engineer Story (High Viral Engagement)

**Target Audience:** SREs, Platform Engineers, DevOps, Backend Developers  
**Recommended Attachment:** [`assets/causal_dag_terminal.svg`](causal_dag_terminal.svg)

```markdown
Every engineer has lived through this nightmare:

Developer A: "api.internal.corp:443 works perfectly on my laptop."
Developer B: "api.internal.corp:443 completely times out on staging."

So the manual triage routine begins:
• ping (tells you nothing about port 443)
• traceroute (hides asymmetric return paths)
• ip route / ip rule (dumps 150 irrelevant subnets)
• iptables / nftables (hundreds of lines of packet filters)
• curl -v (fails, but doesn't tell you WHY)

After 2 hours of comparing terminal text side-by-side, someone notices a missing `ip rule lookup 200` policy routing entry.

We got tired of this manual guessing game, so we built NetDiff (written in Go, 100% open source).

NetDiff turns network troubleshooting into a semantic differential:

1️⃣ Capture relevant state:
   $ netdiff capture api.internal.corp:443 -o good.ndiff
   $ netdiff capture api.internal.corp:443 -o bad.ndiff

2️⃣ Pinpoint the root cause with a Causal DAG:
   $ netdiff graph good.ndiff bad.ndiff

Instead of dumping 94 network differences, NetDiff traces the 8-layer network flow (DNS ➔ Policy Rules ➔ FIB Routing ➔ Interfaces ➔ ARP ➔ Firewalls ➔ TLS ➔ TCP Socket) and isolates the EARLIEST divergence in 15ms.

3️⃣ Guarded Automated Fix with Auto-Rollback:
   $ netdiff fix good.ndiff bad.ndiff --apply

NetDiff applies the verified remediation command, runs an active canary probe, and AUTOMATICALLY ROLLS BACK if connection does not recover. Zero operator risk.

4️⃣ Natural Language Q&A:
   $ netdiff ask good.ndiff bad.ndiff "Is this blocked by firewall or routing?"

100% offline-first. Zero external dependencies. Optional Gemini AI reasoning when you need deep conversational explanations.

Check it out and give it a star on GitHub:
👉 https://github.com/Ackintya/netdiff

What's the weirdest networking bug you've ever had to debug across environments? Drop it below! 👇

#golang #networking #devops #sre #cloudengineering #linux #kubernetes #platformengineering #opensource
```

---

## 🔬 Post 2: Deep-Dive Systems Architecture

**Target Audience:** Network Architects, Staff SREs, Kernel & Linux Systems Engineers  
**Recommended Attachment:** [`assets/architecture_infographic.svg`](architecture_infographic.svg)

```markdown
Why do ping, traceroute, and curl fail at diagnosing modern Linux network outages?

Because modern network stacks are NOT linear:
• Advanced Policy Routing (FIB rule priorities and tables 1-255)
• Network namespaces and virtual ethernet pairs (veth)
• Intermediate container overlay networks (Calico, Cilium, WireGuard)
• Kernel socket drops and path MTU blackholes
• Asymmetric egress routing

When two machines have 94 network differences, 92 of them are noise. Only 2 matter to your target socket.

We designed NetDiff around a Dual-Core Diagnostic Architecture:

🔹 1. The 8-Layer Causal Flow Engine
NetDiff evaluates network dependencies in strict causal order:
1. DNS Resolution (Nameserver latency, A/AAAA records)
2. IP Policy Routing (ip rule priorities)
3. Kernel FIB Routing (Prefix match, egress dev, gateway)
4. Network Interfaces (OperState UP/DOWN, MTU, link flags)
5. Neighbor Table (ARP/NDP MAC mapping, REACHABLE vs FAILED)
6. Host Firewall Filtering (nftables/iptables OUTPUT drops)
7. TLS Handshake & X.509 (Cert trust, cipher suite, SANs)
8. Kernel TCP_INFO Telemetry (RTTus, retransmissions, lost packets)

🔹 2. Dual Diagnostic Cores
• Local Deterministic Causal Engine: Zero external calls. Runs 100% offline inside air-gapped datacenters. Resolves root cause in 15ms.
• Bounded Gemini AI Reasoning Layer: Type-safe JSON schema enforcement. Powers natural-language debugging via `netdiff ask`.

🔹 3. Closed-Loop SRE Tooling
• `netdiff graph`: Visual terminal ASCII/Unicode causal DAG tree
• `netdiff fix --apply`: Guarded automated remediation with canary probe & automatic rollback
• `netdiff watch`: Proactive baseline drift auditor streaming NDJSON alerts before customer-facing outages occur
• `netdiff report --html`: Standalone offline interactive HTML incident report

See the full architectural breakdown below ⬇️

GitHub repository:
👉 https://github.com/Ackintya/netdiff

#networking #linux #kernel #sre #platformengineering #golang #devops #infrastructure
```

---

## 📑 7-Slide LinkedIn Carousel Outline (PDF Document)

Export the slides below into a 1080 × 1350 (4:5 portrait) PDF carousel for maximum LinkedIn reach:

### Slide 1: Cover
* **Headline:** "Works on my machine." The death of manual network triage.
* **Sub-headline:** Why comparing `ip route`, `iptables`, and `curl -v` by hand wastes 3 hours of SRE time.
* **Visual:** NetDiff neon emblem with split working/failing connection icons.

### Slide 2: The Core Problem
* **Headline:** 94 differences found. Only 2 matter.
* **Body:**
  * Two machines always have different subnets, docker bridges, and local routes.
  * Generic tools dump all of them.
  * Engineers drown in irrelevant configuration diffs.

### Slide 3: The 8-Layer Causal Flow
* **Headline:** How NetDiff models network dependencies.
* **Body:**
  * Step 1: DNS ➔ Step 2: Policy Rules ➔ Step 3: FIB Routing ➔ Step 4: Interface Link & MTU ➔ Step 5: Neighbor ARP ➔ Step 6: Firewall ➔ Step 7: TLS ➔ Step 8: Kernel TCP_INFO.
* **Visual:** Diagram extracted from `architecture_infographic.svg`.

### Slide 4: Real-World Case Study (The VPN Drop)
* **Headline:** From 2 hours of debugging to 15 milliseconds.
* **Terminal output:**
  ```text
  ✗ [2] Policy Routing [DIVERGENT] ◄── EARLIEST DIVERGENCE (ROOT CAUSE)
    └── tun0 (VPN) ≠ eth0 (fallback default)
  ```
* **Visual:** Highlighted snippet from `causal_dag_terminal.svg`.

### Slide 5: Guarded Fix with Automatic Rollback
* **Headline:** Safe Automated Remediation (`netdiff fix`)
* **Body:**
  1. Synthesizes verified bash commands.
  2. Runs immediate canary socket probe.
  3. Automatically rolls back if connection does not recover.
  * Zero risk to production routes or iptables.

### Slide 6: Proactive Baseline Drift Auditor
* **Headline:** Catch outages BEFORE customers notice (`netdiff watch`)
* **Body:**
  * Continuously audits live endpoints against saved baselines (`~/.netdiff/baselines/`).
  * Emits instant terminal alerts and NDJSON event streams for SIEM/Datadog.

### Slide 7: Call to Action
* **Headline:** Try it in 30 seconds.
* **Body:**
  * Single static Go binary. Zero dependencies. Linux, macOS, and Windows.
  * `go install github.com/Ackintya/netdiff/cmd/netdiff@latest`
  * Or test inside network namespaces with `bash scripts/demo_setup.sh`.
* **Link:** `github.com/Ackintya/netdiff`

---

## 🎬 30-Second Video / GIF Recording Guide

To create a viral terminal GIF/video:
1. Run `bash scripts/demo_setup.sh` inside an Ubuntu VM or Docker container.
2. Record using [vhs](https://github.com/charmbracelet/vhs) or [asciinema](https://asciinema.org/):
   ```bash
   vhs demo.tape
   ```
3. The demo automatically:
   - Sets up isolated network namespaces (`ndiff-good` and `ndiff-bad`)
   - Demonstrates the Causal DAG divergence
   - Runs `netdiff ask`
   - Executes guarded automated fix with canary probe
   - Shows connection recovery inside `ndiff-bad`
   - Generates the standalone HTML report
