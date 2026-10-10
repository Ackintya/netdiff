Here is the full project plan I’d use now, incorporating the strongest version of **NetDiff** plus the bounded Gemini reasoning layer.

# NetDiff

## One-line pitch

**NetDiff explains why a network connection works in one environment and fails in another.**

The core problem is the classic:

> “It works on my machine.”

Instead of manually comparing route tables, DNS, interfaces, VPN state, proxy settings, TCP behavior, MTU, and firewall configuration, NetDiff captures only the network state relevant to a target connection and identifies the differences most capable of explaining the failure.

The key idea is not generic diagnostics.

The key idea is:

> **Compare a known-good environment against a failing environment and rank the differences that matter to this specific connection.**

---

# 1. Product goal

NetDiff is aimed at:

- software engineers
- network engineers
- SREs
- platform engineers
- DevOps engineers
- infrastructure engineers

Typical situation:

```text
Developer A:
api.internal.company:443 works

Developer B:
api.internal.company:443 times out
```

Today, troubleshooting often becomes:

```text
ip addr
ip route
ip rule
resolvectl
dig
curl -v
ss
traceroute
nft
VPN status
proxy environment
...
```

Then somebody manually compares outputs.

NetDiff turns that into:

```bash
netdiff capture api.internal.company:443 --output good.ndiff
```

on the working environment,

and:

```bash
netdiff capture api.internal.company:443 --output bad.ndiff
```

on the broken environment.

Then:

```bash
netdiff compare good.ndiff bad.ndiff
```

NetDiff produces:

```text
Target
api.internal.company:443

WORKING                    FAILING

DNS
10.40.8.21                 10.40.8.21
✓ same

Route
table 200                  main
⚠ different

Egress
tun0                       eth0
⚠ different

Source
10.8.0.14                  192.168.1.84
⚠ different

TCP
connected                  timeout
✗ different


HIGH-RELEVANCE DIFFERENCE

The failing environment routes the destination
through eth0 rather than the VPN interface tun0.

This difference can explain the observed TCP timeout.
```

---

# 2. What makes NetDiff different

NetDiff should NOT become:

> “A script that runs ping, dig, traceroute and curl.”

Many tools already do generic network diagnostics.

NetDiff's differentiator is **semantic comparison**.

Suppose two machines have 94 networking differences.

NetDiff should not output:

```text
94 differences found
```

It should determine:

```text
94 total differences

2 HIGH relevance
4 MEDIUM relevance
88 irrelevant to this target
```

For example:

```text
HIGH
Route for destination differs

HIGH
Selected source address differs

MEDIUM
MTU differs

LOW / IGNORED
Interface indexes differ

LOW / IGNORED
Temporary IPv6 addresses differ
```

That filtering/ranking engine is the heart of the project.

---

# 3. Core mental model

NetDiff should reason about a specific connection as a dependency chain.

For a target:

```text
api.foo.com:443
```

the simplified path is:

```text
Hostname
   |
   v
DNS resolution
   |
   v
Destination IP
   |
   v
Policy-routing rules
   |
   v
Routing-table lookup
   |
   v
Source-address selection
   |
   v
Next hop
   |
   v
Egress interface
   |
   v
Local policy / MTU
   |
   v
TCP connection
```

NetDiff compares these chains between working and failing environments.

Conceptually:

```text
             WORKING                FAILING

api.foo.com              api.foo.com
     |                        |
     v                        v
10.40.8.21              10.40.8.21
     |                        |
     v                        v
rule 100                 rule 0
     |                        |
     v                        v
table 200                main
     |                        |
     v                        v
tun0                     eth0
     |                        |
     v                        v
CONNECTED                TIMEOUT
```

The first significant divergence becomes highly relevant.

That is a powerful and understandable model.

---

# 4. V1 scope

V1 should be deliberately narrow.

## Input

One hostname/IP and TCP port.

Examples:

```bash
netdiff capture github.com:443
netdiff capture 10.0.8.14:5432
netdiff capture redis.internal:6379
```

## Platform

**Linux only.**

Do not support Windows or macOS initially.

## V1 collects

### DNS

- hostname
- resolver configuration
- resolved A/AAAA addresses
- resolution success/failure
- resolution latency

### Routing

- selected route to destination
- routing table
- relevant policy-routing rule
- source IP
- next hop
- route metric
- ECMP/nexthop where straightforward

### Interface

- selected egress interface
- interface state
- address
- MTU
- interface type where identifiable

### Neighbor

Where relevant:

- next-hop neighbor entry
- ARP/NDP state

### TCP

- connect success
- timeout
- connection refused
- reset
- latency

These should be represented as different outcomes rather than just:

```text
TCP FAILED
```

### Environment

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `NO_PROXY`
- relevant lowercase variants

---

# 5. Explicitly OUT of V1

Do not initially build:

- eBPF
- packet capture
- Kubernetes
- Docker analysis
- VXLAN parsing
- BGP
- SDN controller
- distributed agents
- historical monitoring
- automatic remediation
- arbitrary firewall-rule reasoning
- Windows
- macOS
- web dashboard
- AI-generated shell commands

These are expansion opportunities.

They are not prerequisites.

The first objective is to prove:

> **NetDiff can reliably explain several real “works here, fails there” cases.**

---

# 6. Architecture

Use Go for the core.

```text
                  CLI
                   |
                   v
             Target Parser
                   |
                   v
              Probe Planner
                   |
        +----------+----------+
        |          |          |
        v          v          v
      DNS       Netlink      TCP
   Collector    Collector    Probe
        |          |          |
        +----------+----------+
                   |
                   v
            Raw Snapshot
                   |
                   v
              Normalizer
                   |
                   v
          Semantic Snapshot
                   |
          +--------+--------+
          |                 |
          v                 v
      Snapshot A        Snapshot B
          |                 |
          +--------+--------+
                   |
                   v
              Diff Engine
                   |
                   v
          Relevance Engine
                   |
                   v
          Evidence Bundle
                   |
          +--------+---------+
          |                  |
          v                  v
 Deterministic Output   Gemini Reasoner
                             |
                             v
                     Explanation /
                     next-best probe
```

---

# 7. Major components

## A. Target parser

Input:

```text
api.example.com:443
```

Produces:

```text
host = api.example.com
port = 443
protocol = TCP
```

Later it could support UDP, but not initially.

---

# 8. Probe planner

The probe planner determines what information is necessary for the target.

For:

```text
api.foo.com:443
```

it could schedule:

```text
resolve hostname
identify target IP
lookup route
identify source address
identify egress interface
inspect interface
inspect relevant neighbor
attempt TCP connection
capture proxy environment
```

The planner prevents NetDiff from indiscriminately collecting the entire machine.

That keeps the tool target-specific.

---

# 9. Collectors

Each collector should have a narrow responsibility.

Conceptually:

```go
type Collector interface {
    Collect(ctx context.Context, target Target) (Evidence, error)
}
```

Possible collectors:

```text
DNSCollector
RouteCollector
InterfaceCollector
NeighborCollector
TCPCollector
ProxyCollector
```

Later:

```text
TLSCollector
FirewallCollector
ContainerCollector
EBPFCollector
```

---

# 10. Linux data collection

Prefer native APIs where practical.

## Interfaces

Use Linux netlink.

Collect:

- interface names
- indexes
- addresses
- flags
- MTU
- operational state

Go libraries can simplify netlink access.

## Routing

Use netlink to obtain:

- route to destination
- table
- gateway
- interface
- preferred source
- route metric

Policy routing should also eventually come from netlink.

## Neighbor information

Use the neighbor table through netlink.

Example:

```text
10.0.0.1
state: REACHABLE
interface: eth0
MAC: ...
```

## DNS

This needs care.

Start with:

- `/etc/resolv.conf`
- Go resolver result
- possibly systemd-resolved information

Later improve resolver attribution.

Do not spend three weeks trying to perfectly model every Linux resolver setup in V1.

## TCP

Use Go networking APIs initially.

Capture:

```text
success
refused
timeout
reset
latency
```

Later lower-level instrumentation can expose:

- SYN retries
- RTT
- retransmissions

## Proxy

Read environment variables.

Simple and useful.

## Firewall

Probably defer real semantic firewall analysis.

V1 can optionally detect:

```text
nftables active
iptables active
```

but should not pretend to understand every rule.

---

# 11. Snapshot format

A capture should produce a portable structured file.

For example:

```text
good.ndiff
bad.ndiff
```

Internally perhaps JSON initially.

Conceptually:

```text
Snapshot

metadata
target

dns
route
policyRouting
source
interface
neighbor
tcp
proxy

collectionErrors
timestamp
version
```

Example:

```json
{
  "target": {
    "hostname": "api.foo.com",
    "port": 443,
    "protocol": "tcp"
  },
  "dns": {},
  "route": {},
  "interface": {},
  "tcp": {},
  "proxy": {}
}
```

The format should include a schema version because this could become a real interchange format.

---

# 12. Semantic normalization

This is one of the more interesting technical pieces.

Raw state contains machine-specific noise.

Example:

```text
Machine A
ifindex 17
tun0

Machine B
ifindex 6
wg0
```

Raw comparison:

```text
DIFFERENT
```

Semantic comparison might say:

```text
Both:
tunnel/VPN-like egress interfaces
```

NetDiff should separate:

```text
raw value
semantic role
```

For example:

```text
Raw:
interface = tun0

Normalized:
interface_role = tunnel
```

Do this conservatively.

Do not build a giant AI classifier.

Examples of normalization:

```text
interface indexes → ignored

temporary addresses → lower importance

equivalent route semantics → normalized

environment ordering → normalized

DNS result sets → compared as sets

ECMP order → normalized where order does not matter
```

---

# 13. Diff engine

The diff engine compares normalized snapshots.

A difference should be an actual object.

Conceptually:

```text
Difference

category
field
workingValue
failingValue
semanticMeaning
dependencyNode
rawEvidence
```

Example:

```text
category:
routing

field:
egress_interface

working:
tun0

failing:
eth0
```

---

# 14. Relevance engine

This is probably the most important custom logic.

NetDiff should ask:

> Can this difference plausibly affect this connection?

For example:

```text
hostname differs?
irrelevant — target explicitly specified

interface index differs?
irrelevant

DNS result differs?
high relevance

selected route differs?
high relevance

route metric differs but route selected is identical?
low relevance

MTU differs?
medium initially

TCP result differs?
high symptom relevance
```

The ranking should primarily be deterministic.

Possible relevance dimensions:

```text
dependency proximity
causal plausibility
observed symptom consistency
whether downstream state differs
whether the field directly affects target path
```

Example scoring:

```text
route selected differs        +4
egress interface differs      +4
source address differs        +3
TCP outcome differs           +4
MTU differs                   +1
hostname differs               0
ifindex differs                0
```

But don't make this merely arbitrary numbers.

It would be better to represent evidence rules.

Example:

```text
IF
destination IP identical

AND
route differs

AND
TCP succeeds on good

AND
TCP times out on bad

THEN
route divergence = HIGH relevance
```

This gives you explainable ranking.

---

# 15. Evidence graph

A lightweight dependency graph could make the system much stronger.

Example:

```text
DNS
 |
 v
Destination
 |
 v
Policy Rule
 |
 v
Route
 |
 v
Source
 |
 v
Interface
 |
 v
TCP
```

Differences at upstream nodes can affect downstream behavior.

Suppose:

```text
Destination same
Route different
Interface different
TCP different
```

Then the graph makes route divergence much more compelling.

But if:

```text
Route same
Interface same
TCP different
```

NetDiff knows to investigate lower layers instead.

This graph does not need to become a general-purpose graph database.

An in-memory typed DAG is enough.

---

# 16. Deterministic result

NetDiff must work WITHOUT Gemini.

Example:

```text
NETDIFF

Target:
api.foo.com:443

Result:
working host connected
failing host timed out


HIGH RELEVANCE

ROUTING PATH DIFFERS

Working:
table 200 → tun0

Failing:
main → eth0

Why this matters:
The selected route determines where packets for the
destination leave the host.


MEDIUM RELEVANCE

SOURCE ADDRESS DIFFERS

Working:
10.8.0.14

Failing:
192.168.1.81


LOW RELEVANCE

INTERFACE MTU DIFFERS

1500 → 1420
```

This alone must be useful.

---

# 17. Gemini integration

Gemini should sit above the deterministic engine.

Gemini does NOT:

- collect network state
- parse route tables
- decide whether TCP succeeded
- calculate routing decisions
- execute arbitrary shell commands
- replace the relevance engine

Gemini receives a structured evidence bundle.

Example:

```text
Target:
10.40.8.21:443

Observed symptom:
GOOD connects
BAD times out

Same:
DNS result
destination IP
proxy configuration

Different:
routing table
selected interface
source address

Working:
table 200 → tun0

Failing:
main → eth0
```

---

# 18. Gemini responsibility 1: evidence synthesis

Gemini converts structured evidence into a human explanation.

Example:

```text
The routing difference is the strongest current explanation.

Both environments resolve the hostname to the same address,
which makes DNS less likely.

The working environment sends traffic through the VPN,
while the failing environment sends the same destination
through its normal interface.

If the destination is reachable only from the VPN,
this difference can explain the TCP timeout.
```

The model should state uncertainty appropriately.

---

# 19. Gemini responsibility 2: competing hypotheses

Sometimes multiple differences are plausible.

Example:

```text
route differs
MTU differs
TCP behavior differs
```

Gemini could output:

```text
Hypothesis 1
Routing divergence
Confidence: high

Hypothesis 2
MTU-related path issue
Confidence: low

Why:
The failing connection never establishes TCP,
making MTU less likely than route selection.
```

Important:

The confidence is not fake statistical certainty.

Better wording might be:

```text
support: strong
support: moderate
support: weak
```

---

# 20. Gemini responsibility 3: next-best diagnostic probe

This may be the most interesting AI component.

Instead of simply explaining:

```text
Possible VPN routing problem
```

Gemini asks:

> What test would best distinguish between the current hypotheses?

NetDiff exposes a fixed catalog:

```text
TEST_DNS_WITH_RESOLVER

TEST_TCP_BIND_INTERFACE

TEST_TCP_BIND_SOURCE

TEST_ROUTE_LOOKUP

TEST_MTU

TEST_PROXY_DISABLED

TEST_DIRECT_IP

TEST_NEIGHBOR
```

Gemini may choose one.

Example:

```text
Suggested validation:

TEST_TCP_BIND_INTERFACE(tun0)

Reason:
If the failing host succeeds when traffic is forced through
tun0, that would strongly support the routing hypothesis.
```

The NetDiff engine—not Gemini—constructs and executes the test.

---

# 21. Active diagnosis loop

Eventually:

```text
collect
  |
  v
compare
  |
  v
hypothesize
  |
  v
choose next probe
  |
  v
execute safely
  |
  v
collect evidence
  |
  v
update hypothesis
```

Example:

```text
Initial assessment:
VPN routing divergence

Suggested test:
force connection through tun0

Result:
connection succeeds

Updated assessment:
Strong evidence that normal route selection on the failing
environment is responsible.
```

This is much more impressive than:

> “Ask an LLM what's wrong.”

---

# 22. Gemini responsibility 4: incident report generation

After diagnosis:

```bash
netdiff report good.ndiff bad.ndiff
```

could generate:

```text
Incident Summary

Target:
api.internal:443

Working environment:
host-a

Failing environment:
host-b

Observed behavior:
Host A establishes TCP in 27 ms.
Host B times out.

Most significant difference:
Host A routes 10.40.0.0/16 through tun0/table 200.
Host B uses the main table through eth0.

Validation:
Explicit connection through tun0 succeeds on Host B.

Recommended investigation:
Inspect VPN-installed policy-routing rules on Host B.
```

Very useful for:

- support tickets
- Slack
- GitHub issues
- escalation to network teams

---

# 23. Privacy

This matters if sending data to Gemini.

The `.ndiff` snapshot could contain:

- internal hostnames
- private IPs
- DNS servers
- interfaces
- route information

NetDiff should therefore have an explicit:

```bash
netdiff explain --ai
```

rather than automatically sending everything.

Potential later feature:

```bash
netdiff explain --ai --redact
```

where internal identifiers are transformed while preserving relationships.

Example:

```text
api.prod.internal
→ HOST_A

10.40.8.21
→ IP_A
```

The deterministic engine should remain entirely local.

---

# 24. CLI design

Possible interface:

```bash
netdiff capture TARGET
```

Example:

```bash
netdiff capture api.foo.com:443
```

Save:

```bash
netdiff capture api.foo.com:443 -o host-a.ndiff
```

Compare:

```bash
netdiff compare host-a.ndiff host-b.ndiff
```

AI explanation:

```bash
netdiff explain host-a.ndiff host-b.ndiff --ai
```

Detailed output:

```bash
netdiff compare host-a.ndiff host-b.ndiff --verbose
```

JSON:

```bash
netdiff compare host-a.ndiff host-b.ndiff --json
```

---

# 25. Same-machine before/after mode

NetDiff doesn't have to require two physical machines.

Example:

```bash
netdiff capture foo.internal:443 -o before.ndiff
```

Connect VPN.

```bash
netdiff capture foo.internal:443 -o after.ndiff
```

Then:

```bash
netdiff compare before.ndiff after.ndiff
```

Now NetDiff can answer:

> “What networking state did connecting this VPN actually change?”

This dramatically increases usefulness and demoability.

---

# 26. Demo environment

Testing/demo environments should use Linux network namespaces.

Important distinction:

The user does NOT need namespaces.

Namespaces are only for our deterministic demo and tests.

Example demo topology:

```text
                SERVER
            10.40.8.21:8080
                  ^
                  |
        +---------+---------+
        |                   |
       VPN                wrong path
        |                   |
      GOOD                 BAD
```

Good namespace:

```text
10.40.0.0/16 → vpn0
```

Bad namespace:

```text
default → eth0
```

Same application.

Same target.

Different network state.

---

# 27. Signature 30-second demo

The video starts:

```text
“It works on one machine but not another.
Why?”
```

Then:

```text
GOOD

$ curl 10.40.8.21:8080
200 OK
```

Then:

```text
BAD

$ curl 10.40.8.21:8080
timeout
```

Then:

```bash
netdiff compare good.ndiff bad.ndiff
```

Visual output:

```text
               NETDIFF

       WORKING           FAILING

Target
10.40.8.21        =      10.40.8.21

Policy rule
rule 100          !=     missing
    |                       |
    v                       v

Routing
table 200         !=     main
    |                       |
    v                       v

Egress
tun0              !=     eth0
    |                       |
    ✓                       X


LIKELY EXPLANATION

The failing environment bypasses
the VPN route.
```

Then optionally:

```text
AI validation recommendation:

Test the target through tun0.

Run validation?
```

Execute.

```text
✓ connection succeeds through tun0
```

Final:

```text
DIAGNOSIS STRENGTHENED

Missing VPN policy route.
```

That's a very strong demo.

---

# 28. First demo scenarios

Create three polished scenarios.

## Scenario A — routing

Good:

```text
destination → VPN
```

Bad:

```text
destination → default interface
```

This should be the flagship demo.

## Scenario B — DNS

Good:

```text
api.internal
→ corporate resolver
→ 10.40.8.21
```

Bad:

```text
api.internal
→ local resolver
→ NXDOMAIN
```

NetDiff:

```text
DNS resolution diverges before routing occurs.
```

## Scenario C — proxy

Good:

```text
HTTPS_PROXY unset
```

Bad:

```text
HTTPS_PROXY=http://bad-proxy:8080
```

NetDiff identifies the environment divergence.

These three already demonstrate that NetDiff isn't hard-coded for one bug.

---

# 29. Testing strategy

Tests should automatically construct and destroy environments.

Use:

- Linux network namespaces
- veth pairs
- routes
- policy rules
- lightweight HTTP/TCP server
- optional dnsmasq/CoreDNS
- nftables later

Potential integration tests:

### 1. Identical environments

Expect:

```text
no meaningful differences
```

### 2. Missing route

Expect:

```text
routing difference → HIGH
```

### 3. Wrong next hop

Expect:

```text
next-hop difference → HIGH
```

### 4. Different egress interface

Expect:

```text
egress difference → HIGH
```

### 5. DNS success vs NXDOMAIN

Expect:

```text
DNS → HIGH
route comparison not applicable
```

### 6. Different DNS results

Expect:

```text
destination divergence → HIGH
```

### 7. Connection refused

Expect:

```text
remote endpoint reachable
service/listener likely issue
```

This is important.

`ECONNREFUSED` should NOT be diagnosed like timeout.

### 8. TCP timeout

Expect:

```text
network/path/policy investigation
```

### 9. Proxy difference

Expect:

```text
proxy difference relevant
```

### 10. MTU-only difference

Expect:

```text
low/medium unless symptom supports it
```

### 11. Irrelevant interface difference

Add an unused interface to one host.

Expect:

```text
ignored
```

### 12. Different interface indexes only

Expect:

```text
no semantic difference
```

That test demonstrates normalization.

---

# 30. Development phases

## Phase 0 — project skeleton

Goal:

Create professional Go project and CLI.

Build:

```text
netdiff --help
netdiff capture
netdiff compare
```

No deep networking yet.

Learn:

- Go project structure
- CLI handling
- testing

---

## Phase 1 — target + basic probes

Implement:

- target parsing
- DNS resolution
- TCP connection
- basic timing

Example:

```text
Target: google.com:443
DNS: success
TCP: connected
Latency: 21 ms
```

No diff yet.

---

## Phase 2 — Linux networking state

Add:

- route lookup
- source address
- egress interface
- MTU
- next hop
- neighbor state

This is where the project starts becoming genuine systems work.

Learn:

- netlink
- Linux routing
- interface management
- source selection

---

## Phase 3 — snapshot format

Create portable captures.

```bash
netdiff capture foo.com:443 -o machine.ndiff
```

Implement:

- schema
- versioning
- serialization
- validation

---

## Phase 4 — semantic diff

Compare:

```text
DNS
route
interface
source
neighbor
TCP
proxy
```

Build normalization rules.

This should produce useful comparisons before any AI exists.

---

## Phase 5 — relevance engine

Build target-specific reasoning.

Start simple.

Examples:

```text
DNS differs → HIGH

route differs → HIGH

egress differs → HIGH

source differs → MEDIUM/HIGH

MTU differs → MEDIUM

unused interface differs → IGNORE
```

Then improve using dependency relationships.

---

## Phase 6 — dependency graph

Represent:

```text
hostname
↓
destination
↓
route
↓
source
↓
interface
↓
TCP
```

Use the graph to:

- rank differences
- explain propagation
- identify earliest divergence

---

## Phase 7 — polished CLI

Make output visually strong.

Support:

```text
summary
verbose
json
```

Use:

```text
✓ same
⚠ meaningful difference
✗ failure
```

Don't make the output noisy.

---

# 31. First public release

At this point, release:

```text
NetDiff v0.1
```

WITHOUT Gemini.

This is important.

The core tool should already be respectable.

README:

> **Why does the network work here but fail there?**

GIF.

Install command.

Three examples.

Architecture diagram.

---

# 32. Phase 8 — Gemini explanation layer

Then add:

```bash
netdiff explain good.ndiff bad.ndiff --ai
```

Gemini receives:

- structured target
- normalized differences
- probe outcomes
- relevance ranking

NOT raw command dumps.

Gemini returns:

```text
hypotheses
support level
reasoning summary
possible next test
```

Validate output schema.

---

# 33. Phase 9 — bounded active diagnostics

Implement a fixed probe catalog.

Gemini can request:

```text
route lookup
TCP with bound source
TCP with bound interface
alternate resolver
direct-IP connection
small/large packet test
proxy bypass
```

The engine validates the request.

Then executes it.

Gemini never constructs arbitrary commands.

---

# 34. Phase 10 — web visualization

Only after the CLI is genuinely good.

The web interface can visualize two dependency paths.

Example:

```text
                WORKING        FAILING

DNS                ✓              ✓
                   |              |
                   v              v
Destination        same           same
                   |              |
                   v              v
Policy             100          missing  ←
                   |              |
                   v              v
Route              VPN           default ←
                   |              |
                   v              v
TCP                ✓              ✗
```

Click a node:

```text
Route divergence

Working:
table 200
tun0
10.40.0.0/16

Failing:
main
eth0
default route
```

This becomes the LinkedIn visual layer.

---

# 35. Future feature: Docker comparison

Eventually:

```bash
netdiff capture docker:frontend api:8080
```

Compare two containers.

Inspect:

- namespace
- veth
- bridge
- route
- NAT
- bind address

Potential diagnosis:

```text
GOOD
service bound 0.0.0.0:8080

BAD
service bound 127.0.0.1:8080
```

Very strong extension.

---

# 36. Future feature: good flow vs bad flow

Instead of comparing machines:

```bash
netdiff record foo.com:443 --name good
```

Later:

```bash
netdiff record foo.com:443 --name bad
```

Compare runtime behavior.

Potential later signals:

- RTT
- retransmissions
- route changes
- interface changes
- TCP state
- eBPF evidence

---

# 37. Future feature: eBPF

Only add eBPF if it unlocks something valuable.

Examples:

- retransmission visibility
- socket lifecycle
- connect latency
- packet drop evidence
- process attribution

Don't use eBPF purely because it looks impressive.

A good rule:

> If NetDiff cannot answer an important question using normal Linux interfaces, then consider eBPF.

---

# 38. Future feature: Kubernetes

Eventually:

```text
working pod
vs
broken pod
```

Compare:

- DNS
- service endpoints
- NetworkPolicy
- routing
- CNI state
- namespaces

But this is a separate major expansion.

---

# 39. Future feature: remote agent

Instead of manually transferring snapshots:

```text
netdiff agent
```

Controller:

```bash
netdiff compare host-a host-b --target foo:443
```

Then:

```text
host A
  |
  +----\
        controller
  +----/
  |
host B
```

This introduces:

- gRPC
- concurrency
- distributed collection
- authentication
- remote coordination

This would strongly increase the Apple Compute Networking relevance.

But it is a later version.

---

# 40. Proposed Go repository

Something like:

```text
netdiff/

cmd/
  netdiff/

internal/
  target/
  collector/
    dns/
    route/
    interface/
    neighbor/
    tcp/
    proxy/

  snapshot/
  normalize/
  diff/
  relevance/
  evidence/
  probe/
  explain/
  ai/

pkg/
  model/

test/
  integration/
  netns/

examples/

docs/
  architecture.md
  snapshot-format.md
  diagnostics.md

scripts/
```

Avoid creating dozens of tiny packages prematurely.

Start simpler and split when responsibilities become clear.

---

# 41. Technical skills demonstrated

A strong NetDiff implementation demonstrates:

## Go

- interfaces
- concurrency
- contexts
- networking APIs
- structured data
- error handling
- testing

## Linux networking

- interfaces
- routing
- policy routing
- source selection
- ARP/NDP
- MTU
- sockets
- network namespaces

## Network fundamentals

- DNS
- TCP/IP
- route selection
- next hops
- failures
- VPN behavior
- connection semantics

## Systems engineering

- state collection
- normalization
- deterministic reasoning
- evidence modeling
- portable snapshots

## Software architecture

- collectors
- data models
- dependency graphs
- comparison engines
- plugin-like extensibility

## Debugging

Most importantly:

> turning raw system state into an explanation.

---

# 42. What NetDiff does NOT demonstrate strongly

By itself it does not prove:

- line-rate packet processing
- DPDK
- SmartNIC programming
- ASIC programming
- distributed consensus
- BGP implementation
- high-scale SDN controller architecture
- kernel module development

That is okay.

Your Arista experience carries much of the control-plane/networking story.

The project adds independent systems engineering.

---

# 43. Apple Compute Networking relevance

NetDiff helps with:

### Go

Core implementation.

### Networking

Extensive Linux and TCP/IP work.

### Network debugging

This is literally the product.

### Routing

Central to the comparison model.

### Infrastructure software

CLI/tooling, structured state collection, APIs.

### Reliability

Failure analysis and repeatable diagnostics.

### Concurrency

Collectors and probes can run concurrently.

### SDN-style thinking

NetDiff reasons about:

```text
state
→ forwarding decision
→ observed behavior
```

which is closely related to control/forwarding-plane reasoning.

Later remote agents/gRPC can strengthen distributed-systems relevance.

---

# 44. Why this is valuable alongside Arista

Arista demonstrates:

```text
professional network software experience
BGP
EVPN
VXLAN
convergence
forwarding consequences
```

NetDiff demonstrates:

```text
independent systems design
Go
Linux networking
product thinking
diagnostic reasoning
testing
shipping
```

They complement each other.

You don't need the project to recreate your internship.

---

# 45. Why this is valuable alongside RouteLens

Eventually:

```text
RouteLens
browser/network request visibility

NetDiff
environment-to-environment network diagnosis
```

RouteLens demonstrates:

```text
consumer/developer product
Chrome extension
distribution
visual UX
```

NetDiff demonstrates:

```text
systems/network depth
Go
Linux
diagnosis engine
```

Very good combination.

---

# 46. Resume version eventually

If the project reaches the relevance-engine stage:

```text
NetDiff | Go, Linux, TCP/IP, Netlink
```

Potential bullets:

```text
• Built a Linux network diagnostics engine in Go that compares
target-specific DNS, routing, interface, policy-routing, and TCP
state across working and failing environments.

• Designed a semantic diff and dependency-based relevance engine
to rank network-state differences capable of explaining connectivity
failures while filtering unrelated host configuration.

• Developed reproducible namespace-based integration tests for
routing, DNS, proxy, and TCP failure scenarios.
```

Later, with Gemini:

```text
• Added an LLM-assisted reasoning layer over structured diagnostic
evidence to rank hypotheses and select bounded follow-up probes
without delegating network-state collection or execution to the model.
```

That last bullet is actually strong because it shows you used AI thoughtfully rather than bolting a chatbot onto the project.

---

# 47. GitHub README opening

Something like:

```text
# NetDiff

## It works on my machine. Why?

NetDiff compares the network path of a working environment
against a failing one and identifies the differences most
likely to explain the failure.

Instead of comparing dozens of diagnostic commands manually:

    netdiff capture api.internal:443 -o good.ndiff
    netdiff capture api.internal:443 -o bad.ndiff
    netdiff compare good.ndiff bad.ndiff

NetDiff tells you where the two environments diverge.
```

Then immediately show the GIF.

---

# 48. The core rule for the entire project

Every proposed feature should be tested against:

> **Does this help explain why the same connection works here and fails there?**

If not, don't build it yet.

That prevents NetDiff from becoming a generic networking toolbox.

---

# 49. What I would build first

Do NOT start with Gemini.

Do NOT start with UI.

Do NOT start with eBPF.

The first milestone should be:

```bash
netdiff capture google.com:443
```

producing:

```text
DNS
destination
source
route
gateway
interface
MTU
TCP result
```

Then:

```bash
netdiff compare a.ndiff b.ndiff
```

showing a clean semantic diff.

Once those two commands feel genuinely useful, add relevance ranking.

Only after that add Gemini.

---

# 50. Final product vision

The finished system should eventually feel like this:

```text
User:
“This works from my laptop but not from the server.”

             |
             v

          NetDiff

             |
             v

    collect both environments

             |
             v

      normalize network state

             |
             v

       compare dependency paths

             |
             v

     isolate meaningful divergence

             |
             v

     deterministic explanation

             |
             +-----------------+
             |                 |
             v                 v

      show evidence       AI reasoning
                              |
                              v
                     select validation
                           probe
                              |
                              v
                       gather evidence

                              |
                              v

                        conclusion
```

The product promise remains extremely simple:

# **Works here. Fails there. NetDiff tells you what's different that matters.**

That is the version I would commit to building.

The biggest design decision I’d preserve from everything we discussed is: **the Gemini layer comes after the deterministic diagnostic engine, not before it**. That keeps the project technically impressive even if the AI integration is removed entirely.