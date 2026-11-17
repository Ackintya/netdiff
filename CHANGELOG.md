# NetDiff Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-11-17

### Added
- **Validation Probe `TEST_INTERFACE_STATE`**:
  - Registered in validation catalog (`internal/probe/catalog.go`) and reasoner allowed catalog (`internal/ai/gemini.go`).
  - Implements interface existence check, administrative status (`net.FlagUp`), and operational carrier state (`operstate` via sysfs on Linux).
  - Emits structured `InterfaceStateResult` payload on `ProbeResult`.
  - Supports context cancellation and target-independent execution without `--target`.
- **Automated Reproducible Network Laboratory (`scripts/lab/lab.sh`)**:
  - Isolated Linux network namespace harness (`nd-client` and `nd-server`) connected via `veth` pair (`10.10.0.1/24` <-> `10.10.0.2/24`).
  - Supports modular operations: `setup`, `baseline`, `inject <scenario>`, `capture <name>`, `verify <scenario>`, `restore`, `cleanup`, and `run-all`.
  - Isolated mock HTTP service and UDP mock DNS server (`scripts/lab/mock_dns.py`) serving dedicated sandboxes rather than repository root.
  - Integration test harness with `//go:build integration` (`test/integration/lab_test.go`).
- **Five Reproducible Linux Failure Scenarios**:
  1. *Interface Disabled*: Detects lost connectivity, observes route failure, recommends and validates `TEST_INTERFACE_STATE`, confirming administrative DOWN state.
  2. *Missing Route*: Detects route lookup failure while interface remains administratively UP, refuting interface-down hypothesis and confirming route misconfiguration.
  3. *Firewall Drop*: Detects active packet filtering (`nftables` / `iptables`) while TCP times out; ranks firewall difference as HIGH relevance.
  4. *DNS Misconfiguration*: Identifies upstream name resolution failure independently of transport path; recommends `TEST_DNS_WITH_RESOLVER`.
  5. *TCP Port Closed*: Accurately distinguishes TCP RST (`refused`) from route failure or timeout (`unreachable` / `timeout`), confirming complete network path reachability.
- **Continuous Integration (`.github/workflows/ci.yml`)**:
  - Automated formatting verification (`gofmt -l .`).
  - Build validation across Linux AMD64.
  - Race-detected unprivileged unit tests (`go test -v -race ./...`).
  - Privileged Linux network laboratory automated run (`sudo ./scripts/lab/lab.sh run-all`).
- **Centralized Versioning (`pkg/version`)**:
  - Single authoritative version declaration (`version.Version = "0.4.0"`, `version.SchemaVersion = "ndiff/v1"`).

### Changed
- **Diagnostic Engine & Relevance Scoring**:
  - Replaced naive `r.Differences[0].Rationale` summary derivation in `internal/diff/diff.go` with causal path divergence synthesis.
  - Eliminated hardcoded fallback interfaces (`"tun0"`, `"eth0"`) in explanation engine (`internal/ai/gemini.go`).
  - Replaced fabricated interface and route defaults in non-Linux collectors (`iface_other.go`, `route_other.go`) with explicit error indicators.
  - Updated firewall collector (`firewall_linux.go`) to inspect active iptables rules and drop policies via `iptables -S` rather than checking mere procfs module existence.
  - Added interface link state evaluation (administrative UP flag and operational carrier state) to `diffInterface`.
  - Updated dual dependency DAG in interactive UI (`internal/ui/assets/index.html`) to render the `Route Lookup` node.
  - Updated Markdown incident report generator (`internal/report/report.go`) to render `Route Lookup` and `Interface Link State`.
- **Closed-Loop Probe Validation**:
  - Tailored validation assessment in `cmd/netdiff/main.go` to specific probe types instead of assuming every probe tests routing bypass.
  - Added clear execution environment notice alerting users when local probe execution runs outside a target namespace.

### Fixed
- Fixed bug where `netdiff probe` unconditionally required `--target` even for local target-independent probes.
- Fixed syntax and missing import defects in CLI and test packages.
- Formatted all Go files cleanly according to `gofmt`.

---

## [0.3.0] - 2026-10-16
- Initial release with route lookup divergence detection, dual DAG UI server, and report generator.
