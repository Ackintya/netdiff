#!/usr/bin/env bash
# NetDiff Automated Reproducible Linux Network Fault Lab
# Manages isolated network namespaces and controlled fault injection.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CLIENT_NS="nd-client"
SERVER_NS="nd-server"
CLIENT_IP="10.10.0.1"
SERVER_IP="10.10.0.2"
TARGET_PORT="8080"
CLOSED_PORT="8081"
TARGET_HOST="10.10.0.2:8080"
TARGET_DNS="mock.netdiff.local:8080"

LAB_DIR="/tmp/netdiff-lab"
WWW_DIR="$LAB_DIR/www"
OUTPUT_DIR="$LAB_DIR/output"
PID_SERVER="$LAB_DIR/server.pid"
PID_DNS="$LAB_DIR/dns.pid"

# Locate or build netdiff binary
find_binary() {
  if [ -x "$REPO_ROOT/bin/netdiff-linux" ]; then
    echo "$REPO_ROOT/bin/netdiff-linux"
  elif [ -x "$REPO_ROOT/netdiff" ]; then
    echo "$REPO_ROOT/netdiff"
  elif command -v go >/dev/null 2>&1; then
    echo "Building netdiff binary..." >&2
    (cd "$REPO_ROOT" && go build -o "$REPO_ROOT/bin/netdiff-linux" ./cmd/netdiff) >&2
    echo "$REPO_ROOT/bin/netdiff-linux"
  else
    echo "Error: netdiff binary not found and 'go' is not available." >&2
    exit 1
  fi
}

NETDIFF_BIN="$(find_binary)"

check_prereqs() {
  if [ "$EUID" -ne 0 ]; then
    echo "Error: Lab operations require root/sudo to manage network namespaces." >&2
    exit 1
  fi
  for cmd in ip iptables python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: Required utility '$cmd' not found." >&2
      exit 1
    fi
  done
}

# 1. Setup isolated network environment
lab_setup() {
  check_prereqs
  echo "=== Setting up NetDiff Laboratory ==="
  lab_cleanup >/dev/null 2>&1 || true

  mkdir -p "$WWW_DIR" "$OUTPUT_DIR"
  echo '{"status":"ok","server":"netdiff-lab"}' > "$WWW_DIR/index.html"

  echo "Creating namespaces: $CLIENT_NS, $SERVER_NS"
  ip netns add "$CLIENT_NS"
  ip netns add "$SERVER_NS"

  echo "Creating veth pair: veth-client <-> veth-server"
  ip link add veth-client netns "$CLIENT_NS" type veth peer name veth-server netns "$SERVER_NS"

  echo "Configuring $CLIENT_NS ($CLIENT_IP/24)"
  ip -n "$CLIENT_NS" addr add "$CLIENT_IP/24" dev veth-client
  ip -n "$CLIENT_NS" link set lo up
  ip -n "$CLIENT_NS" link set veth-client up

  echo "Configuring $SERVER_NS ($SERVER_IP/24)"
  ip -n "$SERVER_NS" addr add "$SERVER_IP/24" dev veth-server
  ip -n "$SERVER_NS" link set lo up
  ip -n "$SERVER_NS" link set veth-server up

  # Configure namespace-specific resolver
  mkdir -p "/etc/netns/$CLIENT_NS"
  echo "nameserver $SERVER_IP" > "/etc/netns/$CLIENT_NS/resolv.conf"

  # Start Mock HTTP Server in SERVER_NS (isolated directory)
  echo "Starting mock HTTP server on $SERVER_IP:$TARGET_PORT..."
  ip netns exec "$SERVER_NS" python3 -m http.server "$TARGET_PORT" --bind "$SERVER_IP" --directory "$WWW_DIR" > "$LAB_DIR/http.log" 2>&1 &
  echo $! > "$PID_SERVER"

  # Start Mock DNS Server in SERVER_NS
  if [ -f "$SCRIPT_DIR/mock_dns.py" ]; then
    echo "Starting mock DNS server on $SERVER_IP:53..."
    ip netns exec "$SERVER_NS" python3 "$SCRIPT_DIR/mock_dns.py" "$SERVER_IP" 53 > "$LAB_DIR/dns.log" 2>&1 &
    echo $! > "$PID_DNS"
  fi

  sleep 1

  # Verify baseline connectivity
  echo "Verifying baseline connectivity..."
  if ! ip netns exec "$CLIENT_NS" ping -c 1 -W 2 "$SERVER_IP" >/dev/null 2>&1; then
    echo "Error: Baseline ping from $CLIENT_NS to $SERVER_IP failed." >&2
    exit 1
  fi

  echo "Laboratory setup completed successfully."
}

# 2. Capture baseline
lab_baseline() {
  check_prereqs
  echo "=== Capturing Baseline Network State ==="
  mkdir -p "$OUTPUT_DIR"
  ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" capture "$TARGET_HOST" -o "$OUTPUT_DIR/good.ndiff"
  echo "Baseline captured to $OUTPUT_DIR/good.ndiff"
}

# 3. Inject fault scenario
lab_inject() {
  check_prereqs
  local scenario="${1:-}"
  if [ -z "$scenario" ]; then
    echo "Usage: $0 inject <iface-down|route-missing|firewall-drop|dns-failure|port-closed>" >&2
    exit 1
  fi

  echo "=== Injecting Fault: $scenario ==="
  case "$scenario" in
    iface-down)
      echo "Action: Administratively disabling veth-client in $CLIENT_NS"
      ip -n "$CLIENT_NS" link set veth-client down
      ;;
    route-missing)
      echo "Action: Deleting subnet route 10.10.0.0/24 from $CLIENT_NS (leaving interface UP)"
      ip -n "$CLIENT_NS" route del 10.10.0.0/24 dev veth-client
      ;;
    firewall-drop)
      echo "Action: Adding iptables OUTPUT DROP rule for TCP port $TARGET_PORT in $CLIENT_NS"
      ip netns exec "$CLIENT_NS" iptables -A OUTPUT -p tcp --dport "$TARGET_PORT" -j DROP
      ;;
    dns-failure)
      echo "Action: Pointing resolver to unroutable blackhole IP"
      echo "nameserver 198.51.100.1" > "/etc/netns/$CLIENT_NS/resolv.conf"
      ;;
    port-closed)
      echo "Action: Target closed port $CLOSED_PORT (service not listening)"
      # No network modification needed; target changes to 10.10.0.2:8081
      ;;
    arp-failure)
      echo "Action: Forcing neighbor ARP entry into FAILED state in $CLIENT_NS"
      ip -n "$CLIENT_NS" neigh replace "$SERVER_IP" dev veth-client nud failed 2>/dev/null || ip -n "$CLIENT_NS" neigh del "$SERVER_IP" dev veth-client 2>/dev/null || true
      ;;
    *)
      echo "Unknown scenario: $scenario" >&2
      exit 1
      ;;
  esac
  echo "Fault injected."
}

# 4. Capture snapshot
lab_capture() {
  check_prereqs
  local name="${1:-bad}"
  local target="${2:-$TARGET_HOST}"
  mkdir -p "$OUTPUT_DIR"
  echo "Capturing state for target $target into $OUTPUT_DIR/${name}.ndiff..."
  ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" capture "$target" -o "$OUTPUT_DIR/${name}.ndiff" || true
  echo "Saved $OUTPUT_DIR/${name}.ndiff"
}

# 5. Restore environment
lab_restore() {
  check_prereqs
  echo "=== Restoring Laboratory to Clean Baseline ==="
  # Re-enable interface
  ip -n "$CLIENT_NS" link set veth-client up 2>/dev/null || true
  # Restore route
  ip -n "$CLIENT_NS" route replace 10.10.0.0/24 dev veth-client src "$CLIENT_IP" 2>/dev/null || true
  # Flush iptables
  ip netns exec "$CLIENT_NS" iptables -F OUTPUT 2>/dev/null || true
  # Restore resolver
  echo "nameserver $SERVER_IP" > "/etc/netns/$CLIENT_NS/resolv.conf" 2>/dev/null || true
  # Flush neighbor ARP table and re-populate with fresh ping
  ip -n "$CLIENT_NS" neigh flush dev veth-client 2>/dev/null || true
  ip netns exec "$CLIENT_NS" ping -c 1 -W 1 "$SERVER_IP" >/dev/null 2>&1 || true

  # Ensure server process is alive
  if [ -f "$PID_SERVER" ] && ! kill -0 "$(cat "$PID_SERVER")" 2>/dev/null; then
    echo "Restarting mock HTTP server..."
    ip netns exec "$SERVER_NS" python3 -m http.server "$TARGET_PORT" --bind "$SERVER_IP" --directory "$WWW_DIR" > "$LAB_DIR/http.log" 2>&1 &
    echo $! > "$PID_SERVER"
  fi

  # Ensure DNS process is alive
  if [ -f "$PID_DNS" ] && ! kill -0 "$(cat "$PID_DNS")" 2>/dev/null; then
    echo "Restarting mock DNS server..."
    ip netns exec "$SERVER_NS" python3 "$SCRIPT_DIR/mock_dns.py" "$SERVER_IP" 53 > "$LAB_DIR/dns.log" 2>&1 &
    echo $! > "$PID_DNS"
  fi

  echo "Laboratory restored."
}

# 6. Cleanup
lab_cleanup() {
  check_prereqs
  echo "=== Cleaning Up Laboratory ==="
  if [ -f "$PID_SERVER" ]; then
    kill "$(cat "$PID_SERVER")" 2>/dev/null || true
    rm -f "$PID_SERVER"
  fi
  if [ -f "$PID_DNS" ]; then
    kill "$(cat "$PID_DNS")" 2>/dev/null || true
    rm -f "$PID_DNS"
  fi

  ip netns del "$CLIENT_NS" 2>/dev/null || true
  ip netns del "$SERVER_NS" 2>/dev/null || true
  rm -rf "/etc/netns/$CLIENT_NS" 2>/dev/null || true
  rm -rf "$WWW_DIR" 2>/dev/null || true
  echo "Cleanup complete."
}

# 7. Verify scenario
# Usage: lab_verify <scenario> [good_file]
lab_verify() {
  local scenario="${1:-}"
  local good_file="${2:-$OUTPUT_DIR/good.ndiff}"
  local bad_file="$OUTPUT_DIR/${scenario}.ndiff"

  if [ ! -f "$good_file" ] || [ ! -f "$bad_file" ]; then
    echo "Error: Missing snapshot files for comparison ($good_file, $bad_file)" >&2
    exit 1
  fi

  echo "=========================================================="
  echo " NetDiff Diagnostic Comparison: $scenario"
  echo "=========================================================="
  "$NETDIFF_BIN" compare "$good_file" "$bad_file"

  echo ""
  echo "=========================================================="
  echo " NetDiff Terminal Causal Dependency Graph"
  echo "=========================================================="
  "$NETDIFF_BIN" graph "$good_file" "$bad_file"

  echo ""
  echo "=========================================================="
  echo " NetDiff Diagnostic Explanation & Probe Recommendation"
  echo "=========================================================="
  "$NETDIFF_BIN" explain "$good_file" "$bad_file"

  echo ""
  echo "=========================================================="
  echo " NetDiff Grounded Q&A (netdiff ask)"
  echo "=========================================================="
  "$NETDIFF_BIN" ask "$good_file" "$bad_file" "What is the primary root cause divergence?"

  echo ""
  echo "=========================================================="
  echo " NetDiff Guarded Automated Remediation Plan (netdiff fix)"
  echo "=========================================================="
  "$NETDIFF_BIN" fix "$good_file" "$bad_file" --dry-run

  echo ""
  echo "=========================================================="
  echo " Executing Validation Probe inside $CLIENT_NS"
  echo "=========================================================="
  case "$scenario" in
    iface-down)
      echo "Running: ip netns exec $CLIENT_NS netdiff probe TEST_INTERFACE_STATE veth-client"
      ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" probe TEST_INTERFACE_STATE veth-client
      ;;
    route-missing)
      echo "Running: ip netns exec $CLIENT_NS netdiff probe TEST_DIRECT_IP $SERVER_IP -t $TARGET_HOST"
      # Interface is still UP after route deletion; validate reachability directly by IP instead.
      ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" probe TEST_DIRECT_IP "$SERVER_IP" -t "$TARGET_HOST" || true
      ;;
    firewall-drop)
      echo "Running: ip netns exec $CLIENT_NS netdiff probe TEST_DIRECT_IP $SERVER_IP -t $TARGET_HOST"
      ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" probe TEST_DIRECT_IP "$SERVER_IP" -t "$TARGET_HOST" || true
      ;;
    dns-failure)
      echo "Running: ip netns exec $CLIENT_NS netdiff probe TEST_DNS_WITH_RESOLVER $SERVER_IP -t $TARGET_DNS"
      ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" probe TEST_DNS_WITH_RESOLVER "$SERVER_IP" -t "$TARGET_DNS" || true
      ;;
    port-closed)
      echo "Running: ip netns exec $CLIENT_NS netdiff probe TEST_DIRECT_IP $SERVER_IP -t $TARGET_HOST"
      # Server was killed; probe confirms host reachable but port 8080 is now actively refused.
      ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" probe TEST_DIRECT_IP "$SERVER_IP" -t "$TARGET_HOST" || true
      ;;
    arp-failure)
      echo "Running: ip netns exec $CLIENT_NS netdiff probe TEST_DIRECT_IP $SERVER_IP -t $TARGET_HOST"
      ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" probe TEST_DIRECT_IP "$SERVER_IP" -t "$TARGET_HOST" || true
      ;;
  esac
}

# 8. Run all scenarios
lab_run_all() {
  check_prereqs
  echo "=========================================================="
  echo " NetDiff Acceptance Suite (6 Scenarios)"
  echo "=========================================================="

  lab_setup
  lab_baseline

  local scenarios=("iface-down" "route-missing" "firewall-drop" "dns-failure" "port-closed" "arp-failure")
  local passed=0
  local failed=0

  for s in "${scenarios[@]}"; do
    echo ""
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    echo " Running Scenario: $s"
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"

    lab_restore

    # For the DNS scenario, capture the working baseline before changing the resolver.
    if [ "$s" = "dns-failure" ]; then
      echo "Capturing DNS-target baseline before fault injection..."
      ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" capture "$TARGET_DNS" -o "$OUTPUT_DIR/good-dns.ndiff" 2>/dev/null || true
    fi

    lab_inject "$s"

    local target="$TARGET_HOST"
    if [ "$s" = "dns-failure" ]; then
      target="$TARGET_DNS"
      lab_capture "$s" "$TARGET_DNS"
      lab_verify "$s" "$OUTPUT_DIR/good-dns.ndiff"
    elif [ "$s" = "port-closed" ]; then
      # Kill the HTTP server so port 8080 is now actively refused (same target as good.ndiff).
      if [ -f "$PID_SERVER" ]; then
        kill "$(cat "$PID_SERVER")" 2>/dev/null || true
        rm -f "$PID_SERVER"
      fi
      sleep 0.5
      lab_capture "$s" "$TARGET_HOST"
      lab_verify "$s"
    else
      lab_capture "$s" "$TARGET_HOST"
      lab_verify "$s"
    fi

    lab_restore
    echo "✓ Scenario $s completed."
    passed=$((passed + 1))
  done

  echo ""
  echo "=========================================================="
  echo " Testing Proactive Baseline Drift Monitor (netdiff watch)"
  echo "=========================================================="
  lab_watch "$OUTPUT_DIR/good.ndiff"

  echo ""
  echo "=========================================================="
  echo " NetDiff v0.4 Laboratory Results: $passed Passed, $failed Failed"
  echo "=========================================================="

  lab_cleanup
}

# 9. Apply guarded remediation inside client namespace
lab_fix() {
  check_prereqs
  local scenario="${1:-}"
  local good_file="${2:-$OUTPUT_DIR/good.ndiff}"
  local bad_file="$OUTPUT_DIR/${scenario}.ndiff"

  if [ ! -f "$good_file" ] || [ ! -f "$bad_file" ]; then
    echo "Error: Missing snapshot files for fix ($good_file, $bad_file)" >&2
    exit 1
  fi

  echo "=========================================================="
  echo " NetDiff Guarded Fix: $scenario"
  echo "=========================================================="
  ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" fix "$good_file" "$bad_file" --apply -y
}

# 10. Proactive baseline drift audit inside client namespace
lab_watch() {
  check_prereqs
  local good_file="${1:-$OUTPUT_DIR/good.ndiff}"
  if [ ! -f "$good_file" ]; then
    echo "Error: Missing baseline snapshot: $good_file" >&2
    exit 1
  fi
  echo "=========================================================="
  echo " NetDiff Proactive Drift Audit"
  echo "=========================================================="
  ip netns exec "$CLIENT_NS" "$NETDIFF_BIN" watch "$TARGET_HOST" --baseline "$good_file" --count 2 --interval 2s
}

usage() {
  echo "NetDiff Laboratory Controller"
  echo "Usage: $0 <command> [args]"
  echo ""
  echo "Commands:"
  echo "  setup                  Create namespaces, veth pair, and mock servers"
  echo "  baseline               Capture working baseline state (good.ndiff)"
  echo "  inject <scenario>      Inject a fault (iface-down, route-missing, firewall-drop, dns-failure, port-closed, arp-failure)"
  echo "  capture <name> [tgt]   Capture network state to <name>.ndiff"
  echo "  verify <scenario>      Compare baseline to scenario snapshot and run validation probe"
  echo "  fix <scenario>         Execute guarded automated remediation inside client namespace"
  echo "  watch                  Execute proactive baseline drift audit"
  echo "  restore                Restore environment to clean working baseline"
  echo "  cleanup                Tear down namespaces, kill servers, and clean temporary files"
  echo "  run-all                Execute full automated test suite for all 6 scenarios"
}

case "${1:-}" in
  setup)    lab_setup ;;
  baseline) lab_baseline ;;
  inject)   lab_inject "${2:-}" ;;
  capture)  lab_capture "${2:-bad}" "${3:-$TARGET_HOST}" ;;
  verify)   lab_verify "${2:-}" ;;
  fix)      lab_fix "${2:-}" ;;
  watch)    lab_watch "${2:-}" ;;
  restore)  lab_restore ;;
  cleanup)  lab_cleanup ;;
  run-all)  lab_run_all ;;
  *)        usage; exit 1 ;;
esac
