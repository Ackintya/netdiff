#!/usr/bin/env bash
# NetDiff Automated Namespace Demo & Verification Harness
# Sets up isolated network namespaces to reproduce the canonical VPN routing failure.
set -euo pipefail

echo "=========================================================="
echo " Setting up NetDiff Demo Environment (Network Namespaces)"
echo "=========================================================="

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script creates network namespaces and must be run as root (or with sudo)."
  exit 1
fi

SERVER_NS="ndiff-server"
GOOD_NS="ndiff-good"
BAD_NS="ndiff-bad"
TARGET_IP="10.40.8.21"
TARGET_PORT="8080"

# Build netdiff binary if not present
if [ ! -f "./netdiff" ]; then
  echo "Compiling netdiff binary..."
  go build -o ./netdiff ./cmd/netdiff
fi

# Cleanup any previous runs
cleanup() {
  echo "Cleaning up network namespaces..."
  ip netns del "$SERVER_NS" 2>/dev/null || true
  ip netns del "$GOOD_NS" 2>/dev/null || true
  ip netns del "$BAD_NS" 2>/dev/null || true
}
trap cleanup EXIT

cleanup

echo "1. Creating network namespaces: $SERVER_NS, $GOOD_NS, $BAD_NS..."
ip netns add "$SERVER_NS"
ip netns add "$GOOD_NS"
ip netns add "$BAD_NS"

# 2. Wire Good Namespace <-> Server Namespace via veth-good / vpn0
echo "2. Wiring $GOOD_NS to $SERVER_NS via VPN tunnel pair..."
ip link add veth-good netns "$GOOD_NS" type veth peer name veth-srv-g netns "$SERVER_NS"
ip -n "$GOOD_NS" link set veth-good name vpn0
ip -n "$GOOD_NS" addr add 10.8.0.14/24 dev vpn0
ip -n "$GOOD_NS" link set vpn0 up
ip -n "$GOOD_NS" link set lo up

ip -n "$SERVER_NS" addr add 10.8.0.1/24 dev veth-srv-g
ip -n "$SERVER_NS" link set veth-srv-g up
ip -n "$SERVER_NS" link set lo up

# In Server NS: assign target IP 10.40.8.21 on a loopback dummy
ip -n "$SERVER_NS" addr add "$TARGET_IP/32" dev lo

# 3. Policy routing in GOOD_NS: route 10.40.0.0/16 through table 200 via vpn0
echo "3. Configuring policy routing rule in $GOOD_NS (lookup table 200 via vpn0)..."
ip -n "$GOOD_NS" rule add to 10.40.0.0/16 lookup 200
ip -n "$GOOD_NS" route add 10.40.0.0/16 dev vpn0 table 200

# 4. Wire Bad Namespace <-> Server Namespace with VPN interface and table 200 (but missing ip rule)
echo "4. Wiring $BAD_NS with VPN link and fallback physical path..."
ip link add veth-bad netns "$BAD_NS" type veth peer name veth-srv-b netns "$SERVER_NS"
ip -n "$BAD_NS" link set veth-bad name vpn0
ip -n "$BAD_NS" addr add 10.8.0.15/24 dev vpn0
ip -n "$BAD_NS" link set vpn0 up
ip -n "$BAD_NS" link set lo up

ip -n "$SERVER_NS" addr add 10.8.0.2/24 dev veth-srv-b
ip -n "$SERVER_NS" link set veth-srv-b up

# Configure dummy eth0 physical interface on BAD_NS with default route
ip link add veth-dummy netns "$BAD_NS" type veth peer name veth-dummy-p netns "$BAD_NS"
ip -n "$BAD_NS" link set veth-dummy name eth0
ip -n "$BAD_NS" addr add 192.168.1.84/24 dev eth0
ip -n "$BAD_NS" link set eth0 up
ip -n "$BAD_NS" route add default dev eth0 2>/dev/null || true

# In BAD_NS: configure table 200 routing through vpn0
ip -n "$BAD_NS" route add 10.40.0.0/16 dev vpn0 table 200

# Notice: BAD_NS is missing the policy rule for 10.40.0.0/16!
# Destination packets will fall through to the default route on eth0 and timeout.

echo "5. Starting mock target TCP server on $TARGET_IP:$TARGET_PORT..."
ip netns exec "$SERVER_NS" python3 -m http.server "$TARGET_PORT" --bind "$TARGET_IP" &
SERVER_PID=$!
sleep 1

echo "=========================================================="
echo " Executing NetDiff Captures across environments"
echo "=========================================================="

echo "[WORKING HOST] Capturing state..."
ip netns exec "$GOOD_NS" ./netdiff capture "$TARGET_IP:$TARGET_PORT" -o /tmp/good.ndiff

echo "[FAILING HOST] Capturing state..."
ip netns exec "$BAD_NS" ./netdiff capture "$TARGET_IP:$TARGET_PORT" -o /tmp/bad.ndiff || true

echo ""
echo "=========================================================="
echo " NetDiff Semantic Diff & Root Cause Analysis"
echo "=========================================================="
./netdiff compare /tmp/good.ndiff /tmp/bad.ndiff

echo ""
echo "=========================================================="
echo " NetDiff Terminal Causal Dependency Graph"
echo "=========================================================="
./netdiff graph /tmp/good.ndiff /tmp/bad.ndiff

echo ""
echo "=========================================================="
echo " NetDiff Diagnostic Explanation & Next-Best Probe"
echo "=========================================================="
./netdiff explain /tmp/good.ndiff /tmp/bad.ndiff

echo ""
echo "=========================================================="
echo " NetDiff Natural Language Grounded Q&A (netdiff ask)"
echo "=========================================================="
./netdiff ask /tmp/good.ndiff /tmp/bad.ndiff "Is this failure caused by a host firewall or policy routing rule divergence?"

echo ""
echo "=========================================================="
echo " NetDiff Guarded Automated Remediation (netdiff fix)"
echo "=========================================================="
echo "[1] Dry-Run Mode (Simulate remediation without touching system state):"
./netdiff fix /tmp/good.ndiff /tmp/bad.ndiff --dry-run

echo ""
echo "[2] Apply Mode with Canary Verification (Executed inside $BAD_NS):"
# Execute fix inside the failing namespace with canary probe
ip netns exec "$BAD_NS" ./netdiff fix /tmp/good.ndiff /tmp/bad.ndiff --apply -y

echo ""
echo "Verifying connection recovery inside $BAD_NS after fix:"
ip netns exec "$BAD_NS" ./netdiff check "$TARGET_IP:$TARGET_PORT"

echo ""
echo "=========================================================="
echo " NetDiff Proactive Baseline Drift Monitor (netdiff watch)"
echo "=========================================================="
ip netns exec "$GOOD_NS" ./netdiff watch "$TARGET_IP:$TARGET_PORT" --baseline /tmp/good.ndiff --count 2 --interval 2s

echo ""
echo "=========================================================="
echo " NetDiff Automated Markdown & Interactive HTML Reports"
echo "=========================================================="
./netdiff report /tmp/good.ndiff /tmp/bad.ndiff
./netdiff report /tmp/good.ndiff /tmp/bad.ndiff --html -o /tmp/report.html
echo "✓ Standalone interactive HTML report saved to /tmp/report.html"

kill $SERVER_PID 2>/dev/null || true
echo ""
echo "Demo completed successfully!"
