# NetDiff Snapshot Specification (`.ndiff`)

The `.ndiff` snapshot format is a portable, structured JSON representation of target-specific network state.

## Schema Version
Current schema version: `ndiff/v1`

## Structure

```json
{
  "schema_version": "ndiff/v1",
  "metadata": {
    "netdiff_version": "0.1.0",
    "captured_at": "2026-10-09T17:00:00Z",
    "hostname": "host-a",
    "os": "linux"
  },
  "target": {
    "raw": "api.internal.company:443",
    "host": "api.internal.company",
    "port": 443,
    "protocol": "tcp",
    "is_ip": false
  },
  "dns": {
    "hostname": "api.internal.company",
    "nameservers": ["10.8.0.2"],
    "a_records": ["10.40.8.21"],
    "aaaa_records": [],
    "resolution_ms": 14,
    "success": true
  },
  "route": {
    "destination_ip": "10.40.8.21",
    "table": 200,
    "table_name": "table 200",
    "gateway": "10.8.0.1",
    "egress_interface": "tun0",
    "preferred_source": "10.8.0.14",
    "metric": 50,
    "policy_rule": "from all to 10.40.0.0/16 lookup 200",
    "success": true
  },
  "interface": {
    "name": "tun0",
    "index": 12,
    "addresses": ["10.8.0.14/24"],
    "mtu": 1420,
    "flags": ["UP", "POINTOPOINT"],
    "oper_state": "up",
    "is_tunnel": true,
    "role": "tunnel"
  },
  "neighbor": {
    "ip": "10.8.0.1",
    "mac": "00:11:22:33:44:55",
    "state": "REACHABLE",
    "interface": "tun0",
    "present": true
  },
  "tcp": {
    "status": "connected",
    "latency_ms": 27,
    "remote_ip": "10.40.8.21",
    "remote_port": 443
  },
  "proxy": {
    "http_proxy": "",
    "https_proxy": "",
    "no_proxy": "",
    "active": false
  },
  "collection_errors": []
}
```
