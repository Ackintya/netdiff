#!/usr/bin/env python3
"""
Simple mock DNS server for NetDiff laboratory experiments.
Responds to A queries for mock.netdiff.local with 10.10.0.2.
Responds to all other queries with NXDOMAIN.
"""
import socket
import sys

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.2"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 53

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except Exception as e:
        sys.stderr.write(f"Failed to bind {host}:{port}: {e}\n")
        sys.exit(1)

    print(f"Mock DNS server listening on {host}:{port}", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12:
                continue

            transaction_id = data[:2]
            qdcount = int.from_bytes(data[4:6], "big")

            idx = 12
            domain_parts = []
            while idx < len(data):
                length = data[idx]
                if length == 0:
                    idx += 1
                    break
                idx += 1
                domain_parts.append(data[idx:idx+length].decode("utf-8", errors="ignore"))
                idx += length
            domain = ".".join(domain_parts)

            qtype = int.from_bytes(data[idx:idx+2], "big") if idx+2 <= len(data) else 1
            idx += 4

            question_section = data[12:idx]

            if domain == "mock.netdiff.local" and qtype == 1:
                resp_flags = b"\x81\x80"
                ancount = b"\x00\x01"
                answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x0a\x00\x02"
                response = transaction_id + resp_flags + b"\x00\x01" + ancount + b"\x00\x00\x00\x00" + question_section + answer
            else:
                resp_flags = b"\x81\x83"
                response = transaction_id + resp_flags + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question_section

            sock.sendto(response, addr)
        except Exception:
            pass

if __name__ == "__main__":
    main()
