#!/usr/bin/env python3
"""
parse_http_pcap.py

PCAP/PCAPNG processing script for Project No. 2 (Phase 4 - Option A).

This script takes a pcap or pcapng file as input, identifies TCP packets
containing HTTP traffic, and prints the following information for each
HTTP request/response:
    - Source and destination IP addresses and ports
    - HTTP method and request path (for requests)
    - Host header (for requests)
    - Response status code (for responses)
    - Relative packet timestamp from the beginning of the capture

Usage:
    python3 parse_http_pcap.py capture.pcapng

Requirements:
    pip install scapy --break-system-packages
"""

import argparse
import sys

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


# Standard HTTP methods used to identify HTTP request packets
HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH")


def is_http_request(payload: bytes) -> bool:
    """Checks whether a payload is an HTTP request."""
    return payload.startswith(HTTP_METHODS) and b"HTTP/" in payload.split(b"\r\n", 1)[0]


def is_http_response(payload: bytes) -> bool:
    """Checks whether a payload is an HTTP response."""
    return payload.startswith(b"HTTP/")


def parse_request(payload: bytes) -> dict:
    """Extracts key information from an HTTP request (method, path, version, Host, User-Agent)."""
    lines = payload.split(b"\r\n")
    request_line = lines[0].decode(errors="ignore")
    method, path, version = (request_line.split(" ", 2) + ["", "", ""])[:3]

    headers = {}
    for line in lines[1:]:
        if b":" in line:
            key, _, value = line.partition(b":")
            headers[key.decode(errors="ignore").strip()] = value.decode(errors="ignore").strip()

    return {
        "method": method,
        "path": path,
        "version": version,
        "host": headers.get("Host", "-"),
        "user_agent": headers.get("User-Agent", "-"),
    }


def parse_response(payload: bytes) -> dict:
    """Extracts key information from an HTTP response (version, status code, reason phrase)."""
    lines = payload.split(b"\r\n")
    status_line = lines[0].decode(errors="ignore")
    parts = status_line.split(" ", 2)

    version = parts[0] if len(parts) > 0 else "-"
    status_code = parts[1] if len(parts) > 1 else "-"
    reason = parts[2] if len(parts) > 2 else "-"

    return {
        "version": version,
        "status_code": status_code,
        "reason": reason,
    }


def process_pcap(file_path: str) -> None:
    """Reads a pcap/pcapng file and prints all detected HTTP exchanges."""
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - Report any pcap reading error
        print(f"[ERROR] Failed to read pcap file: {exc}")
        sys.exit(1)

    if len(packets) == 0:
        print("The capture file is empty or contains no packets.")
        return

    start_time = float(packets[0].time)
    found_http = False

    print(f"Processing {len(packets)} packets from file '{file_path}'...\n")
    print("=" * 70)

    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
            continue

        payload = bytes(packet[Raw].load)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        relative_time = float(packet.time) - start_time

        if is_http_request(payload):
            found_http = True
            info = parse_request(payload)

            print(f"[t = {relative_time:.6f}s]  HTTP Request")
            print(f"  {src_ip}:{src_port}  ->  {dst_ip}:{dst_port}")
            print(f"  Method: {info['method']}    Path: {info['path']}    Version: {info['version']}")
            print(f"  Host: {info['host']}")
            print(f"  User-Agent: {info['user_agent']}")
            print("-" * 70)

        elif is_http_response(payload):
            found_http = True
            info = parse_response(payload)

            print(f"[t = {relative_time:.6f}s]  HTTP Response")
            print(f"  {src_ip}:{src_port}  ->  {dst_ip}:{dst_port}")
            print(f"  Version: {info['version']}    Status Code: {info['status_code']} {info['reason']}")
            print("-" * 70)

    if not found_http:
        print("No readable HTTP traffic (Plain Text) was found in this file.")
        print("The traffic may be encrypted using HTTPS or the capture filter may be incorrect.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process pcap/pcapng files and extract HTTP request/response information"
    )

    parser.add_argument(
        "pcap_file",
        help="Path to the input .pcap or .pcapng file"
    )

    args = parser.parse_args()

    process_pcap(args.pcap_file)


if __name__ == "__main__":
    main()