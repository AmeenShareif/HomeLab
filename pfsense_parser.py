"""
pfsense_parser.py

Parses raw pfSense filterlog syslog entries into structured dicts.
I wrote this because pfSense logs aren't in CEF format and I needed
a way to normalize them before ingesting into Sentinel / doing analysis locally.

Can be used standalone (pipe logs through it) or imported as a module.

Usage:
    # Parse a saved log file
    python pfsense_parser.py --file pfsense.log

    # Parse stdin (e.g. tail a live log over SSH)
    ssh admin@192.168.56.1 "clog /var/log/filter.log" | python pfsense_parser.py

    # Output JSON
    python pfsense_parser.py --file pfsense.log --json

    # Filter to only blocked traffic
    python pfsense_parser.py --file pfsense.log --action block

    # Show top 10 source IPs
    python pfsense_parser.py --file pfsense.log --top-sources 10

Reference for pfSense log format:
    https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html
"""

import re
import sys
import json
import argparse
from collections import Counter
from datetime import datetime


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# pfSense syslog header pattern
# Example: <134>Jan 15 03:22:11 filterlog[12345]: <log body>
SYSLOG_PATTERN = re.compile(
    r"(?:<\d+>)?(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+filterlog\[\d+\]:\s+(?P<body>.*)"
)


def parse_ipv4_fields(fields):
    """
    Parse IPv4-specific fields from a pfSense filterlog entry.
    IPv4 field positions after the common header fields (index 8+):
    8:  IP version (4)
    9:  TOS
    10: ECN
    11: TTL
    12: ID
    13: offset
    14: flags
    15: proto ID
    16: proto name
    17: length
    18: src IP
    19: dst IP
    20+: protocol-specific fields
    """
    if len(fields) < 20:
        return {}

    result = {
        "ip_version": "4",
        "ttl":        fields[11] if len(fields) > 11 else "",
        "protocol":   fields[16].lower() if len(fields) > 16 else "",
        "src_ip":     fields[18] if len(fields) > 18 else "",
        "dst_ip":     fields[19] if len(fields) > 19 else "",
    }

    proto = result["protocol"]

    if proto in ("tcp", "udp") and len(fields) > 21:
        result["src_port"] = _safe_int(fields[20])
        result["dst_port"] = _safe_int(fields[21])
    elif proto == "icmp" and len(fields) > 20:
        result["icmp_type"] = fields[20] if len(fields) > 20 else ""
        result["icmp_code"] = fields[21] if len(fields) > 21 else ""
        result["src_port"] = None
        result["dst_port"] = None
    else:
        result["src_port"] = None
        result["dst_port"] = None

    if proto == "tcp" and len(fields) > 22:
        result["tcp_flags"] = fields[22]

    return result


def parse_ipv6_fields(fields):
    """
    Parse IPv6-specific fields. Similar structure but slightly different offsets.
    """
    if len(fields) < 19:
        return {}

    result = {
        "ip_version": "6",
        "protocol":   fields[15].lower() if len(fields) > 15 else "",
        "src_ip":     fields[17] if len(fields) > 17 else "",
        "dst_ip":     fields[18] if len(fields) > 18 else "",
    }

    proto = result["protocol"]
    if proto in ("tcp", "udp") and len(fields) > 20:
        result["src_port"] = _safe_int(fields[19])
        result["dst_port"] = _safe_int(fields[20])
    else:
        result["src_port"] = None
        result["dst_port"] = None

    return result


def parse_filterlog_entry(raw_line):
    """
    Parse a single pfSense filterlog syslog line.
    Returns a dict of structured fields, or None if the line isn't a filterlog entry.
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    # match syslog header
    m = SYSLOG_PATTERN.search(raw_line)
    if not m:
        # might be a raw filterlog line without syslog header
        body = raw_line
        timestamp = None
    else:
        body = m.group("body")
        year = datetime.now().year
        timestamp = f"{m.group('month')} {m.group('day')} {year} {m.group('time')}"

    fields = [field.strip() for field in body.split(",")]
    if len(fields) < 9:
        return None

    # common fields (always present regardless of IP version)
    entry = {
        "timestamp":   timestamp,
        "raw":         raw_line,
        "rule_number": fields[0],
        "interface":   fields[4],
        "reason":      fields[5],
        "action":      fields[6].lower(),       # "pass" or "block"
        "direction":   fields[7].lower(),       # "in" or "out"
        "ip_version":  fields[8],
    }

    # parse IP version specific fields
    if fields[8] == "4":
        entry.update(parse_ipv4_fields(fields))
    elif fields[8] == "6":
        entry.update(parse_ipv6_fields(fields))

    return entry


def _safe_int(val):
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_entry(entry):
    """Format a parsed entry as a readable one-liner."""
    action = entry.get("action", "?").upper()
    direction = entry.get("direction", "?")
    proto = entry.get("protocol", "?").upper()
    src = entry.get("src_ip", "?")
    src_port = entry.get("src_port")
    dst = entry.get("dst_ip", "?")
    dst_port = entry.get("dst_port")
    iface = entry.get("interface", "?")
    ts = entry.get("timestamp") or ""

    src_str = f"{src}:{src_port}" if src_port is not None else src
    dst_str = f"{dst}:{dst_port}" if dst_port is not None else dst

    return f"{ts:<20} {action:<6} {direction:<4} {iface:<6} {proto:<5} {src_str:<25} -> {dst_str}"


def print_summary(entries):
    """Print a summary of parsed entries."""
    total = len(entries)
    blocked = sum(1 for e in entries if e.get("action") == "block")
    passed = sum(1 for e in entries if e.get("action") == "pass")

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Total entries : {total}")
    print(f"  Blocked       : {blocked}")
    print(f"  Passed        : {passed}")

    if entries:
        proto_counts = Counter(e.get("protocol", "unknown") for e in entries)
        print(f"\n  Top protocols:")
        for proto, count in proto_counts.most_common(5):
            print(f"    {proto:<10} {count}")

        src_counts = Counter(e.get("src_ip", "") for e in entries if e.get("src_ip"))
        print(f"\n  Top source IPs:")
        for ip, count in src_counts.most_common(5):
            print(f"    {ip:<20} {count}")

        dst_port_counts = Counter(
            e.get("dst_port") for e in entries
            if e.get("dst_port") is not None
        )
        print(f"\n  Top destination ports:")
        for port, count in dst_port_counts.most_common(5):
            print(f"    {port:<10} {count}")

    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse pfSense filterlog syslog entries into structured output."
    )
    parser.add_argument("--file", type=str, help="Input log file (default: stdin)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--action", choices=["block", "pass"], help="Filter by action")
    parser.add_argument("--protocol", type=str, help="Filter by protocol (tcp, udp, icmp)")
    parser.add_argument("--src-ip", type=str, help="Filter by source IP")
    parser.add_argument("--dst-port", type=int, help="Filter by destination port")
    parser.add_argument("--top-sources", type=int, help="Show top N source IPs and exit")
    parser.add_argument("--summary", action="store_true", help="Print summary stats")
    return parser.parse_args()


def main():
    args = parse_args()

    # read input
    if args.file:
        try:
            with open(args.file, "r", errors="replace") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        lines = sys.stdin.readlines()

    # parse
    entries = []
    for line in lines:
        entry = parse_filterlog_entry(line)
        if entry:
            entries.append(entry)

    # filter
    if args.action:
        entries = [e for e in entries if e.get("action") == args.action]
    if args.protocol:
        entries = [e for e in entries if e.get("protocol") == args.protocol.lower()]
    if args.src_ip:
        entries = [e for e in entries if e.get("src_ip") == args.src_ip]
    if args.dst_port:
        entries = [e for e in entries if e.get("dst_port") == args.dst_port]

    # top sources shortcut
    if args.top_sources:
        counts = Counter(e.get("src_ip", "") for e in entries if e.get("src_ip"))
        print(f"\nTop {args.top_sources} source IPs ({len(entries)} total entries):\n")
        for ip, count in counts.most_common(args.top_sources):
            print(f"  {ip:<20} {count}")
        print()
        return

    # output
    if args.json:
        # remove raw field to keep output clean
        clean = [{k: v for k, v in e.items() if k != "raw"} for e in entries]
        print(json.dumps(clean, indent=2))
    else:
        print(f"{'TIMESTAMP':<20} {'ACTION':<6} {'DIR':<4} {'IFACE':<6} {'PROTO':<5} {'SOURCE':<25}   {'DESTINATION'}")
        print("-" * 90)
        for entry in entries:
            print(format_entry(entry))

    if args.summary:
        print_summary(entries)


if __name__ == "__main__":
    main()
