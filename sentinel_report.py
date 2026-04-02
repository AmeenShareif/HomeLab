"""
sentinel_report.py

Pulls recent incidents from Microsoft Sentinel via the Azure REST API
and outputs a formatted summary report.

Built to avoid clicking through the Sentinel UI every time and to practice
working with the Azure API.

Requirements:
    pip install requests azure-identity

Usage:
    python sentinel_report.py
    python sentinel_report.py --days 7 --output report.txt
    python sentinel_report.py --severity High Medium

Setup:
    Set the following environment variables before running:
        AZURE_TENANT_ID      - your Azure AD tenant ID
        AZURE_CLIENT_ID      - app registration client ID
        AZURE_CLIENT_SECRET  - app registration client secret
        AZURE_SUBSCRIPTION_ID
        AZURE_RESOURCE_GROUP
        SENTINEL_WORKSPACE   - your Log Analytics workspace name

    The app registration needs "Microsoft Sentinel Reader" role on the workspace.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone

import requests
from azure.identity import ClientSecretCredential


# ---------------------------------------------------------------------------
# Config — pulled from environment variables
# ---------------------------------------------------------------------------

TENANT_ID       = os.environ.get("AZURE_TENANT_ID")
CLIENT_ID       = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET   = os.environ.get("AZURE_CLIENT_SECRET")
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP  = os.environ.get("AZURE_RESOURCE_GROUP")
WORKSPACE_NAME  = os.environ.get("SENTINEL_WORKSPACE")

SENTINEL_API_VERSION = "2023-11-01"
REQUEST_TIMEOUT = 30

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
SEVERITY_COLORS = {
    "High":          "\033[91m",   # red
    "Medium":        "\033[93m",   # yellow
    "Low":           "\033[94m",   # blue
    "Informational": "\033[37m",   # white
}
RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def validate_config():
    """Make sure the Azure env vars are set before we do anything else."""
    missing = [
        name for name, value in (
            ("AZURE_TENANT_ID", TENANT_ID),
            ("AZURE_CLIENT_ID", CLIENT_ID),
            ("AZURE_CLIENT_SECRET", CLIENT_SECRET),
            ("AZURE_SUBSCRIPTION_ID", SUBSCRIPTION_ID),
            ("AZURE_RESOURCE_GROUP", RESOURCE_GROUP),
            ("SENTINEL_WORKSPACE", WORKSPACE_NAME),
        )
        if not value
    ]

    if missing:
        print("ERROR: Missing Azure environment variables:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        sys.exit(1)


def build_base_url():
    """Build the Sentinel ARM base URL for the current workspace."""
    return (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights"
    )


def get_token():
    """Get an Azure access token using service principal credentials."""
    credential = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )
    token = credential.get_token("https://management.azure.com/.default")
    return token.token


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def request_json(url, token, params=None):
    """GET a JSON response from the Sentinel API and fail cleanly on errors."""
    headers = {"Authorization": f"Bearer {token}"}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print(f"ERROR: API request failed for {url}", file=sys.stderr)
        print(f"  {exc}", file=sys.stderr)
        sys.exit(1)


def get_incidents(token, base_url, days=1, severities=None):
    """
    Fetch Sentinel incidents from the last N days.
    Optionally filter by severity list e.g. ['High', 'Medium']
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = f"{base_url}/incidents"
    params = {
        "api-version": SENTINEL_API_VERSION,
        "$filter": f"properties/createdTimeUtc ge {cutoff_str}",
        "$orderby": "properties/createdTimeUtc desc",
        "$top": 100,
    }

    incidents = []
    while url:
        data = request_json(url, token, params)
        incidents.extend(data.get("value", []))
        url = data.get("nextLink")      # handle pagination
        params = {}                     # nextLink already has params baked in

    # filter by severity if specified
    if severities:
        severities_lower = [s.lower() for s in severities]
        incidents = [
            i for i in incidents
            if i["properties"].get("severity", "").lower() in severities_lower
        ]

    return incidents


def get_incident_alerts(token, base_url, incident_id):
    """Get alerts associated with a specific incident."""
    url = f"{base_url}/incidents/{incident_id}/alerts"
    params = {"api-version": SENTINEL_API_VERSION}

    data = request_json(url, token, params)
    return data.get("value", [])


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_time(iso_string):
    """Convert ISO timestamp to readable format."""
    if not iso_string:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso_string


def severity_color(severity):
    return SEVERITY_COLORS.get(severity, "") + severity + RESET


def build_report(incidents, include_alerts=False, token=None, base_url=None):
    """Build a formatted text report from incident list."""
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("=" * 70)
    lines.append(f"  SENTINEL INCIDENT REPORT — Generated {now}")
    lines.append("=" * 70)
    lines.append("")

    if not incidents:
        lines.append("No incidents found for the specified time range and filters.")
        return "\n".join(lines)

    # summary counts
    severity_counts = {}
    status_counts = {}
    for inc in incidents:
        props = inc["properties"]
        sev = props.get("severity", "Unknown")
        status = props.get("status", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1

    lines.append(f"Total incidents: {len(incidents)}")
    lines.append("")
    lines.append("By severity:")
    for sev in ["High", "Medium", "Low", "Informational"]:
        count = severity_counts.get(sev, 0)
        if count:
            lines.append(f"  {severity_color(sev):<10} {count}")
    lines.append("")
    lines.append("By status:")
    for status, count in sorted(status_counts.items()):
        lines.append(f"  {status:<15} {count}")
    lines.append("")
    lines.append("-" * 70)
    lines.append("")

    # sort by severity then time
    sorted_incidents = sorted(
        incidents,
        key=lambda i: i["properties"].get("createdTimeUtc", ""),
        reverse=True,
    )
    sorted_incidents.sort(
        key=lambda i: SEVERITY_ORDER.get(i["properties"].get("severity", ""), 99)
    )

    for inc in sorted_incidents:
        props = inc["properties"]
        inc_id = inc["name"]
        inc_number = props.get("incidentNumber", "?")
        title = props.get("title", "No title")
        severity = props.get("severity", "Unknown")
        status = props.get("status", "Unknown")
        created = format_time(props.get("createdTimeUtc"))
        updated = format_time(props.get("lastModifiedTimeUtc"))
        description = props.get("description", "").strip()
        tactics = ", ".join(props.get("additionalData", {}).get("tactics", [])) or "None"
        alert_count = props.get("additionalData", {}).get("alertsCount", 0)
        owner = props.get("owner", {}).get("assignedTo") or "Unassigned"

        lines.append(f"[#{inc_number}] {title}")
        lines.append(f"  Severity : {severity_color(severity)}")
        lines.append(f"  Status   : {status}")
        lines.append(f"  Owner    : {owner}")
        lines.append(f"  Created  : {created}")
        lines.append(f"  Updated  : {updated}")
        lines.append(f"  Tactics  : {tactics}")
        lines.append(f"  Alerts   : {alert_count}")

        if description:
            # wrap description to 65 chars
            words = description.split()
            line = "  Desc     : "
            for word in words:
                if len(line) + len(word) > 70:
                    lines.append(line)
                    line = "             " + word + " "
                else:
                    line += word + " "
            lines.append(line.rstrip())

        if include_alerts and token and base_url:
            alerts = get_incident_alerts(token, base_url, inc_id)
            if alerts:
                lines.append(f"  Alerts:")
                for alert in alerts[:5]:          # cap at 5 per incident
                    alert_props = alert.get("properties", {})
                    alert_name = alert_props.get("alertDisplayName", "Unknown alert")
                    alert_time = format_time(alert_props.get("timeGenerated"))
                    lines.append(f"    - [{alert_time}] {alert_name}")

        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Pull Sentinel incidents and generate a summary report."
    )
    parser.add_argument(
        "--days", type=int, default=1,
        help="How many days back to pull incidents (default: 1)"
    )
    parser.add_argument(
        "--severity", nargs="+",
        choices=["High", "Medium", "Low", "Informational"],
        help="Filter by severity (e.g. --severity High Medium)"
    )
    parser.add_argument(
        "--output", type=str,
        help="Save report to a file instead of printing to stdout"
    )
    parser.add_argument(
        "--alerts", action="store_true",
        help="Include alert details for each incident (slower)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output raw JSON instead of formatted report"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    validate_config()
    base_url = build_base_url()

    print("Authenticating...", file=sys.stderr)
    token = get_token()

    print(f"Fetching incidents (last {args.days} day(s))...", file=sys.stderr)
    incidents = get_incidents(token, base_url, days=args.days, severities=args.severity)
    print(f"Found {len(incidents)} incident(s).", file=sys.stderr)

    if args.json:
        output = json.dumps(incidents, indent=2)
    else:
        output = build_report(incidents, include_alerts=args.alerts, token=token, base_url=base_url)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report saved to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
