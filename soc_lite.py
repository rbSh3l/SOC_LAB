#!/usr/bin/env python3
"""
SOC-Lite Triage Tool
Author: Raeon Bryan / rbSh3l
Purpose: Defensive SOC lab tool for parsing Windows/Linux/Splunk-style CSV logs,
         detecting suspicious events, mapping alerts to MITRE ATT&CK, and producing
         a Markdown triage report.

Safe use: This tool is for blue-team lab analysis only. It does not exploit,
attack, persist, or modify target systems.

Example:
    python soc_lite.py --input sample_logs/auth_events.csv --output reports/triage_report.md
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class Alert:
    severity: str
    rule: str
    tactic: str
    technique: str
    description: str
    evidence: Dict[str, str]
    recommendation: str


FAILED_LOGIN_PATTERNS = [
    re.compile(r"failed password", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
    re.compile(r"4625", re.IGNORECASE),
    re.compile(r"failed logon", re.IGNORECASE),
]

SUCCESS_LOGIN_PATTERNS = [
    re.compile(r"accepted password", re.IGNORECASE),
    re.compile(r"4624", re.IGNORECASE),
    re.compile(r"successful logon", re.IGNORECASE),
]

PRIV_ESC_PATTERNS = [
    re.compile(r"sudo", re.IGNORECASE),
    re.compile(r"privilege", re.IGNORECASE),
    re.compile(r"4672", re.IGNORECASE),
    re.compile(r"special privileges", re.IGNORECASE),
]

SUSPICIOUS_PROCESS_PATTERNS = [
    re.compile(r"powershell.*-enc", re.IGNORECASE),
    re.compile(r"powershell.*-encodedcommand", re.IGNORECASE),
    re.compile(r"cmd\.exe.*\/c", re.IGNORECASE),
    re.compile(r"curl .*http", re.IGNORECASE),
    re.compile(r"wget .*http", re.IGNORECASE),
    re.compile(r"nc(\.exe)?\s+-", re.IGNORECASE),
]

COMMON_FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "date", "datetime", "_time"],
    "user": ["user", "username", "account", "account_name", "src_user"],
    "src_ip": ["src_ip", "source_ip", "ip", "client_ip", "src", "remote_address"],
    "host": ["host", "hostname", "computer", "computer_name", "device"],
    "event_id": ["event_id", "eventcode", "event_code", "id"],
    "message": ["message", "msg", "event", "details", "raw", "_raw"],
    "process": ["process", "process_name", "command", "command_line", "cmdline"],
}


def normalize_row(row: Dict[str, str]) -> Dict[str, str]:
    lowered = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
    normalized: Dict[str, str] = {}

    for canonical, aliases in COMMON_FIELD_ALIASES.items():
        normalized[canonical] = ""
        for alias in aliases:
            if alias in lowered:
                normalized[canonical] = lowered[alias]
                break

    normalized["raw"] = json.dumps(row, ensure_ascii=False)
    return normalized


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row. Add columns like timestamp,user,src_ip,host,event_id,message.")
        return [normalize_row(row) for row in reader]


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global
    except ValueError:
        return False


def match_any(patterns: Iterable[re.Pattern], text: str) -> bool:
    return any(pattern.search(text or "") for pattern in patterns)


def build_text(row: Dict[str, str]) -> str:
    return " ".join([
        row.get("event_id", ""),
        row.get("message", ""),
        row.get("process", ""),
        row.get("raw", ""),
    ])


def detect_alerts(rows: List[Dict[str, str]], failed_threshold: int = 5) -> List[Alert]:
    alerts: List[Alert] = []
    failed_by_user_ip: Counter[Tuple[str, str]] = Counter()
    failed_rows_by_user_ip: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)

    for row in rows:
        text = build_text(row)
        user = row.get("user") or "unknown_user"
        src_ip = row.get("src_ip") or "unknown_ip"

        if match_any(FAILED_LOGIN_PATTERNS, text):
            key = (user, src_ip)
            failed_by_user_ip[key] += 1
            failed_rows_by_user_ip[key].append(row)

        if match_any(PRIV_ESC_PATTERNS, text):
            alerts.append(Alert(
                severity="Medium",
                rule="Privileged activity observed",
                tactic="Privilege Escalation / Defense Evasion",
                technique="T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism",
                description="A privilege-related event was observed. This may be normal admin activity or suspicious privilege use.",
                evidence={
                    "timestamp": row.get("timestamp", ""),
                    "user": user,
                    "host": row.get("host", ""),
                    "event_id": row.get("event_id", ""),
                    "message": row.get("message", "")[:300],
                },
                recommendation="Validate whether the user was expected to perform privileged activity. Check change tickets, admin groups, and nearby login events.",
            ))

        if match_any(SUSPICIOUS_PROCESS_PATTERNS, text):
            alerts.append(Alert(
                severity="High",
                rule="Suspicious command or process pattern",
                tactic="Execution / Command and Control",
                technique="T1059 - Command and Scripting Interpreter",
                description="Command-line activity matched a suspicious pattern commonly seen in hands-on-keyboard activity or malware execution.",
                evidence={
                    "timestamp": row.get("timestamp", ""),
                    "user": user,
                    "host": row.get("host", ""),
                    "src_ip": src_ip,
                    "process": row.get("process", ""),
                    "message": row.get("message", "")[:300],
                },
                recommendation="Review parent process, command line, user context, endpoint timeline, and any network connections from this host.",
            ))

        if is_public_ip(src_ip) and match_any(SUCCESS_LOGIN_PATTERNS, text):
            alerts.append(Alert(
                severity="Medium",
                rule="Successful login from public IP",
                tactic="Initial Access",
                technique="T1078 - Valid Accounts",
                description="A successful login from a public IP address was detected. This may be expected remote access or suspicious account use.",
                evidence={
                    "timestamp": row.get("timestamp", ""),
                    "user": user,
                    "src_ip": src_ip,
                    "host": row.get("host", ""),
                    "event_id": row.get("event_id", ""),
                },
                recommendation="Confirm source IP ownership, VPN usage, geo-location, MFA status, and whether the user normally logs in from this source.",
            ))

    for (user, src_ip), count in failed_by_user_ip.items():
        if count >= failed_threshold:
            sample = failed_rows_by_user_ip[(user, src_ip)][0]
            alerts.append(Alert(
                severity="High",
                rule="Multiple failed logins from same user/source",
                tactic="Credential Access",
                technique="T1110 - Brute Force",
                description=f"Detected {count} failed login events for the same user/source combination.",
                evidence={
                    "first_seen": sample.get("timestamp", ""),
                    "user": user,
                    "src_ip": src_ip,
                    "host": sample.get("host", ""),
                    "failed_count": str(count),
                },
                recommendation="Check for password spraying, brute force, disabled accounts, lockouts, and successful login after the failures.",
            ))

    return sorted(alerts, key=lambda a: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(a.severity, 9))


def summarize(rows: List[Dict[str, str]], alerts: List[Alert]) -> Dict[str, object]:
    users = Counter(row.get("user") or "unknown_user" for row in rows)
    src_ips = Counter(row.get("src_ip") or "unknown_ip" for row in rows)
    hosts = Counter(row.get("host") or "unknown_host" for row in rows)
    severities = Counter(alert.severity for alert in alerts)

    return {
        "total_events": len(rows),
        "total_alerts": len(alerts),
        "severity_counts": dict(severities),
        "top_users": users.most_common(5),
        "top_source_ips": src_ips.most_common(5),
        "top_hosts": hosts.most_common(5),
    }


def markdown_table(items: List[Tuple[str, int]], left: str, right: str) -> str:
    if not items:
        return "No data found.\n"
    lines = [f"| {left} | {right} |", "|---|---:|"]
    lines.extend(f"| {name} | {count} |" for name, count in items)
    return "\n".join(lines) + "\n"


def write_report(path: Path, rows: List[Dict[str, str]], alerts: List[Alert]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = summarize(rows, alerts)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# SOC-Lite Triage Report",
        "",
        f"Generated: {now}",
        "",
        "## Executive Summary",
        "",
        f"- Total events reviewed: **{summary['total_events']}**",
        f"- Total alerts generated: **{summary['total_alerts']}**",
        f"- Severity counts: `{json.dumps(summary['severity_counts'])}`",
        "",
        "## Top Users",
        markdown_table(summary["top_users"], "User", "Events"),
        "## Top Source IPs",
        markdown_table(summary["top_source_ips"], "Source IP", "Events"),
        "## Top Hosts",
        markdown_table(summary["top_hosts"], "Host", "Events"),
        "## Alert Details",
        "",
    ]

    if not alerts:
        lines.append("No alerts generated from the current rule set.")
    else:
        for idx, alert in enumerate(alerts, start=1):
            lines.extend([
                f"### Alert {idx}: {alert.rule}",
                "",
                f"- Severity: **{alert.severity}**",
                f"- MITRE Tactic: {alert.tactic}",
                f"- MITRE Technique: {alert.technique}",
                f"- Description: {alert.description}",
                f"- Recommendation: {alert.recommendation}",
                "",
                "Evidence:",
                "```json",
                json.dumps(alert.evidence, indent=2),
                "```",
                "",
            ])

    path.write_text("\n".join(lines), encoding="utf-8")


def write_json(path: Path, alerts: List[Alert]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(a) for a in alerts], indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SOC-Lite defensive log triage tool")
    parser.add_argument("--input", required=True, help="Path to CSV log file")
    parser.add_argument("--output", default="reports/triage_report.md", help="Markdown report output path")
    parser.add_argument("--json", default="reports/alerts.json", help="JSON alert output path")
    parser.add_argument("--failed-threshold", type=int, default=5, help="Failed login threshold per user/source")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    rows = read_csv(input_path)
    alerts = detect_alerts(rows, failed_threshold=args.failed_threshold)
    write_report(Path(args.output), rows, alerts)
    write_json(Path(args.json), alerts)

    print(f"[+] Events analyzed: {len(rows)}")
    print(f"[+] Alerts generated: {len(alerts)}")
    print(f"[+] Markdown report: {args.output}")
    print(f"[+] JSON alerts: {args.json}")


if __name__ == "__main__":
    main()
