#!/usr/bin/env python3
"""
Generate a GitHub Actions Job Summary table from an enriched Trivy scan report.

Usage:
    python3 generate_summary.py <trivy-report.json> <kev.json> <version>
"""

import json
import os
import sys

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "UNKNOWN": "⚪",
}


def fmt_date(raw: str) -> str:
    """Trim ISO8601 datetime to YYYY-MM-DD, or return '-' if missing."""
    if not raw:
        return "-"
    return raw[:10]


def fmt_age(days) -> str:
    if days is None:
        return "Unknown"
    return f"{days}d"


def fmt_epss(percent) -> str:
    if percent is None:
        return "-"
    return f"{percent:.2f}%"


def main():
    if len(sys.argv) < 4:
        print("Usage: generate_summary.py <trivy-report.json> <kev.json> <version>")
        sys.exit(1)

    trivy_path, kev_path, version = sys.argv[1], sys.argv[2], sys.argv[3]
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        print("GITHUB_STEP_SUMMARY not set", file=sys.stderr)
        sys.exit(1)

    with open(trivy_path) as f:
        trivy = json.load(f)

    kev_ids = set()
    if os.path.exists(kev_path):
        with open(kev_path) as f:
            kev_data = json.load(f)
        kev_ids = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}

    vulns = []
    for result in trivy.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            vulns.append(v)

    vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.get("Severity", "UNKNOWN"), 4))

    lines = []
    lines.append(f"## \U0001f6e1\ufe0f Security Scan Summary: n8nio/n8n:{version}")
    lines.append("")

    if not vulns:
        lines.append("\u2705 No vulnerabilities found.")
        lines.append("")
    else:
        # Calculate counts for the high-level summary table
        crit_count = sum(1 for v in vulns if v.get("Severity") == "CRITICAL")
        high_count = sum(1 for v in vulns if v.get("Severity") == "HIGH")
        med_count = sum(1 for v in vulns if v.get("Severity") == "MEDIUM")
        low_count = sum(1 for v in vulns if v.get("Severity") in ["LOW", "UNKNOWN"])
        kev_count = sum(1 for v in vulns if v.get("KevHit") or v.get("VulnerabilityID", "") in kev_ids)
        summary = trivy.get("AnalysisSummary", {})
        manual_review_count = summary.get("manual_review_count", 0)
        auto_eligible_count = summary.get("auto_allowed_critical_high_count", 0)
        has_crit_high = crit_count + high_count > 0
        has_kev = kev_count > 0

        if manual_review_count > 0:
            status = "🟠 Manual Review"
        elif has_crit_high or has_kev:
            status = "✅ Auto Eligible"
        else:
            status = "✅ Clean"
        kev_emoji = "✅ Yes" if has_kev else "No"

        # High-level summary table
        lines.append("| Version | CRITICAL | HIGH | MEDIUM | LOW/UNKNOWN | KEV | Manual Review | Auto Eligible | Status |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        lines.append(
            f"| {version} | {crit_count} | {high_count} | {med_count} | {low_count} | {kev_emoji} | {manual_review_count} | {auto_eligible_count} | {status} |"
        )
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("### \U0001f4ca Vulnerability Details")
    lines.append("")

    if vulns:
        lines.append("| CVE | Severity | Published | Age | Package | Version | Fixed In | Reachability | KEV | EPSS | EPSS Risk | Gate |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for v in vulns:
            cve_id = v.get("VulnerabilityID", "")
            severity = v.get("Severity", "")
            emoji = SEVERITY_EMOJI.get(severity, "")
            pub_date = fmt_date(v.get("PublishedDate", ""))
            age = fmt_age(v.get("AgeDays"))
            pkg = v.get("PkgName", "")
            installed = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion") or "None"
            reachable = "Yes" if v.get("Reachable") else "No"
            kev = "\u2705 Yes" if v.get("KevHit") or cve_id in kev_ids else "No"
            epss = fmt_epss(v.get("EpssPercent"))
            epss_risk = v.get("EpssRisk", "-")
            gate = v.get("GateDecision", "AUTO_ALLOWED")
            lines.append(
                f"| {cve_id} | {emoji} {severity} | {pub_date} | {age} | {pkg} | {installed} | {fixed} | {reachable} | {kev} | {epss} | {epss_risk} | {gate} |"
            )

    lines.append("")
    lines.append("---")
    lines.append("")

    with open(summary_path, "a") as f:
        f.write("\n".join(lines) + "\n")

    kev_count = sum(1 for v in vulns if v.get("KevHit") or v.get("VulnerabilityID", "") in kev_ids)
    print(f"Summary written: {len(vulns)} vulnerabilities, {kev_count} KEV hits")


if __name__ == "__main__":
    main()
