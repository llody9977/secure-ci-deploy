#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/trivy-report.raw.json" <<'EOF'
{
  "Results": [
    {
      "Target": "pkg",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1111",
          "PkgName": "busybox",
          "InstalledVersion": "1.0",
          "Severity": "HIGH",
          "PublishedDate": "2026-02-20T00:00:00Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2222",
          "PkgName": "openssl",
          "InstalledVersion": "3.0",
          "Severity": "MEDIUM",
          "PublishedDate": "2025-12-01T00:00:00Z"
        }
      ]
    }
  ]
}
EOF

cat > "$tmpdir/package-files.tsv" <<'EOF'
busybox	/bin/busybox
openssl	/lib/libssl.so.3
EOF

cat > "$tmpdir/tracee-events.jsonl" <<'EOF'
{"container":{"id":"host-no-match"},"eventName":"sched_process_exec","args":[{"name":"pathname","value":"/bin/busybox"}]}
{"container":{"id":"abc123deadbeef"},"eventName":"sched_process_exec","args":[{"name":"pathname","value":"/bin/busybox"}]}
EOF

printf 'abc123deadbeefcafebabe\n' > "$tmpdir/target-container-id.txt"
cat > "$tmpdir/kev.json" <<'EOF'
{"vulnerabilities":[]}
EOF

python3 .github/scripts/merge_tracee_reachability.py \
  "$tmpdir/trivy-report.raw.json" \
  "$tmpdir/package-files.tsv" \
  "$tmpdir/tracee-events.jsonl" \
  "$tmpdir/target-container-id.txt" \
  "$tmpdir/trivy-report.tracee.json"

python3 .github/scripts/enrich_findings.py \
  "$tmpdir/trivy-report.tracee.json" \
  "$tmpdir/kev.json" \
  "$tmpdir/trivy-report.enriched.json"

summary_path="$tmpdir/summary.md"
GITHUB_STEP_SUMMARY="$summary_path" python3 .github/scripts/generate_summary.py \
  "$tmpdir/trivy-report.enriched.json" \
  "$tmpdir/kev.json" \
  "fixture"

jq -e '.ReachabilitySummary.matched_event_count == 1' "$tmpdir/trivy-report.tracee.json" > /dev/null
jq -e '.ReachabilitySummary.reachable_vulnerability_count == 1' "$tmpdir/trivy-report.tracee.json" > /dev/null
jq -e '[.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID == "CVE-2024-1111") | .Reachability] | any(. == "Yes")' "$tmpdir/trivy-report.enriched.json" > /dev/null
jq -e '[.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID == "CVE-2024-2222") | .Reachability] | any(. == "No")' "$tmpdir/trivy-report.enriched.json" > /dev/null
grep -q "Reachability" "$summary_path"

echo "Tracee merge fixture passed."
