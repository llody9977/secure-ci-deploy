#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: collect_package_files.sh <image_ref> <trivy_report.json> <output_tsv>" >&2
  exit 1
fi

IMAGE_REF="$1"
REPORT_PATH="$2"
OUTPUT_PATH="$3"
WORK_DIR="$(mktemp -d)"
PKG_LIST="$WORK_DIR/vulnerable-packages.txt"
APK_AWK="$WORK_DIR/apk-installed.awk"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

jq -r '[.Results[]?.Vulnerabilities[]?.PkgName] | unique | map(select(length > 0)) | .[]' "$REPORT_PATH" > "$PKG_LIST"

cat > "$APK_AWK" <<'EOF'
BEGIN {
  while ((getline line < "/workspace/vulnerable-packages.txt") > 0) {
    wanted[line] = 1
  }
}
/^P:/ {
  pkg = substr($0, 3)
  dir = ""
  next
}
/^F:/ {
  if (wanted[pkg]) {
    dir = substr($0, 3)
  }
  next
}
/^R:/ {
  if (wanted[pkg] && dir != "") {
    print pkg "\t/" dir "/" substr($0, 3)
  }
  next
}
/^$/ {
  pkg = ""
  dir = ""
}
EOF

if [ ! -s "$PKG_LIST" ]; then
  : > "$OUTPUT_PATH"
  exit 0
fi

if ! docker run --rm \
  -v "$WORK_DIR:/workspace:ro" \
  --entrypoint /bin/sh \
  "$IMAGE_REF" \
  -eu -c '
    if command -v dpkg-query >/dev/null 2>&1; then
      while IFS= read -r pkg; do
        dpkg-query -L "$pkg" 2>/dev/null | awk -v pkg="$pkg" '"'"'NF && $0 ~ "^/" {print pkg "\t" $0}'"'"' || true
      done < /workspace/vulnerable-packages.txt
    elif command -v apk >/dev/null 2>&1; then
      while IFS= read -r pkg; do
        apk info -L "$pkg" 2>/dev/null | awk -v pkg="$pkg" '"'"'NF && $0 ~ "^/" {print pkg "\t" $0}'"'"' || true
      done < /workspace/vulnerable-packages.txt
    elif [ -f /lib/apk/db/installed ]; then
      awk -F: -f /workspace/apk-installed.awk /lib/apk/db/installed
    elif command -v rpm >/dev/null 2>&1; then
      while IFS= read -r pkg; do
        rpm -ql "$pkg" 2>/dev/null | awk -v pkg="$pkg" '"'"'NF && $0 ~ "^/" {print pkg "\t" $0}'"'"' || true
      done < /workspace/vulnerable-packages.txt
    else
      echo "Warning: unsupported package manager in image, continuing without package-file reachability mapping." >&2
      exit 0
    fi
  ' | sort -u > "$OUTPUT_PATH"; then
  echo "Warning: package-file collection failed for $IMAGE_REF, continuing with empty reachability map." >&2
  : > "$OUTPUT_PATH"
fi
