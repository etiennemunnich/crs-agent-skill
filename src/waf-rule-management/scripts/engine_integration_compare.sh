#!/usr/bin/env bash
# Cross-engine integration check for ModSecurity vs Coraza.
#
# Runs the same payload matrix against both engines, captures audit logs,
# and generates analysis output via analyze_log.py.
#
# Usage:
#   bash scripts/engine_integration_compare.sh [INCIDENT_ID]
#
# Example:
#   bash scripts/engine_integration_compare.sh IT-ENGINE-CHECK-001
#
# Artifacts:
#   engine-compare/<INCIDENT_ID>/
#     responses-modsec.txt
#     responses-coraza.txt
#     audit-modsec.log
#     audit-coraza.log
#     analysis-modsec.txt
#     analysis-coraza.txt
#     analysis-modsec.json
#     analysis-coraza.json
#     summary.md
#
# Cross-platform: works on macOS, Linux, and Windows (Git Bash / WSL).
# Supports both docker compose and finch compose (auto-detected).
#
# On macOS, finch's vz VM cannot read TCC-protected paths (~/Documents,
# ~/Desktop, ~/Downloads).  When this is detected, compose assets are
# staged to an OS-appropriate temp location automatically.
# Docker Desktop does not have this limitation on any platform.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="${SKILL_DIR}/assets/docker"
ANALYZER="${SCRIPT_DIR}/analyze_log.py"

INCIDENT_ID="${1:-IT-ENGINE-CHECK-$(date +%Y%m%d-%H%M%S)}"
ARTIFACT_DIR="${SKILL_DIR}/engine-compare/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"

if [ ! -f "${ANALYZER}" ]; then
  echo "ERROR: analyzer not found at ${ANALYZER}" >&2
  exit 1
fi

# --- Detect container runtime ---
USE_FINCH=false
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v finch >/dev/null 2>&1; then
  finch vm start >/dev/null 2>&1 || true
  COMPOSE_CMD=(finch compose)
  USE_FINCH=true
else
  echo "ERROR: neither 'docker compose' nor 'finch compose' is available." >&2
  exit 1
fi

# --- Stage compose assets when the container runtime can't read the project dir ---
# This is needed on macOS with finch (vz VM can't access TCC-protected paths
# like ~/Documents, ~/Desktop, ~/Downloads).  On Linux/WSL/Windows the compose
# directory is almost always readable, so staging is skipped automatically.
#
# The staging path is OS-aware:
#   macOS  : ~/.cache/crs-inttest/staging-<pid>  (inside finch vz mount)
#   Linux  : /tmp/crs-inttest-<user>/staging-<pid>
#   Windows: $TEMP/crs-inttest/staging-<pid>  (Git Bash / MSYS / Cygwin)
COMPOSE_DIR="${DOCKER_DIR}"
STAGING_DIR=""

get_staging_base() {
  case "$(uname -s)" in
    Darwin)        echo "${HOME}/.cache/crs-inttest" ;;
    MINGW*|MSYS*|CYGWIN*) echo "${TEMP:-/tmp}/crs-inttest" ;;
    *)             echo "/tmp/crs-inttest-${USER:-$(id -un 2>/dev/null || echo unknown)}" ;;
  esac
}

stage_compose_assets() {
  STAGING_DIR="$(get_staging_base)/staging-$$"
  mkdir -p "${STAGING_DIR}"
  cp "${DOCKER_DIR}/docker-compose.yaml"        "${STAGING_DIR}/"
  cp "${DOCKER_DIR}/docker-compose.coraza.yaml"  "${STAGING_DIR}/" 2>/dev/null || true
  cp "${DOCKER_DIR}/.ftw.yaml"                   "${STAGING_DIR}/" 2>/dev/null || true

  if [ -f "${DOCKER_DIR}/.env" ]; then
    cp "${DOCKER_DIR}/.env" "${STAGING_DIR}/.env"
  elif [ -f "${DOCKER_DIR}/.env.example" ]; then
    cp "${DOCKER_DIR}/.env.example" "${STAGING_DIR}/.env"
  fi

  if [ -f "${DOCKER_DIR}/custom-rules.conf" ]; then
    cp "${DOCKER_DIR}/custom-rules.conf" "${STAGING_DIR}/"
  else
    echo "# empty" > "${STAGING_DIR}/custom-rules.conf"
  fi

  COMPOSE_DIR="${STAGING_DIR}"
  echo "Staged compose assets to ${STAGING_DIR} (container runtime could not read project dir)"
}

if $USE_FINCH; then
  # Test whether finch can actually read the project directory.
  # On Linux this usually succeeds; on macOS it fails for TCC-protected paths.
  if ! "${COMPOSE_CMD[@]}" -f "${DOCKER_DIR}/docker-compose.yaml" config >/dev/null 2>&1; then
    stage_compose_assets
  fi
fi

# Create .env from example if missing (docker path only; staging already handled).
if [ -z "${STAGING_DIR}" ] && [ ! -f "${DOCKER_DIR}/.env" ] && [ -f "${DOCKER_DIR}/.env.example" ]; then
  cp "${DOCKER_DIR}/.env.example" "${DOCKER_DIR}/.env"
  echo "Created ${DOCKER_DIR}/.env from .env.example"
fi

MODSEC_FILE="${COMPOSE_DIR}/docker-compose.yaml"
CORAZA_FILE="${COMPOSE_DIR}/docker-compose.coraza.yaml"
TARGET="http://localhost:8080"
HOST_HEADER="Host: localhost"

run_compose() {
  local compose_file="$1"
  shift
  "${COMPOSE_CMD[@]}" --project-directory "${COMPOSE_DIR}" -f "${compose_file}" "$@"
}

wait_ready() {
  local max_wait="${1:-30}"
  for i in $(seq 1 "$max_wait"); do
    local code
    code="$(curl -sS -o /dev/null -w "%{http_code}" -H "${HOST_HEADER}" "${TARGET}/" 2>/dev/null || true)"
    if [ "$code" != "000" ] && [ -n "$code" ]; then
      echo "  WAF ready (HTTP ${code}) after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "  WARNING: WAF not ready after ${max_wait}s" >&2
  return 1
}

probe_matrix() {
  local out_file="$1"
  : > "${out_file}"

  run_probe() {
    local probe_id="$1"
    shift
    local code
    code="$(curl -sS -o /dev/null -w "%{http_code}" "$@" || true)"
    echo "${probe_id} ${code}" | tee -a "${out_file}"
  }

  # Attack probes — same payload via multiple content-types.
  run_probe "P1-GET"    -H "${HOST_HEADER}" "${TARGET}/api/search?q=select%201"
  run_probe "P1-JSON"   -H "${HOST_HEADER}" -H "Content-Type: application/json" \
    --data '{"q":"select 1"}' "${TARGET}/"
  run_probe "P1-MP"     -H "${HOST_HEADER}" -F 'q=select 1' "${TARGET}/"
  run_probe "P1-URLENC" -H "${HOST_HEADER}" -H "Content-Type: application/x-www-form-urlencoded" \
    --data 'q=select 1' "${TARGET}/"

  # XSS and LFI probes.
  run_probe "P2-XSS"    -H "${HOST_HEADER}" "${TARGET}/?q=<script>alert(1)</script>"
  run_probe "P3-LFI"    -H "${HOST_HEADER}" "${TARGET}/?file=/etc/passwd"

  # Benign controls.
  run_probe "C1-GET"    -H "${HOST_HEADER}" "${TARGET}/api/health"
  run_probe "C2-JSON"   -H "${HOST_HEADER}" -H "Content-Type: application/json" \
    --data '{"q":"hello world"}' "${TARGET}/"
}

collect_logs() {
  local compose_file="$1"
  local service_name="$2"
  local out_file="$3"
  # Use compose logs (not raw docker/finch logs) so --project-directory is
  # respected and the staging workaround applies to log capture too.
  # Compose prefixes each line with "container_name |" — strip everything
  # before the first '{' so the output is clean JSON-per-line.
  run_compose "${compose_file}" logs "${service_name}" 2>&1 \
    | sed -n 's/^[^{]*\({.*}\)$/\1/p' > "${out_file}" || true
  local count
  count="$(wc -l < "${out_file}" | tr -d ' ')"
  echo "  Captured ${count} JSON log lines -> ${out_file}"
}

analyze_logs() {
  local log_file="$1"
  local text_file="$2"
  local json_file="$3"
  python3 "${ANALYZER}" "${log_file}" --summary --top-rules 20 --explain > "${text_file}" 2>/dev/null || true
  python3 "${ANALYZER}" "${log_file}" --summary --top-rules 20 --explain --output json > "${json_file}" 2>/dev/null || true
}

build_comparison_table() {
  # Build side-by-side markdown table from the two response files.
  local modsec_file="${ARTIFACT_DIR}/responses-modsec.txt"
  local coraza_file="${ARTIFACT_DIR}/responses-coraza.txt"
  if [ ! -f "$modsec_file" ] || [ ! -f "$coraza_file" ]; then
    echo "| (no data) | | | |"
    return
  fi
  paste "$modsec_file" "$coraza_file" | while IFS=$'\t' read -r modsec coraza; do
    local pid ms cz match
    pid=$(echo "$modsec" | awk '{print $1}')
    ms=$(echo "$modsec" | awk '{print $2}')
    cz=$(echo "$coraza" | awk '{print $2}')
    match="YES"
    [ "$ms" != "$cz" ] && match="**NO**"
    echo "| $pid | $ms | $cz | $match |"
  done
}

summarize() {
  local summary_file="${ARTIFACT_DIR}/summary.md"
  local comparison_rows
  comparison_rows="$(build_comparison_table)"
  local modsec_responses coraza_responses
  modsec_responses="$(cat "${ARTIFACT_DIR}/responses-modsec.txt" 2>/dev/null || echo "(no data)")"
  coraza_responses="$(cat "${ARTIFACT_DIR}/responses-coraza.txt" 2>/dev/null || echo "(no data)")"

  cat > "${summary_file}" <<SUMEOF
# Engine Integration Summary: ${INCIDENT_ID}

## Inputs
- Target: ${TARGET}
- Payload matrix: P1 (SQLi) + P2 (XSS) + P3 (LFI) across content-types + benign controls

## Probe Results (HTTP status)

### ModSecurity
\`\`\`
${modsec_responses}
\`\`\`

### Coraza
\`\`\`
${coraza_responses}
\`\`\`

## Side-by-Side Comparison

| Probe | ModSecurity | Coraza | Match? |
|-------|-------------|--------|--------|
${comparison_rows}

## Artifacts
- \`responses-modsec.txt\` / \`responses-coraza.txt\`
- \`audit-modsec.log\` / \`audit-coraza.log\`
- \`analysis-modsec.txt\` / \`analysis-coraza.txt\`
- \`analysis-modsec.json\` / \`analysis-coraza.json\`

## Notes
- Compare top rule IDs and explanation output between engines.
- If one engine has empty audit logs, verify audit log format/parts in image defaults.
- Coraza uses Caddy-style JSON logging; the analyzer handles both formats.
SUMEOF
  echo "Wrote ${summary_file}"
}

cleanup() {
  run_compose "${MODSEC_FILE}" down >/dev/null 2>&1 || true
  run_compose "${CORAZA_FILE}" down >/dev/null 2>&1 || true
  # Remove staging directory if we created one.
  if [ -n "${STAGING_DIR}" ] && [ -d "${STAGING_DIR}" ]; then
    rm -rf "${STAGING_DIR}"
  fi
}
trap cleanup EXIT

# --- ModSecurity ---
echo "==> Starting ModSecurity..."
run_compose "${MODSEC_FILE}" up -d
wait_ready 30
echo "==> Running probes against ModSecurity..."
probe_matrix "${ARTIFACT_DIR}/responses-modsec.txt"
collect_logs "${MODSEC_FILE}" "crs" "${ARTIFACT_DIR}/audit-modsec.log"
analyze_logs \
  "${ARTIFACT_DIR}/audit-modsec.log" \
  "${ARTIFACT_DIR}/analysis-modsec.txt" \
  "${ARTIFACT_DIR}/analysis-modsec.json"

# --- Coraza ---
echo "==> Swapping to Coraza..."
run_compose "${MODSEC_FILE}" down
run_compose "${CORAZA_FILE}" up -d
wait_ready 30
echo "==> Running probes against Coraza..."
probe_matrix "${ARTIFACT_DIR}/responses-coraza.txt"
collect_logs "${CORAZA_FILE}" "coraza-crs" "${ARTIFACT_DIR}/audit-coraza.log"
analyze_logs \
  "${ARTIFACT_DIR}/audit-coraza.log" \
  "${ARTIFACT_DIR}/analysis-coraza.txt" \
  "${ARTIFACT_DIR}/analysis-coraza.json"

summarize

echo ""
echo "Done. Artifacts in: ${ARTIFACT_DIR}"
