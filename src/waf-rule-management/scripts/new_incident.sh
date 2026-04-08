#!/usr/bin/env bash
# Create an incident workspace directory structure.
#
# Usage:
#   bash scripts/new_incident.sh <INCIDENT_ID>
#
# Example:
#   bash scripts/new_incident.sh CVE-2025-55182
#   bash scripts/new_incident.sh RISK-2026-003
#
# Creates:
#   incidents/<INCIDENT_ID>/
#     tests/            - directory for go-ftw regression test YAML files
#     rules.conf        - empty file (agent/user writes virtual-patch rules here)
#     REPORT.md         - from assets/REPORT-template.md (agent/user fills in)
#
# The LLM agent populates these files following the conventions in:
#   references/first-responder-risk-runbook.md
#
# Rule ID allocation convention:
#   Each incident gets a 100-ID block in the custom range (100000-199999).
#   Blocks: 100000-100099, 100100-100199, 100200-100299, ...
#   This script prints the next available block by scanning existing incidents.

set -euo pipefail

INCIDENT_ID="${1:?Usage: $0 <INCIDENT_ID>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
INCIDENTS_DIR="${SKILL_DIR}/incidents"
INCIDENT_DIR="${INCIDENTS_DIR}/${INCIDENT_ID}"

if [ -d "$INCIDENT_DIR" ]; then
    echo "ERROR: Incident directory already exists: ${INCIDENT_DIR}"
    echo "  Use it directly or remove it first."
    exit 1
fi

# --- Create directory structure ---
mkdir -p "${INCIDENT_DIR}/tests"
touch "${INCIDENT_DIR}/rules.conf"
ASSETS_DIR="${SKILL_DIR}/assets"
TEMPLATE="${ASSETS_DIR}/REPORT-template.md"
if [ -f "$TEMPLATE" ]; then
    sed "s/<INCIDENT_ID>/${INCIDENT_ID}/g" "$TEMPLATE" > "${INCIDENT_DIR}/REPORT.md"
else
    touch "${INCIDENT_DIR}/REPORT.md"
fi

# --- Rule ID allocation ---
# Scan existing incidents to find the next free 100-ID block.
NEXT_BASE=100000
if [ -d "$INCIDENTS_DIR" ]; then
    for f in "${INCIDENTS_DIR}"/*/rules.conf; do
        [ -f "$f" ] || continue
        MAX_ID=$(grep -oE 'id:[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1 || true)
        if [ -n "$MAX_ID" ]; then
            BLOCK=$(( (MAX_ID / 100 + 1) * 100 ))
            [ "$BLOCK" -gt "$NEXT_BASE" ] && NEXT_BASE="$BLOCK"
        fi
    done
fi
RANGE_END=$((NEXT_BASE + 99))

echo "Incident workspace created: ${INCIDENT_DIR}"
echo ""
echo "  Rule ID range: ${NEXT_BASE}–${RANGE_END}"
echo ""
echo "  Files to populate:"
echo "    incidents/${INCIDENT_ID}/REPORT.md    — incident report"
echo "    incidents/${INCIDENT_ID}/rules.conf   — virtual-patch rules"
echo "    incidents/${INCIDENT_ID}/tests/*.yaml — go-ftw regression tests"
echo ""
echo "  See: references/first-responder-risk-runbook.md for conventions and formats."
