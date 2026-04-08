# Incident Report: <INCIDENT_ID>

## Risk ID / Advisory

- **ID**: <INCIDENT_ID>
- **Description**: <short description>
- **Advisory URL**: <link>
- **CVSS**: <score>
- **Date**: <YYYY-MM-DD>

## Hypothesis

<What is the vulnerability? How does the attack work? What should the WAF detect?>

## Probe Matrix

| ID | Description | Vector | Content-Type | Expected |
|----|-------------|--------|--------------|----------|
| P1 | <attack desc> | <payload> | application/json | 403 |
| P1-MP | <same, multipart> | <payload> | multipart/form-data | 403 |
| C1 | Normal GET | benign | — | 200 |

## Results: CRS Baseline (no custom rules)

| Probe | HTTP | Verdict | Rule IDs | Notes |
|-------|------|---------|----------|-------|

## Results: With Virtual Patches

| Probe | Before | After | Custom Rule |
|-------|--------|-------|-------------|

## Sandbox Comparison

| Payload | Local | Sandbox | Match? |
|---------|-------|---------|--------|

## Gaps Identified

1. <gap>

## Custom Rules Written

| Rule ID | Description | File |
|---------|-------------|------|

## Follow-Up

| Action | Owner | Due | Status |
|--------|-------|-----|--------|

## Environment

| Engine | Version | CRS Version | PL | Inbound Threshold | Image Tag |
|--------|---------|-------------|----|-------------------|-----------|
| ModSecurity | v3.x | v4.x | 1 | 5 | owasp/modsecurity-crs:nginx |
| Coraza | vX.x | v4.x | 1 | 5 | ghcr.io/coreruleset/coraza-crs:caddy-alpine |
