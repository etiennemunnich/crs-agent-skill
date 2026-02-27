# Test Fixtures (Synthetic)

These files are intentionally small, synthetic fixtures used by unit tests.

- `audit_native.log` is **not** a full real-world audit trail.
- It exists to validate parser behavior deterministically (sections A/B/F/H/Z, rule-id extraction, message parsing).
- Do not treat fixture content as production logging guidance.

For real engine verification, use:

- `src/waf-rule-management/assets/docker/docker-compose.yaml` (ModSecurity + CRS)
- `src/waf-rule-management/assets/docker/docker-compose.coraza.yaml` (Coraza + CRS)

Then capture runtime logs and analyze with `src/waf-rule-management/scripts/analyze_log.py`.
