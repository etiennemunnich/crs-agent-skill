#!/usr/bin/env bash
# Run the same checks locally that CI runs on GitHub.
# Usage: bash scripts/lint.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
FAILED=0

step() { printf "\n${YELLOW}▶ %s${NC}\n" "$1"; }
pass() { printf "${GREEN}  ✔ %s${NC}\n" "$1"; }
fail() { printf "${RED}  ✘ %s${NC}\n" "$1"; FAILED=1; }

# ── Markdown lint ──────────────────────────────────────────────
step "Markdown lint"
MD_FILES=(README.md CONTRIBUTING.md SECURITY.md .github/PULL_REQUEST_TEMPLATE.md
          src/waf-rule-management/SKILL.md src/waf-rule-management/README.md
          "src/waf-rule-management/references/")
if command -v markdownlint-cli2 &>/dev/null; then
    markdownlint-cli2 "${MD_FILES[@]}" && pass "markdownlint" || fail "markdownlint"
elif command -v npx &>/dev/null; then
    npx markdownlint-cli2 "${MD_FILES[@]}" && pass "markdownlint (npx)" || fail "markdownlint (npx)"
else
    fail "markdownlint-cli2 not found (npm install -g markdownlint-cli2)"
fi

# ── YAML lint ──────────────────────────────────────────────────
step "YAML lint"
if command -v yamllint &>/dev/null; then
    yamllint -d relaxed src/waf-rule-management/assets/ && pass "yamllint" || fail "yamllint"
else
    fail "yamllint not found (brew install yamllint)"
fi

# ── ShellCheck ─────────────────────────────────────────────────
step "ShellCheck"
if command -v shellcheck &>/dev/null; then
    shellcheck -S warning src/waf-rule-management/scripts/*.sh && pass "shellcheck" || fail "shellcheck"
else
    fail "shellcheck not found (brew install shellcheck)"
fi

# ── Python syntax ──────────────────────────────────────────────
step "Python syntax check"
py_ok=true
for f in src/waf-rule-management/scripts/*.py; do
    python3 -m py_compile "$f" 2>&1 || { fail "py_compile: $f"; py_ok=false; }
done
$py_ok && pass "All .py files compile"

# ── Python --help flags ───────────────────────────────────────
step "Python --help flags"
help_ok=true
for f in src/waf-rule-management/scripts/*.py; do
    python3 "$f" --help >/dev/null 2>&1 || { fail "--help failed: $f"; help_ok=false; }
done
$help_ok && pass "All .py scripts support --help"

# ── Agent Skill validation ────────────────────────────────────
step "Agent Skill validation (skills-ref)"
if command -v skills-ref &>/dev/null; then
    skills-ref validate src/waf-rule-management && pass "skills-ref validate" || fail "skills-ref validate"
else
    fail "skills-ref not found (pip install 'git+https://github.com/agentskills/agentskills.git#subdirectory=skills-ref')"
fi

# ── Summary ────────────────────────────────────────────────────
echo ""
if [ "$FAILED" -eq 0 ]; then
    printf "${GREEN}All checks passed.${NC}\n"
else
    printf "${RED}Some checks failed. Fix before pushing.${NC}\n"
    exit 1
fi
