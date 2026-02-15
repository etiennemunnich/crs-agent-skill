#!/usr/bin/env bash
# Install tools required for WAF rule management.
# Run from skill root or any directory.
# Installs latest versions from GitHub where possible.

set -e

echo "Installing WAF rule management tools..."
echo "Required: python3+pip, go, go-ftw, crs-toolchain, docker/finch"
echo "Optional: crslang, modsec-rules-check/rules-check"
echo ""

# ---------------------------------------------------------------------------
# Python deps
# ---------------------------------------------------------------------------
install_pyyaml() {
    if python3 -c "import yaml" &>/dev/null; then
        echo "  PyYAML: already installed"
        return
    fi
    # Try standard pip first, fall back to --break-system-packages for
    # externally-managed environments (PEP 668 / macOS Homebrew Python).
    if command -v python3 &>/dev/null; then
        if python3 -m pip install pyyaml 2>/dev/null; then
            echo "  PyYAML: ok"
        elif python3 -m pip install --user --break-system-packages pyyaml 2>/dev/null; then
            echo "  PyYAML: ok (--user --break-system-packages)"
        else
            echo "  PyYAML: FAILED — install manually: python3 -m pip install pyyaml"
            return 1
        fi
    else
        echo "  PyYAML: python3 not found — install Python 3.8+ and pip"
        return 1
    fi
}
install_pyyaml || true

# ---------------------------------------------------------------------------
# Go tools (required)
# Uses v2 module paths for latest major versions.
# ---------------------------------------------------------------------------
if command -v go &>/dev/null; then
    echo ""
    echo "Installing Go tools (latest from GitHub)..."

    # go-ftw v2 — official CRS WAF testing framework
    echo "  go-ftw: installing..."
    go install github.com/coreruleset/go-ftw/v2@latest 2>&1 | tail -1 || true
    echo "  go-ftw: ok ($(go version -m "$(go env GOPATH)/bin/go-ftw" 2>/dev/null | grep '^\tmod' | awk '{print $3}' || echo 'installed'))"

    # crs-toolchain v2 — regex assembly, fp-finder
    echo "  crs-toolchain: installing..."
    go install github.com/coreruleset/crs-toolchain/v2@latest 2>&1 | tail -1 || true
    echo "  crs-toolchain: ok ($(go version -m "$(go env GOPATH)/bin/crs-toolchain" 2>/dev/null | grep '^\tmod' | awk '{print $3}' || echo 'installed'))"
else
    echo ""
    echo "  Go: not found — install Go (https://go.dev/doc/install), then rerun."
    echo "    go install github.com/coreruleset/go-ftw/v2@latest"
    echo "    go install github.com/coreruleset/crs-toolchain/v2@latest"
fi

# ---------------------------------------------------------------------------
# Optional: crslang (primary parser validation for validate_rule.py)
# Built from source — no tagged Go module, so we clone and build.
# ---------------------------------------------------------------------------
echo ""
echo "Installing optional tools..."

if command -v crslang &>/dev/null; then
    echo "  crslang: already installed ($(which crslang))"
elif command -v go &>/dev/null; then
    echo "  crslang: building from source..."
    CRSLANG_TMP="$(mktemp -d)"
    if git clone --depth 1 https://github.com/coreruleset/crslang.git "$CRSLANG_TMP/crslang" 2>/dev/null; then
        if (cd "$CRSLANG_TMP/crslang" && go build -o "$(go env GOPATH)/bin/crslang" . 2>&1); then
            echo "  crslang: ok ($(which crslang 2>/dev/null || echo "$(go env GOPATH)/bin/crslang"))"
        else
            echo "  crslang: build failed — try manually: git clone https://github.com/coreruleset/crslang && cd crslang && go build"
        fi
    else
        echo "  crslang: clone failed — check network and try manually"
    fi
    rm -rf "$CRSLANG_TMP"
else
    echo "  crslang: skipped (Go not available)"
fi

# ---------------------------------------------------------------------------
# Optional: modsec-rules-check (official legacy ModSecurity parser validation)
# Installed via Homebrew on macOS, or from system packages on Linux.
# ---------------------------------------------------------------------------
if command -v modsec-rules-check &>/dev/null || command -v rules-check &>/dev/null; then
    echo "  modsec-rules-check: already installed"
elif command -v brew &>/dev/null; then
    echo "  modsec-rules-check: installing via Homebrew..."
    if brew install modsecurity 2>&1 | tail -3; then
        echo "  modsec-rules-check: ok"
    else
        echo "  modsec-rules-check: brew install failed — try manually: brew install modsecurity"
    fi
elif command -v apt-get &>/dev/null; then
    echo "  modsec-rules-check: installing via apt..."
    if sudo apt-get install -y libmodsecurity3 modsecurity-utils 2>&1 | tail -3; then
        echo "  modsec-rules-check: ok"
    else
        echo "  modsec-rules-check: apt install failed — try manually"
    fi
else
    echo "  modsec-rules-check: no package manager found — install from ModSecurity source or packages"
fi

# ---------------------------------------------------------------------------
# Container runtime
# ---------------------------------------------------------------------------
echo ""
if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    echo "  Docker: ok ($(docker --version 2>/dev/null | head -1))"
elif command -v finch &>/dev/null; then
    echo "  Finch: ok ($(finch --version 2>/dev/null | head -1))"
else
    echo "  Docker/Finch: not found — install for local go-ftw testing"
    echo "    Docker: https://docker.com"
    echo "    Finch:  https://runfinch.com"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Installed tool summary ==="
GOBIN="$(go env GOPATH 2>/dev/null)/bin"
export GOBIN
for tool in go-ftw crs-toolchain crslang modsec-rules-check rules-check; do
    if command -v "$tool" &>/dev/null; then
        ver=$(go version -m "$(which "$tool")" 2>/dev/null | grep '^\tmod' | awk '{print $3}' || echo "installed")
        echo "  $tool: $ver ($(which "$tool"))"
    fi
done
python3 -c "import yaml; print(f'  PyYAML: {yaml.__version__}')" 2>/dev/null || true

echo ""
echo "Done. Run scripts with --help for usage."
echo "Add $(go env GOPATH 2>/dev/null)/bin to your PATH if Go tools are not found."
