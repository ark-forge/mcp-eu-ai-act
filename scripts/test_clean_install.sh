#!/bin/bash
# Clean Install Test for EU AI Act Compliance Checker MCP Server
# Simulates a fresh user installing and running the server
# Exit code: 0 = success, 1 = failure

set -e

INSTALL_DIR="/tmp/test-mcp-clean-install-$$"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "============================================"
echo "  Clean Install Test"
echo "  Source: $REPO_DIR"
echo "  Target: $INSTALL_DIR"
echo "============================================"

cleanup() {
    rm -rf "$INSTALL_DIR"
}
trap cleanup EXIT

# Step 1: Create clean directory
echo ""
echo "[1/6] Creating clean install directory..."
mkdir -p "$INSTALL_DIR"

# Step 2: Copy only distributable files (simulate git clone)
echo "[2/6] Copying distributable files..."
cp "$REPO_DIR/server.py" "$INSTALL_DIR/"
cp "$REPO_DIR/manifest.json" "$INSTALL_DIR/"
cp "$REPO_DIR/requirements.txt" "$INSTALL_DIR/"
cp "$REPO_DIR/README.md" "$INSTALL_DIR/"
cp "$REPO_DIR/LICENSE" "$INSTALL_DIR/"
cp -r "$REPO_DIR/tests" "$INSTALL_DIR/tests" 2>/dev/null || true

# Step 3: Create virtual environment
echo "[3/6] Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Step 4: Install dependencies
echo "[4/6] Installing dependencies..."
pip install -q --upgrade pip
pip install -q pytest pytest-cov

# Step 5: Run import test
echo "[5/6] Testing server import..."
cd "$INSTALL_DIR"
python3 -c "
from server import MCPServer, EUAIActChecker
server = MCPServer()
tools = server.list_tools()
assert len(tools['tools']) == 3, f'Expected 3 tools, got {len(tools[\"tools\"])}'

# Quick scan test
result = server.handle_request('scan_project', {'project_path': '.'})
assert 'results' in result, 'Missing results in scan'
assert result['tool'] == 'scan_project', 'Wrong tool name'

# Quick compliance test
result = server.handle_request('check_compliance', {'project_path': '.', 'risk_category': 'minimal'})
assert result['results']['risk_category'] == 'minimal', 'Wrong risk category'

# Quick report test
result = server.handle_request('generate_report', {'project_path': '.', 'risk_category': 'limited'})
assert 'report_date' in result['results'], 'Missing report_date'

print('All import tests passed')
"

# Step 6: Run test suite
echo "[6/6] Running test suite..."
if [ -d "tests" ]; then
    python3 -m pytest tests/ -v --tb=short -q
    echo ""
    echo "[OK] All tests passed"
else
    echo "[SKIP] No tests directory found"
fi

deactivate

echo ""
echo "============================================"
echo "  CLEAN INSTALL TEST: PASSED"
echo "============================================"
