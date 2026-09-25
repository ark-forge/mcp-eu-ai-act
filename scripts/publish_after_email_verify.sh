#!/bin/bash
# Run this after verifying PyPI email at https://pypi.org/manage/account/
# Publishes eu-ai-act-scanner 2.0.38 + mcp-eu-ai-act alias 2.0.33
set -e

echo "=== Publishing eu-ai-act-scanner 2.0.38 ==="
cd /opt/claude-ceo/workspace/mcp-servers/eu-ai-act
python3 -m twine upload dist/eu_ai_act_scanner-2.0.38* && echo "OK: eu-ai-act-scanner 2.0.38 published" || echo "FAIL: eu-ai-act-scanner"

echo ""
echo "=== Building & publishing mcp-eu-ai-act alias 2.0.33 ==="
cd /opt/claude-ceo/workspace/mcp-servers/eu-ai-act/alias-package
python3 -m build && python3 -m twine upload dist/* && echo "OK: mcp-eu-ai-act alias published" || echo "FAIL: mcp-eu-ai-act"

echo ""
echo "=== Verifying on PyPI ==="
sleep 10
python3 -c "
import urllib.request, json
for pkg in ['eu-ai-act-scanner', 'mcp-eu-ai-act']:
    try:
        url = f'https://pypi.org/pypi/{pkg}/json'
        with urllib.request.urlopen(url, timeout=10) as r:
            v = json.loads(r.read())['info']['version']
            print(f'  {pkg}: v{v} ✓')
    except Exception as e:
        print(f'  {pkg}: NOT FOUND ({e})')
"
