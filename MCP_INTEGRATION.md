# Intégration MCP - EU AI Act Compliance Checker

## Configuration MCP

Pour intégrer ce serveur dans un système compatible MCP (Claude Code, VS Code, etc.), suivez les étapes ci-dessous.

## 1. Configuration Claude Code

### Fichier de configuration MCP

Créer ou modifier le fichier `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "eu-ai-act-compliance": {
      "command": "python3",
      "args": [
        "/opt/claude-ceo/workspace/mcp-servers/eu-ai-act/server.py"
      ],
      "env": {},
      "metadata": {
        "name": "EU AI Act Compliance Checker",
        "description": "Vérifie la conformité EU AI Act des projets AI",
        "version": "1.0.0",
        "author": "ArkForge"
      }
    }
  }
}
```

## 2. Configuration VS Code

### Extension MCP pour VS Code

1. Installer l'extension MCP pour VS Code
2. Ajouter la configuration dans `.vscode/mcp-servers.json`:

```json
{
  "servers": {
    "eu-ai-act-compliance": {
      "type": "python",
      "path": "/opt/claude-ceo/workspace/mcp-servers/eu-ai-act/server.py",
      "enabled": true
    }
  }
}
```

## 3. Utilisation dans Claude Code

Une fois configuré, le serveur MCP sera disponible dans Claude Code via les commandes:

### Scanner un projet

```
@eu-ai-act-compliance scan_project /path/to/project
```

### Vérifier la conformité

```
@eu-ai-act-compliance check_compliance /path/to/project --risk=limited
```

### Générer un rapport

```
@eu-ai-act-compliance generate_report /path/to/project --risk=high
```

## 4. Intégration programmatique

### Python

```python
from server import MCPServer

server = MCPServer()

# Scanner un projet
result = server.handle_request("scan_project", {
    "project_path": "/path/to/project"
})

# Vérifier la conformité
result = server.handle_request("check_compliance", {
    "project_path": "/path/to/project",
    "risk_category": "high"
})

# Générer un rapport
result = server.handle_request("generate_report", {
    "project_path": "/path/to/project",
    "risk_category": "limited"
})
```

### API REST (via wrapper)

Si vous souhaitez exposer le serveur MCP via une API REST, créez un wrapper Flask/FastAPI:

```python
from flask import Flask, request, jsonify
from server import MCPServer

app = Flask(__name__)
server = MCPServer()

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    result = server.handle_request("scan_project", data)
    return jsonify(result)

@app.route('/api/compliance', methods=['POST'])
def compliance():
    data = request.json
    result = server.handle_request("check_compliance", data)
    return jsonify(result)

@app.route('/api/report', methods=['POST'])
def report():
    data = request.json
    result = server.handle_request("generate_report", data)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

## 5. Intégration CI/CD

### GitHub Actions

Créer `.github/workflows/eu-ai-act-compliance.yml`:

```yaml
name: EU AI Act Compliance Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  compliance:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'

    - name: Install MCP Server
      run: |
        git clone https://github.com/ark-forge/mcp-eu-ai-act.git
        cd eu-ai-act-mcp
        pip install -r requirements.txt

    - name: Run Compliance Check
      run: |
        python3 eu-ai-act-mcp/server.py << EOF
        from server import MCPServer
        import json
        import sys

        server = MCPServer()
        result = server.handle_request("generate_report", {
            "project_path": ".",
            "risk_category": "high"
        })

        compliance_pct = result['results']['compliance_summary']['compliance_percentage']

        print(json.dumps(result, indent=2))

        if compliance_pct < 80:
            print(f"❌ Compliance below threshold: {compliance_pct}%")
            sys.exit(1)
        else:
            print(f"✅ Compliance OK: {compliance_pct}%")
            sys.exit(0)
        EOF
```

### GitLab CI

Créer `.gitlab-ci.yml`:

```yaml
stages:
  - compliance

eu-ai-act-check:
  stage: compliance
  image: python:3.9
  script:
    - git clone https://github.com/ark-forge/mcp-eu-ai-act.git
    - cd eu-ai-act-mcp && pip install -r requirements.txt
    - python3 -c "
      from server import MCPServer;
      import sys;
      server = MCPServer();
      result = server.handle_request('check_compliance', {'project_path': '.', 'risk_category': 'high'});
      pct = result['results']['compliance_percentage'];
      print(f'Compliance: {pct}%');
      sys.exit(0 if pct >= 80 else 1)"
  only:
    - main
    - develop
```

## 6. Variables d'environnement

Le serveur peut être configuré avec des variables d'environnement:

```bash
# Niveau de log
export MCP_LOG_LEVEL=INFO

# Seuil de conformité minimum
export MCP_COMPLIANCE_THRESHOLD=80

# Catégorie de risque par défaut
export MCP_DEFAULT_RISK_CATEGORY=limited
```

## 7. Monitoring et Logging

Le serveur génère des logs qui peuvent être capturés:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/eu-ai-act-mcp.log'),
        logging.StreamHandler()
    ]
)
```

## 8. Tests d'intégration

Exécuter les tests avant déploiement:

```bash
# Tests unitaires
python3 test_server.py

# Tests d'intégration
python3 example_usage.py

# Test complet avec projet réel
python3 server.py
```

## 9. Dépendances

### Requirements minima

- Python 3.7+
- Aucune dépendance externe (utilise uniquement la stdlib)

### Optionnel pour fonctionnalités avancées

```txt
# Pour API REST
flask>=2.0.0
fastapi>=0.95.0
uvicorn>=0.20.0

# Pour génération de rapports PDF
reportlab>=3.6.0

# Pour analyse avancée
pyyaml>=6.0
```

## 10. Sécurité

### Bonnes pratiques

- ✅ Le serveur est en lecture seule (ne modifie pas les fichiers)
- ✅ Pas d'exécution de code arbitraire
- ✅ Validation des chemins de fichiers
- ✅ Gestion des erreurs robuste
- ✅ Pas de dépendances externes vulnérables

### Limitations

- Le serveur ne fait que scanner et analyser
- Il ne collecte aucune donnée externe
- Il ne communique pas sur le réseau
- Tous les traitements sont locaux

## Support

Pour toute question ou problème:
- Issues: GitHub repository
- Email: support@arkforge.fr
- Documentation: `/opt/claude-ceo/workspace/mcp-servers/eu-ai-act/README.md`

---

**Version**: 1.0.0
**Dernière mise à jour**: 2026-02-09
**Maintenu par**: ArkForge
