# EU AI Act Compliance Checker - MCP Server

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![MCP](https://img.shields.io/badge/MCP-1.0-green)
![License](https://img.shields.io/badge/license-MIT-green)
![CI/CD](https://github.com/ark-forge/mcp-eu-ai-act/actions/workflows/qa-mcp-eu-ai-act.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)

**Automated EU AI Act compliance verification for AI projects** - MCP Server to automatically check compliance with European Union AI Act regulations.

## Keywords
`EU AI Act` · `compliance checker` · `MCP server` · `AI regulation` · `risk assessment` · `artificial intelligence` · `legal compliance` · `transparency` · `Model Context Protocol` · `automated audit` · `GDPR` · `AI governance`

## 🎯 Features / Fonctionnalités

- **Automatic detection** of AI models (OpenAI, Anthropic, HuggingFace, TensorFlow, PyTorch, LangChain)
- **Risk categorization** according to EU AI Act (unacceptable, high, limited, minimal)
- **Compliance verification** with regulatory requirements
- **Detailed JSON reports** generation
- **Actionable recommendations** to achieve compliance
- **GDPR alignment** checking
- **MCP protocol integration** for seamless workflow

## 📋 EU AI Act - Catégories de Risque

### Risque Inacceptable (Interdit)
- Manipulation comportementale
- Notation sociale par les gouvernements
- Surveillance de masse biométrique

### Risque Élevé (High)
- Systèmes de recrutement
- Systèmes de crédit
- Application de la loi
- Gestion des infrastructures critiques

**Exigences**: Documentation technique complète, gestion des risques, surveillance humaine, enregistrement UE

### Risque Limité (Limited)
- Chatbots
- Systèmes de recommandation
- Génération de contenu

**Exigences**: Transparence, information des utilisateurs, marquage du contenu AI

### Risque Minimal (Minimal)
- Filtres anti-spam
- Jeux vidéo
- Applications non critiques

**Exigences**: Aucune obligation spécifique

## 🚀 Installation

### Via Smithery (Recommended)

```bash
smithery install @arkforge/mcp-eu-ai-act
```

[Smithery](https://smithery.ai) is the official MCP server registry. Installing via Smithery ensures you get the latest stable version with automatic updates.

### Manual Installation

```bash
cd /opt/claude-ceo/workspace/mcp-servers/eu-ai-act
chmod +x server.py
```

## 📖 Utilisation

### 1. En ligne de commande

```bash
python3 server.py
```

### 2. En tant que module Python

```python
from server import MCPServer

# Initialiser le serveur
server = MCPServer()

# Scanner un projet
scan_result = server.handle_request("scan_project", {
    "project_path": "/path/to/project"
})

# Vérifier la conformité
compliance_result = server.handle_request("check_compliance", {
    "project_path": "/path/to/project",
    "risk_category": "limited"  # ou "high", "minimal", "unacceptable"
})

# Générer un rapport complet
report = server.handle_request("generate_report", {
    "project_path": "/path/to/project",
    "risk_category": "high"
})
```

## 🔧 MCP Tools

### scan_project

Scanne un projet pour détecter l'utilisation de modèles AI.

**Paramètres**:
- `project_path` (string, required): Chemin vers le projet

**Retour**:
```json
{
  "files_scanned": 150,
  "ai_files": [
    {
      "file": "src/main.py",
      "frameworks": ["openai", "langchain"]
    }
  ],
  "detected_models": {
    "openai": ["src/main.py", "src/api.py"],
    "langchain": ["src/main.py"]
  }
}
```

### check_compliance

Vérifie la conformité EU AI Act.

**Paramètres**:
- `project_path` (string, required): Chemin vers le projet
- `risk_category` (string, optional): Catégorie de risque (`unacceptable`, `high`, `limited`, `minimal`) - défaut: `limited`

**Retour**:
```json
{
  "risk_category": "limited",
  "description": "Systèmes à risque limité (chatbots, deepfakes)",
  "requirements": [
    "Obligations de transparence",
    "Information claire aux utilisateurs sur interaction avec AI"
  ],
  "compliance_status": {
    "transparence": true,
    "information_utilisateurs": true,
    "marquage_contenu": false
  },
  "compliance_score": "2/3",
  "compliance_percentage": 66.7
}
```

### generate_report

Génère un rapport de conformité complet.

**Paramètres**:
- `project_path` (string, required): Chemin vers le projet
- `risk_category` (string, optional): Catégorie de risque - défaut: `limited`

**Retour**:
```json
{
  "report_date": "2026-02-09T10:30:00",
  "project_path": "/path/to/project",
  "scan_summary": {
    "files_scanned": 150,
    "ai_files_detected": 5,
    "frameworks_detected": ["openai", "langchain"]
  },
  "compliance_summary": {
    "risk_category": "limited",
    "compliance_score": "2/3",
    "compliance_percentage": 66.7
  },
  "detailed_findings": {
    "detected_models": {...},
    "compliance_checks": {...},
    "requirements": [...]
  },
  "recommendations": [
    "❌ Créer documentation: Marquage Contenu",
    "ℹ️ Système à risque limité - Assurer transparence complète"
  ]
}
```

## 🔍 Frameworks Détectés

Le serveur détecte automatiquement les frameworks AI suivants:

- **OpenAI**: GPT-3.5, GPT-4, API OpenAI
- **Anthropic**: Claude, API Anthropic
- **HuggingFace**: Transformers, pipelines, modèles
- **TensorFlow**: Keras, modèles .h5
- **PyTorch**: Modèles .pt, .pth
- **LangChain**: Chaînes LLM, agents

## 📊 Vérifications de Conformité

### Pour systèmes à risque élevé (high)
- ✅ Documentation technique
- ✅ Système de gestion des risques
- ✅ Transparence et information utilisateurs
- ✅ Gouvernance des données
- ✅ Surveillance humaine
- ✅ Robustesse et cybersécurité

### Pour systèmes à risque limité (limited)
- ✅ Transparence (README, docs)
- ✅ Information sur l'utilisation d'AI
- ✅ Marquage du contenu généré

### Pour systèmes à risque minimal (minimal)
- ✅ Documentation basique

## 🛡️ Exigences Réglementaires

Ce serveur vérifie la conformité avec:
- **EU AI Act** (Règlement UE 2024/1689)
- **RGPD** (protection des données)
- **Transparence algorithmique**
- **Obligations de documentation**

## 📝 Exemple de Rapport

```bash
$ python3 server.py

=== EU AI Act Compliance Checker - MCP Server ===

Available tools:
- scan_project: Scanne un projet pour détecter l'utilisation de modèles AI
- check_compliance: Vérifie la conformité EU AI Act
- generate_report: Génère un rapport de conformité complet

=== Testing with current project ===

1. Scanning project...
Files scanned: 150
AI files detected: 5
Frameworks: openai, anthropic

2. Checking compliance (limited risk)...
Compliance score: 2/3 (66.7%)
Status: ⚠️ Partial compliance

3. Generating full report...
✅ Report generated successfully
```

## 🔗 Intégration MCP

Ce serveur est compatible avec le Model Context Protocol et peut être intégré dans:
- Claude Code
- VS Code avec extension MCP
- Outils de CI/CD
- Pipelines de déploiement

## 📚 Documentation EU AI Act

Ressources officielles:
- [EU AI Act - Texte officiel](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206)
- [Commission Européenne - AI Act](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [Guide de conformité](https://artificialintelligenceact.eu/)

## 🤝 Contribution

Ce serveur est développé par ArkForge dans le cadre du système CEO autonome.

## 📄 License

MIT License - Voir LICENSE pour plus de détails

## 🎯 Roadmap

- [ ] Intégration avec bases de données de conformité UE
- [ ] Support multi-langues (FR, EN, DE, ES)
- [ ] Génération automatique de documentation de conformité
- [ ] Scoring de risque automatique
- [ ] Export PDF des rapports
- [ ] Intégration CI/CD (GitHub Actions, GitLab CI)

---

**Version**: 1.0.0
**Date**: 2026-02-09
**Maintenu par**: ArkForge CEO System
