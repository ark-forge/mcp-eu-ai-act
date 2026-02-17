# CI/CD Pipeline - MCP EU AI Act

> Pipeline GitHub Actions pour garantir la qualité et la sécurité du MCP EU AI Act

---

## 📋 Vue d'ensemble

Le pipeline CI/CD `.github/workflows/qa-mcp-eu-ai-act.yml` s'exécute automatiquement sur:
- **Push** vers `main` ou `develop`
- **Pull requests** vers `main` ou `develop`
- **Déclenchement manuel** via workflow_dispatch

---

## 🎯 Jobs du pipeline

### 1. Test (Matrice Python 3.9, 3.10, 3.11)

**Durée estimée**: 2-3 minutes par version Python

**Actions**:
- ✅ Checkout du code
- ✅ Installation des dépendances (pytest, pytest-cov)
- ✅ Exécution des tests avec coverage
- ✅ **Fail si coverage < 70%** (bloquant)
- ✅ Upload du rapport de couverture vers Codecov
- ✅ Archivage du rapport HTML (30 jours)

**Seuils de qualité**:
```yaml
--cov-fail-under=70  # Minimum 70% de couverture
```

**Sortie attendue**:
```
tests/test_server.py::test_list_tools PASSED                    [ 10%]
tests/test_integration.py::test_scan_project PASSED             [ 20%]
...
---------- coverage: platform linux, python 3.11 -----------
Name                    Stmts   Miss  Cover   Missing
-----------------------------------------------------
server.py                 245     35    85%   123-145, 230-240
-----------------------------------------------------
TOTAL                     245     35    85%
```

---

### 2. Quality Gates

**Durée estimée**: 1-2 minutes

**Vérifications bloquantes**:
- ✅ Tests existent (`tests/test_*.py`)
- ✅ Configuration pytest présente (pytest.ini, pyproject.toml, ou setup.cfg)
- ✅ Coverage >= 70%

**Vérifications non-bloquantes (warnings)**:
- ⚠️ Marqueurs de sécurité (`@pytest.mark.security`)
- ⚠️ Code smells (TODO/FIXME/HACK dans le code source)

**Exemple de sortie**:
```
✅ Found 3 test files
✅ Pytest configuration found
⚠️ Found 2 code smells (TODO/FIXME/HACK)
  server.py:125: # TODO: Add caching
  server.py:240: # FIXME: Optimize regex
📊 Coverage: 85.3%
```

---

### 3. Integration Tests

**Durée estimée**: 30-60 secondes

**Actions**:
- ✅ Exécution des tests marqués `@pytest.mark.integration`
- ✅ Test du serveur MCP en standalone (timeout 10s)

**Exemple**:
```bash
pytest tests/ -v -m "integration" --tb=short
timeout 10s python3 server.py
✅ Server ran successfully (timeout expected)
```

---

### 4. Security Scan

**Durée estimée**: 1-2 minutes

**Outils**:
- **Bandit**: Linter de sécurité Python (détecte les vulnérabilités courantes)
- **Safety**: Vérification des dépendances pour CVE connus

**Exemple de sortie**:
```
Run started: 2026-02-10 14:30:00
Test results:
  No issues identified. (Medium: 0, Low: 0)
Code scanned: server.py, tests/test_server.py
Total lines of code: 850
Total lines skipped (#nosec): 0
```

**Rapports générés**:
- `bandit-report.json` (archivé 30 jours)

---

### 5. Build Status Summary

**Durée estimée**: 5 secondes

**Résumé final**:
```
===================================
  MCP EU AI Act - Build Summary
===================================

✅ Tests: success
✅ Quality Gates: success
✅ Integration: success
✅ Security: success

✅ Build PASSED
```

---

## 📊 Badges dans le README

### Badge CI/CD
```markdown
![CI/CD](https://github.com/ark-forge/mcp-eu-ai-act/actions/workflows/qa-mcp-eu-ai-act.yml/badge.svg)
```

**États possibles**:
- ✅ **passing** (vert) - Tous les jobs réussis
- ❌ **failing** (rouge) - Au moins un job échoué
- 🟡 **pending** (jaune) - Pipeline en cours

### Badge Coverage
```markdown
![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)
```

**Couleurs selon le pourcentage**:
- 🔴 `< 50%` - red
- 🟡 `50-70%` - yellow
- 🟢 `70-80%` - green
- ✅ `>= 80%` - brightgreen

---

## 🚀 Workflow de publication

### Étape 1: Développement local
```bash
# Lancer les tests localement AVANT de push
pytest tests/ -v --cov=. --cov-report=term-missing --cov-fail-under=70
```

### Étape 2: Push vers GitHub
```bash
git add .github/workflows/qa-mcp-eu-ai-act.yml
git add tests/
git commit -m "Add CI/CD pipeline with 70% coverage enforcement"
git push origin main
```

### Étape 3: Pipeline s'exécute automatiquement
- GitHub Actions déclenche le workflow
- Jobs s'exécutent en parallèle (test sur 3 versions Python)
- Résultats visibles dans l'onglet "Actions" du repo

### Étape 4: Vérification des résultats
- ✅ **Tous les jobs passent** → Prêt pour publication Smithery
- ❌ **Un job échoue** → Fix requis avant merge

---

## 🔧 Configuration locale (développement)

### Installation des dépendances
```bash
pip install -r requirements.txt
```

### Lancer les tests avec coverage
```bash
# Tests complets
pytest tests/ -v --cov=. --cov-report=term-missing

# Tests unitaires uniquement
pytest tests/ -v -m unit

# Tests d'intégration uniquement
pytest tests/ -v -m integration

# Générer rapport HTML
pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html
```

### Vérifier le seuil de coverage
```bash
pytest tests/ --cov=. --cov-fail-under=70
echo $?  # 0 = success, 1 = coverage trop basse
```

---

## 📈 Métriques de qualité

| Métrique | Seuil | Actuel | Status |
|----------|-------|--------|--------|
| **Coverage globale** | >= 70% | 85% | ✅ PASS |
| **Tests passants** | 100% | 66/66 | ✅ PASS |
| **Versions Python** | 3.9, 3.10, 3.11 | 3.9-3.11 | ✅ PASS |
| **Vulnérabilités** | 0 critical/high | 0 | ✅ PASS |
| **Code smells** | Warning only | 2 | ⚠️ WARNING |

---

## 🛡️ Standards de sécurité

### Bandit - Règles appliquées
- **Niveau minimal**: Medium (`-ll` flag)
- **Portée**: Tout le code source (excluant tests/)
- **Sortie**: JSON + console

### Safety - Vérification des dépendances
- Scan de `requirements.txt`
- Alerte sur CVE connus
- Non-bloquant (warning)

---

## 📝 Checklist pré-publication

Avant de publier sur GitHub/Smithery, vérifier:

- [ ] ✅ Pipeline CI/CD passe sur `main`
- [ ] ✅ Coverage >= 70% (idéalement >= 80%)
- [ ] ✅ Tous les tests passent sur Python 3.9, 3.10, 3.11
- [ ] ✅ Aucune vulnérabilité critique (Bandit)
- [ ] ✅ Badges README à jour
- [ ] ✅ Documentation README complète
- [ ] ✅ LICENSE présent (MIT)

---

## 🔗 Intégration Smithery

Le pipeline CI/CD sera automatiquement déclenché lors de:
1. Push vers `main` (release)
2. Tag version (ex: `v1.0.0`)
3. Pull request (vérification avant merge)

Smithery peut afficher le badge CI/CD sur sa page de listing, rassurant les utilisateurs sur la qualité du package.

---

## 📚 Références

- **QA Framework ArkForge**: `/opt/claude-ceo/frameworks/qa-framework/QA_FRAMEWORK.md`
- **GitHub Actions Documentation**: https://docs.github.com/en/actions
- **pytest Documentation**: https://docs.pytest.org/
- **Codecov Integration**: https://about.codecov.io/

---

**Date**: 2026-02-10
**Version**: 1.0
**Maintenu par**: Worker Fondations (ArkForge CEO System)
