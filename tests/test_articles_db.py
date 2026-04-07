"""Tests for eu_ai_act_articles.json knowledge base — TDD for v2 compliance tools."""
import json
from pathlib import Path

import pytest

DATA_FILE = Path(__file__).parent.parent / "data" / "eu_ai_act_articles.json"

EXPECTED_ARTICLES = {
    "5", "6", "9", "10", "11", "12", "13", "14", "15", "17", "25", "50", "52", "Annex III"
}

VALID_APPLIES_TO = {"unacceptable", "high", "limited", "minimal"}
VALID_STAKEHOLDERS = {"provider", "deployer", "distributor", "importer"}

SCHEMA_REQUIRED_FIELDS = [
    "article",
    "title",
    "applies_to",
    "stakeholder",
    "summary",
    "requirements",
    "checklist",
    "effort_days",
    "deadline_critical",
    "template_available",
    "content_keywords",
    "required_sections",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def db():
    """Load and return the full knowledge base as a dict."""
    assert DATA_FILE.exists(), f"Knowledge base not found at {DATA_FILE}"
    with DATA_FILE.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def articles(db):
    """Return the list of article objects."""
    return db["articles"]


@pytest.fixture(scope="module")
def articles_by_id(articles):
    """Return a dict keyed by article identifier."""
    return {a["article"]: a for a in articles}


# ---------------------------------------------------------------------------
# 1. JSON integrity
# ---------------------------------------------------------------------------

def test_json_loads_successfully():
    """File must exist and be valid JSON."""
    assert DATA_FILE.exists(), f"Knowledge base not found at {DATA_FILE}"
    with DATA_FILE.open(encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, dict), "Top-level structure must be a JSON object"


# ---------------------------------------------------------------------------
# 2. Top-level fields
# ---------------------------------------------------------------------------

def test_required_top_level_fields(db):
    """version, articles and enforcement_deadline must all be present."""
    for field in ("version", "articles", "enforcement_deadline"):
        assert field in db, f"Missing top-level field: {field}"
    assert isinstance(db["articles"], list), "'articles' must be a list"


# ---------------------------------------------------------------------------
# 3. Article presence
# ---------------------------------------------------------------------------

def test_all_14_articles_present(articles_by_id):
    """All 14 required article identifiers must be present."""
    missing = EXPECTED_ARTICLES - set(articles_by_id.keys())
    assert not missing, f"Missing article(s): {missing}"


def test_annex_iv_present(articles_by_id):
    """Annex IV must be present as a separate entry."""
    assert "Annex IV" in articles_by_id, "Annex IV entry is missing from the knowledge base"


# ---------------------------------------------------------------------------
# 4. No duplicates
# ---------------------------------------------------------------------------

def test_no_duplicate_articles(articles):
    """No two entries may share the same article identifier."""
    ids = [a["article"] for a in articles]
    seen = set()
    duplicates = set()
    for aid in ids:
        if aid in seen:
            duplicates.add(aid)
        seen.add(aid)
    assert not duplicates, f"Duplicate article identifiers: {duplicates}"


# ---------------------------------------------------------------------------
# 5. Schema — required fields on every article
# ---------------------------------------------------------------------------

def test_schema_required_fields(articles):
    """Every article object must contain all required schema fields."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        for field in SCHEMA_REQUIRED_FIELDS:
            if field not in art:
                errors.append(f"Article '{aid}' missing field: {field}")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 6. applies_to valid values
# ---------------------------------------------------------------------------

def test_applies_to_valid_values(articles):
    """applies_to must only contain values from the allowed set."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        for val in art.get("applies_to", []):
            if val not in VALID_APPLIES_TO:
                errors.append(f"Article '{aid}': invalid applies_to value '{val}'")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 7. stakeholder valid values
# ---------------------------------------------------------------------------

def test_stakeholder_valid_values(articles):
    """stakeholder must only contain values from the allowed set."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        for val in art.get("stakeholder", []):
            if val not in VALID_STAKEHOLDERS:
                errors.append(f"Article '{aid}': invalid stakeholder value '{val}'")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 8. effort_days
# ---------------------------------------------------------------------------

def test_effort_days_is_integer(articles):
    """effort_days must be an integer >= 0 for every article."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        ed = art.get("effort_days")
        if not isinstance(ed, int) or ed < 0:
            errors.append(f"Article '{aid}': effort_days={ed!r} is not a non-negative integer")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 9. requirements non-empty
# ---------------------------------------------------------------------------

def test_requirements_non_empty(articles):
    """Every article must have at least one requirement."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        reqs = art.get("requirements", [])
        if not reqs:
            errors.append(f"Article '{aid}' has no requirements")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 10. checklist non-empty
# ---------------------------------------------------------------------------

def test_checklist_non_empty(articles):
    """Every article must have at least one checklist item."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        cl = art.get("checklist", [])
        if not cl:
            errors.append(f"Article '{aid}' has no checklist items")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 11. checklist item schema
# ---------------------------------------------------------------------------

def test_checklist_items_have_required_fields(articles):
    """Each checklist item must contain at least 'item' and 'required' fields."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        for idx, ci in enumerate(art.get("checklist", [])):
            for field in ("item", "required"):
                if field not in ci:
                    errors.append(
                        f"Article '{aid}' checklist item {idx}: missing field '{field}'"
                    )
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 12. content_keywords non-empty
# ---------------------------------------------------------------------------

def test_content_keywords_non_empty(articles):
    """content_keywords must be a non-empty list for every article."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        kw = art.get("content_keywords", [])
        if not isinstance(kw, list) or len(kw) == 0:
            errors.append(f"Article '{aid}': content_keywords is empty or not a list")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 13. required_sections non-empty
# ---------------------------------------------------------------------------

def test_required_sections_non_empty(articles):
    """required_sections must be a non-empty list for every article."""
    errors = []
    for art in articles:
        aid = art.get("article", "<unknown>")
        rs = art.get("required_sections", [])
        if not isinstance(rs, list) or len(rs) == 0:
            errors.append(f"Article '{aid}': required_sections is empty or not a list")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 14. High-risk articles apply to "high"
# ---------------------------------------------------------------------------

def test_high_risk_articles_all_present(articles_by_id):
    """Articles 9, 10, 11, 12, 13, 14, 15 and 17 must all apply to 'high'."""
    high_risk_ids = {"9", "10", "11", "12", "13", "14", "15", "17"}
    errors = []
    for aid in high_risk_ids:
        art = articles_by_id.get(aid)
        if art is None:
            errors.append(f"Article '{aid}' not found in knowledge base")
            continue
        if "high" not in art.get("applies_to", []):
            errors.append(f"Article '{aid}': expected 'high' in applies_to, got {art['applies_to']}")
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# 15. Article 52 — limited risk
# ---------------------------------------------------------------------------

def test_article_52_applies_to_limited(articles_by_id):
    """Article 52 must include 'limited' in applies_to."""
    art = articles_by_id.get("52")
    assert art is not None, "Article 52 not found"
    assert "limited" in art.get("applies_to", []), (
        f"Expected 'limited' in Article 52 applies_to, got {art['applies_to']}"
    )


# ---------------------------------------------------------------------------
# 16. Article 5 — unacceptable risk
# ---------------------------------------------------------------------------

def test_article_5_applies_to_unacceptable(articles_by_id):
    """Article 5 must include 'unacceptable' in applies_to."""
    art = articles_by_id.get("5")
    assert art is not None, "Article 5 not found"
    assert "unacceptable" in art.get("applies_to", []), (
        f"Expected 'unacceptable' in Article 5 applies_to, got {art['applies_to']}"
    )


# ---------------------------------------------------------------------------
# 17. Enforcement deadline
# ---------------------------------------------------------------------------

def test_enforcement_deadline_is_correct(db):
    """enforcement_deadline must equal '2026-08-02'."""
    assert db.get("enforcement_deadline") == "2026-08-02", (
        f"Expected '2026-08-02', got {db.get('enforcement_deadline')!r}"
    )
