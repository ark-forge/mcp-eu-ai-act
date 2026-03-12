# Contributing to mcp-eu-ai-act

## Before you start

Open an issue first for any non-trivial change. This avoids wasted effort if the direction doesn't fit the project.

For typos and small doc fixes, a PR directly is fine.

## Branching

- `main` is stable and protected — no direct push
- Create a branch from `main`: `feat/your-feature` or `fix/your-fix`
- Open a PR against `main`

## Development setup

```bash
git clone https://github.com/ark-forge/mcp-eu-ai-act.git
cd mcp-eu-ai-act
pip install -e ".[dev]"
```

## Running the scanner locally

```bash
python -m eu_ai_act_scanner scan ./your-project
```

## Running tests

```bash
pytest tests/ -q
```

## Pull request checklist

- [ ] Tests pass locally
- [ ] README updated if behavior changed
- [ ] CHANGELOG entry added under `[Unreleased]`
- [ ] New compliance rules include test coverage

## What we accept

- Bug fixes
- New framework detections (add to the 26 supported frameworks)
- New compliance rules (EU AI Act articles, GDPR)
- Improved error messages and output formatting
- Documentation improvements

## What requires an issue first

- Changes to the core scanning algorithm
- New output formats
- Breaking changes to the CLI interface

## Questions

Open an issue or reach out at [arkforge.tech](https://arkforge.tech).
