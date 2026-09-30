# AGENTS.md — apex-ebpf-sentinel

**Company:** GlacierEQ
**Domain:** Autonomous Systems Engineering

## Quick Rules
- **Test command:** `PYTHONPATH=src pytest tests/ -v`
- **Lint:** `ruff check src/ tests/`
- **No drive-by edits** — load the skill first.

## Architecture
- `src/apex_ebpf_sentinel/core.py` — Domain logic (Autonomous Systems Engineering)
- `tests/` — Verified test suite
- `.github/workflows/ci.yml` — Enforced CI pipeline
