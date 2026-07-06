# RedCell task runner.  Install `just` (brew install just) or run the commands directly.

# day-zero: the deterministic verifier, no install needed
demo:
    python3 scripts/demo_verifier.py

# stdlib-only verifier tests, no install needed
test-spine:
    python3 tests/test_verifier_determinism.py

# full install + full test suite (needs uv: https://docs.astral.sh/uv/)
setup:
    uv sync

test:
    uv run pytest -q

lint:
    uv run ruff check .

# bring up local infra (postgres+pgvector, ollama)
up:
    docker compose up -d

# run the target MCP server (needs `uv sync`)
target:
    uv run python -m redcell_target.mcp_server

# the campaign freezes winners into corpus/<version>/ automatically
freeze:
    python3 scripts/run_campaign.py

# the guardrail-regression gate, run locally (fails on ASR regression)
gate:
    python3 scripts/run_gate.py
