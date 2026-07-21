.PHONY: dev test lint typecheck all

## Install deps against the SUITE.lock-locked substrate (Plan 019 B2)
# Installs regista at the released version pinned in SUITE.lock (the single
# source of truth for what to develop against), then `-e .[dev]`. Same install
# shape CI uses. Override the substrate deliberately with
# DEV_AGAINST=main|<ref>|sibling (see docs/develop-against-lock.md).
dev:
	python scripts/dev-install.py

## Run tests (Postgres-dependent tests skip without a live DSN)
test:
	pytest tests/ -v

## Lint with ruff
lint:
	ruff check src/ tests/

## Type check with mypy
typecheck:
	mypy src/dossier/

## Lint, type-check, and test
all: lint typecheck test
