PYTHON ?= python
ENV ?= development

.PHONY: install dev test sample eval ingest docker-up docker-down docker-build-env docker-run-env eval-quick

install:
	uv sync

dev:
	uv run uvicorn app.main:app --reload

test:
	uv run pytest

sample:
	uv run python scripts/run_sample.py

eval:
	uv run python evals/run_eval.py

eval-quick: eval

ingest:
	uv run python scripts/ingest_knowledge.py

docker-up:
	docker compose up --build

docker-down:
	docker compose down

docker-build-env:
	docker compose --env-file .env.$(ENV) build

docker-run-env:
	docker compose --env-file .env.$(ENV) up
