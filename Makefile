.PHONY: help setup dev test test-unit test-integration test-security lint typecheck format build docker-build up down clean fixtures

help:
	@echo "StegoSentinel - Developer Command Interface"
	@echo "==========================================="
	@echo "make setup           - Install dependencies and generate test fixtures"
	@echo "make fixtures        - Generate safe synthetic test fixtures"
	@echo "make dev             - Start backend API and frontend locally"
	@echo "make test            - Run all test suites (unit, integration, security)"
	@echo "make test-unit       - Run unit tests only"
	@echo "make test-security   - Run security and boundary tests"
	@echo "make test-integration- Run end-to-end integration tests"
	@echo "make lint            - Run linter (ruff, eslint)"
	@echo "make typecheck       - Run type checking (mypy, tsc)"
	@echo "make format          - Format python and frontend code"
	@echo "make docker-build    - Build production docker images"
	@echo "make up              - Start complete docker-compose stack"
	@echo "make down            - Stop docker-compose stack"
	@echo "make clean           - Remove caches, temporary files, and local DBs"

setup: fixtures
	@echo "Installing backend dependencies..."
	cd backend && uv sync
	@echo "Installing frontend dependencies..."
	cd frontend && npm install

fixtures:
	@echo "Generating safe synthetic fixtures..."
	python3 scripts/generate_fixtures.py

dev:
	@echo "Starting StegoSentinel local development services..."
	python3 scripts/run_dev.py

test:
	@echo "Running full test suite..."
	cd backend && uv run pytest tests/ -v

test-unit:
	@echo "Running unit tests..."
	cd backend && uv run pytest tests/unit/ -v

test-security:
	@echo "Running security tests..."
	cd backend && uv run pytest tests/security/ -v

test-integration:
	@echo "Running integration tests..."
	cd backend && uv run pytest tests/integration/ -v

lint:
	@echo "Linting backend with ruff..."
	cd backend && uv run ruff check app/ tests/
	@echo "Linting frontend..."
	cd frontend && npm run lint || true

typecheck:
	@echo "Running backend typecheck..."
	cd backend && uv run mypy app/ || true

format:
	cd backend && uv run ruff format app/ tests/

docker-build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	rm -rf backend/stegosentinel.db
	rm -rf storage/quarantine/*
	touch storage/quarantine/.gitkeep
