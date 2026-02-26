.PHONY: install test test-quick test-latency lint format typecheck clean all

all: lint typecheck test

install:
	pip install -e ".[dev]"
	python -m spacy download en_core_web_sm

test:
	pytest tests/ -v --cov=aumos_security_runtime --cov-report=term-missing

test-quick:
	pytest tests/ -x -q --no-header

test-latency:
	pytest tests/test_latency.py -v --benchmark-only

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

typecheck:
	mypy src/aumos_security_runtime/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +
	rm -rf dist/ build/ *.egg-info

docker-build:
	docker build -t aumos/security-runtime:dev .

docker-run:
	docker compose -f docker-compose.dev.yml up -d
