.PHONY: help install test scan scan-all gate docker-build docker-up clean

help:
	@echo "DevSecOps Security Pipeline Management Commands:"
	@echo "  make install       - Install application and security tooling dependencies"
	@echo "  make test          - Run test suite for target app and security engine"
	@echo "  make scan          - Run fast local security audit (Secrets, SAST, SCA)"
	@echo "  make scan-all      - Run full security audit suite including DAST"
	@echo "  make gate          - Evaluate security gatekeeper against existing reports"
	@echo "  make docker-build  - Build hardened multi-stage Docker target container"
	@echo "  make docker-up     - Spin up target container in background"
	@echo "  make clean         - Clean temporary reports, cache, and artifacts"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test:
	pytest -v tests/

scan:
	python run_pipeline.py --secrets --sast --sca

scan-all:
	python run_pipeline.py --all

gate:
	python run_pipeline.py --gate-only --fail-on-gate

docker-build:
	docker build -t devsecops-target-app:latest .

docker-up:
	docker compose up -d target-app

clean:
	rm -rf __pycache__ .pytest_cache reports/*.json reports/*.html reports/*.sarif reports/*.md
