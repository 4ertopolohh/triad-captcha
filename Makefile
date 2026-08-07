PYTHON ?= python
NPM ?= npm
COMPOSE ?= docker compose

.PHONY: help install-python install-react lint-python test-python test-repository \
	build-python check-react pack-react check-compose check-versions check

help:
	@echo "TriadCAPTCHA local quality commands"
	@echo "  make install-python   Install Django package test/lint dependencies"
	@echo "  make install-react    Install the locked React dependency tree"
	@echo "  make check            Run local lint, tests, builds, and static checks"

install-python:
	$(PYTHON) -m pip install -e "./packages/django[test,lint]" build twine

install-react:
	$(NPM) --prefix packages/react ci

lint-python:
	$(PYTHON) -m ruff check packages/django tests scripts examples/django-react-demo/backend

test-python:
	cd packages/django && $(PYTHON) -m pytest tests

test-repository:
	$(PYTHON) -m pytest tests

build-python:
	$(PYTHON) -m build packages/django
	$(PYTHON) -m twine check packages/django/dist/*

check-react:
	$(NPM) --prefix packages/react run typecheck
	$(NPM) --prefix packages/react run lint
	$(NPM) --prefix packages/react test
	$(NPM) --prefix packages/react run build

pack-react:
	cd packages/react && $(NPM) pack --dry-run

check-compose:
	$(COMPOSE) --env-file .env.example -f infra/docker-compose.yml config --quiet

check-versions:
	$(PYTHON) scripts/check_versions.py

check: lint-python test-python test-repository build-python check-react pack-react check-compose check-versions
