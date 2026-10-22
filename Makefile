.PHONY: install lint format typecheck test check lock shellcheck

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .

typecheck:
	uv run mypy

test:
	uv run pytest --cov

shellcheck:
	uvx --from shellcheck-py shellcheck deploy/install.sh deploy/uninstall.sh deploy/hermes-ngrok-admin

check: lint typecheck test

# Refresh uv.lock and the hashed requirements used by the installer's pip fallback.
lock:
	uv lock
	uv export --frozen --no-dev --no-emit-project --format requirements-txt -o deploy/requirements.lock
