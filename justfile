# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 deadmon contributors
# Based on the original deadman work by upa@haeena.net.

set dotenv-load
set shell := ['bash', '-c']
python_files := "deadmon/*.py bin/deadmon bin/deadmon-convert-config tests/*.py"

@_:
    just --list

# Generate the uv lock file
[group('lifecycle')]
lock:
    uv lock

# Upgrade all dependencies to their latest versions
[group('lifecycle')]
update:
    uv sync --upgrade --all-extras

# Install the runtime dependencies
[group('lifecycle')]
install:
    uv sync --all-extras --no-dev

# Install the development dependencies
[group('lifecycle')]
dev-install:
    uv sync --all-extras

# Run all QA checks (linting, formatting, tests, and config validation)
[group('qa')]
check:
    uv run python -m py_compile {{python_files}}
    just lint
    just format-check
    just test
    uv run deadmon --check-config deadmon.conf

# Run code linting (use with --fix to automatically fix issues, but review changes before committing)
[group('qa')]
lint:
    uv run ruff check {{python_files}}

# Check code formatting without making changes (useful for CI checks)
[group('qa')]
format-check:
    uv run ruff format --check {{python_files}}

# Automatically fix formatting issues (use with caution, review changes before committing)
[group('qa')]
format:
    uv run ruff check --fix {{python_files}}
    uv run ruff format {{python_files}}

# Run unit tests
[group('qa')]
test:
    uv run python -m unittest discover -s tests

# Dump the configuration file to stdout (useful for debugging config issues)
[group('config')]
dump-config:
    uv run deadmon --dump-config deadmon.conf

# Convert the configuration file and print the output to stdout (useful for debugging config issues)
[group('config')]
convert-config input="deadmon.conf":
    uv run python bin/deadmon-convert-config {{input}}

# Convert the configuration file and save the output to a new file (useful for converting old configs to new formats)
[group('config')]
convert-config-to input output:
    uv run python bin/deadmon-convert-config {{input}} --output {{output}}

# Run the deadmon server (make sure to adjust host, port, and config path as needed)
[group('run')]
run host="127.0.0.1" port="8000" config="deadmon.conf":
    uv run deadmon --host {{host}} --port {{port}} {{config}}

# Remove temporary files
[group('lifecycle')]
[confirm("This will delete .venv, caches, and __pycache__ directories. Continue?")]
clean:
    rm -rf .venv .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
    find . -type d -name "__pycache__" -exec rm -r {} +

# Clean up build artifacts
[group('lifecycle')]
distclean:
    rm -rf dist

# Recreate project virtualenv from nothing
[group('lifecycle')]
[confirm("This will delete and recreate the entire virtual environment. Continue?")]
fresh: clean dev-install

# Generate the Docker Compose configuration (useful for debugging the compose file without running it)
[group('qa')]
docker-config:
    docker compose config

# Build the Python package
[group('build')]
build:
    uv build

# Build the docker container image
[group('build')]
docker-build:
    docker buildx build --platform linux/amd64,linux/arm64 -t xorrkaz/deadmon:latest -t xorrkaz/deadmon:$(uv version --short) .

# Publish the docker container image to Docker Hub
[group('publish')]
docker-publish:
    docker login
    docker buildx build --platform linux/amd64,linux/arm64 -t xorrkaz/deadmon:latest -t xorrkaz/deadmon:$(uv version --short) --push .

# Publish the Python package to PyPi (requires a PyPi token)
[group('publish')]
pypi-publish: build
    @echo -n PyPi Token: ; \
    read -s token ; \
    echo ; \
    echo "Publishing package to PyPi..." ; \
    uv publish --token "$token"   

# Publish both the Python package and the Docker image
[group('publish')]
publish: build docker-build pypi-publish docker-publish

# Load the Docker image locally (for testing without pushing to Docker Hub)
[group('run')]
docker-load:
    docker buildx build --platform linux/amd64,linux/arm64 -t xorrkaz/deadmon:latest -t xorrkaz/deadmon:$(uv version --short) --load .

# Run the Docker container (make sure to adjust volume mounts and ports as needed)
[group('run')]
docker-up:
    docker compose up --build -d

# Stop and remove the Docker container
[group('run')]
docker-down:
    docker compose down

# Check if the container can ping an IPv6 address
[group('run')]
docker-ipv6-check target="2001:4860:4860::8888":
    docker compose exec deadmon ping -6 -c 1 {{target}}
