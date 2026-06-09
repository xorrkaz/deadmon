# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 deadmon contributors
# Based on the original deadman work by upa@haeena.net.

set dotenv-load
set shell := ['bash', '-c']
python_files := "deadmon/*.py bin/deadmon bin/deadmon-convert-config tests/*.py"

@_:
    just --list

[group('lifecycle')]
sync:
    uv sync

[group('lifecycle')]
lock:
    uv lock

[group('lifecycle')]
update:
    uv sync --upgrade --all-extras

[group('lifecycle')]
install:
    uv sync --all-extras --no-dev

[group('lifecycle')]
dev-install:
    uv sync --all-extras

[group('qa')]
check:
    uv run python -m py_compile {{python_files}}
    just lint
    just format-check
    just test
    uv run deadmon --check-config deadmon.conf

[group('qa')]
lint:
    uv run ruff check {{python_files}}

[group('qa')]
format-check:
    uv run ruff format --check {{python_files}}

[group('qa')]
format:
    uv run ruff check --fix {{python_files}}
    uv run ruff format {{python_files}}

[group('qa')]
test:
    uv run python -m unittest discover -s tests

[group('config')]
dump-config:
    uv run deadmon --dump-config deadmon.conf

[group('config')]
convert-config input="deadmon.conf":
    uv run python bin/deadmon-convert-config {{input}}

[group('config')]
convert-config-to input output:
    uv run python bin/deadmon-convert-config {{input}} --output {{output}}

[group('run')]
run host="127.0.0.1" port="8000" config="deadmon.conf":
    uv run deadmon --host {{host}} --port {{port}} {{config}}

# Remove temporary files
[group('lifecycle')]
[confirm("This will delete .venv, caches, and __pycache__ directories. Continue?")]
clean:
    rm -rf .venv .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
    find . -type d -name "__pycache__" -exec rm -r {} +

[group('lifecycle')]
distclean:
    rm -rf dist

# Recreate project virtualenv from nothing
[group('lifecycle')]
[confirm("This will delete and recreate the entire virtual environment. Continue?")]
fresh: clean dev-install

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

[group('publish')]
pypi-publish: build
    @echo -n PyPi Token: ; \
    read -s token ; \
    echo ; \
    echo "Publishing package to PyPi..." ; \
    uv publish --token "$token"   

[group('publish')]
publish: build docker-build pypi-publish docker-publish

[group('run')]
docker-up:
    docker compose up --build -d

[group('run')]
docker-down:
    docker compose down

[group('run')]
docker-ipv6-check target="2001:4860:4860::8888":
    docker compose exec deadmon ping -6 -c 1 {{target}}
