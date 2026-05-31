# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 deadmon contributors
# Based on the original deadman work by upa@haeena.net.

set shell := ["sh", "-eu", "-c"]
python_files := "deadmon/*.py bin/deadmon bin/deadmon-convert-config tests/*.py"

default:
    just --list

sync:
    uv sync

lock:
    uv lock

check:
    uv run python -m py_compile {{python_files}}
    just lint
    just test
    uv run deadmon --check-config deadmon.conf

lint:
    uv run black --check {{python_files}}
    uv run ruff check {{python_files}}

format:
    uv run black {{python_files}}
    uv run ruff check --fix {{python_files}}

test:
    uv run python -m unittest discover -s tests

dump-config:
    uv run deadmon --dump-config deadmon.conf

convert-config input="deadmon.conf":
    uv run python bin/deadmon-convert-config {{input}}

convert-config-to input output:
    uv run python bin/deadmon-convert-config {{input}} --output {{output}}

run host="127.0.0.1" port="8000" config="deadmon.conf":
    uv run deadmon --host {{host}} --port {{port}} {{config}}

docker-config:
    docker compose config

docker-build:
    docker compose build

docker-up:
    docker compose up --build -d

docker-down:
    docker compose down

docker-ipv6-check target="2001:4860:4860::8888":
    docker compose exec deadmon ping -6 -c 1 {{target}}
