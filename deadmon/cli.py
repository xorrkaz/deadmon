# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 Joe Clarke <jclarke@marcuscom.com>
# Based on the original deadman work by upa@haeena.net.

from __future__ import annotations

import argparse
import json
import os
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="deadmon",
        description="Web-native reachability monitor for ICMP, relay, RouterOS, SNMP, and TCP targets.",
    )
    parser.add_argument(
        "config",
        nargs="?",
        default=os.environ.get("DEADMON_CONFIG", "deadmon.conf"),
        help="YAML or JSON deadmon config file",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("DEADMON_HOST", "127.0.0.1"),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("DEADMON_PORT", "8000")),
    )
    parser.add_argument(
        "--root-path",
        default=os.environ.get("DEADMON_ROOT_PATH", ""),
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("DEADMON_LOG_LEVEL", "info"),
    )
    parser.add_argument(
        "--forwarded-allow-ips",
        default=os.environ.get("FORWARDED_ALLOW_IPS", "*"),
        help="uvicorn forwarded_allow_ips value for reverse proxy deployments",
    )
    parser.add_argument("--reload", action="store_true", help="enable uvicorn auto-reload")
    parser.add_argument("--check-config", action="store_true", help="validate config and exit")
    parser.add_argument(
        "--dump-config",
        action="store_true",
        help="print sanitized parsed config and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    os.environ["DEADMON_CONFIG"] = args.config

    if args.check_config or args.dump_config:
        try:
            from deadmon.app import load_config, public_config

            config = load_config(args.config)
        except Exception as exc:  # noqa: BLE001 - CLI should show config/import errors plainly
            print(f"deadmon: config error: {exc}", file=sys.stderr)
            return 2

        if args.dump_config:
            print(json.dumps(public_config(config), indent=2))
        else:
            print(f"deadmon: ok - {len(config.targets)} targets across {len(config.groups)} groups, {config.poll_interval}s cadence")
        return 0

    try:
        import uvicorn
    except ModuleNotFoundError:
        print(
            "deadmon: uvicorn is not installed. Install dependencies with `uv sync`.",
            file=sys.stderr,
        )
        return 2

    if args.reload:
        app_ref = "deadmon.app:app"
    else:
        try:
            from deadmon.app import create_app
        except Exception as exc:  # noqa: BLE001 - config errors are user-facing here
            print(f"deadmon: startup error: {exc}", file=sys.stderr)
            return 2
        app_ref = create_app(args.config)

    uvicorn.run(
        app_ref,
        host=args.host,
        port=args.port,
        reload=args.reload,
        proxy_headers=True,
        forwarded_allow_ips=args.forwarded_allow_ips,
        root_path=args.root_path,
        log_level=args.log_level,
    )
    return 0
