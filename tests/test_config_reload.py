# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 Joe Clarke <jclarke@marcuscom.com>
# Based on the original deadman work by upa@haeena.net.

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import IsolatedAsyncioTestCase

from deadmon.app import (
    PING_FAILED,
    DeadmonASGI,
    MonitorService,
    ProbeResult,
    effective_alert_config,
    normalize_config,
)


def config_with_targets(*targets, threshold=3, retain_results=30):
    return normalize_config(
        {
            "app": {
                "retain_results": retain_results,
                "latency_warning_ms": 100,
                "latency_critical_ms": 250,
            },
            "alerts": {
                "enabled": True,
                "threshold": threshold,
                "clear_threshold": 2,
                "channels": [{"name": "global-slack", "type": "slack"}],
            },
            "groups": [
                {
                    "name": "WAN",
                    "targets": list(targets),
                }
            ],
        },
        Path("test.yaml"),
    )


def raw_config(*targets, threshold=3, retain_results=30):
    return {
        "app": {
            "retain_results": retain_results,
            "latency_warning_ms": 100,
            "latency_critical_ms": 250,
        },
        "alerts": {
            "enabled": True,
            "threshold": threshold,
            "clear_threshold": 2,
            "channels": [{"name": "global-slack", "type": "slack"}],
        },
        "groups": [
            {
                "name": "WAN",
                "targets": list(targets),
            }
        ],
    }


async def call_asgi_json(app, method, path):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await app(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
        },
        receive,
        send,
    )

    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return status, json.loads(body.decode("utf-8"))


class ConfigReloadTests(IsolatedAsyncioTestCase):
    async def test_reload_preserves_state_for_unchanged_target(self):
        config = config_with_targets({"name": "router", "address": "192.0.2.10", "note": "old"}, threshold=1)
        monitor = MonitorService(config)
        target = config.targets[0]
        state = monitor.states[target.stable_id]

        transition = state.consume(
            ProbeResult(success=False, code=PING_FAILED, message="failed"),
            alert_threshold=1,
            clear_threshold=2,
            rtt_scale_ms=10,
        )
        self.assertIsNotNone(transition)
        self.assertTrue(state.alert_active)

        new_config = config_with_targets(
            {"name": "router", "address": "192.0.2.10", "note": "new"},
            threshold=2,
            retain_results=10,
        )

        result = await monitor.reload_config(new_config)
        new_target = new_config.targets[0]
        reloaded_state = monitor.states[new_target.stable_id]

        self.assertIs(reloaded_state, state)
        self.assertEqual(result["preserved_targets"], 1)
        self.assertEqual(result["added_targets"], 0)
        self.assertEqual(result["removed_targets"], 0)
        self.assertEqual(reloaded_state.sent, 1)
        self.assertEqual(reloaded_state.consecutive_down, 1)
        self.assertTrue(reloaded_state.alert_active)
        self.assertEqual(len(reloaded_state.history), 1)
        self.assertEqual(reloaded_state.target.note, "new")
        self.assertEqual(reloaded_state.retain_results, 10)
        self.assertEqual(effective_alert_config(new_target, monitor.config).threshold, 2)

    async def test_reload_replaces_state_for_added_and_removed_targets(self):
        config = config_with_targets({"name": "router-a", "address": "192.0.2.10"})
        monitor = MonitorService(config)
        old_target_id = config.targets[0].stable_id

        new_config = config_with_targets({"name": "router-b", "address": "192.0.2.11"})

        result = await monitor.reload_config(new_config)
        new_target_id = new_config.targets[0].stable_id

        self.assertEqual(result["preserved_targets"], 0)
        self.assertEqual(result["added_targets"], 1)
        self.assertEqual(result["removed_targets"], 1)
        self.assertNotIn(old_target_id, monitor.states)
        self.assertIn(new_target_id, monitor.states)

    async def test_reload_endpoint_reloads_config_without_replacing_existing_state(self):
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "deadmon.json"
            config_path.write_text(
                json.dumps(raw_config({"name": "router", "address": "192.0.2.10", "note": "old"})),
                encoding="utf-8",
            )
            app = DeadmonASGI(config_path)
            target = app.config.targets[0]
            state = app.monitor.states[target.stable_id]

            state.consume(
                ProbeResult(success=False, code=PING_FAILED, message="failed"),
                alert_threshold=3,
                clear_threshold=2,
                rtt_scale_ms=10,
            )

            config_path.write_text(
                json.dumps(
                    raw_config(
                        {"name": "router", "address": "192.0.2.10", "note": "new"},
                        threshold=1,
                        retain_results=10,
                    )
                ),
                encoding="utf-8",
            )

            status, payload = await call_asgi_json(app, "POST", "/api/reload")
            reloaded_target = app.config.targets[0]

            self.assertEqual(status, 200)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["preserved_targets"], 1)
            self.assertEqual(app.monitor.reload_count, 1)
            self.assertIs(app.monitor.states[reloaded_target.stable_id], state)
            self.assertEqual(state.sent, 1)
            self.assertEqual(state.consecutive_down, 1)
            self.assertEqual(state.target.note, "new")

    def test_reload_bad_config_exits_process(self):
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "deadmon.json"
            config_path.write_text(
                json.dumps(raw_config({"name": "router", "address": "192.0.2.10"})),
                encoding="utf-8",
            )
            script = f"""
import asyncio
from pathlib import Path
from deadmon.app import DeadmonASGI

path = Path({str(config_path)!r})
app = DeadmonASGI(path)
path.write_text("groups: [", encoding="utf-8")
asyncio.run(app.reload_config())
"""

            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("deadmon: failed to reload config", result.stderr)
            self.assertIn("exiting", result.stderr)
