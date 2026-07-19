# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 Joe Clarke <jclarke@marcuscom.com>
# Based on the original deadman work by upa@haeena.net.

from __future__ import annotations

import asyncio
import base64
import json
import os
import platform
import re
import signal
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from shutil import which
from typing import Any, NoReturn


def _detect_version() -> str:
    try:
        return metadata.version("deadmon")
    except metadata.PackageNotFoundError:
        pass
    import tomllib

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        return str(data["project"]["version"])
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return "0.0.0"


APP_VERSION = _detect_version()
PING_SUCCESS = "success"
PING_FAILED = "failed"
PING_TIMEOUT = "timeout"
PING_SSH_FAILED = "ssh_failed"
DEFAULT_SNMPPING = "bundled"

SECRET_KEYS = {"password", "community", "key", "webhook_url"}
TOP_LEVEL_KEYS = {"app", "alerts", "groups"}
APP_KEYS = {
    "name",
    "public_url",
    "poll_interval",
    "tab_rotation_interval",
    "timeout",
    "rtt_scale_ms",
    "latency_warning_ms",
    "latency_critical_ms",
    "retain_results",
    "authentication",
}
ALERT_KEYS = {"enabled", "threshold", "clear_threshold", "channels"}
AUTHENTICATION_KEYS = {"username", "password", "password_env"}
ALERT_CHANNEL_KEYS = {
    "name",
    "type",
    "enabled",
    "webhook_url",
    "webhook_url_env",
    "channel",
    "icon_emoji",
    "timeout",
}
GROUP_KEYS = {
    "id",
    "name",
    "description",
    "latency_warning_ms",
    "latency_critical_ms",
    "alerts",
    "targets",
}
TARGET_KEYS = {
    "name",
    "address",
    "note",
    "info_url",
    "relay",
    "source",
    "tcp",
    "osname",
    "alerts",
    "latency_warning_ms",
    "latency_critical_ms",
}
RELAY_CONFIG_KEYS = {
    "relay",
    "via",
    "os",
    "user",
    "key",
    "community",
    "username",
    "password",
    "method",
    "snmpping",
    "verify",
}
TCP_KEYS = {"dstport", "method"}


@dataclass(slots=True)
class ProbeResult:
    success: bool = False
    code: str = PING_FAILED
    rtt_ms: float = 0.0
    ttl: int | None = None
    message: str = ""
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class TargetConfig:
    name: str
    address: str
    group_id: str
    group_name: str
    note: str = ""
    info_url: str | None = None
    relay: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    tcp: dict[str, Any] | None = None
    osname: str | None = None
    alerts: bool | None = None
    latency_warning_ms: float | None = None
    latency_critical_ms: float | None = None

    @property
    def stable_id(self) -> str:
        return slugify(f"{self.group_name}-{self.name}-{self.address}")


@dataclass(slots=True)
class GroupConfig:
    name: str
    group_id: str
    description: str = ""
    latency_warning_ms: float | None = None
    latency_critical_ms: float | None = None
    alerts: AlertOverride | None = None
    targets: list[TargetConfig] = field(default_factory=list)


@dataclass(slots=True)
class AlertChannel:
    name: str
    kind: str
    enabled: bool = True
    webhook_url: str | None = None
    webhook_url_env: str | None = None
    destination_channel: str | None = None
    icon_emoji: str | None = None
    timeout: float = 5.0

    def resolved_url(self) -> str | None:
        if self.webhook_url:
            return self.webhook_url
        if self.webhook_url_env:
            return os.environ.get(self.webhook_url_env)
        return None


@dataclass(slots=True)
class AlertConfig:
    enabled: bool = True
    threshold: int = 3
    clear_threshold: int = 2
    channels: list[AlertChannel] = field(default_factory=list)


@dataclass(slots=True)
class AuthenticationConfig:
    username: str
    password: str | None = None
    password_env: str | None = None


@dataclass(slots=True)
class AlertOverride:
    enabled: bool | None = None
    threshold: int | None = None
    clear_threshold: int | None = None
    channels: list[AlertChannel] | None = None


@dataclass(slots=True)
class DeadmonConfig:
    name: str
    path: Path
    public_url: str | None = None
    poll_interval: float = 5.0
    tab_rotation_interval: float = 15.0
    timeout: float = 1.0
    rtt_scale_ms: int = 10
    latency_warning_ms: float = 100.0
    latency_critical_ms: float = 250.0
    retain_results: int = 30
    authentication: dict | None = None
    groups: list[GroupConfig] = field(default_factory=list)
    alerts: AlertConfig = field(default_factory=AlertConfig)

    @property
    def targets(self) -> list[TargetConfig]:
        return [target for group in self.groups for target in group.targets]


@dataclass(slots=True)
class AlertTransition:
    action: str
    target_id: str
    target_name: str
    address: str
    group_name: str
    note: str
    info_url: str | None
    probe: str
    status: str
    threshold: int
    clear_threshold: int
    consecutive_down: int
    consecutive_up: int
    latest_rtt_ms: float
    avg_rtt_ms: float
    loss_rate: float
    sent: int
    ttl: int | None
    last_code: str
    last_message: str
    happened_at: datetime


class ConfigError(RuntimeError):
    pass


class TargetState:
    def __init__(
        self,
        target: TargetConfig,
        retain_results: int,
        latency_warning_ms: float,
        latency_critical_ms: float,
    ) -> None:
        self.target = target
        self.retain_results = retain_results
        self.latency_warning_ms = latency_warning_ms
        self.latency_critical_ms = latency_critical_ms
        self.history: deque[dict[str, Any]] = deque(maxlen=retain_results)
        self.up: bool | None = None
        self.alert_active = False
        self.alert_since: datetime | None = None
        self.updated_at: datetime | None = None
        self.last_change_at: datetime | None = None
        self.latest_rtt_ms = 0.0
        self.avg_rtt_ms = 0.0
        self.total_rtt_ms = 0.0
        self.ttl: int | None = None
        self.sent = 0
        self.loss = 0
        self.consecutive_down = 0
        self.consecutive_up = 0
        self.last_message = "waiting for first probe"
        self.last_code = "pending"
        self.latest_latency_state = "pending"

    def reconfigure(
        self,
        target: TargetConfig,
        retain_results: int,
        latency_warning_ms: float,
        latency_critical_ms: float,
    ) -> None:
        self.target = target
        self.latency_warning_ms = latency_warning_ms
        self.latency_critical_ms = latency_critical_ms
        if retain_results != self.retain_results:
            self.history = deque(self.history, maxlen=retain_results)
            self.retain_results = retain_results

    @property
    def loss_rate(self) -> float:
        if self.sent == 0:
            return 0.0
        return self.loss / self.sent * 100.0

    @property
    def status(self) -> str:
        if self.up is None:
            return "pending"
        if self.alert_active and not self.up:
            return "down"
        if self.alert_active or not self.up or self.latest_latency_state in {"warn", "critical"}:
            return "degraded"
        return "up"

    def consume(
        self,
        result: ProbeResult,
        alert_threshold: int,
        clear_threshold: int,
        rtt_scale_ms: int,
    ) -> AlertTransition | None:
        previous_up = self.up
        self.up = result.success
        self.updated_at = result.checked_at
        self.latest_rtt_ms = result.rtt_ms if result.success else 0.0
        self.ttl = result.ttl
        self.sent += 1
        self.last_message = result.message
        self.last_code = result.code
        self.latest_latency_state = result_latency_state(
            result,
            warning_ms=self.latency_warning_ms,
            critical_ms=self.latency_critical_ms,
        )

        if previous_up is not result.success:
            self.last_change_at = result.checked_at

        if result.success:
            self.consecutive_up += 1
            self.consecutive_down = 0
            self.total_rtt_ms += result.rtt_ms
            successes = self.sent - self.loss
            if successes > 0:
                self.avg_rtt_ms = self.total_rtt_ms / successes
        else:
            self.consecutive_down += 1
            self.consecutive_up = 0
            self.loss += 1

        self.history.append(
            {
                "success": result.success,
                "code": result.code,
                "rtt_ms": round(result.rtt_ms, 3),
                "level": result_level(result, rtt_scale_ms),
                "height_px": result_height_px(result, rtt_scale_ms),
                "latency_state": self.latest_latency_state,
                "checked_at": isoformat(result.checked_at),
            }
        )

        if not self.alert_active and self.consecutive_down >= alert_threshold:
            self.alert_active = True
            self.alert_since = result.checked_at
            return self._transition(
                "active",
                result.checked_at,
                alert_threshold=alert_threshold,
                clear_threshold=clear_threshold,
            )

        if self.alert_active and self.consecutive_up >= clear_threshold:
            self.alert_active = False
            self.alert_since = None
            return self._transition(
                "cleared",
                result.checked_at,
                alert_threshold=alert_threshold,
                clear_threshold=clear_threshold,
            )

        return None

    def _transition(
        self,
        action: str,
        happened_at: datetime,
        alert_threshold: int,
        clear_threshold: int,
    ) -> AlertTransition:
        return AlertTransition(
            action=action,
            target_id=self.target.stable_id,
            target_name=self.target.name,
            address=self.target.address,
            group_name=self.target.group_name,
            note=self.target.note,
            info_url=self.target.info_url,
            probe=target_probe_label(self.target),
            status=self.status,
            threshold=alert_threshold,
            clear_threshold=clear_threshold,
            consecutive_down=self.consecutive_down,
            consecutive_up=self.consecutive_up,
            latest_rtt_ms=self.latest_rtt_ms,
            avg_rtt_ms=self.avg_rtt_ms,
            loss_rate=self.loss_rate,
            sent=self.sent,
            ttl=self.ttl,
            last_code=self.last_code,
            last_message=self.last_message,
            happened_at=happened_at,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.target.stable_id,
            "name": self.target.name,
            "address": self.target.address,
            "group_id": self.target.group_id,
            "group_name": self.target.group_name,
            "note": self.target.note,
            "info_url": self.target.info_url,
            "status": self.status,
            "up": self.up,
            "alert_active": self.alert_active,
            "alert_since": isoformat(self.alert_since),
            "updated_at": isoformat(self.updated_at),
            "last_change_at": isoformat(self.last_change_at),
            "latest_rtt_ms": round(self.latest_rtt_ms, 3),
            "avg_rtt_ms": round(self.avg_rtt_ms, 3),
            "latency_state": self.latest_latency_state,
            "latency_warning_ms": clean_float(self.latency_warning_ms),
            "latency_critical_ms": clean_float(self.latency_critical_ms),
            "loss_rate": round(self.loss_rate, 2),
            "sent": self.sent,
            "loss": self.loss,
            "ttl": self.ttl,
            "consecutive_down": self.consecutive_down,
            "consecutive_up": self.consecutive_up,
            "last_code": self.last_code,
            "last_message": self.last_message,
            "relay": public_relay(self.target.relay),
            "source": self.target.source,
            "tcp": public_tcp(self.target.tcp),
            "history": list(self.history),
        }


class ProbeRunner:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    async def probe(self, target: TargetConfig) -> ProbeResult:
        if target.tcp:
            return await self._tcp_probe(target)

        relay = target.relay or {}
        via = relay.get("via")
        if via == "snmp":
            return await self._snmp_probe(target)
        if via == "routeros_api":
            return await self._routeros_probe(target)

        return await self._icmp_probe(target)

    async def _icmp_probe(self, target: TargetConfig) -> ProbeResult:
        osname = target.osname or target.relay.get("os") or platform.system()
        ip_version = which_ip_version(target.address)
        if not ip_version:
            return ProbeResult(code=PING_FAILED, message=f"cannot resolve {target.address}")

        ping_args = ping_command(osname, ip_version)
        if not ping_args:
            return ProbeResult(code=PING_FAILED, message=f"ping is not supported on {osname}")

        cmd: list[str] = []
        relay = target.relay or {}
        via = relay.get("via")
        if via == "netns":
            relay_name = relay.get("relay")
            if not relay_name:
                return ProbeResult(code=PING_FAILED, message="netns relay is missing relay")
            cmd += ["ip", "netns", "exec", str(relay_name)]
        elif via == "vrf":
            relay_name = relay.get("relay")
            if not relay_name:
                return ProbeResult(code=PING_FAILED, message="vrf relay is missing relay")
            cmd += ["ip", "vrf", "exec", str(relay_name)]
        elif relay:
            relay_host = relay.get("relay")
            if not relay_host:
                return ProbeResult(code=PING_FAILED, message="ssh relay is missing relay")
            cmd += [
                "ssh",
                "-o",
                "ConnectTimeout=3",
                "-o",
                "StrictHostKeyChecking=no",
            ]
            if relay.get("key"):
                cmd += ["-i", str(relay["key"])]
            if relay.get("user"):
                cmd += ["-l", str(relay["user"])]
            cmd.append(str(relay_host))

        cmd += ping_args
        if target.source:
            if osname == "Linux":
                cmd += ["-I", target.source]
            elif osname == "Darwin":
                cmd += ["-S", target.source]
            else:
                return ProbeResult(code=PING_FAILED, message=f"source is not supported on {osname}")

        cmd.append(target.address)
        output, timed_out = await run_command(cmd, timeout=self.timeout)
        return parse_ping_output(output, timed_out=timed_out)

    async def _tcp_probe(self, target: TargetConfig) -> ProbeResult:
        tcp = target.tcp or {}
        port = int(tcp.get("dstport") or 0)
        if port <= 0:
            return ProbeResult(code=PING_FAILED, message="tcp probe is missing dstport")

        if str(tcp.get("method", "")).lower() == "hping3":
            cmd = ["hping3", "-S", target.address, "-p", str(port), "-c", "1"]
            output, timed_out = await run_command(cmd, timeout=self.timeout)
            if timed_out:
                return ProbeResult(code=PING_TIMEOUT, message="hping3 timed out")
            rtt_match = re.search(r"round-trip min/avg/max\s*=\s*(\d+(?:\.\d+)?)", output)
            if rtt_match:
                return ProbeResult(
                    success=True,
                    code=PING_SUCCESS,
                    rtt_ms=float(rtt_match.group(1)),
                    ttl=-1,
                    message="tcp hping3 success",
                )
            return ProbeResult(code=PING_FAILED, message=first_line(output) or "hping3 failed")

        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.address, port),
                timeout=self.timeout,
            )
            writer.close()
            await writer.wait_closed()
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return ProbeResult(
                success=True,
                code=PING_SUCCESS,
                rtt_ms=rtt_ms,
                ttl=-1,
                message=f"tcp/{port} connected",
            )
        except TimeoutError:
            return ProbeResult(code=PING_TIMEOUT, message=f"tcp/{port} timed out")
        except OSError as exc:
            return ProbeResult(code=PING_FAILED, message=f"tcp/{port} failed: {exc}")

    async def _snmp_probe(self, target: TargetConfig) -> ProbeResult:
        relay = target.relay or {}
        community = relay.get("community")
        relay_host = relay.get("relay")
        if not community:
            return ProbeResult(code=PING_FAILED, message="snmp relay is missing community")
        if not relay_host:
            return ProbeResult(code=PING_FAILED, message="snmp relay is missing relay")

        timeout_seconds = max(1, int(self.timeout + 0.999))
        cmd = [
            *snmpping_command(relay),
            "-Cc1",
            "-v",
            "2c",
            "-c",
            str(community),
            "-t",
            str(timeout_seconds),
            str(relay_host),
            target.address,
        ]
        output, timed_out = await run_command(cmd, timeout=timeout_seconds + 2.0)
        return parse_snmpping_output(output, timed_out=timed_out)

    async def _routeros_probe(self, target: TargetConfig) -> ProbeResult:
        return await asyncio.to_thread(self._routeros_probe_sync, target)

    def _routeros_probe_sync(self, target: TargetConfig) -> ProbeResult:
        relay = target.relay or {}
        username = relay.get("username")
        password = relay.get("password")
        relay_host = relay.get("relay")
        if not username or not password:
            return ProbeResult(code=PING_FAILED, message="routeros_api requires username and password")
        if not relay_host:
            return ProbeResult(code=PING_FAILED, message="routeros_api relay is missing relay")

        method = relay.get("method", "https")
        verify = str(relay.get("verify", "true")).lower() == "true"
        url = f"{method}://{relay_host}/rest/ping"
        payload = json.dumps({"address": target.address, "count": 1}).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")
        context = None if verify else ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                details = json.loads(response.read().decode("utf-8"))
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            return ProbeResult(code=PING_FAILED, message=f"routeros_api failed: {exc}")

        if not details:
            return ProbeResult(code=PING_FAILED, message="routeros_api returned no ping details")

        packet_loss = str(details[0].get("packet-loss", "100")).strip().rstrip("%")
        try:
            if int(packet_loss) > 0:
                return ProbeResult(code=PING_FAILED, message=f"routeros_api packet loss {packet_loss}%")
        except ValueError:
            return ProbeResult(code=PING_FAILED, message=f"routeros_api packet loss {packet_loss}")

        rtt_ms = routeros_duration_to_ms(str(details[0].get("min-rtt", "")))
        ttl = safe_int(details[0].get("ttl"), default=-1)
        return ProbeResult(
            success=True,
            code=PING_SUCCESS,
            rtt_ms=rtt_ms,
            ttl=ttl,
            message="routeros_api ping success",
        )


class AlertManager:
    def __init__(self, config: AlertConfig, app_name: str, public_url: str | None) -> None:
        self.config = config
        self.app_name = app_name
        self.public_url = public_url

    async def notify(self, transition: AlertTransition) -> list[dict[str, Any]]:
        if not self.config.enabled:
            return []

        enabled_channels = [channel for channel in self.config.channels if channel.enabled]
        if not enabled_channels:
            return []

        return await asyncio.gather(*[self._notify_channel(channel, transition) for channel in enabled_channels])

    async def _notify_channel(self, channel: AlertChannel, transition: AlertTransition) -> dict[str, Any]:
        url = channel.resolved_url()
        if not url:
            return {
                "channel": channel.name,
                "kind": channel.kind,
                "ok": False,
                "message": "webhook URL is not configured",
            }

        if channel.kind == "slack":
            body = self._slack_payload(channel, transition)
        elif channel.kind == "webex":
            body = {"markdown": self._webex_markdown(transition)}
        else:
            body = {"text": self._fallback_text(transition)}

        try:
            await asyncio.to_thread(post_json, url, body, channel.timeout)
            return {
                "channel": channel.name,
                "kind": channel.kind,
                "ok": True,
                "message": "delivered",
            }
        except Exception as exc:  # noqa: BLE001 - delivery errors are reported in state
            return {
                "channel": channel.name,
                "kind": channel.kind,
                "ok": False,
                "message": str(exc),
            }

    def _fallback_text(self, transition: AlertTransition) -> str:
        label = "ACTIVE" if transition.action == "active" else "CLEARED"
        if transition.action == "active":
            streak = f"{transition.consecutive_down} consecutive failures"
        else:
            streak = f"{transition.consecutive_up} consecutive successes"
        return (
            f"*{self.app_name} {label}*: {transition.target_name} "
            f"({transition.address}) in {transition.group_name}. "
            f"{streak}; loss {transition.loss_rate:.1f}% over {transition.sent} probes."
        )

    def _slack_payload(self, channel: AlertChannel, transition: AlertTransition) -> dict[str, Any]:
        severity = alert_severity(transition)
        fields = [
            slack_field("Target", transition.target_name),
            slack_field("Group", transition.group_name),
            slack_field("Address", code_span(transition.address)),
            slack_field("Probe", transition.probe),
            slack_field("Status", f"{severity['slack_icon']} {severity['label']}"),
            slack_field("Failure streak", str(transition.consecutive_down)),
            slack_field("Recovery streak", str(transition.consecutive_up)),
            slack_field("Loss", f"{transition.loss_rate:.1f}% over {transition.sent} probes"),
            slack_field("Latest RTT", format_ms(transition.latest_rtt_ms)),
            slack_field("Average RTT", format_ms(transition.avg_rtt_ms)),
            slack_field("Alert threshold", f"{transition.threshold} failures"),
            slack_field("Clear threshold", f"{transition.clear_threshold} successes"),
            slack_field(
                "Last result",
                code_span(transition.last_message or transition.last_code),
            ),
            slack_field("Checked", isoformat(transition.happened_at) or "unknown"),
        ]
        if transition.ttl is not None:
            fields.append(slack_field("TTL", str(transition.ttl)))
        if transition.note:
            fields.append(slack_field("Note", transition.note, short=False))
        if transition.info_url:
            fields.append(slack_field("Info", slack_link(transition.info_url, "Open info link")))
        if self.public_url:
            fields.append(slack_field("Dashboard", slack_link(self.public_url, "Open Deadmon")))

        attachment = {
            "color": severity["slack_color"],
            "title": f"{severity['title']}: {transition.target_name}",
            "fallback": self._fallback_text(transition),
            "fields": fields,
            "footer": self.app_name,
            "ts": int(transition.happened_at.timestamp()),
            "mrkdwn_in": ["text", "fields"],
        }
        title_link = self.public_url or transition.info_url
        if title_link:
            attachment["title_link"] = title_link

        payload = {
            "text": self._fallback_text(transition),
            "attachments": [attachment],
        }
        if channel.destination_channel:
            payload["channel"] = channel.destination_channel
        if channel.icon_emoji:
            payload["icon_emoji"] = channel.icon_emoji
        return payload

    def _webex_markdown(self, transition: AlertTransition) -> str:
        severity = alert_severity(transition)
        if transition.action == "active":
            streak = f"{transition.consecutive_down} consecutive failed probes"
            state_line = f"**{transition.target_name}** is unreachable from **{transition.group_name}**"
            status_value = f"{severity['webex_state_icon']} Active outage"
        else:
            streak = f"{transition.consecutive_up} consecutive successful probes"
            state_line = f"**{transition.target_name}** is reachable again from **{transition.group_name}**"
            status_value = f"{severity['webex_state_icon']} Cleared"

        lines = [
            f"{severity['webex_icon']} **{severity['title']}: {transition.target_name}**",
            "",
            state_line,
            "",
            f"- **Status:** {status_value}",
            f"- **Address:** `{transition.address}`",
            f"- **Probe:** {transition.probe}",
            f"- **Streak:** `{streak}`",
            f"- **Loss:** `{transition.loss_rate:.1f}%` over `{transition.sent}` probes",
            f"- **Latest RTT:** `{format_ms(transition.latest_rtt_ms)}`",
            f"- **Average RTT:** `{format_ms(transition.avg_rtt_ms)}`",
            f"- **Thresholds:** `{transition.threshold}` failures / `{transition.clear_threshold}` successes",
            f"- **Last result:** `{transition.last_message or transition.last_code}`",
            f"- **Checked:** `{isoformat(transition.happened_at)}`",
        ]
        if transition.ttl is not None:
            lines.append(f"- **TTL:** `{transition.ttl}`")
        if transition.note:
            lines.extend(["", f"**Note:** {transition.note}"])

        links = []
        if self.public_url:
            links.append(f"[Open Deadmon Dashboard]({self.public_url})")
        if transition.info_url:
            links.append(f"[Open Info Link]({transition.info_url})")
        if links:
            lines.extend(["", " | ".join(links)])

        return "\n".join(lines)


class MonitorService:
    def __init__(self, config: DeadmonConfig) -> None:
        self.config = config
        self.runner = ProbeRunner(timeout=config.timeout)
        self.states = {target.stable_id: new_target_state(target, config) for target in config.targets}
        self.started_at = datetime.now(UTC)
        self.last_tick_at: datetime | None = None
        self.last_tick_duration_ms = 0.0
        self.last_error: str | None = None
        self.last_reload_at: datetime | None = None
        self.reload_count = 0
        self.alert_log: deque[dict[str, Any]] = deque(maxlen=50)
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="deadmon-monitor")

    async def stop(self) -> None:
        self._stop.set()
        if not self._task:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass

    async def _run(self) -> None:
        while not self._stop.is_set():
            started = time.perf_counter()
            try:
                await self.tick()
                self.last_error = None
            except Exception as exc:  # noqa: BLE001 - keep the monitor running
                self.last_error = str(exc)

            elapsed = time.perf_counter() - started
            delay = max(0.1, self.config.poll_interval - elapsed)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except TimeoutError:
                continue

    async def tick(self) -> None:
        async with self._lock:
            config = self.config
            runner = self.runner
            targets = list(config.targets)

        started = time.perf_counter()
        results = await asyncio.gather(
            *[runner.probe(target) for target in targets],
            return_exceptions=True,
        )
        transitions: list[tuple[AlertTransition, AlertConfig]] = []
        now = datetime.now(UTC)

        async with self._lock:
            active_config = self.config
            active_targets = {target.stable_id: target for target in active_config.targets}
            for target, result in zip(targets, results, strict=True):
                target = active_targets.get(target.stable_id)
                if target is None:
                    continue
                if isinstance(result, Exception):
                    result = ProbeResult(code=PING_FAILED, message=str(result), checked_at=now)
                state = self.states[target.stable_id]
                alert_config = effective_alert_config(target, active_config)
                transition = state.consume(
                    result,
                    alert_threshold=alert_config.threshold,
                    clear_threshold=alert_config.clear_threshold,
                    rtt_scale_ms=active_config.rtt_scale_ms,
                )
                if transition:
                    transitions.append((transition, alert_config))

            self.last_tick_at = now
            self.last_tick_duration_ms = (time.perf_counter() - started) * 1000.0

        for transition, alert_config in transitions:
            deliveries = await AlertManager(
                alert_config,
                app_name=self.config.name,
                public_url=self.config.public_url,
            ).notify(transition)
            async with self._lock:
                self.alert_log.appendleft(
                    {
                        "action": transition.action,
                        "target_id": transition.target_id,
                        "target_name": transition.target_name,
                        "address": transition.address,
                        "group_name": transition.group_name,
                        "happened_at": isoformat(transition.happened_at),
                        "deliveries": deliveries,
                    }
                )

    async def reload_config(self, new_config: DeadmonConfig) -> dict[str, Any]:
        async with self._lock:
            old_state_count = len(self.states)
            old_ids = set(self.states)
            new_states: dict[str, TargetState] = {}
            preserved = 0

            for target in new_config.targets:
                state = self.states.get(target.stable_id)
                if state:
                    preserved += 1
                    state.reconfigure(
                        target,
                        retain_results=new_config.retain_results,
                        latency_warning_ms=effective_latency_warning_ms(target, new_config),
                        latency_critical_ms=effective_latency_critical_ms(target, new_config),
                    )
                else:
                    state = new_target_state(target, new_config)
                new_states[target.stable_id] = state

            self.config = new_config
            self.runner = ProbeRunner(timeout=new_config.timeout)
            self.states = new_states
            self.reload_count += 1
            self.last_reload_at = datetime.now(UTC)

            new_ids = set(new_states)
            return {
                "ok": True,
                "message": "config reloaded",
                "config_path": str(new_config.path),
                "targets": len(new_states),
                "groups": len(new_config.groups),
                "preserved_targets": preserved,
                "added_targets": len(new_ids - old_ids),
                "removed_targets": old_state_count - preserved,
                "reloaded_at": isoformat(self.last_reload_at),
            }

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            config = self.config
            targets = []
            for target in config.targets:
                target_snapshot = self.states[target.stable_id].snapshot()
                target_snapshot["alerts"] = public_alert_config(effective_alert_config(target, config))
                targets.append(target_snapshot)

            target_by_id = {target["id"]: target for target in targets}
            group_snapshots: list[dict[str, Any]] = []
            for group in config.groups:
                group_targets = [target_by_id[target.stable_id] for target in group.targets]
                group_snapshots.append(
                    {
                        "id": group.group_id,
                        "name": group.name,
                        "description": group.description,
                        "latency_warning_ms": clean_float(effective_group_latency_warning_ms(group, config)),
                        "latency_critical_ms": clean_float(effective_group_latency_critical_ms(group, config)),
                        "alerts": public_alert_config(effective_group_alert_config(group, config)),
                        **status_totals(group_targets),
                    }
                )

            totals = status_totals(targets)
            return {
                "app": {
                    "name": config.name,
                    "version": APP_VERSION,
                    "config_path": str(config.path),
                    "public_url": config.public_url,
                    "poll_interval": config.poll_interval,
                    "tab_rotation_interval": config.tab_rotation_interval,
                    "timeout": config.timeout,
                    "rtt_scale_ms": config.rtt_scale_ms,
                    "latency_warning_ms": clean_float(config.latency_warning_ms),
                    "latency_critical_ms": clean_float(config.latency_critical_ms),
                    "retain_results": config.retain_results,
                    "started_at": isoformat(self.started_at),
                    "last_tick_at": isoformat(self.last_tick_at),
                    "last_tick_duration_ms": round(self.last_tick_duration_ms, 2),
                    "server_time": isoformat(datetime.now(UTC)),
                    "last_error": self.last_error,
                    "last_reload_at": isoformat(self.last_reload_at),
                    "reload_count": self.reload_count,
                },
                "totals": totals,
                "groups": group_snapshots,
                "targets": targets,
                "alerts": {
                    **public_alert_config(config.alerts),
                    "recent": list(self.alert_log),
                },
            }


class DeadmonASGI:
    def __init__(self, config_path: str | os.PathLike[str]) -> None:
        self.config = load_config(config_path)
        self.monitor = MonitorService(self.config)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._previous_sighup_handler: Any = None

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return

        if scope["type"] != "http":
            await send_response(send, 404, "not found", "text/plain; charset=utf-8")
            return

        if self.config.authentication:
            headers = scope.get("headers", [])
            auth_header = None
            for header in headers:
                if header[0].decode("utf-8").lower() == "authorization":
                    auth_header = header[1].decode("utf-8")
                    break

            if not self._authenticate(auth_header):
                await send_response(
                    send,
                    401,
                    "Authentication Required",
                    "text/html; charset=utf-8",
                    additional_headers=[
                        (
                            b"www-authenticate",
                            b"Basic realm='" + self.config.name.encode("utf-8") + b" Login'",
                        )
                    ],
                )
                return

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")
        if method == "GET" and path == "/":
            await send_response(send, 200, INDEX_HTML, "text/html; charset=utf-8")
        elif method == "GET" and path in {"/favicon.svg", "/favicon.ico"}:
            await send_response(send, 200, FAVICON_SVG, "image/svg+xml")
        elif method == "GET" and path == "/assets/app.css":
            await send_response(send, 200, APP_CSS, "text/css; charset=utf-8")
        elif method == "GET" and path == "/assets/app.js":
            await send_response(send, 200, APP_JS, "application/javascript; charset=utf-8")
        elif method == "GET" and path == "/api/state":
            await send_json(send, await self.monitor.snapshot())
        elif method == "GET" and path == "/api/health":
            snapshot = await self.monitor.snapshot()
            status = 200 if snapshot["app"]["last_error"] is None else 503
            await send_json(
                send,
                {
                    "ok": status == 200,
                    "last_error": snapshot["app"]["last_error"],
                    "last_reload_at": snapshot["app"]["last_reload_at"],
                    "reload_count": snapshot["app"]["reload_count"],
                },
                status,
            )
        elif method == "POST" and path == "/api/reload":
            await send_json(send, await self.reload_config())
        # elif method == "GET" and path == "/api/config":
        #    await send_json(send, public_config(self.config))
        else:
            await send_response(send, 404, "not found", "text/plain; charset=utf-8")

    def _authenticate(self, auth_header: str | None) -> bool:
        from base64 import b64decode

        if not auth_header:
            return False

        try:
            atype, creds = auth_header.split(None, 1)
            if atype.lower() != "basic":
                return False

            decoded_creds = b64decode(creds).decode("utf-8")
            username, password = decoded_creds.split(":", 1)
            if self.config.authentication.password_env:
                app_password = os.environ.get(self.config.authentication.password_env, "")
            else:
                app_password = self.config.authentication.password
            if username == self.config.authentication.username and password == app_password:
                return True
        except Exception:
            return False

        return False

    async def reload_config(self) -> dict[str, Any]:
        try:
            new_config = load_config(self.config.path)
            result = await self.monitor.reload_config(new_config)
        except Exception as exc:  # noqa: BLE001 - config reload failures are fatal
            fatal_reload_failure(self.config.path, exc)
        self.config = new_config
        return result

    def _install_signal_handlers(self) -> None:
        if not hasattr(signal, "SIGHUP"):
            return
        try:
            self._loop = asyncio.get_running_loop()
            self._previous_sighup_handler = signal.getsignal(signal.SIGHUP)
            signal.signal(signal.SIGHUP, self._handle_sighup)
        except (RuntimeError, ValueError):
            return

    def _restore_signal_handlers(self) -> None:
        if not hasattr(signal, "SIGHUP") or self._previous_sighup_handler is None:
            return
        try:
            signal.signal(signal.SIGHUP, self._previous_sighup_handler)
        except ValueError:
            pass
        self._previous_sighup_handler = None

    def _handle_sighup(self, _signum: int, _frame: Any) -> None:
        if not self._loop or self._loop.is_closed():
            return
        self._loop.call_soon_threadsafe(lambda: asyncio.create_task(self._reload_from_signal()))

    async def _reload_from_signal(self) -> None:
        await self.reload_config()

    async def _lifespan(self, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                self._install_signal_handlers()
                await self.monitor.start()
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                self._restore_signal_handlers()
                await self.monitor.stop()
                await send({"type": "lifespan.shutdown.complete"})
                return


def create_app(config_path: str | os.PathLike[str] | None = None) -> DeadmonASGI:
    path = config_path or os.environ.get("DEADMON_CONFIG") or "deadmon.conf"
    return DeadmonASGI(path)


def fatal_reload_failure(config_path: Path, error: Exception) -> NoReturn:
    print(f"deadmon: failed to reload config {config_path}: {error}; exiting", file=sys.stderr, flush=True)
    os._exit(1)


def load_config(path: str | os.PathLike[str]) -> DeadmonConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"config file does not exist: {config_path}")

    text = config_path.read_text(encoding="utf-8")
    raw = parse_config_text(text)
    return normalize_config(raw, config_path)


def parse_config_text(text: str) -> dict[str, Any]:
    stripped = text.lstrip()
    if not stripped:
        raise ConfigError("config file is empty")

    if stripped[0] in "[{":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ConfigError("JSON config must be an object")
        return data

    import yaml

    data = yaml.safe_load(text)
    if data is None:
        raise ConfigError("YAML config is empty")
    if not isinstance(data, dict):
        raise ConfigError("YAML config must be an object")
    return data


def normalize_config(raw: dict[str, Any], path: Path) -> DeadmonConfig:
    validate_allowed_keys(raw, TOP_LEVEL_KEYS, "config")

    raw_app = raw.get("app", {})
    if raw_app is None:
        raw_app = {}
    if not isinstance(raw_app, dict):
        raise ConfigError("app must be an object")
    validate_allowed_keys(raw_app, APP_KEYS, "app")
    app = raw_app

    name = str(app.get("name") or "deadmon")
    public_url = optional_str(app.get("public_url"))
    poll_interval = as_float(app.get("poll_interval", 5.0))
    tab_rotation_interval = as_float(app.get("tab_rotation_interval", 15.0))
    timeout = as_float(app.get("timeout", 1.0))
    rtt_scale_ms = as_int(app.get("rtt_scale_ms", 10))
    latency_warning_ms = as_float(app.get("latency_warning_ms", 100.0))
    latency_critical_ms = as_float(app.get("latency_critical_ms", 250.0))
    retain_results = as_int(app.get("retain_results", 30))
    raw_authentication = app.get("authentication")
    alerts = normalize_alerts(raw.get("alerts", {}))

    authentication = normalize_authentication(raw_authentication)

    raw_groups = raw.get("groups")
    if not raw_groups:
        raise ConfigError("config must define groups")

    groups: list[GroupConfig] = []
    used_ids: set[str] = set()
    for index, raw_group in enumerate(as_config_list(raw_groups, "groups"), start=1):
        if not isinstance(raw_group, dict):
            raise ConfigError("each group must be an object")
        validate_allowed_keys(raw_group, GROUP_KEYS, f"group {index}")
        group_name = str(raw_group.get("name") or f"Group {index}")
        group_id = unique_slug(raw_group.get("id") or group_name, used_ids)
        group = GroupConfig(
            name=group_name,
            group_id=group_id,
            description=str(raw_group.get("description") or ""),
            latency_warning_ms=optional_float(raw_group.get("latency_warning_ms")),
            latency_critical_ms=optional_float(raw_group.get("latency_critical_ms")),
            alerts=normalize_group_alerts(raw_group, group_name),
        )
        for raw_target in as_config_list(raw_group.get("targets", []), f"group {group_name} targets"):
            group.targets.append(normalize_target(raw_target, group))
        groups.append(group)

    if not any(group.targets for group in groups):
        raise ConfigError("config contains no targets")

    return DeadmonConfig(
        name=name,
        path=path,
        public_url=public_url,
        poll_interval=max(0.5, poll_interval),
        tab_rotation_interval=max(0.0, tab_rotation_interval),
        timeout=max(0.1, timeout),
        rtt_scale_ms=max(1, rtt_scale_ms),
        latency_warning_ms=max(0.0, latency_warning_ms),
        latency_critical_ms=max(0.0, latency_critical_ms),
        retain_results=max(5, min(120, retain_results)),
        authentication=authentication,
        groups=groups,
        alerts=alerts,
    )


def normalize_alerts(raw_alerts: Any) -> AlertConfig:
    if raw_alerts is None:
        raw_alerts = {}
    if not isinstance(raw_alerts, dict):
        raise ConfigError("alerts must be an object")
    validate_allowed_keys(raw_alerts, ALERT_KEYS, "alerts")

    return AlertConfig(
        enabled=as_bool(raw_alerts.get("enabled", True)),
        threshold=max(1, as_int(raw_alerts.get("threshold", 3))),
        clear_threshold=max(1, as_int(raw_alerts.get("clear_threshold", 2))),
        channels=normalize_alert_channels(raw_alerts.get("channels", []), "alert"),
    )


def normalize_authentication(
    raw_auth: dict[str, str] | None,
) -> AuthenticationConfig | None:
    if not raw_auth:
        return None
    if not isinstance(raw_auth, dict):
        raise ConfigError("authentication must be an object")
    validate_allowed_keys(raw_auth, AUTHENTICATION_KEYS, "authentication")

    username = raw_auth.get("username")
    password = raw_auth.get("password")
    password_env = raw_auth.get("password_env")
    if password_env and password:
        raise ConfigError("authentication cannot specify both password and password_env")
    if (username and not (password or password_env)) or ((password or password_env) and not username):
        raise ConfigError("authentication requires both username and password or password_env")

    return AuthenticationConfig(
        username=str(username),
        password=str(password) if password else None,
        password_env=str(password_env) if password_env else None,
    )


def normalize_group_alerts(raw_group: dict[str, Any], group_name: str) -> AlertOverride | None:
    if "alerts" in raw_group:
        return normalize_alert_override(raw_group.get("alerts"), f"group {group_name} alerts")
    return None


def normalize_alert_override(raw_alerts: Any, context: str) -> AlertOverride:
    if isinstance(raw_alerts, bool):
        return AlertOverride(enabled=raw_alerts)
    if raw_alerts is None:
        raw_alerts = {}
    if not isinstance(raw_alerts, dict):
        raise ConfigError(f"{context} must be an object")
    validate_allowed_keys(raw_alerts, ALERT_KEYS, context)

    channels = None
    if "channels" in raw_alerts:
        channels = normalize_alert_channels(raw_alerts.get("channels", []), context)

    return AlertOverride(
        enabled=optional_bool(raw_alerts.get("enabled")),
        threshold=optional_int(raw_alerts.get("threshold")),
        clear_threshold=optional_int(raw_alerts.get("clear_threshold")),
        channels=channels,
    )


def normalize_alert_channels(raw_channels: Any, context: str) -> list[AlertChannel]:
    channels = []
    for index, raw_channel in enumerate(as_config_list(raw_channels, f"{context} channels"), start=1):
        if not isinstance(raw_channel, dict):
            raise ConfigError(f"{context} channels must be objects")
        validate_allowed_keys(raw_channel, ALERT_CHANNEL_KEYS, f"{context} channel {index}")
        kind = str(raw_channel.get("type") or "").lower()
        if kind not in {"slack", "webex"}:
            raise ConfigError(f"{context} channel {index} has unsupported type: {kind}")
        channels.append(
            AlertChannel(
                name=str(raw_channel.get("name") or kind),
                kind=kind,
                enabled=as_bool(raw_channel.get("enabled", True)),
                webhook_url=optional_str(raw_channel.get("webhook_url")),
                webhook_url_env=optional_str(raw_channel.get("webhook_url_env")),
                destination_channel=optional_str(raw_channel.get("channel")),
                icon_emoji=normalize_icon_emoji(optional_str(raw_channel.get("icon_emoji"))),
                timeout=as_float(raw_channel.get("timeout", 5.0)),
            )
        )
    return channels


def normalize_target(raw_target: Any, group: GroupConfig) -> TargetConfig:
    if not isinstance(raw_target, dict):
        raise ConfigError(f"target in {group.name} must be an object")
    validate_allowed_keys(raw_target, TARGET_KEYS, f"target in {group.name}")

    name = raw_target.get("name")
    address = raw_target.get("address")
    if not name or not address:
        raise ConfigError(f"target in {group.name} is missing name or address")

    relay = normalize_relay(raw_target.get("relay"), f"target {name} relay")

    return TargetConfig(
        name=str(name),
        address=str(address),
        group_id=group.group_id,
        group_name=group.name,
        note=str(raw_target.get("note") or ""),
        info_url=optional_str(raw_target.get("info_url")),
        relay=relay,
        source=optional_str(raw_target.get("source")),
        tcp=parse_tcp(raw_target.get("tcp")),
        osname=optional_str(raw_target.get("osname") or relay.get("os")),
        alerts=target_alerts(raw_target),
        latency_warning_ms=optional_float(raw_target.get("latency_warning_ms")),
        latency_critical_ms=optional_float(raw_target.get("latency_critical_ms")),
    )


def parse_tcp(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        validate_allowed_keys(value, TCP_KEYS, "tcp")
        if "dstport" not in value:
            raise ConfigError("tcp must define dstport")
        dstport = as_int(value["dstport"])
        if dstport <= 0:
            raise ConfigError("tcp dstport must be greater than zero")
        tcp: dict[str, Any] = {"dstport": dstport}
        if "method" in value:
            method = str(value["method"]).lower()
            if method != "hping3":
                raise ConfigError("tcp method must be hping3")
            tcp["method"] = method
        return tcp
    raise ConfigError("tcp must be an object")


def normalize_relay(value: Any, context: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{context} must be an object")
    validate_allowed_keys(value, RELAY_CONFIG_KEYS, context)
    if "via" in value and str(value["via"]) not in {
        "snmp",
        "routeros_api",
        "netns",
        "vrf",
    }:
        raise ConfigError(f"{context} via must be snmp, routeros_api, netns, or vrf")
    if "snmpping" in value and not str(value["snmpping"]).strip():
        raise ConfigError(f"{context} snmpping must be bundled, system, or a command path")
    return dict(value)


def target_alerts(raw_target: dict[str, Any]) -> bool | None:
    if "alerts" not in raw_target:
        return None
    raw_alerts = raw_target["alerts"]
    if isinstance(raw_alerts, bool):
        return raw_alerts
    raise ConfigError("target alerts must be true or false")


def validate_allowed_keys(mapping: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(str(key) for key in mapping if key not in allowed)
    if unknown:
        joined = ", ".join(unknown)
        raise ConfigError(f"{context} has unsupported field(s): {joined}")


def as_config_list(value: Any, context: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise ConfigError(f"{context} must be a list")


def which_ip_version(address: str) -> int | None:
    try:
        family = socket.getaddrinfo(address, None)[0][0]
    except OSError:
        return None
    if family == socket.AF_INET:
        return 4
    if family == socket.AF_INET6:
        return 6
    return None


def ping_command(osname: str, ip_version: int) -> list[str] | None:
    if osname in {"Linux", "Darwin", "FreeBSD"}:
        if ip_version == 4:
            return ["ping", "-c", "1"]
        if ip_version == 6:
            if which("ping6"):
                return ["ping6", "-c", "1"]
            if osname == "Linux":
                return ["ping", "-6", "-c", "1"]
            return ["ping", "-c", "1"]
    return None


def snmpping_command(relay: dict[str, Any]) -> list[str]:
    tool = str(relay.get("snmpping") or DEFAULT_SNMPPING).strip()
    if not tool or tool == DEFAULT_SNMPPING:
        return [sys.executable, "-m", "deadmon.snmpping"]
    if tool == "system":
        return ["snmpping"]
    return [tool]


async def run_command(cmd: list[str], timeout: float) -> tuple[str, bool]:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError as exc:
        return str(exc), False

    timed_out = False
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        timed_out = True
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=1.0)
        except TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            stdout, stderr = await proc.communicate()

    output = stdout.decode("utf-8", errors="replace")
    error = stderr.decode("utf-8", errors="replace")
    return "\n".join(part for part in (output, error) if part), timed_out


def parse_snmpping_output(output: str, timed_out: bool) -> ProbeResult:
    if timed_out:
        return ProbeResult(code=PING_TIMEOUT, message="snmpping timed out")

    rtt_match = re.search(
        r"rtt\s+min/avg/max(?:/(?:stddev|mdev))?\s*=\s*"
        r"(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)",
        output,
        flags=re.IGNORECASE,
    )
    if rtt_match:
        return ProbeResult(
            success=True,
            code=PING_SUCCESS,
            rtt_ms=float(rtt_match.group(2)),
            ttl=-1,
            message="snmp ping success",
        )

    lowered = output.lower()
    if "timed out" in lowered or "0 packets received" in lowered or re.search(r"\b0\s+received\b", lowered) or "0 responses" in lowered:
        return ProbeResult(code=PING_TIMEOUT, message=first_line(output) or "snmpping timed out")
    return ProbeResult(code=PING_FAILED, message=first_line(output) or "snmpping failed")


def parse_ping_output(output: str, timed_out: bool) -> ProbeResult:
    if timed_out:
        return ProbeResult(code=PING_TIMEOUT, message="ping timed out")

    rtt_match = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)", output)
    ttl_match = re.search(r"(?:ttl|hlim)=(\d+)", output, flags=re.IGNORECASE)
    if rtt_match:
        return ProbeResult(
            success=True,
            code=PING_SUCCESS,
            rtt_ms=float(rtt_match.group(1)),
            ttl=int(ttl_match.group(1)) if ttl_match else -1,
            message="ping success",
        )

    lowered = output.lower()
    if "operation timed out" in lowered:
        return ProbeResult(code=PING_TIMEOUT, message="ssh timed out")
    if "ssh:" in lowered or "permission denied" in lowered:
        return ProbeResult(code=PING_SSH_FAILED, message=first_line(output) or "ssh relay failed")
    return ProbeResult(code=PING_FAILED, message=first_line(output) or "ping failed")


def routeros_duration_to_ms(value: str) -> float:
    milliseconds = 0.0
    ms_match = re.search(r"(\d+(?:\.\d+)?)ms", value)
    us_match = re.search(r"(\d+(?:\.\d+)?)us", value)
    if ms_match:
        milliseconds += float(ms_match.group(1))
    if us_match:
        milliseconds += float(us_match.group(1)) / 1000.0
    return milliseconds


def effective_latency_warning_ms(target: TargetConfig, config: DeadmonConfig) -> float:
    value = effective_group_latency_warning_ms(group_for_target(target, config), config)
    if target.latency_warning_ms is not None:
        value = target.latency_warning_ms
    return max(0.0, value)


def effective_latency_critical_ms(target: TargetConfig, config: DeadmonConfig) -> float:
    value = effective_group_latency_critical_ms(group_for_target(target, config), config)
    if target.latency_critical_ms is not None:
        value = target.latency_critical_ms
    return max(0.0, value)


def effective_alert_config(target: TargetConfig, config: DeadmonConfig) -> AlertConfig:
    group_alerts = effective_group_alert_config(group_for_target(target, config), config)
    return AlertConfig(
        enabled=group_alerts.enabled if target.alerts is None else target.alerts,
        threshold=group_alerts.threshold,
        clear_threshold=group_alerts.clear_threshold,
        channels=group_alerts.channels,
    )


def effective_group_alert_config(group: GroupConfig | None, config: DeadmonConfig) -> AlertConfig:
    base = config.alerts
    if not group or not group.alerts:
        return base

    override = group.alerts
    return AlertConfig(
        enabled=base.enabled if override.enabled is None else override.enabled,
        threshold=max(1, override.threshold or base.threshold),
        clear_threshold=max(1, override.clear_threshold or base.clear_threshold),
        channels=base.channels if override.channels is None else override.channels,
    )


def effective_group_latency_warning_ms(group: GroupConfig | None, config: DeadmonConfig) -> float:
    if group and group.latency_warning_ms is not None:
        return max(0.0, group.latency_warning_ms)
    return max(0.0, config.latency_warning_ms)


def effective_group_latency_critical_ms(group: GroupConfig | None, config: DeadmonConfig) -> float:
    if group and group.latency_critical_ms is not None:
        return max(0.0, group.latency_critical_ms)
    return max(0.0, config.latency_critical_ms)


def group_for_target(target: TargetConfig, config: DeadmonConfig) -> GroupConfig | None:
    for group in config.groups:
        if group.group_id == target.group_id:
            return group
    return None


def result_latency_state(result: ProbeResult, warning_ms: float, critical_ms: float) -> str:
    if not result.success:
        return "lost"
    if critical_ms > 0 and result.rtt_ms >= critical_ms:
        return "critical"
    if warning_ms > 0 and result.rtt_ms >= warning_ms:
        return "warn"
    return "ok"


def result_level(result: ProbeResult, rtt_scale_ms: int) -> int:
    if not result.success:
        return 0
    return max(1, min(8, int(result.rtt_ms // rtt_scale_ms) + 1))


def result_height_px(result: ProbeResult, rtt_scale_ms: int) -> float | int:
    if not result.success:
        return 22
    height = 4.0 + (result.rtt_ms / max(1, rtt_scale_ms))
    height = max(4.0, min(22.0, height))
    return clean_float(round(height, 1))


def clean_float(value: float) -> float | int:
    return int(value) if isinstance(value, float) and value.is_integer() else value


def post_json(url: str, body: dict[str, Any], timeout: float) -> None:
    payload = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"deadmon/{APP_VERSION}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status >= 400:
            raise RuntimeError(f"webhook returned HTTP {response.status}")


async def send_json(send: Any, payload: Any, status: int = 200) -> None:
    await send_response(
        send,
        status,
        json.dumps(payload, separators=(",", ":")),
        "application/json; charset=utf-8",
    )


async def send_response(
    send: Any,
    status: int,
    body: str,
    content_type: str,
    additional_headers: list | None = None,
) -> None:
    if not additional_headers:
        additional_headers = []

    headers = [
        (b"content-type", content_type.encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"x-content-type-options", b"nosniff"),
    ]
    headers += additional_headers
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body.encode("utf-8")})


def status_totals(targets: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"total": len(targets), "up": 0, "degraded": 0, "down": 0, "pending": 0}
    for target in targets:
        status = target.get("status", "pending")
        if status not in totals:
            status = "pending"
        totals[status] += 1
    totals["alerts_active"] = sum(1 for target in targets if target.get("alert_active"))
    return totals


def public_relay(relay: dict[str, Any]) -> dict[str, Any] | None:
    if not relay:
        return None
    visible = {}
    for key, value in relay.items():
        if key in SECRET_KEYS:
            continue
        visible[key] = value
    if "via" not in visible:
        visible["via"] = "ssh"
    return visible


def public_tcp(tcp: dict[str, Any] | None) -> dict[str, Any] | None:
    if not tcp:
        return None
    return dict(tcp)


def new_target_state(target: TargetConfig, config: DeadmonConfig) -> TargetState:
    return TargetState(
        target,
        retain_results=config.retain_results,
        latency_warning_ms=effective_latency_warning_ms(target, config),
        latency_critical_ms=effective_latency_critical_ms(target, config),
    )


def target_probe_label(target: TargetConfig) -> str:
    parts = []
    if target.tcp:
        port = target.tcp.get("dstport") or "unknown"
        label = f"tcp/{port}"
        if str(target.tcp.get("method", "")).lower() == "hping3":
            label = f"{label} via hping3"
        parts.append(label)
    elif target.relay:
        via = target.relay.get("via", "ssh")
        relay = target.relay.get("relay")
        parts.append(f"{via} via {relay}" if relay else str(via))
    else:
        parts.append("icmp")

    if target.source:
        parts.append(f"source {target.source}")
    return ", ".join(parts)


def alert_severity(transition: AlertTransition) -> dict[str, str]:
    if transition.action == "cleared":
        return {
            "label": "Cleared",
            "title": "DEADMON RECOVERY",
            "slack_icon": ":large_green_circle:",
            "slack_color": "good",
            "webex_icon": "✅",
            "webex_state_icon": "🟢",
        }
    if transition.status == "down":
        return {
            "label": "Active outage",
            "title": "DEADMON ALERT",
            "slack_icon": ":red_circle:",
            "slack_color": "danger",
            "webex_icon": "🚨",
            "webex_state_icon": "🔴",
        }
    return {
        "label": "Degraded",
        "title": "DEADMON WARNING",
        "slack_icon": ":large_yellow_circle:",
        "slack_color": "warning",
        "webex_icon": "⚠️",
        "webex_state_icon": "🟡",
    }


def slack_field(title: str, value: str, short: bool = True) -> dict[str, Any]:
    return {"title": title, "value": value, "short": short}


def slack_link(url: str, label: str) -> str:
    return f"<{url}|{label}>"


def code_span(value: Any) -> str:
    clean = str(value).replace("`", "'")
    return f"`{clean}`"


def normalize_icon_emoji(value: str | None) -> str | None:
    if not value:
        return None
    clean = value.strip()
    if not clean:
        return None
    if clean.startswith(":") and clean.endswith(":"):
        return clean
    return f":{clean.strip(':')}:"


def format_ms(value: float) -> str:
    if value <= 0:
        return "--"
    if value >= 100:
        return f"{value:.0f} ms"
    if value >= 10:
        return f"{value:.1f} ms"
    return f"{value:.2f} ms"


def public_alert_config(alerts: AlertConfig) -> dict[str, Any]:
    return {
        "enabled": alerts.enabled,
        "threshold": alerts.threshold,
        "clear_threshold": alerts.clear_threshold,
        "channels": [
            {
                "name": channel.name,
                "kind": channel.kind,
                "enabled": channel.enabled,
                "configured": bool(channel.resolved_url()),
                "channel": channel.destination_channel,
                "icon_emoji": channel.icon_emoji,
            }
            for channel in alerts.channels
        ],
    }


def public_config(config: DeadmonConfig) -> dict[str, Any]:
    return {
        "app": {
            "name": config.name,
            "public_url": config.public_url,
            "poll_interval": config.poll_interval,
            "tab_rotation_interval": config.tab_rotation_interval,
            "timeout": config.timeout,
            "rtt_scale_ms": config.rtt_scale_ms,
            "latency_warning_ms": clean_float(config.latency_warning_ms),
            "latency_critical_ms": clean_float(config.latency_critical_ms),
            "retain_results": config.retain_results,
        },
        "alerts": public_alert_config(config.alerts),
        "groups": [
            {
                "id": group.group_id,
                "name": group.name,
                "description": group.description,
                "latency_warning_ms": clean_float(effective_group_latency_warning_ms(group, config)),
                "latency_critical_ms": clean_float(effective_group_latency_critical_ms(group, config)),
                "alerts": public_alert_config(effective_group_alert_config(group, config)),
                "targets": [
                    {
                        "name": target.name,
                        "address": target.address,
                        "note": target.note,
                        "info_url": target.info_url,
                        "relay": public_relay(target.relay),
                        "source": target.source,
                        "tcp": public_tcp(target.tcp),
                        "latency_warning_ms": clean_float(effective_latency_warning_ms(target, config)),
                        "latency_critical_ms": clean_float(effective_latency_critical_ms(target, config)),
                        "alerts": public_alert_config(effective_alert_config(target, config)),
                    }
                    for target in group.targets
                ],
            }
            for group in config.groups
        ],
    }


def first_line(value: str) -> str:
    for line in value.splitlines():
        clean = line.strip()
        if clean:
            return clean[:240]
    return ""


def slugify(value: Any) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", str(value).strip().lower()).strip("-")
    return slug or "item"


def unique_slug(value: Any, used: set[str]) -> str:
    base = slugify(value)
    candidate = base
    counter = 2
    while candidate in used:
        candidate = f"{base}-{counter}"
        counter += 1
    used.add(candidate)
    return candidate


def isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"expected number, got {value!r}") from exc


def as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"expected integer, got {value!r}") from exc


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def optional_str(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return as_int(value)


def optional_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    return as_bool(value)


def optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    return as_float(value)


FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="14" fill="#0f172a"/>
  <rect x="10" y="14" width="44" height="34" rx="6" fill="#111827" stroke="#e5e7eb" stroke-width="4"/>
  <path d="M16 32h8l4-10 8 22 5-14h7" fill="none" stroke="#22c55e" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="49" cy="17" r="7" fill="#ef4444" stroke="#f8fafc" stroke-width="3"/>
  <path d="M26 52h12M32 48v4" fill="none" stroke="#e5e7eb" stroke-width="4" stroke-linecap="round"/>
</svg>
"""


INDEX_HTML = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>deadmon</title>
  <link rel="icon" href="favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="assets/app.css?v={APP_VERSION}">
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 64 64" role="img">
          <rect width="64" height="64" rx="14" fill="#0f172a"/>
          <rect x="10" y="14" width="44" height="34" rx="6" fill="#111827" stroke="#e5e7eb" stroke-width="4"/>
          <path d="M16 32h8l4-10 8 22 5-14h7" fill="none" stroke="#22c55e" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
          <circle cx="49" cy="17" r="7" fill="#ef4444" stroke="#f8fafc" stroke-width="3"/>
          <path d="M26 52h12M32 48v4" fill="none" stroke="#e5e7eb" stroke-width="4" stroke-linecap="round"/>
        </svg>
      </div>
      <div>
        <h1 id="app-name">deadmon</h1>
        <p id="app-meta">{APP_VERSION}</p>
      </div>
    </div>
    <div class="pulse-line">
      <span class="pulse"></span>
      <span id="live-meta">LIVE</span>
    </div>
    <div class="totals" aria-label="reachability totals">
      <div><span id="up-count">0</span><small>UP</small></div>
      <div><span id="degraded-count">0</span><small>DEGRADED</small></div>
      <div><span id="down-count">0</span><small>DOWN</small></div>
    </div>
    <div class="clock">
      <strong id="clock-time">--:--:--</strong>
      <span id="clock-date">----</span>
    </div>
    <div class="controls">
      <button class="rotation-button" id="rotation-toggle" type="button" aria-label="Pause tab rotation" title="Pause tab rotation">||
      </button>
      <button class="theme-button" id="theme-toggle" type="button" aria-label="Toggle theme">Dark</button>
    </div>
  </header>
  <nav class="tabs" id="group-tabs" aria-label="target groups"></nav>
  <main>
    <section class="section-head">
      <div>
        <h2 id="group-title">Targets</h2>
        <p id="group-description"></p>
      </div>
      <div class="section-stats" id="group-stats"></div>
    </section>
    <section class="target-grid" id="target-grid" aria-live="polite"></section>
  </main>
  <script src="assets/app.js?v={APP_VERSION}"></script>
</body>
</html>
"""


APP_CSS = r"""
:root {
  color-scheme: dark;
  --bg: #060a0d;
  --panel: #0d141a;
  --panel-strong: #111b23;
  --line: #1d2b34;
  --line-soft: #14212a;
  --text: #d9e5eb;
  --muted: #7f909b;
  --faint: #4d5d66;
  --accent: #3cb7e8;
  --success: #28d979;
  --warn: #f0b33d;
  --latency-critical: #a78bfa;
  --loss: #94a3b8;
  --danger: #ff5664;
  --shadow: rgba(0, 0, 0, 0.22);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

[data-theme="light"] {
  color-scheme: light;
  --bg: #f4f7f9;
  --panel: #ffffff;
  --panel-strong: #eef4f8;
  --line: #d6e0e7;
  --line-soft: #e9eff3;
  --text: #14222c;
  --muted: #5e707d;
  --faint: #8fa0aa;
  --accent: #0b78b8;
  --success: #0a8d4d;
  --warn: #a66f00;
  --latency-critical: #6d28d9;
  --loss: #475569;
  --danger: #c93445;
  --shadow: rgba(28, 43, 54, 0.08);
}

* {
  box-sizing: border-box;
}

body {
  min-width: 320px;
  margin: 0;
  background: var(--bg);
  color: var(--text);
}

.topbar {
  display: grid;
  grid-template-columns: minmax(190px, 1.2fr) minmax(220px, 1fr) auto auto auto;
  align-items: center;
  gap: 18px;
  min-height: 76px;
  padding: 14px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--panel);
}

.brand {
  display: flex;
  align-items: center;
  min-width: 0;
  gap: 12px;
}

.brand-mark {
  display: grid;
  place-items: center;
  width: 42px;
  height: 42px;
  flex: 0 0 42px;
  border-radius: 10px;
  box-shadow: 0 8px 24px var(--shadow);
}

.brand-mark svg {
  display: block;
  width: 42px;
  height: 42px;
}

h1,
h2,
p {
  margin: 0;
}

h1 {
  font-size: 15px;
  font-weight: 800;
  line-height: 1.2;
  letter-spacing: 0;
}

#app-meta,
#group-description,
.target-note,
.target-sub,
.clock span,
.section-stats {
  color: var(--muted);
}

#app-meta {
  margin-top: 3px;
  font-size: 11px;
}

.pulse-line {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  color: var(--muted);
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
  white-space: nowrap;
}

.pulse {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--success);
  box-shadow: 0 0 12px var(--success);
}

.totals {
  display: grid;
  grid-template-columns: repeat(3, minmax(74px, 1fr));
  border-left: 1px solid var(--line);
  border-right: 1px solid var(--line);
}

.totals div {
  display: grid;
  gap: 2px;
  justify-items: center;
  padding: 0 18px;
  border-left: 1px solid var(--line);
}

.totals div:first-child {
  border-left: 0;
}

.totals span {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 20px;
  font-weight: 800;
}

.totals small,
.section-stats,
.target-meta {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 10px;
  letter-spacing: 0;
  text-transform: uppercase;
}

#up-count {
  color: var(--success);
}

#degraded-count {
  color: var(--warn);
}

#down-count {
  color: var(--danger);
}

.clock {
  display: grid;
  justify-items: end;
  min-width: 116px;
  line-height: 1.1;
}

.clock strong {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 21px;
}

.clock span {
  margin-top: 5px;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 10px;
  text-transform: uppercase;
}

.controls {
  display: flex;
  align-items: center;
  gap: 8px;
}

.theme-button,
.rotation-button {
  min-width: 58px;
  height: 34px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel-strong);
  color: var(--text);
  font: 700 11px "SFMono-Regular", Consolas, monospace;
  text-transform: uppercase;
  cursor: pointer;
}

.rotation-button {
  min-width: 34px;
  width: 34px;
  padding: 0;
  font-size: 14px;
}

.rotation-button.is-paused {
  color: var(--warn);
  border-color: color-mix(in srgb, var(--warn) 70%, var(--line));
}

.theme-button:hover,
.rotation-button:hover {
  border-color: var(--accent);
}

.tabs {
  display: flex;
  gap: 8px;
  overflow-x: auto;
  padding: 8px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--panel);
}

.tab {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 34px;
  padding: 0 12px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: transparent;
  color: var(--muted);
  font: 700 11px "SFMono-Regular", Consolas, monospace;
  text-transform: uppercase;
  white-space: nowrap;
  cursor: pointer;
}

.tab.active {
  color: var(--text);
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 13%, transparent);
}

.tab .index {
  min-width: 22px;
  padding: 2px 5px;
  border-radius: 4px;
  background: var(--line-soft);
  color: var(--accent);
}

main {
  padding: 0 14px 32px;
}

.section-head {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 16px;
  min-height: 52px;
  padding: 10px 0 6px;
  border-bottom: 1px solid var(--line);
}

h2 {
  font-size: 14px;
  line-height: 1.3;
  text-transform: uppercase;
}

#group-description {
  margin-top: 4px;
  font-size: 11px;
}

.section-stats {
  white-space: nowrap;
}

.target-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 760px), 1fr));
  gap: 0 28px;
}

.target-row {
  display: grid;
  grid-template-columns: 12px minmax(120px, 0.9fr) minmax(120px, 1fr) minmax(120px, 0.9fr) minmax(170px, 1.2fr) 78px 70px;
  align-items: center;
  min-width: 0;
  min-height: 28px;
  gap: 8px;
  border-bottom: 1px solid var(--line-soft);
  color: var(--text);
  overflow: hidden;
}

.target-row > * {
  min-width: 0;
}

.target-row.is-down {
  background: color-mix(in srgb, var(--danger) 14%, transparent);
}

.target-row.is-degraded {
  background: color-mix(in srgb, var(--warn) 10%, transparent);
}

.target-row.is-degraded.latency-critical {
  background: color-mix(in srgb, var(--latency-critical) 12%, transparent);
}

.target-row.is-degraded.latency-lost {
  background: color-mix(in srgb, var(--loss) 10%, transparent);
}

.target-row.has-recent-failure {
  background: color-mix(in srgb, var(--warn) 8%, transparent);
}

.state-rail {
  width: 100%;
  height: 100%;
  min-height: 28px;
  background: var(--faint);
}

.is-up .state-rail {
  background: var(--success);
}

.is-degraded .state-rail {
  background: var(--warn);
}

.is-degraded.latency-critical .state-rail {
  background: var(--latency-critical);
}

.is-degraded.latency-lost .state-rail {
  background: var(--loss);
}

.is-down .state-rail {
  background: var(--danger);
}

.is-up.has-recent-failure .state-rail {
  background: var(--warn);
}

.target-main,
.target-address,
.target-note {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.target-main {
  font-size: 12px;
  font-weight: 800;
}

.target-sub {
  margin-top: 2px;
  font-size: 10px;
}

.target-address,
.target-note,
.metric {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
}

.target-address {
  color: var(--muted);
}

.history {
  display: grid;
  grid-template-columns: repeat(var(--history-count), minmax(4px, 1fr));
  align-items: end;
  gap: 2px;
  width: 100%;
  height: 22px;
  min-width: 0;
  overflow: hidden;
}

.pip {
  height: var(--pip-height, 4px);
  border-radius: 2px;
  background: var(--success);
}

.pip.level-0 {
  height: var(--pip-height, 22px);
}

.pip.level-2 {
  height: var(--pip-height, 6px);
}

.pip.level-3 {
  height: var(--pip-height, 8px);
}

.pip.level-4 {
  height: var(--pip-height, 10px);
}

.pip.level-5 {
  height: var(--pip-height, 13px);
}

.pip.level-6 {
  height: var(--pip-height, 16px);
}

.pip.level-7 {
  height: var(--pip-height, 19px);
}

.pip.level-8 {
  height: var(--pip-height, 22px);
}

.pip.latency-ok {
  background: var(--success);
  background-image: none;
}

.pip.latency-warn {
  background: var(--warn);
  background-image: none;
}

.pip.latency-critical {
  background: var(--latency-critical);
  background-image: none;
}

.pip.latency-lost {
  background: var(--loss);
  background-image: repeating-linear-gradient(
    135deg,
    color-mix(in srgb, var(--loss) 90%, #000 10%) 0 3px,
    color-mix(in srgb, var(--loss) 35%, transparent) 3px 6px
  );
}

.target-row.is-down .pip.latency-lost {
  background: var(--danger);
  background-image: repeating-linear-gradient(
    135deg,
    color-mix(in srgb, var(--danger) 88%, #000 12%) 0 3px,
    color-mix(in srgb, var(--danger) 45%, transparent) 3px 6px
  );
}

.pip.empty {
  height: 4px;
  background: var(--line);
  opacity: 0.42;
}

.metric {
  justify-self: end;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.metric strong {
  color: var(--text);
}

.metric.rtt.latency-warn strong {
  color: var(--warn);
}

.metric.rtt.latency-critical strong {
  color: var(--latency-critical);
}

.metric.rtt.latency-lost strong {
  color: var(--loss);
}

.target-row.is-down .metric.rtt.latency-lost strong {
  color: var(--danger);
}

.empty-state {
  grid-column: 1 / -1;
  padding: 24px 0;
  color: var(--muted);
  font-size: 13px;
}

@media (max-width: 1180px) {
  .topbar {
    grid-template-columns: 1fr auto;
  }

  .pulse-line,
  .totals,
  .clock {
    grid-column: auto;
  }

  .target-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 760px) {
  .topbar {
    grid-template-columns: 1fr auto;
    gap: 12px;
    padding: 12px;
  }

  .pulse-line,
  .totals,
  .clock {
    grid-column: 1 / -1;
  }

  .totals {
    border: 1px solid var(--line);
  }

  .totals div {
    padding: 8px;
  }

  .tabs {
    padding: 8px 12px;
  }

  main {
    padding: 0 10px 24px;
  }

  .section-head {
    align-items: start;
    flex-direction: column;
  }

  .target-row {
    grid-template-columns: 10px minmax(0, 1fr) 82px;
    grid-template-areas:
      "rail main rtt"
      "rail addr loss"
      "rail note note"
      "rail hist hist";
    min-height: 74px;
    padding: 6px 0;
  }

  .state-rail {
    grid-area: rail;
    min-height: 74px;
  }

  .target-main {
    grid-area: main;
  }

  .target-address {
    grid-area: addr;
  }

  .target-note {
    grid-area: note;
  }

  .history {
    grid-area: hist;
  }

  .metric.rtt {
    grid-area: rtt;
  }

  .metric.loss {
    grid-area: loss;
  }
}
"""


APP_JS = r"""
const state = {
  data: null,
  activeGroup: null,
  rotationKey: null,
  rotationTimer: null,
  rotationPaused: localStorage.getItem("deadmon.rotationPaused") === "true",
  theme: localStorage.getItem("deadmon.theme") || "dark",
};

const els = {
  appName: document.getElementById("app-name"),
  appMeta: document.getElementById("app-meta"),
  liveMeta: document.getElementById("live-meta"),
  upCount: document.getElementById("up-count"),
  degradedCount: document.getElementById("degraded-count"),
  downCount: document.getElementById("down-count"),
  clockTime: document.getElementById("clock-time"),
  clockDate: document.getElementById("clock-date"),
  rotationToggle: document.getElementById("rotation-toggle"),
  themeToggle: document.getElementById("theme-toggle"),
  groupTabs: document.getElementById("group-tabs"),
  groupTitle: document.getElementById("group-title"),
  groupDescription: document.getElementById("group-description"),
  groupStats: document.getElementById("group-stats"),
  targetGrid: document.getElementById("target-grid"),
};

function setTheme(theme) {
  state.theme = theme;
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("deadmon.theme", theme);
  els.themeToggle.textContent = theme === "dark" ? "Light" : "Dark";
}

function toggleTheme() {
  setTheme(state.theme === "dark" ? "light" : "dark");
}

function setRotationPaused(paused) {
  state.rotationPaused = Boolean(paused);
  localStorage.setItem("deadmon.rotationPaused", state.rotationPaused ? "true" : "false");
  updateRotationToggle();
  resetTabRotation();
  if (state.data) configureTabRotation(state.data);
}

function toggleRotation() {
  setRotationPaused(!state.rotationPaused);
}

function updateRotationToggle() {
  els.rotationToggle.textContent = state.rotationPaused ? ">" : "||";
  els.rotationToggle.classList.toggle("is-paused", state.rotationPaused);
  els.rotationToggle.setAttribute("aria-pressed", state.rotationPaused ? "true" : "false");
  els.rotationToggle.setAttribute(
    "aria-label",
    state.rotationPaused ? "Resume tab rotation" : "Pause tab rotation"
  );
  els.rotationToggle.title = state.rotationPaused ? "Resume tab rotation" : "Pause tab rotation";
}

function updateClock() {
  const now = new Date();
  els.clockTime.textContent = new Intl.DateTimeFormat([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(now);
  els.clockDate.textContent = new Intl.DateTimeFormat([], {
    weekday: "short",
    month: "short",
    day: "2-digit",
    year: "numeric",
  }).format(now);
}

async function refresh() {
  try {
    const response = await fetch("api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    state.data = data;
    if (!state.activeGroup && data.groups.length) {
      state.activeGroup = data.groups[0].id;
    }
    if (!data.groups.some((group) => group.id === state.activeGroup)) {
      state.activeGroup = data.groups[0]?.id || null;
    }
    render(data);
  } catch (error) {
    els.liveMeta.textContent = `STALE - ${error.message}`;
  }
}

function render(data) {
  const targetWord = data.totals.total === 1 ? "TARGET" : "TARGETS";
  els.appName.textContent = data.app.name;
  els.appMeta.textContent = `${data.app.version} - ${shortPath(data.app.config_path)}`;
  els.liveMeta.textContent =
    `LIVE - ${data.totals.total} ${targetWord.toLowerCase()} - ${formatSeconds(data.app.poll_interval)} cadence - \
        ${formatSeconds(data.app.tab_rotation_interval)} tabs`;
  els.upCount.textContent = data.totals.up;
  els.degradedCount.textContent = data.totals.degraded;
  els.downCount.textContent = data.totals.down;
  configureTabRotation(data);
  renderTabs(data.groups);
  renderActiveGroup(data);
}

function renderTabs(groups) {
  els.groupTabs.replaceChildren(
    ...groups.map((group, index) => {
      const button = document.createElement("button");
      button.className = `tab${group.id === state.activeGroup ? " active" : ""}`;
      button.type = "button";
      button.dataset.group = group.id;
      button.innerHTML = `<span class="index">${String(index + 1).padStart(2, "0")}</span>${escapeHtml(group.name)}`;
      button.addEventListener("click", () => {
        state.activeGroup = group.id;
        resetTabRotation();
        if (state.data) render(state.data);
      });
      return button;
    })
  );
}

function renderActiveGroup(data) {
  const group = data.groups.find((item) => item.id === state.activeGroup) || data.groups[0];
  if (!group) return;
  const targets = data.targets
    .filter((target) => target.group_id === group.id)
    .map((target, index) => ({ ...target, config_index: index }))
    .sort(compareTargets);
  els.groupTitle.textContent = group.name;
  els.groupDescription.textContent = group.description || "";
  els.groupStats.textContent =
    `${group.up} up - ${group.degraded} degraded - ${group.down} down - ${group.total} total`;
  els.targetGrid.style.setProperty("--history-count", String(data.app.retain_results));

  if (!targets.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No targets";
    els.targetGrid.replaceChildren(empty);
    return;
  }

  els.targetGrid.replaceChildren(...targets.map((target) => renderTarget(target, data.app.retain_results)));
}

function renderTarget(target, retainResults) {
  const row = document.createElement("article");
  const recentFailureClass = recentFailureCount(target) > 0 ? " has-recent-failure" : "";
  row.className = `target-row is-${target.status} latency-${target.latency_state}${recentFailureClass}`;
  row.title = target.last_message || "";

  const statusLabel = targetStatusLabel(target);
  const note = target.note || relayLabel(target) || target.last_code || "";
  const latest = target.up ? formatMs(target.latest_rtt_ms) : "--";
  const avg = target.avg_rtt_ms ? formatMs(target.avg_rtt_ms) : "--";
  const rttTitle = latencyTooltip(target);

  row.innerHTML = `
    <div class="state-rail" aria-hidden="true"></div>
    <div class="target-main">
      <div>${escapeHtml(target.name)}</div>
      <div class="target-sub">${escapeHtml(statusLabel)}</div>
    </div>
    <div class="target-address">${escapeHtml(target.address)}</div>
    <div class="target-note">${escapeHtml(note)}</div>
    <div class="history">${renderHistory(target.history, retainResults)}</div>
    <div class="metric rtt latency-${target.latency_state}" title="${escapeHtml(rttTitle)}"><strong>${latest}</strong><span> ms</span>
    <div class="target-sub">avg ${avg}</div></div>
    <div class="metric loss"><strong>${target.loss_rate.toFixed(0)}%</strong><div class="target-sub">${target.sent} snt</div></div>
  `;
  return row;
}

function configureTabRotation(data) {
  const groups = rotatableGroups(data.groups);
  const intervalSeconds = Number(data.app.tab_rotation_interval || 0);
  const intervalMs = Math.max(0, intervalSeconds * 1000);
  const key = `${intervalMs}:${state.rotationPaused ? "paused" : "running"}:${groups.map((group) => group.id).join(",")}`;

  if (state.rotationKey === key) return;
  clearTabRotation();
  state.rotationKey = key;

  if (state.rotationPaused || intervalMs <= 0 || groups.length < 2) return;
  state.rotationTimer = window.setInterval(rotateActiveGroup, intervalMs);
}

function clearTabRotation() {
  if (state.rotationTimer) {
    window.clearInterval(state.rotationTimer);
    state.rotationTimer = null;
  }
}

function resetTabRotation() {
  state.rotationKey = null;
  clearTabRotation();
}

function rotateActiveGroup() {
  if (!state.data) return;
  const groups = rotatableGroups(state.data.groups);
  if (groups.length < 2) return;

  const currentIndex = groups.findIndex((group) => group.id === state.activeGroup);
  const nextIndex = currentIndex === -1 ? 0 : (currentIndex + 1) % groups.length;
  state.activeGroup = groups[nextIndex].id;
  render(state.data);
}

function rotatableGroups(groups) {
  const populated = groups.filter((group) => group.total > 0);
  return populated.length > 1 ? populated : groups;
}

function compareTargets(left, right) {
  const leftWeight = targetSortWeight(left);
  const rightWeight = targetSortWeight(right);
  if (leftWeight !== rightWeight) return leftWeight - rightWeight;

  // Preserve configured order inside each severity bucket so normal RTT updates do not churn rows.
  return left.config_index - right.config_index;
}

function targetSortWeight(target) {
  if (target.status === "down") return 0;
  if (target.up === false || target.latency_state === "lost") return 1;
  if (target.latency_state === "critical") return 2;
  if (target.latency_state === "warn") return 3;
  if (target.status === "degraded") return 4;
  if (target.status === "pending") return 5;
  return 6;
}

function recentFailureCount(target) {
  return target.history.filter((item) => !item.success).length;
}

function renderHistory(history, retainResults) {
  const emptyCount = Math.max(0, retainResults - history.length);
  const empty = Array.from({ length: emptyCount }, () => '<span class="pip empty"></span>');
  const pips = history.map((item) => {
    const state = item.latency_state || (item.success ? "ok" : "lost");
    const label = item.success ? `${formatMs(item.rtt_ms)} ms - ${latencyStateLabel(state)}` : `lost - ${item.code}`;
    return `<span class="pip level-${item.level} latency-${state}" style="--pip-height: ${pipHeight(item)}px" title="${escapeHtml(label)}">\
    </span>`;
  });
  return empty.concat(pips).join("");
}

function pipHeight(item) {
  const explicit = Number(item.height_px);
  if (Number.isFinite(explicit)) return clamp(explicit, 4, 22);
  const fallback = 4 + Math.max(0, Number(item.level || 1) - 1) * 2.5;
  return clamp(fallback, 4, 22);
}

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

function targetStatusLabel(target) {
  if (target.alert_active && target.up === false) return "ALERT";
  if (target.alert_active && target.up === true) return "RECOVERING";
  if (target.status === "down") return "DOWN";
  if (target.up === false) return "LOSS";
  if (target.latency_state === "critical") return "CRITICAL LATENCY";
  if (target.latency_state === "warn") return "HIGH LATENCY";
  return target.status.toUpperCase();
}

function latencyTooltip(target) {
  const warning = Number(target.latency_warning_ms || 0);
  const critical = Number(target.latency_critical_ms || 0);
  const thresholds = [];
  if (warning > 0) thresholds.push(`warning >= ${formatMs(warning)} ms`);
  if (critical > 0) thresholds.push(`critical >= ${formatMs(critical)} ms`);
  const thresholdText = thresholds.length ? thresholds.join(", ") : "latency thresholds disabled";
  if (target.latency_state === "lost") return `Lost probe; ${thresholdText}`;
  return `${latencyStateLabel(target.latency_state)}; ${thresholdText}`;
}

function latencyStateLabel(value) {
  if (value === "critical") return "critical latency";
  if (value === "warn") return "high latency";
  if (value === "lost") return "lost probe";
  if (value === "pending") return "pending";
  return "latency ok";
}

function relayLabel(target) {
  if (target.tcp) {
    const port = target.tcp.dstport;
    return port ? `tcp/${port}` : "tcp";
  }
  if (target.source) return `source ${target.source}`;
  if (!target.relay) return "";
  const via = target.relay.via || "ssh";
  const relay = target.relay.relay ? ` ${target.relay.relay}` : "";
  return `${via}${relay}`;
}

function formatMs(value) {
  if (!Number.isFinite(value)) return "--";
  if (value >= 100) return value.toFixed(0);
  if (value >= 10) return value.toFixed(1);
  return value.toFixed(2);
}

function formatSeconds(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "--s";
  return `${Number.isInteger(number) ? number.toFixed(0) : number.toFixed(1)}s`;
}

function shortPath(path) {
  if (!path) return "";
  const parts = path.split("/");
  return parts[parts.length - 1] || path;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

els.rotationToggle.addEventListener("click", toggleRotation);
els.themeToggle.addEventListener("click", toggleTheme);
setTheme(state.theme);
updateRotationToggle();
updateClock();
refresh();
setInterval(updateClock, 1000);
setInterval(refresh, 2000);
"""


app = create_app()
