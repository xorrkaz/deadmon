# Usage Guide

Deadmon is a browser-first reachability monitor. It continuously probes configured
targets, shows current state and recent history, and sends alert notifications
when a target crosses active or cleared thresholds.

## Starting the App

For local use:

```sh
uv sync
just run
```

For Docker:

```sh
just docker-up
```

Open `http://127.0.0.1:8000`.

## Dashboard

The top bar shows:

- App name and version.
- Live target count and polling cadence.
- Counts for up, degraded, and down targets.
- Browser-local time.
- Light/dark theme toggle.

The group tabs switch between configured target groups. Tabs rotate
automatically using `app.tab_rotation_interval`, which defaults to 15 seconds.
Set it to `0` to disable rotation. Empty groups are skipped when at least two
groups contain targets. The top-bar pause button stops automatic tab rotation
for the current browser until it is resumed.

Each target row shows:

- Current status rail.
- Target name and address.
- Optional note or probe source information.
- Recent probe history.
- Latest RTT and average RTT.
- Loss percentage and sent probe count.

History pips use height and color for different meanings. Pip height is
calculated from each probe's RTT using `app.rtt_scale_ms`, so lower latency
renders shorter pips and higher latency renders taller pips. Pip color follows
latency classification: green is within threshold, yellow is successful but
above `latency_warning_ms`, violet is successful but above
`latency_critical_ms`, and gray with striping is a lost probe. Red is reserved
for active down state.

Status meanings:

- `up`: most recent probe succeeded, latency is within threshold, and no alert
  is active.
- `degraded`: the target has a current lost probe but has not crossed the active
  alert threshold, has high latency, or is recovering while an alert remains
  active.
- `down`: the target crossed the active alert threshold and is currently failing.
- `pending`: the target has not completed its first probe.

Rows are sorted dynamically so the most operationally relevant targets rise to
the top: active down targets, current lost probes, critical latency, warning
latency, recovering degraded targets, targets with recent failures, pending
targets, then clean targets in configured order.

Configure global latency thresholds in `app`, override them per group when a
set of targets has a different baseline, and override them again per target
when an individual instance needs its own threshold. Target values win over
group values, and group values win over global values:

```yaml
app:
  rtt_scale_ms: 10
  latency_warning_ms: 100
  latency_critical_ms: 250

groups:
  - name: DNS
    latency_warning_ms: 150
    latency_critical_ms: 350
    targets:
      - name: mroot
        address: 202.12.27.33
      - name: strict-dns
        address: 192.0.2.53
        latency_warning_ms: 50
        latency_critical_ms: 120
```

## Alerts

Deadmon supports Slack and Webex incoming webhook alerts.

Slack messages use attachment fields with severity colors. Webex messages use
markdown with severity emojis. Configure `app.public_url` to link alerts back to
the Deadmon dashboard, and `info_url` on targets that should link to an external
URL, runbook, status page, or LibreNMS context page. Slack channels can set
`channel`, such as `"#noc-alerts"`, to request a destination channel override
when the webhook supports it. They can also set `icon_emoji`, such as
`":scream:"`, to override the webhook avatar.

Two transitions generate notifications:

- `active`: sent after `alerts.threshold` consecutive failed probes.
- `cleared`: sent after `alerts.clear_threshold` consecutive successful probes
  while an alert is active.

Groups can override global alert thresholds and webhook channels:

```yaml
groups:
  - name: WAN
    alerts:
      threshold: 2
      clear_threshold: 3
      channels:
        - name: wan-webex
          type: webex
          webhook_url_env: WAN_WEBEX_WEBHOOK_URL
    targets:
      - name: edge-router
        address: 192.0.2.1
```

If `groups[].alerts.channels` is configured, those channels replace the
top-level channels for that group. If only thresholds are configured, the group
keeps using the top-level channels. A group can suppress delivery while still
tracking dashboard state:

```yaml
groups:
  - name: Lab
    alerts: false
    targets:
      - name: edge-router
        address: 192.0.2.1
```

Individual targets can also suppress inherited alert delivery:

```yaml
groups:
  - name: WAN
    targets:
      - name: planned-work
        address: 192.0.2.44
        alerts: false
```

## Common Commands

List recipes:

```sh
just
```

Install or update the local environment:

```sh
just sync
```

Validate Python files and config:

```sh
just check
```

Print the sanitized parsed config:

```sh
just dump-config
```

Normalize a JSON or YAML config to canonical YAML:

```sh
just convert-config deadmon.conf
uv run python bin/deadmon-convert-config deadmon.conf --output deadmon.yaml
```

Run on a custom address and port:

```sh
just run 0.0.0.0 8080 deadmon.conf
```

Build the Docker image locally:

```sh
just docker-build
```

Publish the Python package to PyPI:

```sh
just pypi-publish
```

Publish the Docker image to Docker Hub:

```sh
just docker-publish
```

Stop the Docker Compose deployment:

```sh
just docker-down
```

## CLI Options

The console entry point is `deadmon`.

```sh
uv run deadmon [OPTIONS] [CONFIG]
```

Useful options:

- `--host`: bind address. Defaults to `127.0.0.1`.
- `--port`: bind port. Defaults to `8000`.
- `--root-path`: ASGI root path for reverse proxy path-prefix deployments.
- `--log-level`: uvicorn log level.
- `--forwarded-allow-ips`: uvicorn forwarded header trust list. Defaults to `*`.
- `--reload`: enable uvicorn reload for development.
- `--check-config`: validate config and exit.
- `--dump-config`: print sanitized parsed config and exit.

Environment defaults:

- `DEADMON_CONFIG`
- `DEADMON_HOST`
- `DEADMON_PORT`
- `DEADMON_ROOT_PATH`
- `DEADMON_LOG_LEVEL`
- `FORWARDED_ALLOW_IPS`

## API Endpoints

The browser dashboard uses the same JSON endpoints operators can inspect:

- `/api/health`: health status.
- `/api/state`: current app, group, target, and alert state.
- `/api/config`: sanitized loaded configuration.

Example:

```sh
curl -sS http://127.0.0.1:8000/api/state
```

## Troubleshooting

If all ICMP targets fail in Docker, verify the container has `NET_RAW`.

If IPv6 targets fail only in Docker, verify that the Docker service network has
IPv6 enabled and that the container has an IPv6 route:

```sh
docker compose exec deadmon ip -6 addr
docker compose exec deadmon ip -6 route
docker compose exec deadmon ping -6 -c 1 2001:4860:4860::8888
```

If a webhook channel is enabled but alerts are not delivered, check that the
matching environment variable is set and visible to the process.

If a target stays degraded, compare `threshold`, `clear_threshold`, and the
target's consecutive success/failure counters in `/api/state`.

If netns or VRF probes fail in Docker, verify the container can see the relevant
host namespace or VRF and has the required Linux capabilities.
