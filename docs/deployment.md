# Deployment Guide

This guide covers local development, Docker Compose deployment, reverse proxy
operation, and the host permissions required by the supported probe types.

## Requirements

- Python 3.11 or newer for local runs.
- `uv` for Python dependency management.
- `just` for local command recipes.
- Docker and Docker Compose for container deployment.
- Network utilities for the probe types you enable:
  - `ping` or `ping6` for ICMP.
  - `ssh` for SSH relay probes.
  - `ip` for Linux netns and VRF probes.
  - `hping3` only if a TCP target is configured with `method: hping3`.

The Docker image installs the common system tools used by the app: `ping`,
`hping3`, `iproute2`, and `openssh-client`.

The published Docker Hub image is available as `xorrkaz/deadmon`.

SNMP relay probes execute a `snmpping`-compatible command. By default, Deadmon
uses its bundled Python implementation, so the Docker image does not install
Net-SNMP. Outside Docker, set `relay.snmpping: system` to use a working
Net-SNMP `snmpping` from `PATH`, or set `relay.snmpping` to an explicit command
path. RFC4560 remote ping requires the remote SNMP agent to support writable
DISMAN-PING-MIB objects.

## Local Deployment

Install dependencies and validate the default config:

```sh
uv sync
just check
```

Run the app on localhost:

```sh
just run
```

Run on all interfaces:

```sh
just run 0.0.0.0 8000 deadmon.conf
```

Open `http://127.0.0.1:8000`.

The `just run` recipe expands to:

```sh
uv run deadmon --host 127.0.0.1 --port 8000 deadmon.conf
```

## Docker Compose Deployment

Build and run:

```sh
just docker-up
```

The service listens on host port `8000` by default. The compose file bind-mounts
`./deadmon.conf` into the container as `/app/deadmon.conf`.

## Docker Hub Image

Run the published image directly without building locally:

```sh
docker run --rm -p 8000:8000 xorrkaz/deadmon
```

If you want to mount a configuration file, use:

```sh
docker run --rm -p 8000:8000 -v "$(pwd)/deadmon.conf:/app/deadmon.conf:ro" xorrkaz/deadmon
```

The published image uses the same runtime environment and should work with the
same host capabilities and network configuration notes described below.

## Publishing

Build the Docker image locally:

```sh
just docker-build
```

Publish the Docker image to Docker Hub:

```sh
just docker-publish
```

Publish the Python package to PyPI:

```sh
just pypi-publish
```

Run the full publish workflow (build + PyPI + Docker Hub):

```sh
just publish
```

The compose file also attaches the service to a user-defined bridge network with
IPv6 address assignment enabled:

```yaml
networks:
  deadmon:
    driver: bridge
    enable_ipv6: true
```

Docker must still be able to create IPv6-enabled networks on the host. On modern
Linux Docker Engine, Docker can allocate a Unique Local Address subnet for that
network automatically. If your Docker daemon is older or centrally configured
with explicit address pools, enable IPv6 in Docker's daemon configuration and
provide an IPv6 pool or fixed subnet that does not conflict with your site
addressing. After changing daemon settings, restart Docker and recreate the
Deadmon network:

```sh
docker compose down
docker compose up --build
```

Validate the compose file:

```sh
just docker-config
```

Build without starting the container:

```sh
just docker-build
```

## Reloading Configuration

Deadmon can re-read its config without restarting the process or container.
Reloads preserve history, alert state, and consecutive success/failure counters
for targets whose stable identity is unchanged. A target keeps its state when
its group name, target name, and address are the same. Added targets start with
empty history, and removed targets are dropped.

The automation-friendly path is `POST /api/reload`:

```sh
curl -fsS -X POST http://127.0.0.1:8000/api/reload
```

When `app.authentication` is enabled, pass the configured Basic credentials:

```sh
curl -fsS -u "$DEADMON_USER:$DEADMON_PASSWORD" -X POST http://127.0.0.1:8000/api/reload
```

If the new config cannot be loaded, Deadmon writes the error to stderr and exits
with a failure. With `restart: unless-stopped`, Docker will try to restart it
and startup will keep failing until the config is fixed. On success, the JSON
response includes preserved, added, and removed target counts.

Example Ansible task:

```yaml
- name: Reload Deadmon configuration
  ansible.builtin.uri:
    url: http://127.0.0.1:8000/api/reload
    method: POST
    status_code: 200
```

With Basic authentication:

```yaml
- name: Reload Deadmon configuration
  ansible.builtin.uri:
    url: http://127.0.0.1:8000/api/reload
    method: POST
    url_username: "{{ deadmon_user }}"
    url_password: "{{ deadmon_password }}"
    force_basic_auth: true
    status_code: 200
```

When Ansible renders the config, prefer a handler so unchanged generated output
does not trigger a reload:

```yaml
- name: Render Deadmon configuration
  ansible.builtin.template:
    src: deadmon.conf.j2
    dest: /opt/deadmon/deadmon.conf
    mode: "0644"
  notify: Reload Deadmon configuration

handlers:
  - name: Reload Deadmon configuration
    ansible.builtin.uri:
      url: http://127.0.0.1:8000/api/reload
      method: POST
      status_code: 200
```

Deadmon also handles `SIGHUP` as a config reload signal. This is useful when
you do not want to expose the reload endpoint beyond localhost:

```sh
docker compose kill -s SIGHUP deadmon
```

A failed signal-triggered reload is fatal in the same way as a bad startup
config: Deadmon logs the config error and exits.

## Alert Webhooks

Slack and Webex webhook URLs should be passed as environment variables instead
of being committed to the config file.

Set `app.public_url` when Deadmon is available through a reverse proxy so alert
messages can link back to the dashboard:

```yaml
app:
  public_url: https://deadmon.example.net/
```

Example shell environment:

```sh
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export WEBEX_WEBHOOK_URL="https://webexapis.com/v1/webhooks/incoming/..."
just docker-up
```

Then enable the channel in `deadmon.conf`:

```yaml
alerts:
  enabled: true
  threshold: 3
  clear_threshold: 2
  channels:
    - name: slack-noc
      type: slack
      enabled: true
      webhook_url_env: SLACK_WEBHOOK_URL
```

An active notification is sent after `threshold` consecutive failed probes. A
cleared notification is sent after `clear_threshold` consecutive successful
probes.

## Authentication

Deadmon can require HTTP Basic authentication for the dashboard and all API
endpoints. Enable it with the `app.authentication` block:

```yaml
app:
  authentication:
    username: admin
    password_env: DEADMON_AUTH_PASSWORD
```

Use `password_env` to read the password from an environment variable (preferred
for production), or set a literal `password` for local testing. A username is
required along with exactly one of `password` or `password_env`. Provide the
secret through your process environment or secret store:

```sh
export DEADMON_AUTH_PASSWORD="change-me"
just docker-up
```

Because Basic authentication sends credentials in a reversible, base64-encoded
header, always pair built-in authentication with TLS terminated at the reverse
proxy. You can alternatively skip `app.authentication` and enforce
authentication and TLS entirely at the proxy layer.

## Reverse Proxy

Deadmon assumes it will normally run behind a reverse proxy. The CLI enables
uvicorn proxy header support by default.

Example Nginx location:

```nginx
location /deadmon/ {
    proxy_pass http://127.0.0.1:8000/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

If the app is mounted under a path prefix, configure the proxy to strip the
prefix before forwarding requests to Deadmon. The example above maps
`/deadmon/` externally to `/` on the app.

You can also pass the external prefix with `--root-path` so uvicorn records the
deployment prefix in the ASGI scope:

```sh
uv run deadmon --host 127.0.0.1 --port 8000 --root-path /deadmon deadmon.conf
```

For Docker Compose, add `DEADMON_ROOT_PATH` or override the command. The proxy
should still forward paths in the form Deadmon serves: `/`, `/assets/...`, and
`/api/...`.

## Probe Permissions

Direct ICMP requires permission to send ping packets. The default compose file
adds `NET_RAW` and explicitly keeps IPv6 enabled inside the container namespace:

```yaml
sysctls:
  net.ipv6.conf.all.disable_ipv6: "0"
  net.ipv6.conf.default.disable_ipv6: "0"
cap_add:
  - NET_RAW
```

If IPv4 targets work but IPv6 targets fail only in Docker, verify container IPv6
routing from inside the running service:

```sh
docker compose exec deadmon ip -6 addr
docker compose exec deadmon ip -6 route
docker compose exec deadmon ping -6 -c 1 2001:4860:4860::8888
```

The ping check is also available as:

```sh
just docker-ipv6-check
```

If the container has no global or ULA IPv6 address, or no IPv6 default route,
the Docker daemon/network is not providing IPv6 to containers yet.

Linux netns and VRF probes may need additional privileges, host networking, or
mounts depending on how namespaces and VRFs are exposed on the host. Start with:

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

Then add only the host mounts your environment requires.

TCP probes use a normal TCP connect by default and do not require raw socket
permissions. If you explicitly set `method: hping3`, raw socket permissions are
required.

## Health Checks

Use `/api/health` for service health:

```sh
curl -fsS http://127.0.0.1:8000/api/health
```

The endpoint returns HTTP 200 when the monitor loop is healthy. It returns HTTP
503 if the monitor has recorded a runtime error. The payload also includes
`reload_count` and `last_reload_at` so automation can inspect successful
reloads.

## Production Checklist

- Replace the sample targets in `deadmon.conf`.
- Run `just check` before deployment.
- Store Slack and Webex webhook URLs in environment variables or a secret store.
- Confirm the container has the capabilities required for your probe types.
- Enable `app.authentication` or enforce authentication at the reverse proxy,
  and terminate TLS at the proxy layer.
- Monitor `/api/health` from your platform or load balancer.
