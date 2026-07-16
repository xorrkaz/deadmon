# Configuration Reference

Deadmon reads one text config file. YAML is preferred, and JSON is supported.

The default path is `deadmon.conf`.

Unknown fields are rejected so stale or misspelled config keys fail during
startup instead of being ignored.

## Top-Level Structure

```yaml
app:
  name: deadmon
  public_url: https://deadmon.example.net/
  poll_interval: 5
  tab_rotation_interval: 15
  timeout: 1.2
  rtt_scale_ms: 10
  latency_warning_ms: 100
  latency_critical_ms: 250
  retain_results: 30
  authentication:
    username: admin
    password: change-me

alerts:
  enabled: true
  threshold: 3
  clear_threshold: 2
  channels: []

groups:
  - name: Infrastructure & Externals
    description: public internet and third-party services
    latency_warning_ms: 150
    latency_critical_ms: 350
    alerts:
      threshold: 2
      clear_threshold: 3
      channels: []
    targets: []
```

## App Fields

- `name`: display name used in the dashboard and alert messages.
- `public_url`: optional external dashboard URL included in alert messages.
- `poll_interval`: seconds between probe cycles.
- `tab_rotation_interval`: seconds between automatic dashboard tab changes.
  Set to `0` to disable tab rotation.
- `timeout`: per-probe timeout in seconds.
- `rtt_scale_ms`: RTT scale for history pip height, in milliseconds per added
  pixel. With the default `10`, a 30 ms probe is visibly shorter than a 100 ms
  probe. Higher values make the height scale less sensitive; lower values make
  it more sensitive.
- `latency_warning_ms`: successful probes at or above this RTT are marked as
  high latency and shown as degraded. This is the global default. Set to `0` to
  disable the warning level.
- `latency_critical_ms`: successful probes at or above this RTT are marked as
  critical latency. This is the global default. Set to `0` to disable the
  critical level.
- `retain_results`: number of recent probe results kept per target.
- `authentication`: optional HTTP Basic authentication for the dashboard and
  API. See [Authentication](#authentication).

Latency thresholds are resolved in this order:

1. `app.latency_warning_ms` and `app.latency_critical_ms` define global defaults.
2. Group-level latency thresholds override the global defaults for every target
   in that group.
3. Target-level latency thresholds override both group and global thresholds for
   that specific target.

## Alert Fields

- `enabled`: global alert delivery switch.
- `threshold`: consecutive failures required for an active alert.
- `clear_threshold`: consecutive successes required for a cleared alert.
- `channels`: Slack or Webex webhook channels.

Slack:

```yaml
alerts:
  channels:
    - name: slack-noc
      type: slack
      enabled: true
      webhook_url_env: SLACK_WEBHOOK_URL
      channel: "#noc-alerts"
      icon_emoji: ":scream:"
```

Webex:

```yaml
alerts:
  channels:
    - name: webex-noc
      type: webex
      enabled: true
      webhook_url_env: WEBEX_WEBHOOK_URL
```

Use `webhook_url_env` for secrets. `webhook_url` is supported but should only be
used for local testing. Slack channels may also set `channel` to request a
destination channel override, for example `"#noc-alerts"`, if the webhook
supports it. Some Slack app incoming webhooks are locked to their configured
channel and may ignore this payload field.

Slack channels may also set `icon_emoji` to override the incoming webhook
avatar, for example `":scream:"`. Values without surrounding colons are
normalized, so `icon_emoji: scream` becomes `:scream:`.

Slack alerts use attachment fields and severity colors. Webex alerts use
markdown with severity emojis. If `app.public_url` or a target `info_url` is
configured, alert messages include those links.

Alert settings are resolved in this order:

1. Top-level `alerts` define global defaults.
2. `groups[].alerts` overrides the global defaults for every target in that
   group.
3. Target-level `alerts: false` can suppress alert delivery for that specific
   target.

Group alert channels replace app-level channels when `groups[].alerts.channels`
is configured. If a group sets `alerts.threshold` without `alerts.channels`, it
keeps using the app-level channels.

Example group-specific alert routing:

```yaml
alerts:
  enabled: true
  threshold: 3
  clear_threshold: 2
  channels:
    - name: noc-slack
      type: slack
      webhook_url_env: SLACK_WEBHOOK_URL
      channel: "#noc-alerts"
      icon_emoji: ":satellite:"

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
      - name: carrier-a
        address: 192.0.2.10

  - name: Lab
    alerts: false
    targets:
      - name: lab-router
        address: 192.0.2.20
```

In this example, the `WAN` group sends to `WAN_WEBEX_WEBHOOK_URL` with stricter
thresholds, while the `Lab` group tracks state but does not deliver alerts.

## Groups

Groups organize targets into dashboard tabs:

```yaml
groups:
  - name: DNS
    description: recursive and authoritative DNS
    latency_warning_ms: 80
    latency_critical_ms: 200
    targets:
      - name: googleDNS
        address: 8.8.8.8
```

Group-level latency thresholds are optional:

- `latency_warning_ms`: high-latency warning threshold for targets in the group.
- `latency_critical_ms`: critical-latency threshold for targets in the group.
- `alerts`: optional alert override for the group. Supports `enabled`,
  `threshold`, `clear_threshold`, and `channels`.

## Target Fields

Required fields:

- `name`: target display name.
- `address`: IPv4 address, IPv6 address, or hostname.

Optional fields:

- `note`: dashboard note.
- `info_url`: optional URL for a runbook, status page, monitored external URL,
  LibreNMS device page, or other operator context. Included in alerts.
- `source`: source interface or address for local ping.
- `relay`: relay configuration for SSH, SNMP, netns, VRF, or RouterOS.
- `tcp`: TCP reachability configuration.
- `alerts`: set to `false` to suppress alert delivery for this target.
- `latency_warning_ms`: target-specific high-latency warning threshold.
- `latency_critical_ms`: target-specific critical-latency threshold.

Latency thresholds only classify successful probes. Lost probes are tracked
separately as reachability failures and are the only condition that contributes
to active and cleared alert thresholds.

Example with global, group, and target-specific latency thresholds:

```yaml
app:
  latency_warning_ms: 100
  latency_critical_ms: 250

groups:
  - name: Remote DNS
    latency_warning_ms: 180
    latency_critical_ms: 400
    targets:
      - name: mroot
        address: 202.12.27.33
        note: M-root DNS
      - name: strict-host
        address: 192.0.2.10
        latency_warning_ms: 50
        latency_critical_ms: 120
```

In this example, `mroot` uses the group thresholds, while `strict-host` uses its
own stricter target thresholds.

## Authentication

The optional `app.authentication` block protects the dashboard and all API
endpoints with HTTP Basic authentication:

```yaml
app:
  authentication:
    username: admin
    password: change-me
```

- `username`: account presented in the browser login prompt.
- `password`: matching password. Mutually exclusive with `password_env`.
- `password_env`: name of an environment variable that holds the password.
  Preferred over `password` so the secret stays out of the config file.

A username is always required, along with exactly one of `password` or
`password_env`. Specifying both `password` and `password_env`, or supplying a
username without a password, fails config validation. When the block is
omitted, Deadmon serves the dashboard and API without authentication.

Read the password from the environment instead of committing it:

```yaml
app:
  authentication:
    username: admin
    password_env: DEADMON_AUTH_PASSWORD
```

```sh
export DEADMON_AUTH_PASSWORD="change-me"
just run
```

The `password_env` variable is resolved on every request, so rotating the
secret takes effect after the process is restarted with the new value.

Credentials are matched on every request, so all routes (including
`/api/state` and `/api/health`) require the configured credentials. The login
realm uses the configured `app.name`.

Basic authentication transmits credentials in a reversible, base64-encoded
header, so always run Deadmon behind TLS (typically terminated at a reverse
proxy) when authentication is enabled. The configured credentials are never
included in the sanitized config output from `--dump-config`.

## Direct ICMP

```yaml
- name: googleDNS
  address: 8.8.8.8
  note: google DNS
  info_url: https://dns.google/
```

## Source Interface or Address

```yaml
- name: googleDNS-from-wan0
  address: 8.8.8.8
  source: wan0
```

Linux uses `ping -I`. macOS uses `ping -S`.

## SSH Relay

```yaml
- name: google-via-ssh
  address: 173.194.117.176
  relay:
    relay: X.X.X.X
    os: Linux
    user: USER
    key: /run/secrets/relay_id_rsa
```

The remote host must have `ping` available. `os` controls the ping command style
used on the relay host.

## SNMP Ping

```yaml
- name: googleDNS-via-snmp
  address: 8.8.8.8
  relay:
    relay: X.X.X.X
    via: snmp
    community: change-me-rw
    snmpping: bundled
```

SNMP relay probes execute a `snmpping`-compatible command. The default is
`snmpping: bundled`, which runs Deadmon's Python implementation of SNMPv2c
RFC4560 REMOPS ping without requiring Net-SNMP. Set `snmpping: system` to use
the Net-SNMP `snmpping` found in `PATH`, or set `snmpping` to an explicit command
path.

For RFC4560 remote ping, the configured community must be able to create, start,
read, and delete `DISMAN-PING-MIB::pingCtlTable` rows on the relay device.

## Linux Network Namespace

```yaml
- name: googleDNS-via-netns
  address: 8.8.8.8
  relay:
    relay: netns1
    via: netns
```

The process must have permission to run `ip netns exec`.

## Linux VRF

```yaml
- name: googleDNS-via-vrf
  address: 8.8.8.8
  relay:
    relay: vrf1
    via: vrf
```

The process must have permission to run `ip vrf exec`.

## RouterOS REST API

```yaml
- name: googleDNS-via-routeros
  address: 8.8.8.8
  relay:
    relay: router.example.net
    via: routeros_api
    username: api-user
    password: change-me
    method: https
    verify: true
```

`method` defaults to `https`. Set `verify: false` only for environments where
the RouterOS certificate cannot be verified.

## TCP Reachability

By default, TCP targets use a normal TCP connection attempt:

```yaml
- name: example-https
  address: example.com
  tcp:
    dstport: 443
```

To use `hping3` instead:

```yaml
- name: example-https-hping
  address: example.com
  tcp:
    dstport: 443
    method: hping3
```

## Normalizing Configs

Use `deadmon-convert-config` to normalize JSON or YAML configs to the canonical
YAML format:

```sh
uv run python bin/deadmon-convert-config deadmon.conf --output deadmon.yaml
```

The converter writes to stdout by default:

```sh
just convert-config deadmon.conf
```

Use `--force` to overwrite an existing output file:

```sh
uv run python bin/deadmon-convert-config deadmon.conf --output deadmon.yaml --force
```

The converter preserves target fields such as `relay`, `source`, `tcp`,
`alerts`, group alert overrides, and target or group latency threshold
overrides. YAML comments are not preserved, so review the generated config
before deployment.
