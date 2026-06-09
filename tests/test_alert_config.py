# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 deadmon contributors
# Based on the original deadman work by upa@haeena.net.

from pathlib import Path
from unittest import TestCase

from deadmon.app import (
    ConfigError,
    effective_alert_config,
    normalize_config,
    parse_config_text,
    public_config,
)


def target_by_name(config, name):
    return next(target for target in config.targets if target.name == name)


class AlertDisableTests(TestCase):
    def test_group_can_disable_app_level_alerts(self):
        config = normalize_config(
            {
                "alerts": {
                    "enabled": True,
                    "threshold": 3,
                    "clear_threshold": 2,
                    "channels": [{"name": "global-slack", "type": "slack"}],
                },
                "groups": [
                    {
                        "name": "Lab",
                        "alerts": False,
                        "targets": [{"name": "lab-router", "address": "192.0.2.10"}],
                    }
                ],
            },
            Path("test.yaml"),
        )

        target_alerts = effective_alert_config(target_by_name(config, "lab-router"), config)

        self.assertFalse(target_alerts.enabled)
        self.assertEqual(target_alerts.threshold, 3)
        self.assertEqual(target_alerts.clear_threshold, 2)
        self.assertEqual([channel.name for channel in target_alerts.channels], ["global-slack"])

    def test_target_can_disable_app_level_alerts(self):
        config = normalize_config(
            {
                "alerts": {
                    "enabled": True,
                    "threshold": 3,
                    "clear_threshold": 2,
                    "channels": [{"name": "global-slack", "type": "slack"}],
                },
                "groups": [
                    {
                        "name": "WAN",
                        "targets": [
                            {"name": "normal-router", "address": "192.0.2.20"},
                            {
                                "name": "maintenance-router",
                                "address": "192.0.2.21",
                                "alerts": False,
                            },
                        ],
                    }
                ],
            },
            Path("test.yaml"),
        )

        normal_alerts = effective_alert_config(target_by_name(config, "normal-router"), config)
        disabled_alerts = effective_alert_config(target_by_name(config, "maintenance-router"), config)

        self.assertTrue(normal_alerts.enabled)
        self.assertFalse(disabled_alerts.enabled)

    def test_target_disable_wins_over_group_enabled_alerts(self):
        config = normalize_config(
            {
                "alerts": {
                    "enabled": True,
                    "threshold": 3,
                    "clear_threshold": 2,
                    "channels": [{"name": "global-slack", "type": "slack"}],
                },
                "groups": [
                    {
                        "name": "WAN",
                        "alerts": {
                            "enabled": True,
                            "threshold": 2,
                            "channels": [{"name": "wan-webex", "type": "webex"}],
                        },
                        "targets": [
                            {
                                "name": "suppressed-router",
                                "address": "192.0.2.30",
                                "alerts": False,
                            }
                        ],
                    }
                ],
            },
            Path("test.yaml"),
        )

        target_alerts = effective_alert_config(target_by_name(config, "suppressed-router"), config)

        self.assertFalse(target_alerts.enabled)
        self.assertEqual(target_alerts.threshold, 2)
        self.assertEqual([channel.name for channel in target_alerts.channels], ["wan-webex"])

    def test_public_config_exposes_effective_disabled_alerts(self):
        config = normalize_config(
            {
                "alerts": {
                    "enabled": True,
                    "channels": [{"name": "global-slack", "type": "slack"}],
                },
                "groups": [
                    {
                        "name": "Lab",
                        "alerts": False,
                        "targets": [{"name": "lab-router", "address": "192.0.2.40"}],
                    }
                ],
            },
            Path("test.yaml"),
        )

        public = public_config(config)

        self.assertFalse(public["groups"][0]["alerts"]["enabled"])
        self.assertFalse(public["groups"][0]["targets"][0]["alerts"]["enabled"])

    def test_target_alerts_must_be_boolean(self):
        with self.assertRaises(ConfigError):
            normalize_config(
                {
                    "groups": [
                        {
                            "name": "WAN",
                            "targets": [
                                {
                                    "name": "router",
                                    "address": "192.0.2.50",
                                    "alerts": {"enabled": False},
                                },
                            ],
                        }
                    ],
                },
                Path("test.yaml"),
            )

    def test_unknown_config_aliases_are_rejected(self):
        with self.assertRaisesRegex(ConfigError, "alerts_enabled"):
            normalize_config(
                {
                    "groups": [
                        {
                            "name": "WAN",
                            "targets": [
                                {
                                    "name": "router",
                                    "address": "192.0.2.60",
                                    "alerts_enabled": False,
                                },
                            ],
                        }
                    ],
                },
                Path("test.yaml"),
            )

    def test_tcp_must_use_object_form(self):
        with self.assertRaisesRegex(ConfigError, "tcp must be an object"):
            normalize_config(
                {
                    "groups": [
                        {
                            "name": "WAN",
                            "targets": [
                                {
                                    "name": "router",
                                    "address": "192.0.2.70",
                                    "tcp": "dstport:443",
                                },
                            ],
                        }
                    ],
                },
                Path("test.yaml"),
            )

    def test_deadman_text_config_is_not_supported(self):
        with self.assertRaises(ConfigError):
            parse_config_text("googleDNS 8.8.8.8\n")
