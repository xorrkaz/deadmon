# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 Joe Clarke <jclarke@marcuscom.com>
# Based on the original deadman work by upa@haeena.net.

import io
import sys
from contextlib import redirect_stdout
from unittest import TestCase

from deadmon.app import PING_SUCCESS, PING_TIMEOUT, parse_snmpping_output, snmpping_command
from deadmon.snmpping import (
    PING_RESULTS_AVERAGE_RTT,
    SNMP_GET_RESPONSE,
    SNMP_INTEGER,
    SNMP_UNSIGNED32,
    PingResult,
    SnmpValue,
    control_probe_count,
    decode_snmp_response,
    encode_snmp_message,
    parse_args,
    ping_result_is_final,
    print_ping_result,
    snmp_inet_address,
    snmp_table_index,
)


class SnmpEncodingTests(TestCase):
    def test_snmp_table_index_uses_length_prefixed_admin_strings(self):
        self.assertEqual(
            snmp_table_index("deadmon", "probe"),
            (
                7,
                100,
                101,
                97,
                100,
                109,
                111,
                110,
                5,
                112,
                114,
                111,
                98,
                101,
            ),
        )

    def test_snmp_inet_address_classifies_ip_and_dns_targets(self):
        self.assertEqual(snmp_inet_address("192.0.2.1"), (1, b"\xc0\x00\x02\x01"))
        self.assertEqual(
            snmp_inet_address("2001:db8::1"),
            (2, bytes.fromhex("20010db8000000000000000000000001")),
        )
        self.assertEqual(snmp_inet_address("example.com"), (16, b"example.com"))

    def test_snmp_response_decode_returns_varbind_values(self):
        oid = PING_RESULTS_AVERAGE_RTT + snmp_table_index("deadmon", "probe")
        message = encode_snmp_message(
            42,
            "public",
            SNMP_GET_RESPONSE,
            [(oid, SnmpValue(SNMP_UNSIGNED32, 27))],
        )

        request_id, error_status, error_index, values = decode_snmp_response(message)

        self.assertEqual(request_id, 42)
        self.assertEqual(error_status, 0)
        self.assertEqual(error_index, 0)
        self.assertEqual(values[oid], 27)

    def test_snmp_response_decode_preserves_error_status(self):
        message = encode_snmp_message(
            43,
            "public",
            SNMP_GET_RESPONSE,
            [((1, 3, 6, 1, 2, 1, 1, 1, 0), SnmpValue(SNMP_INTEGER, 0))],
            error_status=6,
            error_index=1,
        )

        request_id, error_status, error_index, _values = decode_snmp_response(message)

        self.assertEqual(request_id, 43)
        self.assertEqual(error_status, 6)
        self.assertEqual(error_index, 1)

    def test_net_snmp_count_control_is_parsed(self):
        self.assertEqual(control_probe_count(["c1"]), 1)
        self.assertEqual(control_probe_count(["c3"]), 3)
        self.assertEqual(control_probe_count(["q", "c4"]), 4)

    def test_net_snmp_attached_version_argument_is_parsed(self):
        args = parse_args(["-Cc1", "-v2c", "-c", "rw", "192.0.2.254", "192.0.2.1"])

        self.assertEqual(args.version, "2c")
        self.assertEqual(args.count, 1)
        self.assertEqual(args.community, "rw")

    def test_print_ping_result_matches_native_shape(self):
        output = io.StringIO()

        with redirect_stdout(output):
            print_ping_result("192.0.2.254", "192.0.2.1", PingResult(sent=1, responses=1, min_rtt_ms=2, avg_rtt_ms=2, max_rtt_ms=2))

        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "PING 192.0.2.1 (192.0.2.1) from 192.0.2.254 with 0 bytes of extra data",
                "--- 192.0.2.1 ping statistics ---",
                "1 packets transmitted, 1 received, 0% packet loss",
                "rtt min/avg/max/stddev = 2.000/2.000/2.000/0.000 ms",
            ],
        )

    def test_deadmon_snmpping_output_is_parsed(self):
        result = parse_snmpping_output(
            "\n".join(
                [
                    "PING 192.0.2.1 (192.0.2.1) from 192.0.2.254 with 0 bytes of extra data",
                    "--- 192.0.2.1 ping statistics ---",
                    "1 packets transmitted, 1 received, 0% packet loss",
                    "rtt min/avg/max/stddev = 10.000/12.500/15.000/0.000 ms",
                ]
            ),
            timed_out=False,
        )

        self.assertEqual(result.code, PING_SUCCESS)
        self.assertEqual(result.rtt_ms, 12.5)

    def test_snmpping_output_without_responses_is_timeout(self):
        result = parse_snmpping_output(
            "1 packets transmitted, 0 received, 100% packet loss",
            timed_out=False,
        )

        self.assertEqual(result.code, PING_TIMEOUT)

    def test_snmpping_command_can_use_bundled_or_system(self):
        self.assertEqual(snmpping_command({}), [sys.executable, "-m", "deadmon.snmpping"])
        self.assertEqual(snmpping_command({"snmpping": "system"}), ["snmpping"])
        self.assertEqual(snmpping_command({"snmpping": "/usr/local/bin/snmpping"}), ["/usr/local/bin/snmpping"])

    def test_ping_result_does_not_finish_before_probes_are_sent(self):
        self.assertFalse(ping_result_is_final(status=2, sent=0, responses=0, probe_count=1))
        self.assertTrue(ping_result_is_final(status=2, sent=1, responses=0, probe_count=1))
        self.assertTrue(ping_result_is_final(status=3, sent=0, responses=0, probe_count=1))
        self.assertTrue(ping_result_is_final(status=1, sent=1, responses=1, probe_count=1))
