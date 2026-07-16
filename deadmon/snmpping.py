# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 Joe Clarke <jclarke@marcuscom.com>
# Based on the original deadman work by upa@haeena.net.

from __future__ import annotations

import argparse
import math
import re
import secrets
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any

OID = tuple[int, ...]
SNMP_INTEGER = 0x02
SNMP_OCTET_STRING = 0x04
SNMP_NULL = 0x05
SNMP_OBJECT_IDENTIFIER = 0x06
SNMP_UNSIGNED32 = 0x42
SNMP_GET_REQUEST = 0xA0
SNMP_GET_RESPONSE = 0xA2
SNMP_SET_REQUEST = 0xA3
SNMP_ERROR_NAMES = {
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}

PING_CTL_ENTRY = (1, 3, 6, 1, 2, 1, 80, 1, 2, 1)
PING_RESULTS_ENTRY = (1, 3, 6, 1, 2, 1, 80, 1, 3, 1)
PING_CTL_TARGET_ADDRESS_TYPE = PING_CTL_ENTRY + (3,)
PING_CTL_TARGET_ADDRESS = PING_CTL_ENTRY + (4,)
PING_CTL_TIMEOUT = PING_CTL_ENTRY + (6,)
PING_CTL_PROBE_COUNT = PING_CTL_ENTRY + (7,)
PING_CTL_ADMIN_STATUS = PING_CTL_ENTRY + (8,)
PING_CTL_ROW_STATUS = PING_CTL_ENTRY + (23,)
PING_RESULTS_OPER_STATUS = PING_RESULTS_ENTRY + (1,)
PING_RESULTS_MIN_RTT = PING_RESULTS_ENTRY + (4,)
PING_RESULTS_MAX_RTT = PING_RESULTS_ENTRY + (5,)
PING_RESULTS_AVERAGE_RTT = PING_RESULTS_ENTRY + (6,)
PING_RESULTS_PROBE_RESPONSES = PING_RESULTS_ENTRY + (7,)
PING_RESULTS_SENT_PROBES = PING_RESULTS_ENTRY + (8,)


@dataclass(frozen=True, slots=True)
class SnmpValue:
    tag: int
    value: Any = None


@dataclass(frozen=True, slots=True)
class PingResult:
    sent: int = 0
    responses: int = 0
    min_rtt_ms: float = 0.0
    avg_rtt_ms: float = 0.0
    max_rtt_ms: float = 0.0


class SnmpTimeout(TimeoutError):
    pass


class SnmpError(RuntimeError):
    def __init__(self, status: int, index: int = 0, message: str | None = None) -> None:
        self.status = status
        self.index = index
        label = SNMP_ERROR_NAMES.get(status, f"status {status}")
        super().__init__(message or f"{label} at varbind {index}")


class SnmpV2Client:
    def __init__(self, host: str, community: str, timeout: float, retries: int = 0, port: int = 161) -> None:
        self.host = host
        self.community = community
        self.timeout = timeout
        self.retries = max(0, retries)
        self.port = port

    def get(self, oids: list[OID]) -> dict[OID, Any]:
        varbinds = [(oid, SnmpValue(SNMP_NULL)) for oid in oids]
        return self._request(SNMP_GET_REQUEST, varbinds)

    def set(self, varbinds: list[tuple[OID, SnmpValue]]) -> dict[OID, Any]:
        return self._request(SNMP_SET_REQUEST, varbinds)

    def _request(self, pdu_type: int, varbinds: list[tuple[OID, SnmpValue]]) -> dict[OID, Any]:
        request_id = secrets.randbelow(2**31 - 1) + 1
        message = encode_snmp_message(request_id, self.community, pdu_type, varbinds)
        family, socktype, proto, _canonname, sockaddr = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)[0]
        last_timeout: SnmpTimeout | None = None

        for _attempt in range(self.retries + 1):
            deadline = time.monotonic() + self.timeout
            with socket.socket(family, socktype, proto) as udp:
                udp.settimeout(self.timeout)
                udp.sendto(message, sockaddr)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        last_timeout = SnmpTimeout("snmp relay timed out")
                        break
                    udp.settimeout(remaining)
                    try:
                        response, _address = udp.recvfrom(65535)
                    except TimeoutError:
                        last_timeout = SnmpTimeout("snmp relay timed out")
                        break

                    response_id, error_status, error_index, values = decode_snmp_response(response)
                    if response_id != request_id:
                        continue
                    if error_status:
                        raise SnmpError(error_status, error_index)
                    return values

        raise last_timeout or SnmpTimeout("snmp relay timed out")


def remote_ping(relay: str, community: str, target: str, timeout: float, count: int, retries: int) -> PingResult:
    address_type, address_value = snmp_inet_address(target)
    index = snmp_table_index("deadmon", secrets.token_hex(8))
    timeout_seconds = max(1, min(60, math.ceil(timeout)))
    probe_count = max(1, min(15, count))
    request_timeout = max(0.2, min(2.0, timeout))
    deadline = time.monotonic() + (timeout_seconds * probe_count) + request_timeout + 1.0
    client = SnmpV2Client(relay, community, timeout=request_timeout, retries=retries)

    ctl_target_type = PING_CTL_TARGET_ADDRESS_TYPE + index
    ctl_target_address = PING_CTL_TARGET_ADDRESS + index
    ctl_timeout = PING_CTL_TIMEOUT + index
    ctl_probe_count = PING_CTL_PROBE_COUNT + index
    ctl_admin_status = PING_CTL_ADMIN_STATUS + index
    ctl_row_status = PING_CTL_ROW_STATUS + index
    result_status = PING_RESULTS_OPER_STATUS + index
    result_min_rtt = PING_RESULTS_MIN_RTT + index
    result_max_rtt = PING_RESULTS_MAX_RTT + index
    result_average_rtt = PING_RESULTS_AVERAGE_RTT + index
    result_responses = PING_RESULTS_PROBE_RESPONSES + index
    result_sent = PING_RESULTS_SENT_PROBES + index

    try:
        client.set(
            [
                (ctl_target_type, SnmpValue(SNMP_INTEGER, address_type)),
                (ctl_target_address, SnmpValue(SNMP_OCTET_STRING, address_value)),
                (ctl_timeout, SnmpValue(SNMP_UNSIGNED32, timeout_seconds)),
                (ctl_probe_count, SnmpValue(SNMP_UNSIGNED32, probe_count)),
                (ctl_admin_status, SnmpValue(SNMP_INTEGER, 1)),
                (ctl_row_status, SnmpValue(SNMP_INTEGER, 4)),
            ]
        )

        values: dict[OID, Any] = {}
        while time.monotonic() < deadline:
            try:
                values = client.get([result_status, result_min_rtt, result_max_rtt, result_average_rtt, result_responses, result_sent])
            except SnmpError as exc:
                if exc.status in {2, 11, 18}:
                    time.sleep(0.1)
                    continue
                raise

            status = int(values.get(result_status, 0) or 0)
            if status in {2, 3}:
                break
            time.sleep(0.1)

        return PingResult(
            sent=int(values.get(result_sent, 0) or 0),
            responses=int(values.get(result_responses, 0) or 0),
            min_rtt_ms=float(values.get(result_min_rtt, 0) or 0),
            avg_rtt_ms=float(values.get(result_average_rtt, 0) or 0),
            max_rtt_ms=float(values.get(result_max_rtt, 0) or 0),
        )
    finally:
        try:
            client.set([(ctl_row_status, SnmpValue(SNMP_INTEGER, 6))])
        except (OSError, SnmpError, SnmpTimeout):
            pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="snmpping",
        description="SNMPv2c remote ping using RFC4560 DISMAN-PING-MIB.",
    )
    parser.add_argument("-C", dest="controls", action="append", default=[], help="Net-SNMP snmpping controls, e.g. -Cc1")
    parser.add_argument("-v", dest="version", default="2c", help="SNMP version. Only 2c is supported.")
    parser.add_argument("-c", dest="community", default="public", help="SNMP community")
    parser.add_argument("-t", dest="timeout", type=float, default=1.0, help="per-probe timeout in seconds")
    parser.add_argument("-r", dest="retries", type=int, default=0, help="SNMP request retries")
    parser.add_argument("relay", help="SNMP agent that will perform the remote ping")
    parser.add_argument("target", help="target address or hostname to ping from the relay")
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        parser.error(f"unsupported option(s): {' '.join(unknown)}")
    if args.version not in {"2c", "2"}:
        parser.error("only SNMPv2c is supported")
    if args.timeout <= 0:
        parser.error("timeout must be greater than zero")
    if args.retries < 0:
        parser.error("retries must be zero or greater")
    args.count = control_probe_count(args.controls)
    return args


def control_probe_count(controls: list[str]) -> int:
    count = 1
    for control in controls:
        match = re.search(r"c(\d+)", control)
        if match:
            count = int(match.group(1))
    return max(1, min(15, count))


def print_ping_result(relay: str, target: str, result: PingResult) -> None:
    sent = result.sent or 0
    responses = result.responses or 0
    loss = 0.0 if sent <= 0 else max(0.0, min(100.0, (sent - responses) / sent * 100.0))
    print(f"SNMP PING {target} from {relay}")
    print(f"{sent} packets transmitted, {responses} packets received, {loss:.0f}% packet loss")
    if responses > 0:
        min_rtt = result.min_rtt_ms or result.avg_rtt_ms
        max_rtt = result.max_rtt_ms or result.avg_rtt_ms
        print(f"rtt min/avg/max/stddev = {min_rtt:.3f}/{result.avg_rtt_ms:.3f}/{max_rtt:.3f}/0.000 ms")


def snmp_table_index(*values: str) -> OID:
    index: list[int] = []
    for value in values:
        encoded = value.encode("utf-8")
        if len(encoded) > 32:
            raise ValueError("SNMP table index values must be 32 octets or fewer")
        index.extend([len(encoded), *encoded])
    return tuple(index)


def snmp_inet_address(value: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_pton(socket.AF_INET, value)
    except OSError:
        pass
    try:
        return 2, socket.inet_pton(socket.AF_INET6, value)
    except OSError:
        pass

    encoded = value.encode("idna")
    if not encoded or len(encoded) > 255:
        raise ValueError(f"invalid SNMP DNS target address: {value!r}")
    return 16, encoded


def encode_snmp_message(
    request_id: int,
    community: str,
    pdu_type: int,
    varbinds: list[tuple[OID, SnmpValue]],
    error_status: int = 0,
    error_index: int = 0,
) -> bytes:
    varbind_list = ber_tlv(0x30, b"".join(encode_snmp_varbind(oid, value) for oid, value in varbinds))
    pdu = ber_tlv(
        pdu_type,
        b"".join(
            [
                ber_integer(request_id),
                ber_integer(error_status),
                ber_integer(error_index),
                varbind_list,
            ]
        ),
    )
    return ber_tlv(
        0x30,
        b"".join(
            [
                ber_integer(1),
                ber_tlv(SNMP_OCTET_STRING, community.encode("utf-8")),
                pdu,
            ]
        ),
    )


def encode_snmp_varbind(oid: OID, value: SnmpValue) -> bytes:
    return ber_tlv(0x30, ber_oid(oid) + ber_value(value))


def ber_value(value: SnmpValue) -> bytes:
    if value.tag == SNMP_INTEGER:
        return ber_integer(int(value.value))
    if value.tag == SNMP_UNSIGNED32:
        return ber_unsigned32(int(value.value))
    if value.tag == SNMP_OCTET_STRING:
        return ber_tlv(SNMP_OCTET_STRING, bytes(value.value))
    if value.tag == SNMP_OBJECT_IDENTIFIER:
        return ber_oid(tuple(value.value))
    if value.tag == SNMP_NULL:
        return ber_tlv(SNMP_NULL, b"")
    raise ValueError(f"unsupported SNMP value tag: {value.tag:#x}")


def decode_snmp_response(message: bytes) -> tuple[int, int, int, dict[OID, Any]]:
    tag, content, offset = ber_read_tlv(message, 0)
    if tag != 0x30 or offset != len(message):
        raise SnmpError(5, message="invalid SNMP message")

    version_tag, version_content, offset = ber_read_tlv(content, 0)
    if version_tag != SNMP_INTEGER or ber_decode_integer(version_content) != 1:
        raise SnmpError(5, message="unsupported SNMP version")

    community_tag, _community_content, offset = ber_read_tlv(content, offset)
    if community_tag != SNMP_OCTET_STRING:
        raise SnmpError(5, message="invalid SNMP community")

    pdu_tag, pdu_content, offset = ber_read_tlv(content, offset)
    if pdu_tag != SNMP_GET_RESPONSE or offset != len(content):
        raise SnmpError(5, message="invalid SNMP response PDU")

    request_tag, request_content, pdu_offset = ber_read_tlv(pdu_content, 0)
    error_tag, error_content, pdu_offset = ber_read_tlv(pdu_content, pdu_offset)
    index_tag, index_content, pdu_offset = ber_read_tlv(pdu_content, pdu_offset)
    if request_tag != SNMP_INTEGER or error_tag != SNMP_INTEGER or index_tag != SNMP_INTEGER:
        raise SnmpError(5, message="invalid SNMP response header")

    varbinds_tag, varbinds_content, pdu_offset = ber_read_tlv(pdu_content, pdu_offset)
    if varbinds_tag != 0x30 or pdu_offset != len(pdu_content):
        raise SnmpError(5, message="invalid SNMP varbind list")

    return (
        ber_decode_integer(request_content),
        ber_decode_integer(error_content),
        ber_decode_integer(index_content),
        decode_snmp_varbinds(varbinds_content),
    )


def decode_snmp_varbinds(content: bytes) -> dict[OID, Any]:
    values: dict[OID, Any] = {}
    offset = 0
    while offset < len(content):
        tag, varbind_content, offset = ber_read_tlv(content, offset)
        if tag != 0x30:
            raise SnmpError(5, message="invalid SNMP varbind")
        oid_tag, oid_content, value_offset = ber_read_tlv(varbind_content, 0)
        if oid_tag != SNMP_OBJECT_IDENTIFIER:
            raise SnmpError(5, message="invalid SNMP varbind OID")
        value_tag, value_content, value_offset = ber_read_tlv(varbind_content, value_offset)
        if value_offset != len(varbind_content):
            raise SnmpError(5, message="invalid SNMP varbind value")
        values[ber_decode_oid(oid_content)] = ber_decode_value(value_tag, value_content)
    return values


def ber_decode_value(tag: int, content: bytes) -> Any:
    if tag == SNMP_INTEGER:
        return ber_decode_integer(content)
    if tag in {0x41, SNMP_UNSIGNED32, 0x43, 0x46}:
        return int.from_bytes(content or b"\x00", "big", signed=False)
    if tag == SNMP_OCTET_STRING:
        return content
    if tag == SNMP_OBJECT_IDENTIFIER:
        return ber_decode_oid(content)
    if tag == SNMP_NULL or tag in {0x80, 0x81, 0x82}:
        return None
    raise SnmpError(5, message=f"unsupported SNMP response value tag: {tag:#x}")


def ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + ber_length(len(content)) + content


def ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    data = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(data)]) + data


def ber_integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    data = value.to_bytes(length, "big", signed=True)
    while len(data) > 1 and ((data[0] == 0x00 and data[1] < 0x80) or (data[0] == 0xFF and data[1] >= 0x80)):
        data = data[1:]
    return ber_tlv(SNMP_INTEGER, data)


def ber_unsigned32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("SNMP unsigned32 value out of range")
    length = max(1, (value.bit_length() + 7) // 8)
    return ber_tlv(SNMP_UNSIGNED32, value.to_bytes(length, "big", signed=False))


def ber_oid(oid: OID) -> bytes:
    if len(oid) < 2 or oid[0] not in {0, 1, 2} or oid[1] < 0:
        raise ValueError(f"invalid OID: {oid}")
    encoded = [40 * oid[0] + oid[1]]
    for subid in oid[2:]:
        if subid < 0:
            raise ValueError(f"invalid OID: {oid}")
        encoded.extend(ber_base128(subid))
    return ber_tlv(SNMP_OBJECT_IDENTIFIER, bytes(encoded))


def ber_base128(value: int) -> list[int]:
    if value == 0:
        return [0]
    output = [value & 0x7F]
    value >>= 7
    while value:
        output.append(0x80 | (value & 0x7F))
        value >>= 7
    return list(reversed(output))


def ber_read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise SnmpError(5, message="truncated BER value")
    tag = data[offset]
    offset += 1
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        length_size = first_length & 0x7F
        if length_size == 0 or offset + length_size > len(data):
            raise SnmpError(5, message="invalid BER length")
        length = int.from_bytes(data[offset : offset + length_size], "big")
        offset += length_size
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise SnmpError(5, message="truncated BER content")
    return tag, data[offset:end], end


def ber_decode_integer(content: bytes) -> int:
    return int.from_bytes(content or b"\x00", "big", signed=True)


def ber_decode_oid(content: bytes) -> OID:
    if not content:
        raise SnmpError(5, message="empty BER OID")
    first = content[0]
    if first < 40:
        oid = [0, first]
    elif first < 80:
        oid = [1, first - 40]
    else:
        oid = [2, first - 80]

    value = 0
    in_subid = False
    for byte in content[1:]:
        in_subid = True
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            oid.append(value)
            value = 0
            in_subid = False
    if in_subid:
        raise SnmpError(5, message="truncated BER OID")
    return tuple(oid)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        result = remote_ping(
            relay=args.relay,
            community=args.community,
            target=args.target,
            timeout=args.timeout,
            count=args.count,
            retries=args.retries,
        )
        print_ping_result(args.relay, args.target, result)
        return 0 if result.responses > 0 else 1
    except (OSError, SnmpError, SnmpTimeout, ValueError) as exc:
        print(f"snmpping: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
