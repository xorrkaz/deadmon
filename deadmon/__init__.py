# SPDX-License-Identifier: MIT
# Copyright (c) 2018 Interop Tokyo ShowNet NOC team
# Copyright (c) 2026 Joe Clarke <jclarke@marcuscom.com>
# Based on the original deadman work by upa@haeena.net.

"""Deadmon web reachability monitor."""

from importlib import metadata

__all__ = ["__version__"]


def _detect_version() -> str:
    try:
        return metadata.version("deadmon")
    except metadata.PackageNotFoundError:
        return "0.0.0+unknown"


__version__ = _detect_version()
