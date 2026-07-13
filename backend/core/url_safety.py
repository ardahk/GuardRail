from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from urllib.parse import urlparse


class UnsafeTargetURLError(ValueError):
    pass


def _allow_private_targets() -> bool:
    return os.getenv("GUARDRAIL_ALLOW_PRIVATE_TARGETS", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _validate_addresses(hostname: str, addresses: set[str]) -> None:
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if address.is_loopback:
            continue
        if address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
            raise UnsafeTargetURLError(f"Target hostname {hostname!r} resolves to blocked address {address}")
        if address.is_private and not _allow_private_targets():
            raise UnsafeTargetURLError(
                f"Target hostname {hostname!r} resolves to private address {address}; "
                "set GUARDRAIL_ALLOW_PRIVATE_TARGETS=true only for an authorized private target"
            )


async def validate_outbound_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTargetURLError("Target URL must use http or https and include a hostname")
    if parsed.username or parsed.password:
        raise UnsafeTargetURLError("Target URLs containing credentials are not allowed")
    hostname = parsed.hostname
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = {str(literal)}
    except ValueError:
        try:
            records = await asyncio.to_thread(
                socket.getaddrinfo,
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise UnsafeTargetURLError(f"Target hostname could not be resolved: {hostname}") from exc
        addresses = {record[4][0] for record in records}
    _validate_addresses(hostname, addresses)
    return parsed.geturl()
