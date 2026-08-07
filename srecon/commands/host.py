from __future__ import annotations

import ipaddress
import socket

from ..models import HostReport
from ..shodan_client import ShodanClient


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_target_ip(target: str) -> str:
    """Resolve um domínio para IPv4 via DNS (getaddrinfo). IP é devolvido como está."""
    if is_ip(target):
        return target
    try:
        infos = socket.getaddrinfo(
            target, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as e:
        raise ValueError(f"não consegui resolver '{target}' (DNS): {e}") from e
    for info in infos:
        ip = info[4][0]
        if ip:
            return ip
    raise ValueError(f"sem registro A para '{target}'")


def run(client: ShodanClient, target: str, history: bool = False) -> HostReport:
    ip = resolve_target_ip(target)
    return client.host(ip, history=history)
