import ipaddress
import re
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Union

@dataclass
class Target:
    original_input: str
    host: str  # domain or ip
    ip: str = None
    type: str = "unknown" # 'domain', 'ipv4', 'ipv6', 'cidr'
    url: str = None

def parse_input(input_str: str) -> List[Target]:
    """
    Parses a single input string into a list of Target objects.
    Handle URLs, Domains, IPs, and CIDRs.
    """
    input_str = input_str.strip()
    targets = []

    # Check for CIDR
    if "/" in input_str:
        try:
            network = ipaddress.ip_network(input_str, strict=False)
            for ip in network:
                # Skip network and broadcast if desired, but for /31 or /32 it matters.
                # Let's just include all.
                t = Target(
                    original_input=input_str,
                    host=str(ip),
                    ip=str(ip),
                    type="ipv4" if network.version == 4 else "ipv6"
                )
                targets.append(t)
            return targets
        except ValueError:
            pass # Not a valid CIDR

    # Check for URL
    if input_str.startswith("http://") or input_str.startswith("https://"):
        parsed = urlparse(input_str)
        host = parsed.hostname
        t = Target(
            original_input=input_str,
            host=host,
            url=input_str,
            type="url"
        )
        if is_ip(host):
            t.ip = host
        targets.append(t)
        return targets

    # Check for IP
    if is_ip(input_str):
        t = Target(
            original_input=input_str,
            host=input_str,
            ip=input_str,
            type="ipv4" if "." in input_str else "ipv6"
        )
        targets.append(t)
        return targets

    # Assume Domain
    t = Target(
        original_input=input_str,
        host=input_str,
        type="domain"
    )
    targets.append(t)
    return targets

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
