import ipaddress
import re
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Iterator, Union

@dataclass
class Target:
    original_input: str
    host: str  # domain or ip
    ip: str = None
    type: str = "unknown" # 'domain', 'ipv4', 'ipv6', 'cidr'
    url: str = None

def parse_input(input_str: str) -> Iterator[Target]:
    """
    Parses a single input string into an iterator of Target objects.
    Handle URLs, Domains, IPs, and CIDRs.
    
    For CIDRs, yields targets lazily to avoid memory exhaustion on large ranges.
    """
    input_str = input_str.strip()

    # Check for CIDR
    if "/" in input_str:
        try:
            network = ipaddress.ip_network(input_str, strict=False)
            # Yield targets lazily to avoid memory explosion on large CIDRs
            for ip in network:
                yield Target(
                    original_input=input_str,
                    host=str(ip),
                    ip=str(ip),
                    type="ipv4" if network.version == 4 else "ipv6"
                )
            return
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
        yield t
        return

    # Check for IP
    if is_ip(input_str):
        yield Target(
            original_input=input_str,
            host=input_str,
            ip=input_str,
            type="ipv4" if "." in input_str else "ipv6"
        )
        return

    # Assume Domain
    yield Target(
        original_input=input_str,
        host=input_str,
        type="domain"
    )


def parse_input_list(input_str: str) -> List[Target]:
    """
    Convenience wrapper that returns a list instead of an iterator.
    Use with caution on large CIDRs as this will consume memory.
    """
    return list(parse_input(input_str))


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
