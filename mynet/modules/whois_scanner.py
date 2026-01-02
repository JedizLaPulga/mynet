import asyncio
import socket
from typing import Dict, Any
from ipwhois import IPWhois
from .base import BaseModule
from ..core.input_parser import Target

class WhoisScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Whois Scanner"
        self.description = "Retrieves WHOIS and ASN information"

    async def run(self, target: Target) -> Dict[str, Any]:
        """
        Perform WHOIS lookup.
        Warning: content is fetched via network and might be blocking, 
        so we run it in an executor.
        """
        host = target.host if target.host else target.original_input
        
        # Resolve to IP if it's a domain, because ipwhois needs an IP
        try:
            ip = await self._resolve_ip(host)
        except Exception as e:
            return {"error": f"Could not resolve host: {e}"}

        try:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, self._lookup_whois, ip)
            return self._parse_results(results)
        except Exception as e:
            return {"error": str(e)}

    async def _resolve_ip(self, host: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            # Check if host is already an valid IP
            socket.inet_aton(host)
            return host
        except socket.error:
            pass

        # It's a domain, resolve it
        return await loop.run_in_executor(None, socket.gethostbyname, host)

    def _lookup_whois(self, ip: str) -> Dict[str, Any]:
        obj = IPWhois(ip)
        # lookup_rdap is generally faster and returns structured JSON
        return obj.lookup_rdap(depth=1)

    def _parse_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Extract the most useful bits
        return {
            "asn": data.get("asn"),
            "asn_description": data.get("asn_description"),
            "asn_cidr": data.get("asn_cidr"),
            "asn_country_code": data.get("asn_country_code"),
            "query": data.get("query"), # The IP itself
            "network": {
                "name": data.get("network", {}).get("name"),
                "cidr": data.get("network", {}).get("cidr"),
                "country": data.get("network", {}).get("country"),
            },
            "entities": data.get("entities") # handle list of entities?
        }
