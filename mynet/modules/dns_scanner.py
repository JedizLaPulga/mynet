import asyncio
import dns.asyncresolver
from .base import BaseModule
from ..core.input_parser import Target

class DNSScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "DNS Scanner"
        self.description = "Resolves A, AAAA, MX, NS, and CNAME records"

    async def run(self, target: Target) -> dict:
        results = {}
        domain = target.host
        
        # If target is an IP, reverse lookup might be relevant but let's assume we want domain info mostly.
        # If it's an IP, we can do PTR.
        if target.type in ["ipv4", "ipv6"]:
             try:
                # Reverse DNS
                n = dns.reversename.from_address(target.ip)
                answers = await dns.asyncresolver.resolve(n, 'PTR')
                results['ptr'] = [str(r) for r in answers]
             except Exception as e:
                results['ptr_error'] = str(e)
             return results

        record_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']
        
        for rtype in record_types:
            try:
                answers = await dns.asyncresolver.resolve(domain, rtype)
                # Parse answers
                data = []
                for rdata in answers:
                    data.append(str(rdata))
                results[rtype] = data
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                results['error'] = "NXDOMAIN"
                break
            except Exception as e:
                results[f'error_{rtype}'] = str(e)
        
        return results
