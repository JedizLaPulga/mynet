import asyncio
import dns.asyncresolver
import dns.zone
import dns.query
import dns.xfr
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class ZoneTransferScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Zone Transfer Scanner"
        self.description = "Attempts DNS AXFR zone transfer against authoritative nameservers"

    async def run(self, target: Target) -> dict:
        if target.type != "domain":
            return {"error": "Zone transfer only works on domains"}

        domain = target.host
        if not domain:
            return {"error": "No host specified"}

        results = {
            "vulnerable": False,
            "nameservers_tested": [],
            "records": []
        }

        try:
            # 1. Get Nameservers
            # specific resolver
            resolver = dns.asyncresolver.Resolver()
            # 2s timeout for finding NS
            resolver.timeout = 2
            resolver.lifetime = 2
            
            try:
                ns_answer = await resolver.resolve(domain, 'NS')
            except Exception:
                return {"error": "Could not detect nameservers"}

            tasks = []
            for rr in ns_answer:
                ns_name = str(rr.target)
                tasks.append(self._test_axfr(domain, ns_name))

            # Run all NS tests
            axfr_results = await asyncio.gather(*tasks)
            
            for res in axfr_results:
                results["nameservers_tested"].append(res.get("ns"))
                if res.get("success"):
                    results["vulnerable"] = True
                    # If we got one success, we have the records
                    if not results["records"]:
                        results["records"] = res.get("data", [])
        
        except Exception as e:
            return {"error": str(e)}

        return results

    async def _test_axfr(self, domain: str, ns_name: str) -> Dict[str, Any]:
        result = {"ns": ns_name, "success": False, "data": []}
        
        try:
            # Resolve NS to IP first (synchronously or with async resolver)
            # dnspython's make_query needs IP usually for xfr
            resolver = dns.asyncresolver.Resolver()
            ip_ans = await resolver.resolve(ns_name, 'A')
            ns_ip = str(ip_ans[0].address)
            
            # Perform AXFR
            # Note: dns.query.xfr is a generator. We need to run it in a thread executor
            # because standard dnspython xfr is blocking socket usage underneath mostly.
            # Alternately, use the async query method if available in new dnspython, 
            # but xfr usually runs over TCP.
            
            msg = dns.message.make_query(domain, dns.rdatatype.AXFR)
            
            # We run the blocking transfer in a thread
            loop = asyncio.get_running_loop()
            
            def do_xfr():
                try:
                    # xfr returns a generator of messages
                    zone_gen = dns.query.xfr(ns_ip, domain, lifetime=5)
                    # consume the generator
                    records = []
                    for msg in zone_gen:
                        for rr in msg.answer:
                             records.append(str(rr))
                    return records
                except Exception:
                    return None

            records = await loop.run_in_executor(None, do_xfr)
            
            if records:
                result["success"] = True
                result["data"] = records[:100] # Cap results to avoid huge memory dump

        except Exception:
            pass # Fail silently for specific NS failure
            
        return result
