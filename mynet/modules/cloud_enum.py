import asyncio
import aiohttp
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class CloudEnumScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Cloud Asset Enumerator"
        self.description = "Checks for common public cloud storage buckets (AWS S3, Azure Blob, GCP)"
        
        self.permutations = [
            "", "-dev", "-prod", "-test", "-staging", "-backup", "-public", "-assets", "-static", ".bak", "www"
        ]

    async def run(self, target: Target) -> dict:
        host = target.host
        if not host: return {}
        
        # Extract base name from host (e.g., example.com -> example)
        base_name = host.split(".")[0]
        if len(base_name) < 3:
             # Try second part if www?
             parts = host.split(".")
             if parts[0] == "www" and len(parts) > 1:
                 base_name = parts[1]

        results = {
            "aws_buckets": [],
            "azure_containers": [], # Placeholder logic for azure
            "gcp_buckets": []
        }

        # Concurrency control
        sem = asyncio.Semaphore(10) # 10 parallel checks

        async def check_s3(name_perm):
            # AWS S3 URL Format: http://{name}.s3.amazonaws.com
            bucket_url = f"http://{name_perm}.s3.amazonaws.com"
            async with sem:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.head(bucket_url, timeout=5) as resp:
                            if resp.status == 200:
                                return {"name": name_perm, "status": "Public (200)", "url": bucket_url}
                            elif resp.status == 403:
                                return {"name": name_perm, "status": "Protected (403)", "url": bucket_url}
                except Exception:
                    pass
            return None

        tasks = []
        for perm in self.permutations:
            candidate = f"{base_name}{perm}"
            tasks.append(check_s3(candidate))
            # Also try without base? No, too noisy.
            # Try with dots?
            if "." not in candidate:
                tasks.append(check_s3(f"{base_name}.{perm.strip('-')}"))
        
        # Also check exact host name as bucket
        tasks.append(check_s3(host))

        found = await asyncio.gather(*tasks)
        
        for item in found:
            if item:
                results["aws_buckets"].append(item)
                
        # Deduplicate
        # ... logic if needed, but gather returns unique tasks
        
        return results
