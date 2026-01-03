import asyncio
import subprocess
import re
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target
import sys

class TracerouteScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Traceroute Scanner"
        self.description = "Traces the path to the target using system tools"
        self.timeout = 10 # Seconds max per hop or execution time logic

    async def run(self, target: Target) -> dict:
        host = target.host or target.ip
        if not host:
            return {"error": "No host/IP to traceroute"}

        # Running system traceroute is safer/easier than constructing raw packets (requires root/admin)
        # Windows: tracert, Linux/Mac: traceroute
        
        command = ["tracert", "-d", "-h", "15", "-w", "500", host] if sys.platform == "win32" else ["traceroute", "-n", "-m", "15", "-w", "1", host]
        
        try:
            # Run asynchronously
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {"error": f"Traceroute failed: {stderr.decode().strip()}"}

            output = stdout.decode('utf-8', errors='ignore')
            hops = self._parse_output(output, sys.platform == "win32")
            
            return {
                "hops": hops,
                "raw_output": output[:1000] # Truncate if massive
            }

        except Exception as e:
            return {"error": str(e)}

    def _parse_output(self, output: str, is_windows: bool) -> List[Dict[str, Any]]:
        hops = []
        lines = output.splitlines()
        
        # Simple regex strategy to find lines starting with a number
        # Windows:  1    <1 ms    <1 ms    <1 ms  192.168.1.1 
        # Linux:    1  192.168.1.1  0.123 ms  0.100 ms  0.090 ms
        
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Look for hop number at start
            match = re.search(r'^(\d+)\s+', line)
            if match:
                hop_num = int(match.group(1))
                
                # Extract IP if present (basic IPv4 regex)
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    # Try to extract rtt - finding 'ms' and looking back
                    rtt_str = "N/A"
                    # Very naive latency extraction: find last number before 'ms'
                    # Better: regex for all ms values and avg them
                    ms_matches = re.findall(r'([<]?\d+(?:\.\d+)?) ms', line)
                    if ms_matches:
                        rtt_str = f"{ms_matches[-1]} ms"
                        
                    hops.append({"hop": hop_num, "ip": ip, "rtt": rtt_str})
                elif "*" in line:
                     hops.append({"hop": hop_num, "ip": "*", "rtt": "Timeout"})
        
        return hops
