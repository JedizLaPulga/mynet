import asyncio
from .base import BaseModule
from ..core.input_parser import Target

class PortScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Port Scanner"
        self.description = "Scans common ports using asyncio"

    async def scan_port(self, ip, port, timeout):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port, True, None
        except asyncio.TimeoutError:
            return port, False, "Timeout"
        except ConnectionRefusedError:
            return port, False, "Refused"
        except Exception as e:
            return port, False, str(e)

    async def run(self, target: Target) -> dict:
        target_ip = target.ip
        # If we only have a domain, we need to resolve it first? 
        # But the Parser might not have resolved it if it wasn't an IP input.
        # In a real app, the runner might handle resolution, or we do it here.
        
        if not target_ip:
            try:
                loop = asyncio.get_running_loop()
                # Use default resolver
                addr_info = await loop.getaddrinfo(target.host, None)
                # addr_info[0] is (family, type, proto, canonname, sockaddr)
                # sockaddr is (address, port)
                if addr_info:
                     target_ip = addr_info[0][4][0]
                else:
                     return {"error": "Could not resolve host"}
            except Exception as e:
                return {"error": f"Could not resolve host: {e}"}

        open_ports = []
        tasks = []
        timeout = self.config.timeout or 2
        
        # Concurrency limit semaphore
        sem = asyncio.Semaphore(self.config.concurrency)

        async def worker(p):
            async with sem:
                return await self.scan_port(target_ip, p, timeout)

        for port in self.config.ports:
            tasks.append(worker(port))
        
        results = await asyncio.gather(*tasks)
        
        for port, is_open, reason in results:
            if is_open:
                open_ports.append(port)
        
        return {"open_ports": open_ports, "scanned_count": len(tasks), "target_ip": target_ip}
