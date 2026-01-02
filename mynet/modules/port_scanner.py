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
            
            # Banner Grabbing
            banner = None
            try:
                # Give the server a moment to send a banner (common for SSH, FTP, SMTP)
                # Shorter timeout for reading than connecting
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
            except (asyncio.TimeoutError, Exception):
                # If reading fails or times out, we still know the port is open
                pass

            writer.close()
            await writer.wait_closed()
            return port, True, banner
        except asyncio.TimeoutError:
            return port, False, "Timeout"
        except ConnectionRefusedError:
            return port, False, "Refused"
        except Exception as e:
            return port, False, str(e)

    async def run(self, target: Target) -> dict:
        target_ip = target.ip
        
        if not target_ip:
            try:
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(target.host, None)
                if addr_info:
                     target_ip = addr_info[0][4][0]
                else:
                     return {"error": "Could not resolve host"}
            except Exception as e:
                return {"error": f"Could not resolve host: {e}"}

        open_ports_data = [] # List of dicts: {'port': 80, 'banner': '...'}
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
        
        # Collect only open ports
        open_ports_list = []
        for port, is_open, banner in results:
            if is_open:
                open_ports_list.append(port)
                open_ports_data.append({"port": port, "banner": banner})
        
        return {
            "open_ports": open_ports_list, 
            "details": open_ports_data,
            "scanned_count": len(tasks), 
            "target_ip": target_ip
        }
