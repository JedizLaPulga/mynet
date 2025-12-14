import asyncio
import aiohttp
from bs4 import BeautifulSoup
from .base import BaseModule
from ..core.input_parser import Target

class HTTPScanner(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "HTTP Scanner"
        self.description = "Checks HTTP headers, status, and title"

    async def run(self, target: Target) -> dict:
        results = {}
        urls_to_test = []
        
        if target.url:
            urls_to_test.append(target.url)
        else:
            urls_to_test.append(f"http://{target.host}")
            urls_to_test.append(f"https://{target.host}")

        async with aiohttp.ClientSession() as session:
            for url in urls_to_test:
                try:
                    # set generic headers
                    headers = {'User-Agent': self.config.user_agent}
                    async with session.get(url, timeout=self.config.timeout, headers=headers, ssl=False) as response:
                        text = await response.text()
                        soup = BeautifulSoup(text, 'html.parser')
                        title = soup.title.string if soup.title else "No Title"
                        
                        results[url] = {
                            "status": response.status,
                            "server": response.headers.get("Server", "Unknown"),
                            "title": title.strip() if title else "",
                            "content_length": response.headers.get("Content-Length", len(text)),
                        }
                except Exception as e:
                    results[url] = {"error": str(e)}
        
        return results
