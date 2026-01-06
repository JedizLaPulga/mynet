import asyncio
import aiohttp
import re
from typing import Dict, Any, Set, List
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .base import BaseModule
from ..core.input_parser import Target

class EmailHarvester(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Email Harvester"
        self.description = "Scrapes email addresses from the target website"
        self.max_depth = 2
        self.max_pages = 30
        self.email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    async def run(self, target: Target) -> dict:
        start_url = self._get_start_url(target)
        if not start_url:
            return {}

        domain = urlparse(start_url).netloc
        visited = set()
        emails = set()
        queue = asyncio.Queue()
        queue.put_nowait((start_url, 0))

        # We'll use a worker pool for this as well
        tasks = []
        for _ in range(5):
            tasks.append(asyncio.create_task(self._worker(queue, visited, emails, domain)))
        
        await queue.join()
        
        for t in tasks:
            t.cancel()

        return {
            "count": len(emails),
            "emails": sorted(list(emails))
        }

    async def _worker(self, queue: asyncio.Queue, visited: Set[str], emails: Set[str], domain: str):
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    url, depth = await queue.get()
                    
                    if url in visited or len(visited) >= self.max_pages:
                        queue.task_done()
                        continue
                    
                    visited.add(url)
                    
                    # Fetch
                    html = await self._fetch(session, url)
                    if not html:
                        queue.task_done()
                        continue

                    # Extract Emails
                    found = self.email_regex.findall(html)
                    for email in found:
                        # Basic filter to avoid some common false positives like 'user@example.com' if desired
                        # or binary files treated as text.
                        if not email.endswith(('png', 'jpg', 'jpeg', 'gif', 'css', 'js')):
                             emails.add(email.lower())

                    # Crawl deeper
                    if depth < self.max_depth:
                        links = self._extract_links(html, url, domain)
                        for link in links:
                            if link not in visited:
                                queue.put_nowait((link, depth + 1))
                                
                    queue.task_done()
                except asyncio.CancelledError:
                    break
                except Exception:
                    queue.task_done()

    async def _fetch(self, session, url):
        try:
            headers = {'User-Agent': self.config.user_agent}
            async with session.get(url, headers=headers, ssl=False, timeout=self.config.timeout) as resp:
                if resp.status == 200 and "text/html" in resp.headers.get("Content-Type", "").lower():
                    return await resp.text()
        except Exception:
            pass
        return None

    def _extract_links(self, html, base_url, domain):
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                
                # Strict scope: same domain only
                if parsed.netloc == domain and parsed.scheme in ('http', 'https'):
                    links.add(full_url)
        except Exception:
            pass
        return links

    def _get_start_url(self, target: Target):
        if target.url:
            return target.url
        elif target.host:
            return f"http://{target.host}"
        return None
