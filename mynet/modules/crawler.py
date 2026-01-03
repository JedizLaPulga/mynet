import asyncio
import aiohttp
from typing import Dict, Any, Set, List
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from .base import BaseModule
from ..core.input_parser import Target

class Crawler(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Web Crawler"
        self.description = "Recursively crawls the target to map the application structure"
        self.max_depth = 2
        self.max_pages = 50  # Safety limit to prevent infinite scans in this demo version
        self.sem = asyncio.Semaphore(10)
        self.visited: Set[str] = set()
        self.scope_domains: Set[str] = set()

    async def run(self, target: Target) -> dict:
        self.visited.clear()
        self.scope_domains.clear()
        
        start_urls = []
        if target.url:
            start_urls.append(target.url)
        elif target.host:
            start_urls.append(f"http://{target.host}")
            start_urls.append(f"https://{target.host}")

        # Initialize scope based on start URLs
        for url in start_urls:
            domain = urlparse(url).netloc
            self.scope_domains.add(domain)

        # Result structure
        results = {
            "stats": {"visited_count": 0, "total_links_found": 0},
            "map": {} # url -> {status, title, out_links[]}
        }

        # Queue for BFS: (url, depth)
        queue = asyncio.Queue()
        for url in start_urls:
            queue.put_nowait((url, 0))

        # Workers consuming the queue
        # In a real heavy crawler we might spawn N workers.
        # Here we will just process until queue empty or limits hit.
        
        workers = [asyncio.create_task(self._worker(queue, results)) for _ in range(5)]
        await queue.join()
        
        # Cancel workers
        for w in workers:
            w.cancel()
            
        return results

    async def _worker(self, queue: asyncio.Queue, results: Dict[str, Any]):
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    url, depth = await queue.get()
                    
                    if depth > self.max_depth or len(self.visited) >= self.max_pages:
                        queue.task_done()
                        continue

                    # Normalize and Check visited
                    url, _ = urldefrag(url)
                    if url in self.visited:
                        queue.task_done()
                        continue
                    
                    self.visited.add(url)
                    
                    # Crawl
                    data = await self._fetch_and_parse(session, url)
                    if data:
                        results["map"][url] = {
                            "status": data["status"],
                            "title": data["title"],
                            "links_count": len(data["links"])
                        }
                        results["stats"]["visited_count"] += 1
                        results["stats"]["total_links_found"] += len(data["links"])
                        
                        # Add new links to queue
                        if depth < self.max_depth:
                            for link in data["links"]:
                                if link not in self.visited:
                                    queue.put_nowait((link, depth + 1))
                    
                    queue.task_done()
                except asyncio.CancelledError:
                    break
                except Exception:
                    queue.task_done()

    async def _fetch_and_parse(self, session, url: str):
        headers = {'User-Agent': self.config.user_agent}
        async with self.sem:
            try:
                # Use GET stream=True to peek headers first?
                # For crawler we need body.
                # max_size limit is important for industrial crawlers.
                async with session.get(url, headers=headers, ssl=False, timeout=self.config.timeout) as response:
                    # Only parse HTML
                    ct = response.headers.get("Content-Type", "").lower()
                    if "text/html" not in ct:
                        return None
                    
                    if response.status != 200:
                        return {"status": response.status, "title": "", "links": []}

                    text = await response.text()
                    soup = BeautifulSoup(text, 'html.parser')
                    title = soup.title.string.strip() if soup.title and soup.title.string else ""
                    
                    links = set()
                    
                    # Extract hrefs
                    for tag in soup.find_all(['a', 'link'], href=True):
                        href = tag.get('href')
                        abs_url = urljoin(url, href)
                        abs_url, _ = urldefrag(abs_url)
                        
                        # Scope Check: parsing netloc
                        parsed = urlparse(abs_url)
                        if parsed.scheme in ['http', 'https'] and parsed.netloc in self.scope_domains:
                            links.add(abs_url)
                    
                    # Extract src (scripts, etc) - optional, typically these are assets, not pages to crawl recursively usually
                    # But for mapping, we might want to know them. For now, let's stick to 'a href' for navigation.
                            
                    return {
                        "status": response.status,
                        "title": title,
                        "links": list(links)
                    }
            except Exception:
                return None
