import asyncio
import aiohttp
import re
from typing import Dict, Any, List
from .base import BaseModule
from ..core.input_parser import Target

class TechFingerprinter(BaseModule):
    def __init__(self, config):
        super().__init__(config)
        self.name = "Tech Fingerprinter"
        self.description = "Identifies technologies based on headers, meta tags, and cookies"
        
        # Simple signature database
        # In a real app, this would be a large JSON file or Wappalyzer repo
        self.signatures = {
            "server": [
                (r"Apache/([\d\.]+)", "Apache HTTP Server"),
                (r"nginx/([\d\.]+)", "Nginx"),
                (r"cloudflare", "Cloudflare"),
                (r"Microsoft-IIS/([\d\.]+)", "Microsoft IIS"),
                (r"LiteSpeed", "LiteSpeed"),
            ],
            "headers": [
                ("X-Powered-By", r"PHP/([\d\.]+)", "PHP"),
                ("X-Powered-By", r"ASP.NET", "ASP.NET"),
                ("X-Powered-By", r"Express", "Express.js"),
                ("X-Generator", r"Drupal\s?([\d\.]+)?", "Drupal"),
                ("Set-Cookie", r"PHPSESSID", "PHP"),
                ("Set-Cookie", r"JSESSIONID", "Java/Servlet"),
                ("Set-Cookie", r"csrftoken", "Django"),
            ],
            "meta": [
                ("generator", r"WordPress\s?([\d\.]+)?", "WordPress"),
                ("generator", r"Joomla!?", "Joomla"),
                ("viewport", r".*", "Responsive Design", False) # Just a flag
            ],
            "script": [
                (r"jquery[.-]([\d\.]+\d).*\.js", "jQuery"),
                (r"uikit[.-]([\d\.]+\d).*\.js", "UIkit"),
                (r"bootstrap[.-]([\d\.]+\d).*\.js", "Bootstrap"),
                (r"react", "React"),
                (r"vue", "Vue.js")
            ]
        }

    async def run(self, target: Target) -> dict:
        urls = []
        if target.url:
            urls.append(target.url)
        elif target.host:
            urls.append(f"http://{target.host}")
            urls.append(f"https://{target.host}")
        
        results = {}
        async with aiohttp.ClientSession() as session:
            for url in urls:
                try:
                    techs = await self._analyze_url(session, url)
                    if techs:
                         results[url] = techs
                except Exception:
                    pass
        
        return results

    async def _analyze_url(self, session, url) -> List[Dict[str, str]]:
        headers = {'User-Agent': self.config.user_agent}
        try:
            async with session.get(url, timeout=self.config.timeout, headers=headers, ssl=False) as response:
                text = await response.text()
                headers = response.headers
                
                detected = []
                
                # 1. Analyze Headers
                for key, pattern, name in self.signatures["headers"]:
                    val = headers.get(key)
                    if val:
                        match = re.search(pattern, val, re.IGNORECASE)
                        if match:
                             version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                             detected.append({"name": name, "version": version, "source": f"Header: {key}"})

                # 2. Analyze Server Header specifically
                srv = headers.get("Server", "")
                for pattern, name in self.signatures["server"]:
                     match = re.search(pattern, srv, re.IGNORECASE)
                     if match:
                         version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                         detected.append({"name": name, "version": version, "source": "Header: Server"})

                # 3. Analyze Body (Meta tags & Scripts)
                # Naive regex parsing to avoid heavy BS4 if not needed, or use regex on full text
                # Parsing meta tags
                for meta_name, pattern, name, *opt in self.signatures["meta"]:
                     # Find <meta name="..." content="...">
                     # This regex is a bit complex to handle all HTML variations, simplified for POC
                     meta_regex = re.compile(rf'<meta\s+(?:name|property)=["\']{meta_name}["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE)
                     match = meta_regex.search(text)
                     if match:
                         content = match.group(1)
                         ver_match = re.search(pattern, content, re.IGNORECASE)
                         if ver_match:
                             version = ver_match.group(1) if ver_match.lastindex and ver_match.lastindex >= 1 else None
                             detected.append({"name": name, "version": version, "source": f"Meta: {meta_name}"})
                
                # 4. Analyze Scripts (src)
                # Find <script src="...">
                script_regex = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
                scripts = script_regex.findall(text)
                for src in scripts:
                    for pattern, name in self.signatures["script"]:
                        match = re.search(pattern, src, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                            # Deduplicate simple names slightly if needed
                            if not any(d['name'] == name for d in detected):
                                detected.append({"name": name, "version": version, "source": "Script"})

                return detected
        except Exception:
            return []
