from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import json
import csv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.json import JSON
from rich import print as rprint

class OutputHandler:
    def __init__(self, console: Console):
        self.console = console

    def handle(self, results: Dict[str, Any], output_format: str, file_path: Optional[str] = None):
        """
        Main entry point for handling output.
        Displays to console and optionally saves to file.
        """
        # 1. Console Output
        if output_format == "json":
            self._print_json(results)
        else:
            self._print_table(results)

        # 2. File Output
        if file_path:
            self._save_to_file(results, file_path, output_format)

    def _print_json(self, results: Dict[str, Any]):
        json_output = json.dumps(results, indent=2)
        rprint(JSON(json_output))

    def _print_table(self, results: Dict[str, Any]):
        # Registry of renderers for specific modules
        renderers = {
            "DNS Scanner": self._render_dns,
            "SSL Scanner": self._render_ssl,
            "Whois Scanner": self._render_whois,
            "Port Scanner": self._render_ports,
            "HTTP Scanner": self._render_http,
            "Subdomain Scanner": self._render_subdomains,
            "Tech Fingerprinter": self._render_tech,
            "Dir Enumerator": self._render_dir,
            "Web Crawler": self._render_crawler,
            "Traceroute Scanner": self._render_trace,
            "Zone Transfer Scanner": self._render_axfr,
            "Vuln Scanner": self._render_vuln,
            "JS Secret Scanner": self._render_js_secrets,
            "Security Headers": self._render_security_headers,
            "WAF Detection": self._render_waf,
            "Subdomain Takeover": self._render_takeover,
            "Sensitive File Fuzzer": self._render_file_fuzzer,
            "Email Harvester": self._render_email,
            "Wayback Machine Scanner": self._render_wayback,
            "CRT.sh Scanner": self._render_crtsh,
            "Robots & Sitemap Scanner": self._render_robots,
            "Cloud Asset Enumerator": self._render_cloud,
            "CORS Scanner": self._render_cors,
            "API Scanner": self._render_api,
            "Screenshot Capture": self._render_screenshots,
        }

        for host, data in results.items(): 
            # Display host info
            t_info = data.get("target", {})
            scans = data.get("scans", {})
            
            self.console.print(Panel(f"[bold]Results for {host}[/bold] ({t_info.get('type', 'unknown')})", expand=False))

            for module_name, scan_data in scans.items():
                if module_name in renderers:
                    renderers[module_name](scan_data)
                else:
                    self._render_generic(module_name, scan_data)
            
            self.console.print("")

    def _render_generic(self, title: str, data: Any):
        if isinstance(data, dict) and "error" in data:
             self.console.print(f"[red]{title} Error: {data['error']}[/red]")
             return

        table = Table(title=title, show_header=True)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        
        if isinstance(data, dict):
            for k, v in data.items():
                table.add_row(str(k), str(v))
            self.console.print(table)
        elif isinstance(data, list):
            self.console.print(f"[bold]{title}[/bold]: {data}")
        else:
            self.console.print(f"[bold]{title}[/bold]: {data}")

    def _render_dns(self, data: Dict[str, Any]):
        if not data: return
        table = Table(title="DNS Records", show_header=True)
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="magenta")
        
        found = False
        for k, v in data.items():
            if isinstance(v, list):
                for item in v:
                    table.add_row(k, item)
                    found = True
            else:
                table.add_row(k, str(v))
                found = True
        if found:
            self.console.print(table)

    def _render_ssl(self, data: Dict[str, Any]):
        if "error" in data:
             self.console.print(f"[red]SSL Scan Error: {data['error']}[/red]")
             return
        if not data: return

        table = Table(title="SSL Certificate", show_header=True)
        table.add_column("Field", style="yellow")
        table.add_column("Value", style="white")
        
        table.add_row("Subject", data.get("subject", "N/A"))
        table.add_row("Issuer", data.get("issuer", "N/A"))
        table.add_row("Valid From", data.get("valid_from", "N/A"))
        table.add_row("Valid To", data.get("valid_to", "N/A"))
        
        sans = data.get("sans", [])
        if sans:
            san_str = ", ".join(sans[:5]) + (f" (+{len(sans)-5} more)" if len(sans) > 5 else "")
            table.add_row("SANs", san_str)
            
        self.console.print(table)

    def _render_whois(self, data: Dict[str, Any]):
        if "error" in data:
             self.console.print(f"[red]WHOIS Scan Error: {data['error']}[/red]")
             return
        if not data: return

        table = Table(title="WHOIS / ASN Info", show_header=True)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("IP Address", str(data.get("query", "N/A")))
        table.add_row("ASN", str(data.get("asn", "N/A")))
        table.add_row("ASN Desc", str(data.get("asn_description", "N/A")))
        table.add_row("Country", str(data.get("asn_country_code", "N/A")))
        
        network = data.get("network", {})
        if network:
             table.add_row("Network Name", str(network.get("name", "N/A")))
             table.add_row("CIDR", str(network.get("cidr", "N/A")))

        self.console.print(table)

    def _render_ports(self, data: Dict[str, Any]):
        open_ports = data.get("open_ports", [])
        details = data.get("details", [])
        
        if open_ports:
            table = Table(title=f"Open Ports (Scanned {data.get('scanned_count')} ports)", show_header=True)
            table.add_column("Port", style="green")
            table.add_column("State", style="bold green")
            table.add_column("Service/Banner", style="dim white")
            
            banner_map = {d['port']: d.get('banner') for d in details}
            
            for p in open_ports:
                banner = banner_map.get(p)
                banner_str = banner[:50] + "..." if banner and len(banner) > 50 else banner
                table.add_row(str(p), "OPEN", banner_str if banner_str else "")
                
            self.console.print(table)
        else:
            self.console.print("[yellow]No open ports found (in scanned range).[/yellow]")

    def _render_subdomains(self, data: Dict[str, Any]):
        if "error" in data:
             self.console.print(f"[red]Subdomain Scan Error: {data['error']}[/red]")
             return
        
        subdomains = data.get("subdomains", [])
        count = data.get("count", 0)
        
        if not subdomains:
            self.console.print("[yellow]No subdomains found.[/yellow]")
            return

        # Use a Grid or simple Table for list
        table = Table(title=f"Subdomains Found ({count})", show_header=True)
        table.add_column("Domain", style="cyan")
        
        # If there are too many, we might want to paginate or columnize better, 
        # but for now a simple list is fine.
        # Let's show up to 20, then summarize if huge
        limit = 20
        for sub in subdomains[:limit]:
            table.add_row(sub)
            
        if count > limit:
            table.add_row(f"... and {count - limit} more")

        self.console.print(table)


    def _render_tech(self, data: Dict[str, Any]):
        if not data: return
        
        # Data structure is {url: [ {name, version, source}, ... ]}
        
        for url, techs in data.items():
            if not techs: continue
            
            table = Table(title=f"Technologies Detected at {url}", show_header=True)
            table.add_column("Technology", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Source", style="dim")
            
            for t in techs:
                ver = t.get("version")
                table.add_row(
                    t.get("name", "Unknown"), 
                    ver if ver else "", 
                    t.get("source", "")
                )
            self.console.print(table)


    def _render_http(self, data: Dict[str, Any]):
        if not data: return
        table = Table(title="HTTP Info", show_header=True)
        table.add_column("URL", style="blue")
        table.add_column("Status", style="bold")
        table.add_column("Title", style="white")
        table.add_column("Server", style="dim")
        
        for url, info in data.items():
            if "error" in info:
                 table.add_row(url, "[red]Error[/red]", info['error'], "")
            else:
                status_str = f"[green]{info['status']}[/green]" if info['status'] < 400 else f"[red]{info['status']}[/red]"
                table.add_row(url, status_str, info.get('title', ''), info.get('server', ''))
        self.console.print(table)


    def _render_dir(self, data: Dict[str, Any]):
        if not data: return
        
        for base, paths in data.items():
            if not paths: continue
            
            table = Table(title=f"Paths Found on {base}", show_header=True)
            table.add_column("Path", style="blue")
            table.add_column("Status", style="bold")
            table.add_column("Length", style="dim")
            
            for p in paths:
                url = p.get("url", "")
                # Show just the path part to save space, or full URL? Full URL is clearer.
                # Let's show relative path if it starts with base
                display_path = url.replace(base, "") if url.startswith(base) else url
                
                status = p.get("status")
                s_style = "green" if status and status < 400 else "yellow" if status < 500 else "red"
                
                table.add_row(display_path, f"[{s_style}]{status}[/{s_style}]", str(p.get("length")))
                
            self.console.print(table)

    def _render_crawler(self, data: Dict[str, Any]):
        if not data: return
        
        stats = data.get("stats", {})
        s_map = data.get("map", {})
        
        # Summary Panel
        self.console.print(Panel(
            f"[bold cyan]Crawl Summary[/bold cyan]\n"
            f"Pages Visited: [green]{stats.get('visited_count', 0)}[/green]\n"
            f"Total Internal Links: [green]{stats.get('total_links_found', 0)}[/green]",
            expand=False
        ))
        
        if not s_map: return

        # Detailed Table
        table = Table(title="Crawled Map (Top 25)", show_header=True)
        table.add_column("Page URL", style="blue")
        table.add_column("Status", style="bold")
        table.add_column("Title", style="white")
        table.add_column("Links Found", style="dim")
        
        # Sort by URL length (often implies depth) or just alpha
        sorted_pages = sorted(s_map.items(), key=lambda x: x[0])
        
        shown_count = 0
        limit = 25
        
        for url, info in sorted_pages:
            if shown_count >= limit:
                break
                
            status = info.get("status")
            s_style = "green" if status == 200 else "red"
            
            table.add_row(
                url, 
                f"[{s_style}]{status}[/{s_style}]", 
                info.get("title", "")[:30], 
                str(info.get("links_count", 0))
            )
            shown_count += 1
            
        if len(s_map) > limit:
            table.add_row(f"... and {len(s_map) - limit} more pages", "", "", "")
            
        self.console.print(table)

    def _render_trace(self, data: Dict[str, Any]):
        hops = data.get("hops", [])
        if not hops:
            if "error" in data:
                 self.console.print(f"[red]Traceroute Error: {data['error']}[/red]")
            return

        table = Table(title=f"Traceroute Path ({len(hops)} Hops)", show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("IP / Host", style="cyan")
        table.add_column("Latency", style="green")
        
        for hop in hops:
            table.add_row(
                str(hop.get("hop")), 
                hop.get("ip"), 
                hop.get("rtt")
            )
        self.console.print(table)

    def _render_axfr(self, data: Dict[str, Any]):
        if "error" in data:
            # Silence simple errors or show them? Usually AXFR fails is good news.
            # self.console.print(f"[dim]Zone Transfer: {data['error']}[/dim]")
            return

        is_vuln = data.get("vulnerable", False)
        ns_tested = data.get("nameservers_tested", [])
        
        title = "Zone Transfer (AXFR)"
        if is_vuln:
            self.console.print(Panel(
                f"[bold red]VULNERABLE: Zone Transfer Successful![/bold red]\n"
                f"Nameservers Tested: {len(ns_tested)}",
                title=title, border_style="red"
            ))
            records = data.get("records", [])
            if records:
                table = Table(title="Leaked Records (Preview)", show_header=True)
                table.add_column("Record", style="yellow")
                for r in records[:10]:
                    table.add_row(r)
                if len(records) > 10:
                    table.add_row(f"... {len(records)-10} more records")
                self.console.print(table)
        else:
             self.console.print(f"[green]{title}: Secure (Tested {len(ns_tested)} NS)[/green]")

    def _render_vuln(self, data: Dict[str, Any]):
        if not data: return
        
        # data key = "Apache 2.4.49", value = [list of cves]
        
        for software, cves in data.items():
            if not cves: continue
            
            table = Table(title=f"Vulnerabilities for {software}", show_header=True)
            table.add_column("CVE ID", style="bold red")
            table.add_column("CVSS", style="yellow")
            table.add_column("Summary", style="white")
            
            for cve in cves:
                cvss = cve.get("cvss")
                # Color code CVSS
                c_style = "white"
                try:
                    score = float(cvss)
                    if score >= 9.0: c_style = "bold red"
                    elif score >= 7.0: c_style = "red"
                    elif score >= 4.0: c_style = "yellow"
                    else: c_style = "green"
                except: pass
                
                table.add_row(
                    cve.get("id"), 
                    f"[{c_style}]{cvss}[/{c_style}]", 
                    cve.get("summary")
                )
            self.console.print(table)


    def _render_js_secrets(self, data: Dict[str, Any]):
        secrets = data.get("secrets", [])
        if not secrets:
            scanned = data.get("scanned_files", 0)
            if scanned > 0:
                self.console.print(f"[green]JS Secrets: Scanned {scanned} files, no secrets found.[/green]")
            return

        table = Table(title=f"JS Secrets Found ({len(secrets)})", show_header=True)
        table.add_column("Type", style="bold red")
        table.add_column("Value", style="yellow")
        table.add_column("Source", style="dim blue")
        
        for s in secrets:
            table.add_row(s["type"], s["value"], s["source"])
        
        self.console.print(table)

    def _render_security_headers(self, data: Dict[str, Any]):
        if not data: return
        
        score = data.get("score", 0)
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        
        self.console.print(Panel(
            f"Security Score: [{color}]{score}/100[/{color}]",
            title="Security Headers", border_style=color, expand=False
        ))
        
        missing = data.get("missing", [])
        if missing:
            table = Table(title="Missing Security Headers", show_header=True)
            table.add_column("Header", style="red")
            table.add_column("Risk", style="bold")
            for m in missing:
                table.add_row(m["header"], m["risk"])
            self.console.print(table)

    def _render_waf(self, data: Dict[str, Any]):
        if not data: return
        if "error" in data:
            self.console.print(f"[red]WAF Detection Error: {data['error']}[/red]")
            return
            
        if data.get("detected"):
            wafs = ", ".join(data.get("wafs", []))
            confidence = data.get("confidence", 0)
            methods = data.get("detection_methods", [])
            
            # Color code confidence
            conf_color = "green" if confidence >= 70 else "yellow" if confidence >= 40 else "red"
            
            # Build panel content
            content_lines = [
                f"[bold red]WAF(s) Detected: {wafs}[/bold red]",
                f"Confidence: [{conf_color}]{confidence}%[/{conf_color}]",
                f"Detection Methods: {', '.join(methods)}" if methods else "",
            ]
            
            # Add block behavior if present
            block = data.get("block_behavior")
            if block:
                content_lines.append(
                    f"\nBlock Behavior: [yellow]{block.get('trigger')}[/yellow] → "
                    f"HTTP {block.get('status_code')} ({block.get('block_type')})"
                )
            
            self.console.print(Panel(
                "\n".join(line for line in content_lines if line),
                title="WAF Detection",
                border_style="red",
                expand=False
            ))
            
            # Show bypass hints in a separate table
            hints = data.get("bypass_hints", [])
            if hints:
                table = Table(title="Potential Bypass Techniques", show_header=False)
                table.add_column("Hint", style="dim cyan")
                for hint in hints[:5]:  # Limit to 5 hints
                    table.add_row(f"• {hint}")
                self.console.print(table)
            
            # Show evasion results if available
            evasion_results = data.get("evasion_results", [])
            if evasion_results:
                table = Table(title="Evasion Testing Results", show_header=True)
                table.add_column("Technique", style="cyan")
                table.add_column("Type", style="dim")
                table.add_column("Result", style="bold")
                table.add_column("Status", style="dim")
                
                for result in evasion_results:
                    bypassed = result.get("bypassed", False)
                    result_style = "[green]BYPASSED[/green]" if bypassed else "[red]BLOCKED[/red]"
                    status = str(result.get("status_code", result.get("error", "N/A")))
                    table.add_row(
                        result.get("technique", ""),
                        result.get("type", ""),
                        result_style,
                        status
                    )
                self.console.print(table)
        else:
            self.console.print("[green]WAF Detection: No WAF detected[/green]")

    def _render_takeover(self, data: Dict[str, Any]):
        if data.get("vulnerable"):
            self.console.print(Panel(
                f"[bold red]Subdomain Takeover Vulnerability![/bold red]\n"
                f"Provider: {data.get('provider')}\n"
                f"CNAME: {data.get('cname')}",
                border_style="red", expand=False
            ))

    def _render_file_fuzzer(self, data: Dict[str, Any]):
        found = data.get("found", [])
        if not found: return
        
        table = Table(title="Sensitive Files Found", show_header=True)
        table.add_column("URL", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Size", style="dim")
        
        for f in found:
            table.add_row(f["url"], str(f["status"]), str(f["size"]))
        self.console.print(table)

    def _render_email(self, data: Dict[str, Any]):
        emails = data.get("emails", [])
        if not emails: return
        
        table = Table(title=f"Emails Found ({len(emails)})", show_header=True)
        table.add_column("Email", style="green")
        table.add_column("Source", style="dim")
        
        for e in emails[:20]:
            table.add_row(e["email"], e["source"])
        if len(emails) > 20:
            table.add_row(f"... {len(emails)-20} more", "")
        self.console.print(table)

    def _render_wayback(self, data: Dict[str, Any]):
        urls = data.get("urls", [])
        params = data.get("interesting_params", [])
        total = data.get("total_found", 0)
        
        self.console.print(Panel(
            f"Wayback Machine Results\n"
            f"Total URLs Found: {total}\n"
            f"Unique Params: {', '.join(params[:10])}",
            title="Archive.org Scan", border_style="cyan", expand=False
        ))
        
        if urls:
            table = Table(title="Historical URLs (Preview)", show_header=True)
            table.add_column("URL", style="dim")
            for u in urls[:15]:
                table.add_row(u)
            if len(urls) > 15:
                table.add_row(f"... {len(urls)-15} more")
            self.console.print(table)

    def _render_crtsh(self, data: Dict[str, Any]):
        subs = data.get("subdomains", [])
        if not subs: return
        
        table = Table(title=f"CRT.sh Subdomains ({len(subs)})", show_header=False)
        table.add_column("Domain")
        for s in subs[:20]:
            table.add_row(s)
        if len(subs) > 20: 
            table.add_row(f"... {len(subs)-20} more")
        self.console.print(table)

    def _render_robots(self, data: Dict[str, Any]):
        if not data: return
        
        title = "Robots & Sitemap"
        info = []
        if data.get("robots_found"):
            info.append("[green]robots.txt found[/green]")
            dis = data.get("disallowed_paths", [])
            if dis:
                info.append(f"Disallowed: {len(dis)} paths")
        else:
            info.append("[yellow]robots.txt missing[/yellow]")
            
        if data.get("sitemap_found"):
            info.append(f"[green]sitemap.xml found ({data.get('sitemap_count')} URLs)[/green]")
        
        self.console.print(Panel("\n".join(info), title=title, expand=False))
        
        # Optionally show disallowed
        dis = data.get("disallowed_paths", [])
        if dis:
             t = Table(title="Disallowed Paths", show_header=False)
             t.add_column("Path")
             for p in dis[:10]:
                 t.add_row(p)
             if len(dis) > 10: t.add_row("...")
             self.console.print(t)

    def _render_cloud(self, data: Dict[str, Any]):
        buckets = data.get("aws_buckets", [])
        if not buckets: return
        
        table = Table(title="Cloud Buckets Found", show_header=True)
        table.add_column("Name", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("URL", style="dim")
        
        for b in buckets:
            bs = b.get("status")
            style = "green" if "200" in bs else "yellow"
            table.add_row(b["name"], f"[{style}]{bs}[/{style}]", b["url"])
        self.console.print(table)

    def _render_cors(self, data: Dict[str, Any]):
        if not data: return
        if "error" in data:
            self.console.print(f"[red]CORS Scanner Error: {data['error']}[/red]")
            return
        
        if data.get("vulnerable"):
            vulns = data.get("vulnerabilities", [])
            
            # Summary panel
            critical = len([v for v in vulns if v.get("severity") == "critical"])
            high = len([v for v in vulns if v.get("severity") == "high"])
            
            self.console.print(Panel(
                f"[bold red]CORS Misconfiguration Found![/bold red]\n"
                f"Critical: [red]{critical}[/red] | High: [yellow]{high}[/yellow] | Total: {len(vulns)}",
                title="CORS Scanner",
                border_style="red",
                expand=False
            ))
            
            # Vulnerabilities table
            if vulns:
                table = Table(title="CORS Vulnerabilities", show_header=True)
                table.add_column("Type", style="red")
                table.add_column("Origin Tested", style="cyan")
                table.add_column("Severity", style="bold")
                table.add_column("Credentials", style="dim")
                
                for v in vulns[:10]:
                    sev = v.get("severity", "")
                    sev_style = "red" if sev == "critical" else "yellow" if sev == "high" else "dim"
                    creds = "✓ Yes" if v.get("credentials_allowed") else "No"
                    table.add_row(
                        v.get("type", ""),
                        v.get("origin_sent", "")[:40],
                        f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                        creds
                    )
                
                if len(vulns) > 10:
                    table.add_row(f"... and {len(vulns) - 10} more", "", "", "")
                
                self.console.print(table)
            
            # Recommendations
            recs = data.get("recommendations", [])
            if recs:
                table = Table(title="Recommendations", show_header=False)
                table.add_column("Priority", style="bold", width=10)
                table.add_column("Recommendation", style="dim")
                for r in recs[:5]:
                    p = r.get("priority", "")
                    p_style = "red" if p == "critical" else "yellow" if p == "high" else "cyan"
                    table.add_row(f"[{p_style}]{p.upper()}[/{p_style}]", r.get("recommendation", ""))
                self.console.print(table)
        else:
            self.console.print("[green]CORS Scanner: No vulnerabilities found[/green]")

    def _render_api(self, data: Dict[str, Any]):
        if not data: return
        if "error" in data:
            self.console.print(f"[red]API Scanner Error: {data['error']}[/red]")
            return
        
        endpoints = data.get("discovered_endpoints", [])
        api_docs = data.get("api_documentation", {})
        issues = data.get("security_issues", [])
        graphql = data.get("graphql")
        
        # Summary panel
        auth_required = len([e for e in endpoints if e.get("auth_required")])
        public = len(endpoints) - auth_required
        
        summary_lines = [
            f"Endpoints Found: [green]{len(endpoints)}[/green] (Public: {public}, Auth Required: {auth_required})",
        ]
        
        if api_docs and api_docs.get("found"):
            summary_lines.append(f"API Docs: [green]{api_docs.get('type', 'OpenAPI')} {api_docs.get('version', '')}[/green]")
        
        if issues:
            summary_lines.append(f"Security Issues: [red]{len(issues)}[/red]")
        
        if graphql and graphql.get("found"):
            intro = "[red]Introspection Enabled![/red]" if graphql.get("introspection_enabled") else "[green]Introspection Disabled[/green]"
            summary_lines.append(f"GraphQL: {intro}")
        
        self.console.print(Panel(
            "\n".join(summary_lines),
            title="API Scanner",
            border_style="cyan",
            expand=False
        ))
        
        # Endpoints table
        if endpoints:
            table = Table(title=f"Discovered Endpoints ({len(endpoints)})", show_header=True)
            table.add_column("Path", style="cyan")
            table.add_column("Status", style="bold")
            table.add_column("Content-Type", style="dim")
            table.add_column("Auth", style="yellow")
            
            for e in endpoints[:15]:
                status = e.get("status", 0)
                s_style = "green" if status == 200 else "yellow" if status in (401, 403) else "red"
                auth = "Required" if e.get("auth_required") else ""
                table.add_row(
                    e.get("path", ""),
                    f"[{s_style}]{status}[/{s_style}]",
                    e.get("content_type", "")[:30],
                    auth
                )
            
            if len(endpoints) > 15:
                table.add_row(f"... and {len(endpoints) - 15} more", "", "", "")
            
            self.console.print(table)
        
        # Security issues
        if issues:
            table = Table(title="Security Issues", show_header=True)
            table.add_column("Type", style="red")
            table.add_column("Path", style="cyan")
            table.add_column("Severity", style="bold")
            table.add_column("Description", style="dim")
            
            for issue in issues[:10]:
                sev = issue.get("severity", "")
                sev_style = "red" if sev == "high" else "yellow" if sev == "medium" else "dim"
                table.add_row(
                    issue.get("type", ""),
                    issue.get("path", "N/A"),
                    f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                    issue.get("description", "")[:50]
                )
            
            self.console.print(table)
        
        # Technologies
        techs = data.get("technologies", [])
        if techs:
            tech_names = ", ".join([t["name"] for t in techs[:5]])
            self.console.print(f"[dim]Technologies: {tech_names}[/dim]")

    def _save_to_file(self, results: Dict[str, Any], file_path: str, output_format: str):
        # Determine format from file extension if possible, else use output_format or default to json
        if file_path.endswith(".json") or (output_format == "json" and not file_path.endswith((".",))):
            self._write_json(results, file_path)
            
        elif file_path.endswith(".md"):
            self._write_md(results, file_path)
            
        elif file_path.endswith(".html"):
            self._write_html(results, file_path)
            
        elif file_path.endswith(".csv"):
            self._write_csv(results, file_path)
            
        else:
             # Default to JSON
             self._write_json(results, file_path)
             
        self.console.print(f"[blue]Results saved to {file_path}[/blue]")

    def _write_json(self, results: Dict[str, Any], file_path: str):
         with open(file_path, "w") as f:
             json.dump(results, f, indent=2)

    def _write_md(self, results: Dict[str, Any], file_path: str):
        with open(file_path, "w") as f:
            f.write(f"# MyNet Scan Results\n\n")
            for host, data in results.items():
                f.write(f"## {host} ({data.get('target', {}).get('type', 'unknown')})\n\n")
                scans = data.get("scans", {})
                
                # We can reuse similar logic or keep simple MD generation here. 
                # For now, let's keep it somewhat manual but structured.
                if "DNS Scanner" in scans:
                        f.write("### DNS\n")
                        f.write("| Type | Value |\n|---|---|\n")
                        for k, v in scans["DNS Scanner"].items():
                            if isinstance(v, list):
                                for i in v: f.write(f"| {k} | {i} |\n")
                            else:
                                f.write(f"| {k} | {v} |\n")
                        f.write("\n")
                if "Port Scanner" in scans:
                    ports = scans["Port Scanner"].get("open_ports", [])
                    f.write(f"### Ports\nOpen: {', '.join(map(str, ports))}\n\n")
                if "HTTP Scanner" in scans:
                    f.write("### HTTP\n")
                    for url, info in scans["HTTP Scanner"].items():
                        f.write(f"- **{url}**: {info.get('status', 'Err')} - {info.get('title', '')}\n")
                    f.write("\n")
                
                # Add generic dump for others if needed
                # (Optional optimization: iterate scans and dump others)

    def _write_html(self, results: Dict[str, Any], file_path: str):
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MyNet Scan Results</title>
            <style>
                :root { --bg: #0f172a; --card-bg: #1e293b; --text: #f8fafc; --text-muted: #94a3b8; --accent: #38bdf8; --border: #334155; --success: #22c55e; --error: #ef4444; }
                body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.5; }
                h1, h2, h3 { color: var(--text); }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
                .report-date { color: var(--text-muted); font-size: 0.9em; }
                .target-card { background: var(--card-bg); border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid var(--border); }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
                .module-section { background: var(--card-bg); border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid var(--border); }
                .module-title { font-size: 1.25em; font-weight: 600; margin-bottom: 15px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 10px; }
                table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
                th { text-align: left; padding: 10px; background: rgba(255,255,255,0.05); color: var(--text-muted); font-weight: 600; }
                td { padding: 10px; border-bottom: 1px solid var(--border); }
                tr:last-child td { border-bottom: none; }
                .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 500; }
                .badge-green { background: rgba(34, 197, 94, 0.2); color: var(--success); }
                .badge-red { background: rgba(239, 68, 68, 0.2); color: var(--error); }
                .badge-blue { background: rgba(56, 189, 248, 0.2); color: var(--accent); }
                .scroll-table { overflow-x: auto; max-height: 400px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div>
                        <h1>MyNet Scan Report</h1>
                        <div class="report-date">Generated via MyNet Scanner</div>
                    </div>
                </div>
        """
        
        for host, data in results.items():
            t_info = data.get("target", {})
            scans = data.get("scans", {})
            
            html_content += f"""
            <div class="target-card">
                <h2>Target: <span style="color:var(--accent)">{host}</span></h2>
                <div style="color:var(--text-muted)">Type: {t_info.get('type', 'unknown')}</div>
            </div>
            """
            
            # 1. High Level Grid (Ports, Tech, Subdomain snapshot)
            html_content += '<div class="grid">'
            
            # Ports Summary
            if "Port Scanner" in scans:
                ports = scans["Port Scanner"].get("open_ports", [])
                html_content += f"""
                <div class="module-section" style="margin-bottom:0">
                    <div class="module-title">Ports</div>
                    <div style="font-size:2em; font-weight:bold; color:var(--success)">{len(ports)}</div>
                    <div style="color:var(--text-muted)">Open Ports Found</div>
                </div>
                """
            
            # Subdomain Summary
            if "Subdomain Scanner" in scans:
                count = scans["Subdomain Scanner"].get("count", 0)
                html_content += f"""
                <div class="module-section" style="margin-bottom:0">
                    <div class="module-title">Subdomains</div>
                    <div style="font-size:2em; font-weight:bold; color:var(--accent)">{count}</div>
                    <div style="color:var(--text-muted)">Subdomains Identified</div>
                </div>
                """
            
            # Tech Summary (Count unique tech names)
            tech_count = 0
            if "Tech Fingerprinter" in scans:
                unique_tech = set()
                for t_list in scans["Tech Fingerprinter"].values():
                    for t in t_list: unique_tech.add(t.get("name"))
                tech_count = len(unique_tech)
                html_content += f"""
                <div class="module-section" style="margin-bottom:0">
                    <div class="module-title">Technologies</div>
                    <div style="font-size:2em; font-weight:bold; color:#f472b6">{tech_count}</div>
                    <div style="color:var(--text-muted)">Unique Technologies Detected</div>
                </div>
                """
            
            html_content += '</div>' # End Grid

            # Detailed Sections
            
            # Tech
            if "Tech Fingerprinter" in scans and scans["Tech Fingerprinter"]:
                html_content += '<div class="module-section"><div class="module-title">Technology Stack</div><div class="scroll-table"><table><thead><tr><th>Endpoint</th><th>Technology</th><th>Version</th><th>Source</th></tr></thead><tbody>'
                for url, techs in scans["Tech Fingerprinter"].items():
                    for t in techs:
                        html_content += f"<tr><td>{url}</td><td>{t.get('name','')}</td><td>{t.get('version') or ''}</td><td>{t.get('source','')}</td></tr>"
                html_content += '</tbody></table></div></div>'

            # Ports Details
            if "Port Scanner" in scans:
                 p_res = scans["Port Scanner"]
                 details = {d['port']: d.get('banner') for d in p_res.get("details", [])}
                 open_ports = p_res.get("open_ports", [])
                 if open_ports:
                    html_content += '<div class="module-section"><div class="module-title">Open Ports</div><div class="scroll-table"><table><thead><tr><th>Port</th><th>State</th><th>Service Banner</th></tr></thead><tbody>'
                    for p in open_ports:
                        banner = details.get(p)
                        banner_str = (banner[:60] + "...") if banner and len(banner) > 60 else (banner or "")
                        html_content += f"<tr><td>{p}</td><td><span class='badge badge-green'>OPEN</span></td><td style='font-family:monospace; font-size:0.85em'>{banner_str}</td></tr>"
                    html_content += '</tbody></table></div></div>'

            # Subdomains
            if "Subdomain Scanner" in scans:
                subs = scans["Subdomain Scanner"].get("subdomains", [])
                if subs:
                    html_content += f'<div class="module-section"><div class="module-title">Subdomains Found</div><div class="scroll-table" style="max-height:300px"><table><tbody>'
                    # Split into columns could be nice but simple list is fine
                    for sub in subs:
                        html_content += f"<tr><td>{sub}</td></tr>"
                    html_content += '</tbody></table></div></div>'

            # Directory Enum
            if "Dir Enumerator" in scans and scans["Dir Enumerator"]:
                html_content += '<div class="module-section"><div class="module-title">Directory Discovered</div><div class="scroll-table"><table><thead><tr><th>Endpoint</th><th>Status</th><th>Size</th></tr></thead><tbody>'
                for base, paths in scans["Dir Enumerator"].items():
                    for p in paths:
                        status = p.get('status')
                        badge = "badge-green" if status < 400 else "badge-red"
                        html_content += f"<tr><td>{p.get('url')}</td><td><span class='badge {badge}'>{status}</span></td><td>{p.get('length')}</td></tr>"
                html_content += '</tbody></table></div></div>'

            # Crawler
            if "Web Crawler" in scans:
                c_map = scans["Web Crawler"].get("map", {})
                if c_map:
                    html_content += '<div class="module-section"><div class="module-title">Web Crawler Map</div><div class="scroll-table"><table><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Internal Links</th></tr></thead><tbody>'
                    # Limit to top 100 for HTML report sake
                    sorted_pages = sorted(c_map.items(), key=lambda x: x[0])[:100]
                    for url, info in sorted_pages:
                         status = info.get('status')
                         badge = "badge-green" if status == 200 else "badge-red"
                         html_content += f"<tr><td>{url}</td><td><span class='badge {badge}'>{status}</span></td><td>{info.get('title','')}</td><td>{info.get('links_count')}</td></tr>"
                    html_content += '</tbody></table></div></div>'

            # DNS & Whois Grid
            html_content += '<div class="grid">'
            
            if "DNS Scanner" in scans:
                html_content += '<div class="module-section"><div class="module-title">DNS Records</div><div class="scroll-table"><table><tbody>'
                for k, v in scans["DNS Scanner"].items():
                    val_str = "<br>".join(v) if isinstance(v, list) else str(v)
                    html_content += f"<tr><td style='width:50px; font-weight:bold'>{k}</td><td>{val_str}</td></tr>"
                html_content += '</tbody></table></div></div>'
            
            if "Whois Scanner" in scans:
                 w = scans["Whois Scanner"]
                 html_content += '<div class="module-section"><div class="module-title">Whois Info</div><table><tbody>'
                 if "error" not in w:
                     html_content += f"<tr><td>ASN</td><td>{w.get('asn')} ({w.get('asn_description')})</td></tr>"
                     html_content += f"<tr><td>CIDR</td><td>{w.get('network', {}).get('cidr')}</td></tr>"
                     html_content += f"<tr><td>Country</td><td>{w.get('asn_country_code')}</td></tr>"
                 html_content += '</tbody></table></div></div>'

            html_content += '</div>' # End lower grid

            # New Modules HTML Support
            
            # WAF
            if "WAF Detection" in scans:
                waf_data = scans["WAF Detection"]
                if waf_data.get("detected"):
                    wafs = ", ".join(waf_data.get("wafs", []))
                    confidence = waf_data.get("confidence", 0)
                    methods = ", ".join(waf_data.get("detection_methods", []))
                    conf_color = "var(--success)" if confidence >= 70 else "var(--accent)" if confidence >= 40 else "var(--error)"
                    
                    html_content += f'''<div class="module-section" style="border-left: 5px solid var(--error);">
                        <div class="module-title" style="color:var(--error)">WAF Detected</div>
                        <div style="display:flex; gap:30px; align-items:center; margin-bottom:15px">
                            <div><b style="font-size:1.3em">{wafs}</b><br><span style="color:var(--text-muted)">Detected WAF(s)</span></div>
                            <div><span style="font-size:2em; font-weight:bold; color:{conf_color}">{confidence}%</span><br><span style="color:var(--text-muted)">Confidence</span></div>
                        </div>
                        <div style="color:var(--text-muted); margin-bottom:10px">Detection Methods: {methods}</div>'''
                    
                    # Block behavior
                    block = waf_data.get("block_behavior")
                    if block:
                        html_content += f'''<div style="background:rgba(239,68,68,0.1); padding:10px; border-radius:4px; margin-bottom:10px">
                            <b>Block Triggered:</b> {block.get("trigger")} → HTTP {block.get("status_code")} ({block.get("block_type")})
                        </div>'''
                    
                    # Bypass hints
                    hints = waf_data.get("bypass_hints", [])
                    if hints:
                        html_content += '<div style="margin-top:10px"><b>Potential Bypass Techniques:</b><ul style="margin:5px 0; padding-left:20px">'
                        for hint in hints[:5]:
                            html_content += f'<li style="color:var(--text-muted)">{hint}</li>'
                        html_content += '</ul></div>'
                    
                    # Evasion results
                    evasion_results = waf_data.get("evasion_results", [])
                    if evasion_results:
                        html_content += '''<div style="margin-top:15px">
                            <b>Evasion Testing Results:</b>
                            <table style="margin-top:10px">
                                <thead><tr><th>Technique</th><th>Type</th><th>Result</th><th>Status</th></tr></thead>
                                <tbody>'''
                        for result in evasion_results:
                            bypassed = result.get("bypassed", False)
                            badge = "badge-green" if bypassed else "badge-red"
                            result_text = "BYPASSED" if bypassed else "BLOCKED"
                            status = str(result.get("status_code", result.get("error", "N/A")))
                            html_content += f'''<tr>
                                <td>{result.get("technique", "")}</td>
                                <td>{result.get("type", "")}</td>
                                <td><span class="badge {badge}">{result_text}</span></td>
                                <td>{status}</td>
                            </tr>'''
                        html_content += '</tbody></table></div>'
                    
                    html_content += '</div>'

            # Takeover
            if "Subdomain Takeover" in scans:
                to_data = scans["Subdomain Takeover"]
                if to_data.get("vulnerable"):
                    html_content += f'<div class="module-section" style="border-left: 5px solid var(--error); background:rgba(239, 68, 68, 0.1);"><div class="module-title" style="color:var(--error)">Subdomain Takeover Vulnerability</div><div style="font-size:1.2em">Provider: <b>{to_data.get("provider")}</b><br>CNAME: {to_data.get("cname")}</div></div>'

            # Header Scanner
            if "Security Headers" in scans:
                h_data = scans["Security Headers"]
                score = h_data.get("score", 0)
                s_color = "var(--success)" if score >= 80 else "var(--accent)" if score >= 50 else "var(--error)"
                
                html_content += f'<div class="module-section"><div class="module-title">Security Headers</div><div style="display:flex; align-items:center; gap:20px"><div style="font-size:3em; font-weight:bold; color:{s_color}">{score}</div><div>Security Score</div></div>'
                
                missing = h_data.get("missing", [])
                if missing:
                    html_content += '<div class="scroll-table" style="margin-top:10px"><table><thead><tr><th>Missing Header</th><th>Risk</th><th>Description</th></tr></thead><tbody>'
                    for m in missing:
                        html_content += f"<tr><td>{m['header']}</td><td><span class='badge badge-red'>{m['risk']}</span></td><td>{m['description']}</td></tr>"
                    html_content += '</tbody></table></div>'
                html_content += '</div>'

            # JS Secrets
            if "JS Secret Scanner" in scans:
                js_data = scans["JS Secret Scanner"]
                secrets = js_data.get("secrets", [])
                if secrets:
                    html_content += f'<div class="module-section"><div class="module-title">JS Secrets Found ({len(secrets)})</div><div class="scroll-table"><table><thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead><tbody>'
                    for s in secrets:
                         html_content += f"<tr><td><span class='badge badge-red'>{s['type']}</span></td><td style='font-family:monospace'>{s['value']}</td><td><a href='{s['source']}' target='_blank' style='color:var(--accent)'>{s['source'].split('/')[-1]}</a></td></tr>"
                    html_content += '</tbody></table></div></div>'

            # Sensitive Files
            if "Sensitive File Fuzzer" in scans:
                 found = scans["Sensitive File Fuzzer"].get("found", [])
                 if found:
                    html_content += f'<div class="module-section"><div class="module-title">Sensitive Files Exposed</div><div class="scroll-table"><table><thead><tr><th>URL</th><th>Status</th><th>Size</th></tr></thead><tbody>'
                    for f in found:
                        html_content += f"<tr><td>{f['url']}</td><td><span class='badge badge-green'>{f['status']}</span></td><td>{f['size']}</td></tr>"
                    html_content += '</tbody></table></div></div>'

            # Emails
            if "Email Harvester" in scans:
                emails = scans["Email Harvester"].get("emails", [])
                if emails:
                    html_content += f'<div class="module-section"><div class="module-title">Emails Found ({len(emails)})</div><div class="scroll-table"><table><thead><tr><th>Email</th><th>Source</th></tr></thead><tbody>'
                    for e in emails[:50]:
                        html_content += f"<tr><td>{e['email']}</td><td>{e['source']}</td></tr>"
                    html_content += '</tbody></table></div></div>'

            # Wayback
            if "Wayback Machine Scanner" in scans:
                wb = scans["Wayback Machine Scanner"]
                total = wb.get("total_found", 0)
                urls = wb.get("urls", [])
                params = wb.get("interesting_params", [])
                
                html_content += f'<div class="module-section"><div class="module-title">Wayback Machine Archive ({total} URLs)</div>'
                if params:
                    p_str = ", ".join([f"<span class='badge badge-blue'>{p}</span>" for p in params])
                    html_content += f'<div style="margin-bottom:15px"><strong>Params Found:</strong> {p_str}</div>'
                
                if urls:
                     html_content += '<div class="scroll-table"><table><tbody>'
                     for u in urls[:50]:
                         html_content += f"<tr><td><a href='{u}' target='_blank'>{u}</a></td></tr>"
                     html_content += '</tbody></table></div>'
                html_content += '</div>'

            # CRT.sh
            if "CRT.sh Scanner" in scans:
                c_data = scans["CRT.sh Scanner"]
                subs = c_data.get("subdomains", [])
                if subs:
                     html_content += f'<div class="module-section"><div class="module-title">CRT.sh Passive Recon ({len(subs)})</div><div class="scroll-table" style="max-height:200px"><table><tbody>'
                     for s in subs:
                         html_content += f"<tr><td>{s}</td></tr>"
                     html_content += '</tbody></table></div></div>'

            # Robots
            if "Robots & Sitemap Scanner" in scans:
                r_data = scans["Robots & Sitemap Scanner"]
                if r_data:
                    html_content += '<div class="module-section"><div class="module-title">Content Discovery (Robots/Sitemap)</div>'
                    if r_data.get("robots_found"):
                         html_content += f"<div><span class='badge badge-green'>robots.txt</span> found with <b>{len(r_data.get('disallowed_paths', []))}</b> disallowed paths.</div>"
                    if r_data.get("sitemap_found"):
                         html_content += f"<div><span class='badge badge-green'>sitemap.xml</span> found with <b>{r_data.get('sitemap_count')}</b> URLs.</div>"
                    html_content += '</div>'

            # Cloud
            if "Cloud Asset Enumerator" in scans:
                cl_data = scans["Cloud Asset Enumerator"]
                buckets = cl_data.get("aws_buckets", [])
                if buckets:
                     html_content += f'<div class="module-section"><div class="module-title">Cloud Assets</div><div class="scroll-table"><table><thead><tr><th>Name</th><th>Status</th><th>URL</th></tr></thead><tbody>'
                     for b in buckets:
                         bs = b.get("status")
                         badge = "badge-green" if "200" in bs else "badge-blue"
                         html_content += f"<tr><td>{b['name']}</td><td><span class='badge {badge}'>{bs}</span></td><td><a href='{b['url']}' target='_blank'>Link</a></td></tr>"
                     html_content += '</tbody></table></div></div>'

        html_content += """
            <div style="text-align:center; color:var(--text-muted); margin-top:50px; border-top:1px solid var(--border); padding-top:20px">
                MyNet Scanner Report &bull; Confidential
            </div>
            </div>
        </body>
        </html>
        """
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def _write_csv(self, results: Dict[str, Any], file_path: str):
        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Type", "Open Ports", "HTTP Titles", "DNS Info"])
            for host, data in results.items():
                t_type = data.get('target', {}).get('type', 'unknown')
                scans = data.get("scans", {})
                
                ports = ""
                if "Port Scanner" in scans:
                    ports = ",".join(map(str, scans["Port Scanner"].get("open_ports", [])))
                
                http_titles = []
                if "HTTP Scanner" in scans:
                    for info in scans["HTTP Scanner"].values():
                        if "title" in info: http_titles.append(info["title"])
                
                dns_info = str(scans.get("DNS Scanner", {}))
                
                writer.writerow([host, t_type, ports, "; ".join(http_titles), dns_info])
