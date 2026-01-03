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
            "Traceroute Scanner": self._render_trace
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
