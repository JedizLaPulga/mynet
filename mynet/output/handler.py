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
        for host, data in results.items(): 
            # Display host info
            t_info = data.get("target", {})
            scans = data.get("scans", {})
            
            self.console.print(Panel(f"[bold]Results for {host}[/bold] ({t_info.get('type', 'unknown')})", expand=False))

            # DNS Table
            if "DNS Scanner" in scans:
                dns_res = scans["DNS Scanner"]
                if dns_res:
                    table = Table(title="DNS Records", show_header=True)
                    table.add_column("Type", style="cyan")
                    table.add_column("Value", style="magenta")
                    
                    found = False
                    for k, v in dns_res.items():
                        if isinstance(v, list):
                            for item in v:
                                table.add_row(k, item)
                                found = True
                        else:
                            table.add_row(k, str(v))
                            found = True
                    if found:
                        self.console.print(table)

            # SSL Table
            if "SSL Scanner" in scans:
                ssl_res = scans["SSL Scanner"]
                if ssl_res and "error" not in ssl_res and ssl_res:
                    table = Table(title="SSL Certificate", show_header=True)
                    table.add_column("Field", style="yellow")
                    table.add_column("Value", style="white")
                    
                    table.add_row("Subject", ssl_res.get("subject", "N/A"))
                    table.add_row("Issuer", ssl_res.get("issuer", "N/A"))
                    table.add_row("Valid From", ssl_res.get("valid_from", "N/A"))
                    table.add_row("Valid To", ssl_res.get("valid_to", "N/A"))
                    
                    sans = ssl_res.get("sans", [])
                    if sans:
                        # Limit SANs display if too many
                        san_str = ", ".join(sans[:5]) + (f" (+{len(sans)-5} more)" if len(sans) > 5 else "")
                        table.add_row("SANs", san_str)
                        
                    self.console.print(table)
                elif "error" in ssl_res:
                     self.console.print(f"[red]SSL Scan Error: {ssl_res['error']}[/red]")

            # WHOIS Table
            if "Whois Scanner" in scans:
                whois_res = scans["Whois Scanner"]
                if whois_res and "error" not in whois_res:
                    table = Table(title="WHOIS / ASN Info", show_header=True)
                    table.add_column("Field", style="cyan")
                    table.add_column("Value", style="green")
                    
                    table.add_row("IP Address", str(whois_res.get("query", "N/A")))
                    table.add_row("ASN", str(whois_res.get("asn", "N/A")))
                    table.add_row("ASN Desc", str(whois_res.get("asn_description", "N/A")))
                    table.add_row("Country", str(whois_res.get("asn_country_code", "N/A")))
                    
                    network = whois_res.get("network", {})
                    if network:
                         table.add_row("Network Name", str(network.get("name", "N/A")))
                         table.add_row("CIDR", str(network.get("cidr", "N/A")))

                    self.console.print(table)
                elif "error" in whois_res:
                     self.console.print(f"[red]WHOIS Scan Error: {whois_res['error']}[/red]")

            
            # Ports Table
            if "Port Scanner" in scans:
                port_res = scans["Port Scanner"]
                open_ports = port_res.get("open_ports", [])
                details = port_res.get("details", [])
                
                if open_ports:
                    table = Table(title=f"Open Ports (Scanned {port_res.get('scanned_count')} ports)", show_header=True)
                    table.add_column("Port", style="green")
                    table.add_column("State", style="bold green")
                    table.add_column("Service/Banner", style="dim white")
                    
                    # Create a lookup for banners
                    banner_map = {d['port']: d.get('banner') for d in details}
                    
                    for p in open_ports:
                        banner = banner_map.get(p)
                        banner_str = banner[:50] + "..." if banner and len(banner) > 50 else banner
                        table.add_row(str(p), "OPEN", banner_str if banner_str else "")
                        
                    self.console.print(table)
                else:
                    self.console.print("[yellow]No open ports found (in scanned range).[/yellow]")

            # HTTP Table
            if "HTTP Scanner" in scans:
                 http_res = scans["HTTP Scanner"]
                 if http_res:
                    table = Table(title="HTTP Info", show_header=True)
                    table.add_column("URL", style="blue")
                    table.add_column("Status", style="bold")
                    table.add_column("Title", style="white")
                    table.add_column("Server", style="dim")
                    
                    for url, info in http_res.items():
                        if "error" in info:
                             table.add_row(url, "[red]Error[/red]", info['error'], "")
                        else:
                            status_str = f"[green]{info['status']}[/green]" if info['status'] < 400 else f"[red]{info['status']}[/red]"
                            table.add_row(url, status_str, info.get('title', ''), info.get('server', ''))
                    self.console.print(table)
            
            self.console.print("")

    def _save_to_file(self, results: Dict[str, Any], file_path: str, output_format: str):
        # Determine format from file extension if possible, else use output_format or default to json
        if file_path.endswith(".json") or (output_format == "json" and not file_path.endswith((".",))):
            self._write_json(results, file_path)
            
        elif file_path.endswith(".md"):
            self._write_md(results, file_path)
            
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
