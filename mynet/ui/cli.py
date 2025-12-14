import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.json import JSON
from rich import print as rprint
import json
import time

from ..core.config import Config
from ..core.input_parser import parse_input
from ..core.runner import Runner

app = typer.Typer(help="MyNet - High Performance Network Scanner")
console = Console()

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL, IP, or CIDR"),
    ports: str = typer.Option(None, help="Comma-separated ports to scan (e.g. 80,443,22)"),
    concurrency: int = typer.Option(50, help="Concurrency level"),
    timeout: int = typer.Option(5, help="Timeout in seconds"),
    output: str = typer.Option("table", help="Output format: table, json"),
    file_: str = typer.Option(None, "--file", "-f", help="Save output to file")
):
    """
    Run a complete scan on the target.
    """
    # 1. Configuration
    port_list = [int(p) for p in ports.split(",")] if ports else None
    config = Config(
        concurrency=concurrency,
        timeout=timeout,
        ports=port_list
    )
    
    # 2. Parse Input
    console.print(Panel(f"[bold blue]MyNet Scanner[/bold blue]\nTarget: {target}", border_style="blue"))
    
    target_list = parse_input(target)
    if not target_list:
        console.print("[red]Invalid target input.[/red]")
        raise typer.Exit(code=1)
    
    console.print(f"[green]Parsed {len(target_list)} targets.[/green]")

    # 3. Initialize Runner
    runner = Runner(config)
    
    # 4. Run Scan with Spinner
    results = {}
    with console.status(f"[bold green]Scanning {target}...[/bold green]", spinner="dots"):
        # We need to run the async function from sync typer
        results = asyncio.run(runner.run_scan(target_list))

    # 5. Display Results
    if output == "json":
        json_output = json.dumps(results, indent=2)
        rprint(JSON(json_output))
        if file_:
            with open(file_, "w") as f:
                f.write(json_output)
    else:
        # Table Output
        for host, data in results.items(): 
            # Display host info
            t_info = data.get("target", {})
            scans = data.get("scans", {})
            
            console.print(Panel(f"[bold]Results for {host}[/bold] ({t_info.get('type', 'unknown')})", expand=False))

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
                        console.print(table)
            
            # Ports Table
            if "Port Scanner" in scans:
                port_res = scans["Port Scanner"]
                open_ports = port_res.get("open_ports", [])
                if open_ports:
                    table = Table(title=f"Open Ports (Scanned {port_res.get('scanned_count')} ports)", show_header=True)
                    table.add_column("Port", style="green")
                    table.add_column("State", style="bold green")
                    for p in open_ports:
                        table.add_row(str(p), "OPEN")
                    console.print(table)
                else:
                    console.print("[yellow]No open ports found (in scanned range).[/yellow]")

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
                    console.print(table)
            
            console.print("")

    if file_:
        if output == "json" or file_.endswith(".json"):
            with open(file_, "w") as f:
                 json.dump(results, f, indent=2)
            console.print(f"[blue]Results saved to {file_}[/blue]")
        elif file_.endswith(".md"):
             with open(file_, "w") as f:
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
             console.print(f"[blue]Results saved to {file_}[/blue]")
        elif file_.endswith(".csv"):
             import csv
             with open(file_, "w", newline="") as f:
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
             console.print(f"[blue]Results saved to {file_}[/blue]")
        else:
            # Default JSON
            with open(file_, "w") as f:
                 json.dump(results, f, indent=2)
            console.print(f"[blue]Results saved to {file_}[/blue]")

if __name__ == "__main__":
    app()
