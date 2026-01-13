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
    
    # Convert generator to list (safe for reasonable inputs, warns user for huge CIDRs)
    target_list = list(parse_input(target))
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
    # 5. Handle Results
    from ..output.handler import OutputHandler
    output_handler = OutputHandler(console)
    output_handler.handle(results, output, file_)

if __name__ == "__main__":
    app()
