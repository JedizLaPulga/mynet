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
import os

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
    file_: str = typer.Option(None, "--file", "-f", help="Save output to file"),
    diff: str = typer.Option(None, "--diff", "-d", help="Compare against baseline JSON file"),
    save_baseline: str = typer.Option(None, "--save-baseline", "-b", help="Save results as baseline for future diffs"),
):
    """
    Run a complete scan on the target.
    
    Use --diff to compare against a previous scan baseline.
    Use --save-baseline to save current results for future comparisons.
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

    # 5. Handle Diff Mode
    if diff:
        _handle_diff_mode(results, diff, output)
    else:
        # Normal output
        from ..output.handler import OutputHandler
        output_handler = OutputHandler(console)
        output_handler.handle(results, output, file_)

    # 6. Save Baseline if requested
    if save_baseline:
        from ..core.differ import save_baseline as save_bl
        save_bl(results, save_baseline)
        console.print(f"[blue]Baseline saved to {save_baseline}[/blue]")


def _handle_diff_mode(results: dict, baseline_path: str, output_format: str):
    """Handle diff mode - compare results against baseline."""
    from ..core.differ import ScanDiffer, load_baseline, ChangeType

    # Load baseline
    if not os.path.exists(baseline_path):
        console.print(f"[red]Baseline file not found: {baseline_path}[/red]")
        raise typer.Exit(code=1)

    try:
        baseline = load_baseline(baseline_path)
    except json.JSONDecodeError:
        console.print(f"[red]Invalid JSON in baseline file: {baseline_path}[/red]")
        raise typer.Exit(code=1)

    # Perform diff
    differ = ScanDiffer()
    diffs = differ.diff(baseline, results)
    summary = differ.generate_summary(diffs)

    # Display diff results
    _display_diff_results(diffs, summary, output_format)


def _display_diff_results(diffs: dict, summary: dict, output_format: str):
    """Display diff results in a readable format."""
    from ..core.differ import ChangeType

    if output_format == "json":
        # JSON output
        output = {
            "summary": summary,
            "changes": {
                host: [
                    {
                        "module": d.module,
                        "change_type": d.change_type.value,
                        "key": d.key,
                        "old_value": d.old_value,
                        "new_value": d.new_value,
                        "severity": d.severity,
                    }
                    for d in host_diffs
                ]
                for host, host_diffs in diffs.items()
            },
        }
        console.print(JSON(json.dumps(output, indent=2, default=str)))
        return

    # Table output
    if summary["total_changes"] == 0:
        console.print(Panel(
            "[bold green]No changes detected![/bold green]\nScan results match the baseline.",
            title="Diff Results",
            border_style="green",
        ))
        return

    # Summary panel
    summary_lines = [
        f"[bold]Total Changes: {summary['total_changes']}[/bold]",
        f"New: [green]{summary['new']}[/green] | "
        f"Removed: [yellow]{summary['removed']}[/yellow] | "
        f"Changed: [cyan]{summary['changed']}[/cyan]",
    ]

    if summary["high_severity"] > 0:
        summary_lines.append(f"[bold red]⚠ High Severity Issues: {summary['high_severity']}[/bold red]")

    summary_lines.append(f"[dim]Hosts affected: {summary['hosts_affected']}[/dim]")

    border_color = "red" if summary["high_severity"] > 0 else "yellow" if summary["total_changes"] > 0 else "green"
    console.print(Panel(
        "\n".join(summary_lines),
        title="Diff Summary",
        border_style=border_color,
    ))

    # Changes table
    table = Table(title="Changes Detected", show_header=True)
    table.add_column("Host", style="cyan")
    table.add_column("Module", style="blue")
    table.add_column("Change", style="bold")
    table.add_column("Field", style="dim")
    table.add_column("Details", style="white")

    for host, host_diffs in diffs.items():
        for diff in host_diffs[:20]:  # Limit displayed changes
            # Format change type
            if diff.change_type == ChangeType.NEW:
                change_str = "[green]+ NEW[/green]"
            elif diff.change_type == ChangeType.REMOVED:
                change_str = "[yellow]- REMOVED[/yellow]"
            else:
                change_str = "[cyan]~ CHANGED[/cyan]"

            # Format details
            if diff.change_type == ChangeType.NEW:
                details = _format_value(diff.new_value)
            elif diff.change_type == ChangeType.REMOVED:
                details = _format_value(diff.old_value)
            else:
                details = f"{_format_value(diff.old_value)} → {_format_value(diff.new_value)}"

            # Add severity indicator
            if diff.severity == "high":
                change_str = f"[red]⚠[/red] {change_str}"

            table.add_row(
                host[:30],
                diff.module[:20],
                change_str,
                diff.key,
                details[:50],
            )

    console.print(table)

    # Show if truncated
    total_diffs = sum(len(d) for d in diffs.values())
    if total_diffs > 20:
        console.print(f"[dim]... and {total_diffs - 20} more changes[/dim]")


def _format_value(value) -> str:
    """Format a value for display."""
    if value is None:
        return "[dim]None[/dim]"
    if isinstance(value, bool):
        return "[green]Yes[/green]" if value else "[red]No[/red]"
    if isinstance(value, list):
        if len(value) == 0:
            return "[dim][]"
        if len(value) <= 3:
            return str(value)
        return f"[{len(value)} items]"
    if isinstance(value, dict):
        return f"[{len(value)} fields]"
    return str(value)[:30]


if __name__ == "__main__":
    app()
