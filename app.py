#!/usr/bin/env python3
"""IaCGuard.

Run it, give it a Terraform file, a folder or a zip, and it prints the
security findings with Amazon Nova's suggested fixes.

    python3 app.py                      # asks for the path
    python3 app.py samples/insecure.tf  # or take it as an argument

The scanning itself happens in AWS: the file is uploaded to S3, which triggers
a Lambda that runs the rules and calls Nova, and the results come back from
DynamoDB. This script is just the front door.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Missing dependencies. Run:  pip install -r requirements.txt")
    raise SystemExit(1)

console = Console()

CONFIG_FILE = Path(__file__).resolve().parent / ".iacguard.json"
MAX_FILE_BYTES = 1024 * 1024
SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

def load_config() -> dict:
    config = {}
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
        except json.JSONDecodeError:
            console.print(f"[bold red]{CONFIG_FILE.name} is not valid JSON.[/]")
            raise SystemExit(2)

    for key, env in (("region", "IACGUARD_REGION"),
                     ("bucket", "IACGUARD_BUCKET"),
                     ("table", "IACGUARD_TABLE")):
        if os.environ.get(env):
            config[key] = os.environ[env]

    missing = [k for k in ("region", "bucket", "table") if not config.get(k)]
    if missing:
        console.print(Panel(
            f"Missing: {', '.join(missing)}\n\n"
            "The AWS side is not configured yet. Deploy it with:\n"
            "  [bold]make deploy[/]",
            title="[bold red]Not configured[/]", border_style="red"))
        raise SystemExit(2)
    return config


# ---------------------------------------------------------------------------
# input handling: file, directory or zip
# ---------------------------------------------------------------------------

def collect_from_zip(archive: Path, workdir: Path) -> list[Path]:
    """Extract the .tf files from a zip.

    Member paths are validated before extraction: a crafted archive can
    contain entries like ``../../.bashrc`` and overwrite files outside the
    target directory, so anything that does not resolve inside workdir is
    skipped rather than written.
    """
    found = []
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            name = Path(member.filename).name
            if not name.endswith((".tf", ".hcl")):
                continue

            target = (workdir / member.filename).resolve()
            if not str(target).startswith(str(workdir.resolve()) + os.sep):
                console.print(f"  [yellow]skipped unsafe path in archive:[/] "
                              f"{member.filename}")
                continue
            if member.file_size > MAX_FILE_BYTES:
                console.print(f"  [yellow]skipped (too large):[/] {name}")
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            found.append(target)
    return found


def resolve_input(raw: str) -> tuple[list[Path], Path | None]:
    """Turn whatever the user typed into a list of .tf files.

    Returns the files and a temporary directory to clean up afterwards, if one
    was created for a zip.
    """
    # Users paste paths with quotes or a trailing space surprisingly often.
    cleaned = raw.strip().strip("'\"").strip()
    path = Path(cleaned).expanduser()

    if not path.exists():
        console.print(f"[bold red]No such path:[/] {path}")
        return [], None

    if path.is_dir():
        files = sorted(p for p in path.rglob("*.tf") if p.is_file())
        if not files:
            console.print(f"[bold red]No .tf files found in[/] {path}")
        return files, None

    if path.suffix.lower() == ".zip":
        workdir = Path(tempfile.mkdtemp(prefix="iacguard-"))
        try:
            files = collect_from_zip(path, workdir)
        except zipfile.BadZipFile:
            console.print(f"[bold red]Not a readable zip file:[/] {path}")
            shutil.rmtree(workdir, ignore_errors=True)
            return [], None
        if not files:
            console.print(f"[bold red]No .tf files inside[/] {path}")
            shutil.rmtree(workdir, ignore_errors=True)
            return [], None
        return sorted(files), workdir

    if path.suffix.lower() in (".tf", ".hcl"):
        if path.stat().st_size > MAX_FILE_BYTES:
            console.print(f"[bold red]File is larger than 1 MB:[/] {path}")
            return [], None
        return [path], None

    console.print(f"[bold red]Not a Terraform file, folder or zip:[/] {path}")
    return [], None


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

def fetch(table, scan_id: str) -> tuple[dict, list[dict]]:
    from boto3.dynamodb.conditions import Key

    items, kwargs = [], {"KeyConditionExpression": Key("scan_id").eq(scan_id)}
    while True:
        page = table.query(**kwargs)
        items.extend(page.get("Items", []))
        if not page.get("LastEvaluatedKey"):
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    meta = next((i for i in items if i["sk"] == "META"), {})
    findings = [i for i in items if i["sk"] != "META"]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 9),
                                 f.get("rule_id", "")))
    return meta, findings


def run_scan(config: dict, files: list[Path]) -> tuple[dict, list[dict]] | None:
    session = boto3.session.Session(region_name=config["region"])
    s3 = session.client("s3")
    table = session.resource("dynamodb").Table(config["table"])

    scan_id = uuid.uuid4().hex[:12]
    console.print(f"\nUploading {len(files)} file(s) to AWS "
                  f"[dim](scan {scan_id})[/]")
    for path in files:
        s3.upload_file(str(path), config["bucket"],
                       f"uploads/{scan_id}/{path.name}")
        console.print(f"  [dim]•[/] {path.name}")

    deadline = time.time() + 180
    with console.status("[bold]Scanning in AWS Lambda...[/]") as status:
        while time.time() < deadline:
            meta, findings = fetch(table, scan_id)
            if meta.get("status") == "parse_error":
                console.print(Panel(str(meta.get("parse_error", "unknown")),
                                    title="[bold red]Terraform parse error[/]",
                                    border_style="red"))
                return None
            done = int(meta.get("files_scanned", 0))
            if done >= len(files):
                meta["scan_id"] = scan_id
                return meta, findings
            status.update(f"[bold]Scanning in AWS Lambda...[/] "
                          f"{done}/{len(files)} files")
            time.sleep(2)

    console.print("[bold yellow]Timed out waiting for results.[/] "
                  "The scan may still be running.")
    return None


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

def severity_text(value: str) -> Text:
    return Text(f" {value} ", style=SEVERITY_STYLE.get(value, "white"))


def show_results(meta: dict, findings: list[dict]) -> None:
    score = max(0, 100 - int(meta.get("penalty", 0)))
    if score >= 80:
        verdict, colour = "GOOD", "green"
    elif score >= 50:
        verdict, colour = "NEEDS WORK", "yellow"
    else:
        verdict, colour = "FAILING", "red"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(justify="right", style="dim")
    summary.add_column()
    summary.add_row("Files scanned", str(int(meta.get("files_scanned", 0))))
    summary.add_row("Posture score", f"[bold {colour}]{score}/100  {verdict}[/]")
    summary.add_row("Findings",
                    f"[bold red]{int(meta.get('critical_count', 0))} critical[/]  "
                    f"[red]{int(meta.get('high_count', 0))} high[/]  "
                    f"[yellow]{int(meta.get('medium_count', 0))} medium[/]  "
                    f"[cyan]{int(meta.get('low_count', 0))} low[/]")
    summary.add_row("Nova tokens",
                    f"{int(meta.get('tokens_in', 0))} in / "
                    f"{int(meta.get('tokens_out', 0))} out")
    console.print()
    console.print(Panel(summary, title="[bold]Scan result[/]",
                        border_style=colour))

    if not findings:
        console.print("[bold green]No misconfigurations found.[/]\n")
        return

    table = Table(header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Rule", no_wrap=True, style="dim")
    table.add_column("Resource")
    table.add_column("Location", no_wrap=True, style="dim")
    table.add_column("Issue")
    for f in findings:
        table.add_row(severity_text(f["severity"]), f["rule_id"],
                      f"{f['resource_type']}.{f['resource_name']}",
                      f"{f.get('file', '?')}:{int(f.get('line', 0))}",
                      f["title"])
    console.print(table)


def show_fixes(findings: list[dict], limit: int) -> None:
    shown = [f for f in findings if f.get("explanation")][:limit]
    if not shown:
        return

    console.print()
    console.rule("[bold]Amazon Nova — why it matters, and the fix[/]")
    for f in shown:
        console.print()
        console.print(
            severity_text(f["severity"]),
            Text(f"{f['rule_id']}  {f['resource_type']}.{f['resource_name']}"
                 f"  ({f.get('file', '?')}:{int(f.get('line', 0))})",
                 style="bold"))
        console.print(f"[dim]{f['title']}[/]\n")
        console.print(Panel(f["explanation"], title="Why this matters",
                            border_style="blue", padding=(0, 1)))
        if f.get("fixed_code"):
            console.print(Panel(
                Syntax(f["fixed_code"], "hcl", theme="ansi_dark",
                       word_wrap=True),
                title=f"Suggested fix (effort: {f.get('effort', 'unknown')})",
                border_style="green", padding=(0, 1)))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def scan_once(config: dict, raw: str) -> None:
    files, workdir = resolve_input(raw)
    try:
        if not files:
            return
        result = run_scan(config, files)
        if not result:
            return
        meta, findings = result
        show_results(meta, findings)
        if findings and Confirm.ask(
                "\nShow Nova's explanations and fixes?", default=True):
            show_fixes(findings, limit=len(findings))
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    console.print(Panel(
        "[bold]IaCGuard[/] — Terraform security scanning on AWS, with "
        "Amazon Nova writing the fixes",
        border_style="blue"))

    config = load_config()

    # A path given on the command line runs once and exits, which is handy for
    # scripting; with no argument the app is interactive.
    if len(sys.argv) > 1:
        scan_once(config, sys.argv[1])
        return 0

    while True:
        console.print()
        raw = Prompt.ask(
            "[bold]Enter a .tf file, a folder, or a .zip[/] "
            "[dim](or 'q' to quit)[/]")
        if raw.strip().lower() in ("q", "quit", "exit", ""):
            console.print("Bye.")
            return 0
        scan_once(config, raw)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except NoCredentialsError:
        console.print("[bold red]No AWS credentials found.[/] "
                      "Run [bold]aws configure[/].")
        sys.exit(2)
    except ClientError as exc:
        console.print(f"[bold red]AWS error:[/] "
                      f"{exc.response['Error']['Message']}")
        sys.exit(2)
    except KeyboardInterrupt:
        console.print("\nInterrupted.")
        sys.exit(130)
