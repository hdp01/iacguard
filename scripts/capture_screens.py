#!/usr/bin/env python3
"""Capture real terminal output as PNG images for the slide deck.

Commands are run inside a pseudo-terminal at a fixed width, so the tools
produce their normal coloured output rather than the plain fallback they emit
when stdout is a pipe. The captured ANSI is re-rendered by rich into an SVG
terminal frame, which headless Chrome rasterises to PNG.

    python3 scripts/capture_screens.py
"""

import fcntl
import math
import os
import pty
import re
import struct
import subprocess
import sys
import termios
from pathlib import Path

from rich.console import Console
from rich.text import Text

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "screens"
CHROME = "google-chrome"


def run_in_pty(command: str, cols: int, rows: int, stdin_text: str = "") -> str:
    """Run a shell command in a pty and return its output including ANSI."""
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLUMNS"] = str(cols)
        os.environ["LINES"] = str(rows)
        os.environ["FORCE_COLOR"] = "1"
        os.chdir(ROOT)
        os.execvp("bash", ["bash", "-lc", command])

    fcntl.ioctl(fd, termios.TIOCSWINSZ,
                struct.pack("HHHH", rows, cols, 0, 0))

    # Without this the pty echoes whatever is fed to stdin, so an answer to a
    # prompt appears as a stray character at the top of the capture.
    attrs = termios.tcgetattr(fd)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(fd, termios.TCSANOW, attrs)

    if stdin_text:
        os.write(fd, stdin_text.encode())

    chunks = []
    while True:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    os.waitpid(pid, 0)
    return b"".join(chunks).decode("utf-8", errors="replace")


def clean(ansi: str) -> str:
    """Strip control sequences rich cannot interpret.

    Spinners and status lines repaint with cursor moves and erases; replaying
    those into a static image leaves duplicated frames, so the progress
    repaints are dropped and only the final text is kept.
    """
    # A pty terminates lines with CRLF. That trailing \r must go before the
    # carriage-return handling below, or every line is treated as a repaint
    # and reduced to the empty string after its own line ending.
    ansi = ansi.replace("\r\n", "\n")

    # carriage-return repaints: keep the last state of each line
    out_lines = []
    for line in ansi.split("\n"):
        if "\r" in line:
            line = line.split("\r")[-1]
        out_lines.append(line)
    text = "\n".join(out_lines)

    # cursor movement, erase, show/hide cursor, scroll region
    text = re.sub(r"\x1b\[[0-9;]*[ABCDEFGHJKSTfsu]", "", text)
    text = re.sub(r"\x1b\[\?[0-9;]*[hl]", "", text)
    text = re.sub(r"\x1b[=>]", "", text)
    text = re.sub(r"\x1b\][0-9];[^\x07\x1b]*(\x07|\x1b\\)", "", text)
    # The live status line is a transient repaint; its last frame reads
    # "0/1 files" next to a finished result, which is just confusing in a
    # still image.
    text = "\n".join(line for line in text.split("\n")
                     if "Scanning in AWS Lambda" not in line)

    # collapse runs of blank lines left behind by the spinner
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip("\n")


def to_svg(ansi: str, title: str, name: str, cols: int) -> Path:
    console = Console(record=True, width=cols, file=open(os.devnull, "w"),
                      force_terminal=True, color_system="truecolor")
    console.print(Text.from_ansi(ansi))
    svg = OUT / f"{name}.svg"
    svg.write_text(console.export_svg(title=title, clear=True),
                   encoding="utf-8")
    return svg


def to_png(svg: Path, scale: int = 2) -> Path:
    """Rasterise the SVG with headless Chrome.

    The root element carries only a viewBox, so its size comes from there.
    Rather than using --force-device-scale-factor, the SVG is given an
    intrinsic size of scale x the viewBox and rendered 1:1: it is vector art,
    so it stays crisp, and the output dimensions then match --window-size
    exactly instead of interacting with the scale factor and scrollbar width.

    rich also points @font-face at a CDN copy of Fira Code; overriding the
    family to a locally installed mono keeps rendering deterministic and
    offline. DejaVu Sans Mono has effectively the same advance width, so
    rich's pre-computed glyph positions still line up.
    """
    content = svg.read_text(encoding="utf-8")
    viewbox = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', content)
    vw, vh = float(viewbox.group(1)), float(viewbox.group(2))
    width, height = math.ceil(vw * scale), math.ceil(vh * scale)

    content = content.replace(
        '<svg class="rich-terminal"',
        f'<svg class="rich-terminal" width="{width}" height="{height}"', 1)

    html = svg.with_suffix(".html")
    html.write_text(
        "<!doctype html><meta charset='utf-8'>"
        "<style>html,body{margin:0;padding:0;overflow:hidden;"
        "background:#0d1117}"
        "svg{display:block}"
        "text,tspan{font-family:'DejaVu Sans Mono',monospace !important}"
        "</style>"
        f"{content}", encoding="utf-8")

    png = svg.with_suffix(".png")
    subprocess.run(
        [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
         "--hide-scrollbars",
         f"--window-size={width},{height}",
         f"--screenshot={png}", f"file://{html}"],
        check=True, capture_output=True, timeout=120)
    html.unlink()
    svg.unlink()
    return png


def slice_lines(text: str, start_at: str | None,
                max_lines: int | None,
                drop: list[str] | None = None) -> str:
    """Trim a capture to the interesting part.

    Done here rather than with `head`/`sed` in the command: those close the
    pipe while the program is still writing, and the resulting "Broken pipe"
    message lands in the screenshot.
    """
    lines = text.split("\n")
    if drop:
        lines = [l for l in lines
                 if not any(token in l for token in drop)]
    if start_at:
        for index, line in enumerate(lines):
            if start_at in line:
                lines = lines[index:]
                break
    if max_lines:
        lines = lines[:max_lines]
    return "\n".join(lines)


def capture(name: str, title: str, command: str, cols: int = 104,
            rows: int = 120, stdin_text: str = "",
            start_at: str | None = None,
            max_lines: int | None = None,
            drop: list[str] | None = None) -> None:
    print(f"  capturing {name} ...", end=" ", flush=True)
    ansi = clean(run_in_pty(command, cols, rows, stdin_text))
    ansi = slice_lines(ansi, start_at, max_lines, drop)
    png = to_png(to_svg(ansi, title, name, cols))
    size = png.stat().st_size // 1024
    print(f"{png.name} ({size} KB)")


def make_demo_zip() -> Path:
    """Build the zip used by the zip-input screenshot.

    It deliberately contains a nested module, a non-Terraform file, and an
    entry whose path escapes the archive root, so the screenshot shows all
    three behaviours at once.
    """
    import zipfile

    target = ROOT / "build" / "terraform-project.zip"
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w") as z:
        z.write(ROOT / "samples" / "insecure.tf", "project/main.tf")
        z.write(ROOT / "samples" / "secure.tf", "project/modules/db.tf")
        z.writestr("project/README.md", "# not terraform\n")
        z.writestr("../../evil.tf",
                   'resource "aws_s3_bucket" "x" { acl = "public-read" }')
    return target


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    demo_zip = make_demo_zip()
    print(f"Writing to {OUT}")

    shots = [
        dict(name="01-tests", title="make test",
             command="make test", max_lines=8),
        dict(name="02-app-insecure",
             title="python3 app.py  —  insecure Terraform",
             command=".venv/bin/python app.py samples/insecure.tf",
             stdin_text="n\n", max_lines=38),
        dict(name="03-nova-fixes",
             title="Amazon Nova  —  why it matters, and the fix",
             command=".venv/bin/python app.py samples/insecure.tf",
             stdin_text="y\n",
             start_at="why it matters, and the fix", max_lines=32),
        dict(name="04-app-secure",
             title="python3 app.py  —  the hardened equivalent",
             command=".venv/bin/python app.py samples/secure.tf",
             max_lines=18),
        dict(name="05-selfscan",
             title="python3 app.py  —  scanning its own infrastructure",
             command=".venv/bin/python app.py infra",
             stdin_text="n\n", max_lines=32),
        dict(name="06-zip",
             title="python3 app.py  —  zip input, unsafe entry refused",
             command=f".venv/bin/python app.py {demo_zip}",
             stdin_text="n\n", max_lines=24),
        dict(name="07-metrics", title="make metrics  —  live CloudWatch data",
             command="./scripts/metrics.sh", max_lines=22),
        dict(name="08-deploy",
             title="terraform output  —  the live deployment",
             command="terraform -chdir=infra output", max_lines=20,
             drop=["dashboard_url", "console.aws.amazon.com"]),
    ]

    for shot in shots:
        capture(**shot)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
