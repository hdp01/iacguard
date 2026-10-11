"""Terraform (HCL2) parsing and normalisation.

python-hcl2 v8 returns string values and block labels with their surrounding
double quotes intact (``'"aws_s3_bucket"'`` rather than ``'aws_s3_bucket'``).
Every consumer wants the unquoted form, so normalisation happens once here and
the rest of the codebase can assume clean data.
"""

import re
from typing import Any

import hcl2

# Matches:  resource "aws_s3_bucket" "data" {
_BLOCK_RE = re.compile(
    r'^\s*(resource|data|variable|module|provider)\s+"([^"]+)"(?:\s+"([^"]+)")?',
)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def normalise(node: Any) -> Any:
    """Recursively strip HCL2's literal quotes from keys and string values."""
    if isinstance(node, dict):
        return {
            _unquote(k): normalise(v)
            for k, v in node.items()
            if k != "__is_block__"
        }
    if isinstance(node, list):
        return [normalise(item) for item in node]
    if isinstance(node, str):
        return _unquote(node)
    return node


def line_index(source: str) -> dict[tuple[str, ...], int]:
    """Map block identity tuples to their 1-based line number in the source.

    hcl2 discards position information, so findings would otherwise have no
    line to point at. Re-scanning the raw text is cheap and good enough to be
    useful in a report.
    """
    index: dict[tuple[str, ...], int] = {}
    for lineno, line in enumerate(source.splitlines(), start=1):
        match = _BLOCK_RE.match(line)
        if not match:
            continue
        kind, first, second = match.groups()
        key = (kind, first, second) if second else (kind, first)
        index.setdefault(key, lineno)
    return index


class Document:
    """A parsed Terraform document, flattened into the shapes rules want."""

    def __init__(self, source: str, filename: str = "<string>"):
        self.filename = filename
        self.source = source
        self.raw = normalise(hcl2.loads(source))
        self.lines = line_index(source)

    def _flatten(self, kind: str) -> list[dict]:
        """Turn hcl2's nested list-of-dicts into flat records."""
        out = []
        for entry in self.raw.get(kind, []):
            if not isinstance(entry, dict):
                continue
            for label, inner in entry.items():
                if kind == "resource" and isinstance(inner, dict):
                    # resource blocks nest twice: type -> name -> body
                    for name, body in inner.items():
                        if isinstance(body, dict):
                            out.append(
                                {
                                    "type": label,
                                    "name": name,
                                    "body": body,
                                    "line": self.lines.get(
                                        (kind, label, name), 0
                                    ),
                                }
                            )
                else:
                    out.append(
                        {
                            "type": kind,
                            "name": label,
                            "body": inner if isinstance(inner, dict) else {},
                            "line": self.lines.get((kind, label), 0),
                        }
                    )
        return out

    @property
    def resources(self) -> list[dict]:
        return self._flatten("resource")

    @property
    def variables(self) -> list[dict]:
        return self._flatten("variable")
