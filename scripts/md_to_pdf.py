#!/usr/bin/env python3
"""Render the project's Markdown docs to PDF.

A deliberately small Markdown subset -- headings, paragraphs, bullet and
numbered lists, fenced code, tables, block quotes and rules -- which is all the
project docs use. Built on reportlab so it needs no system converter.

    python3 scripts/md_to_pdf.py docs/SLIDE_CONTENT.md docs/slide-content.pdf
"""

import html
import os
import re
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (HRFlowable, KeepTogether, ListFlowable,
                                ListItem, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

INK = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#0b5394")
MUTED = colors.HexColor("#5a6472")
CODE_BG = colors.HexColor("#f4f6f8")
RULE = colors.HexColor("#d4d9e0")

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 18 * mm
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN


DEJAVU_DIR = "/usr/share/fonts/truetype/dejavu"


def register_fonts():
    """Register DejaVu, falling back to the built-in Type1 faces.

    The built-ins are limited to WinAnsi, which has no box-drawing characters,
    arrows, the approximation sign or the rupee sign. Without a Unicode font
    the ASCII architecture diagram renders as a wall of solid blocks and the
    cost table loses its symbols.
    """
    faces = {
        "Doc": "DejaVuSans.ttf",
        "Doc-Bold": "DejaVuSans-Bold.ttf",
        "Doc-Oblique": "DejaVuSans-Oblique.ttf",
        "DocMono": "DejaVuSansMono.ttf",
        "DocMono-Bold": "DejaVuSansMono-Bold.ttf",
    }
    try:
        for name, filename in faces.items():
            path = os.path.join(DEJAVU_DIR, filename)
            if not os.path.exists(path):
                raise FileNotFoundError(path)
            pdfmetrics.registerFont(TTFont(name, path))
        pdfmetrics.registerFontFamily(
            "Doc", normal="Doc", bold="Doc-Bold",
            italic="Doc-Oblique", boldItalic="Doc-Bold")
        return "Doc", "Doc-Bold", "Doc-Oblique", "DocMono"
    except Exception as exc:
        print(f"note: DejaVu unavailable ({exc}); falling back to Helvetica. "
              "Box-drawing characters will not render.", file=sys.stderr)
        return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Courier"


SANS, SANS_B, SANS_I, MONO = register_fonts()


def styles():
    base = getSampleStyleSheet()
    s = {
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=SANS_B,
                             fontSize=19, leading=23, textColor=ACCENT,
                             spaceBefore=4, spaceAfter=9),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=SANS_B,
                             fontSize=14, leading=18, textColor=ACCENT,
                             spaceBefore=15, spaceAfter=7),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName=SANS_B,
                             fontSize=11.5, leading=15, textColor=INK,
                             spaceBefore=11, spaceAfter=5),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName=SANS,
                               fontSize=9.6, leading=13.8, textColor=INK,
                               alignment=TA_LEFT, spaceAfter=6),
        "bullet": ParagraphStyle("bullet", parent=base["BodyText"], fontName=SANS,
                                 fontSize=9.6, leading=13.4, textColor=INK,
                                 spaceAfter=2.5),
        "quote": ParagraphStyle("quote", parent=base["BodyText"], fontName=SANS_I,
                                fontSize=9.4, leading=13.4, textColor=MUTED,
                                leftIndent=10, spaceAfter=6),
        "code": ParagraphStyle("code", fontName=MONO, fontSize=8.0,
                               leading=10.4, textColor=INK),
        "th": ParagraphStyle("th", fontName=SANS_B, fontSize=8.6,
                             leading=11.4, textColor=colors.white),
        "td": ParagraphStyle("td", fontName=SANS, fontSize=8.6,
                             leading=11.4, textColor=INK),
    }
    return s


ST = styles()

_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<![\*\w])\*([^*\n]+)\*(?!\*)")


def inline(text: str) -> str:
    """Convert inline Markdown to reportlab's mini-HTML."""
    text = html.escape(text, quote=False)
    # Placeholders keep code spans from having their contents re-processed.
    spans = []

    def stash(match):
        spans.append(match.group(1))
        return f"\x00{len(spans) - 1}\x00"

    text = _CODE.sub(stash, text)
    text = _BOLD.sub(r"<b>\1</b>", text)
    text = _ITALIC.sub(r"<i>\1</i>", text)
    text = text.replace("--", "&#8212;")

    for index, code in enumerate(spans):
        text = text.replace(
            f"\x00{index}\x00",
            f'<font face="{MONO}" size="8.4" backColor="#f0f2f5">'
            f'{code}</font>',
        )
    return text


def code_block(lines: list[str]):
    body = "\n".join(lines) or " "
    inner = Preformatted(body, ST["code"])
    # Wrapped in a one-cell table purely to get a background and padding.
    return Table(
        [[inner]],
        colWidths=[CONTENT_WIDTH],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]),
    )


def split_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def build_table(rows: list[list[str]]):
    header, body = rows[0], rows[1:]
    ncols = len(header)

    # Column widths proportional to the widest cell, so a narrow "Sev" column
    # does not get the same space as a prose column.
    weights = []
    for col in range(ncols):
        longest = max([len(header[col])] +
                      [len(r[col]) for r in body if col < len(r)] or [1])
        weights.append(max(longest, 6))
    total = sum(weights)
    widths = [CONTENT_WIDTH * w / total for w in weights]

    data = [[Paragraph(inline(c), ST["th"]) for c in header]]
    for row in body:
        padded = row + [""] * (ncols - len(row))
        data.append([Paragraph(inline(c), ST["td"]) for c in padded[:ncols]])

    return Table(
        data,
        colWidths=widths,
        repeatRows=1,
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f7f9fb")]),
            ("GRID", (0, 0), (-1, -1), 0.4, RULE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]),
    )


def convert(md: str) -> list:
    flow, lines, i = [], md.splitlines(), 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # fenced code
        if stripped.startswith("```"):
            i += 1
            buffer = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buffer.append(lines[i])
                i += 1
            i += 1
            flow.append(code_block(buffer))
            flow.append(Spacer(1, 7))
            continue

        # tables
        if stripped.startswith("|") and i + 1 < len(lines) and \
                set(lines[i + 1].strip()) <= set("|-: "):
            rows = [split_row(stripped)]
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            flow.append(build_table(rows))
            flow.append(Spacer(1, 9))
            continue

        # horizontal rule / page break
        if stripped in ("---", "***", "___"):
            flow.append(Spacer(1, 3))
            flow.append(HRFlowable(width="100%", thickness=0.6, color=RULE,
                                   spaceBefore=2, spaceAfter=8))
            i += 1
            continue

        # headings
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            text = stripped[level:].strip()
            key = {1: "h1", 2: "h2", 3: "h3"}.get(level, "h3")
            para = Paragraph(inline(text), ST[key])
            # Keep a heading with whatever follows it rather than stranding it
            # at the foot of a page.
            flow.append(KeepTogether([para, Spacer(1, 1)]) if key != "h1"
                        else para)
            i += 1
            continue

        # block quote
        if stripped.startswith(">"):
            buffer = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                buffer.append(lines[i].strip().lstrip(">").strip())
                i += 1
            flow.append(Paragraph(inline(" ".join(buffer)), ST["quote"]))
            continue

        # lists (bulleted, numbered, checkbox)
        bullet_re = re.compile(r"^\s*[-*+]\s+(.*)$")
        number_re = re.compile(r"^\s*\d+[.)]\s+(.*)$")
        if bullet_re.match(line) or number_re.match(line):
            numbered = bool(number_re.match(line))
            items = []
            while i < len(lines):
                current = lines[i]
                match = (number_re.match(current) if numbered
                         else bullet_re.match(current))
                if not match:
                    # a wrapped continuation line belongs to the last item
                    if (items and current.strip()
                            and current.startswith((" ", "\t"))
                            and not current.strip().startswith(("-", "*", "|"))):
                        items[-1] += " " + current.strip()
                        i += 1
                        continue
                    break
                text = match.group(1)
                text = re.sub(r"^\[[ xX]\]\s*", "☐ ", text)
                items.append(text)
                i += 1
            flow.append(
                ListFlowable(
                    [ListItem(Paragraph(inline(t), ST["bullet"]),
                              leftIndent=14) for t in items],
                    bulletType="1" if numbered else "bullet",
                    bulletFontSize=8 if not numbered else 9.6,
                    start="1" if numbered else None,
                    leftIndent=12,
                )
            )
            flow.append(Spacer(1, 6))
            continue

        # paragraph: join until a blank line or a block starter
        buffer = []
        while i < len(lines) and lines[i].strip() and not \
                lines[i].strip().startswith(("#", "```", "|", ">", "---")) and not \
                bullet_re.match(lines[i]) and not number_re.match(lines[i]):
            buffer.append(lines[i].strip())
            i += 1
        if buffer:
            flow.append(Paragraph(inline(" ".join(buffer)), ST["body"]))

    return flow


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(SANS, 7.6)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, 11 * mm, doc.title)
    canvas.drawRightString(PAGE_WIDTH - MARGIN, 11 * mm,
                           f"Page {canvas.getPageNumber()}")
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(MARGIN, 14 * mm, PAGE_WIDTH - MARGIN, 14 * mm)
    canvas.restoreState()


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2

    source, target = argv[1], argv[2]
    md = open(source, encoding="utf-8").read()

    first = next((l for l in md.splitlines() if l.startswith("# ")), source)
    title = first.lstrip("#").strip()

    doc = SimpleDocTemplate(
        target, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=22 * mm,
        title=title, author="IaCGuard",
    )
    doc.build(convert(md), onFirstPage=footer, onLaterPages=footer)
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
