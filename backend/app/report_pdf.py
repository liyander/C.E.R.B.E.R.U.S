"""Render an analyst report (markdown) as a PDF for emailing.

Uses fpdf2. A Unicode system font is used when one is found; otherwise the
built-in Latin-1 fonts are used and unsupported characters become "?".
"""
import logging
import re
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

# fontTools is chatty about font tables it leaves out when embedding a subset.
logging.getLogger("fontTools").setLevel(logging.ERROR)

INK = (12, 23, 25)
NAVY = (29, 45, 61)
BODY = (45, 58, 61)
QUIET = (107, 124, 127)
RULE = (223, 230, 231)
ACCENT = (15, 118, 110)
PANEL = (244, 247, 247)
LOGO = Path(__file__).parent / "assets" / "logo.png"
BRAND_FONT = Path(__file__).parent / "assets" / "fonts" / "BarlowCondensed-SemiBold.ttf"

# (regular, bold, italic, monospace) - first complete set that exists wins
FONT_SETS = [
    ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/segoeuii.ttf", "C:/Windows/Fonts/consola.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
     "/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf", "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"),
]
LIST_RE = re.compile(r"^(\s*)([-*+•]|\d+[.)])\s+(.*)")
SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
INLINE_RE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


class _Report(FPDF):
    base = "Helvetica"
    mono = "Courier"
    unicode_ok = False
    footer_text = ""

    def clean(self, text) -> str:
        text = re.sub(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", r"\1 (\2)", str(text))
        return text if self.unicode_ok else text.encode("latin-1", "replace").decode("latin-1")

    def footer(self):
        self.set_y(-13)
        self.set_font(self.base, size=8)
        self.set_text_color(*QUIET)
        self.cell(0, 6, self.clean(f"{self.footer_text}   |   Page {self.page_no()} of {{nb}}"), align="C")

    def inline(self, text: str, size: float = 10.5, line: float = 5.6) -> None:
        """Flowing text with **bold** and `code` spans."""
        for seg in INLINE_RE.split(text):
            if not seg:
                continue
            if seg.startswith("**"):
                self.set_font(self.base, "B", size)
                self.set_text_color(*INK)
                self.write(line, self.clean(seg[2:-2]))
            elif seg.startswith("`"):
                self.set_font(self.mono, "", size - 1)
                self.set_text_color(*ACCENT)
                self.write(line, self.clean(seg[1:-1]))
            else:
                self.set_font(self.base, "", size)
                self.set_text_color(*BODY)
                self.write(line, self.clean(seg))
        self.ln(line)


def _cells(line: str) -> list[str]:
    cells, cur, code = [], "", False
    for ch in line.strip():
        if ch == "`":
            code = not code
        if ch == "|" and not code:
            cells.append(cur)
            cur = ""
        else:
            cur += ch
    cells.append(cur)
    if cells and not cells[0].strip():
        cells.pop(0)
    if cells and not cells[-1].strip():
        cells.pop()
    return [re.sub(r"\*\*|`", "", c).strip() for c in cells]


def _new_pdf() -> _Report:
    pdf = _Report(format="A4")
    pdf.set_margins(18, 16, 18)
    pdf.set_auto_page_break(True, margin=18)
    for regular, bold, italic, mono in FONT_SETS:
        if all(Path(p).exists() for p in (regular, bold, italic, mono)):
            pdf.add_font("body", "", regular)
            pdf.add_font("body", "B", bold)
            pdf.add_font("body", "I", italic)
            pdf.add_font("code", "", mono)
            pdf.base, pdf.mono, pdf.unicode_ok = "body", "code", True
            break
    return pdf


def build(title: str, requested_by: str, generated: str, question: str, markdown: str) -> bytes:
    pdf = _new_pdf()
    pdf.footer_text = f"CERBERUS analyst report   |   {generated}"
    pdf.set_title(pdf.clean(title))
    pdf.set_author("CERBERUS")
    pdf.add_page()
    width = pdf.epw

    # Cover band
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, 30, style="F")
    pdf.set_fill_color(*ACCENT)
    pdf.rect(0, 30, pdf.w, 1.4, style="F")
    if LOGO.exists():
        pdf.image(str(LOGO), x=18, y=8, w=14)
    pdf.set_xy(36, 8.5)
    pdf.set_text_color(242, 242, 243)
    if BRAND_FONT.exists():
        pdf.add_font("brand", "", str(BRAND_FONT))
        pdf.set_font("brand", "", 21)
        pdf.set_char_spacing(2.1)
        pdf.cell(60, 8, "CERBERUS", new_x=XPos.LEFT, new_y=YPos.NEXT)
        pdf.set_char_spacing(0)
    else:
        pdf.set_font(pdf.base, "B", 14)
        pdf.cell(60, 8, "C E R B E R U S", new_x=XPos.LEFT, new_y=YPos.NEXT)
    pdf.set_font(pdf.base, "", 8.5)
    pdf.set_text_color(143, 163, 166)
    pdf.cell(60, 5, "Security operations")
    pdf.set_xy(pdf.w - 78, 12)
    pdf.set_font(pdf.base, "B", 9)
    pdf.set_text_color(127, 224, 208)
    pdf.cell(60, 6, "ANALYST REPORT", align="R")

    pdf.set_xy(18, 40)
    pdf.set_font(pdf.base, "B", 20)
    pdf.set_text_color(*INK)
    pdf.multi_cell(width, 9, pdf.clean(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    pdf.set_font(pdf.base, "", 9.5)
    pdf.set_text_color(*QUIET)
    pdf.cell(width, 5, pdf.clean(f"Requested by {requested_by}   |   Generated {generated}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if question:
        pdf.ln(4)
        pdf.set_fill_color(*PANEL)
        pdf.set_font(pdf.base, "B", 8)
        pdf.cell(width, 6, "  QUESTION", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(pdf.base, "", 10.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(width, 5.6, pdf.clean("  " + " ".join(question.split())[:600]), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(width, 2, "", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)

    lines = str(markdown or "").replace("\r", "").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        pdf.set_left_margin(18)
        pdf.set_x(18)
        if line.strip().startswith("```"):
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            pdf.set_font(pdf.mono, "", 9)
            pdf.set_text_color(*INK)
            pdf.set_fill_color(*PANEL)
            pdf.multi_cell(width, 4.8, pdf.clean("\n".join(block) or " "), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)
        elif "|" in line and i + 1 < len(lines) and "-" in lines[i + 1] and SEP_RE.match(lines[i + 1]):
            head = _cells(line)
            rows = []
            i += 2
            while i < len(lines) and lines[i].strip() and "|" in lines[i]:
                rows.append(_cells(lines[i]))
                i += 1
            i -= 1
            pdf.set_font(pdf.base, "", 9.5)
            pdf.set_text_color(*INK)
            pdf.set_draw_color(*RULE)
            with pdf.table(width=width, line_height=6, text_align="LEFT", borders_layout="HORIZONTAL_LINES", padding=1.2,
                           headings_style=FontFace(emphasis="BOLD", color=INK, fill_color=PANEL)) as table:
                table.row([pdf.clean(c) for c in head])
                for row in rows:
                    table.row([pdf.clean(row[k] if k < len(row) else "") for k in range(len(head))])
            pdf.ln(4)
        elif not line.strip():
            pdf.ln(1.5)
        elif m := re.match(r"^\s*(#{1,6})\s+(.*?)\s*#*\s*$", line):
            big = len(m[1]) <= 2
            pdf.ln(3 if big else 2)
            pdf.set_font(pdf.base, "B", 14 if big else 11.5)
            pdf.set_text_color(*INK)
            pdf.multi_cell(width, 7 if big else 6, pdf.clean(re.sub(r"\*\*|`", "", m[2])), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if big:
                pdf.set_draw_color(*RULE)
                pdf.line(18, pdf.get_y() + 0.5, 18 + width, pdf.get_y() + 0.5)
            pdf.ln(2)
        elif re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line):
            pdf.ln(2)
            pdf.set_draw_color(*RULE)
            pdf.line(18, pdf.get_y(), 18 + width, pdf.get_y())
            pdf.ln(3)
        elif line.lstrip().startswith(">"):
            top = pdf.get_y()
            pdf.set_left_margin(24)
            pdf.set_x(24)
            pdf.inline(line.lstrip()[1:].strip())
            pdf.set_draw_color(*ACCENT)
            pdf.set_line_width(0.8)
            pdf.line(20, top, 20, pdf.get_y())
            pdf.set_line_width(0.2)
            pdf.ln(1.5)
        elif m := LIST_RE.match(line):
            indent = 18 + 4 + len(m[1].replace("\t", "    ")) // 2 * 5
            marker = m[2] if m[2][0].isdigit() else ("•" if pdf.unicode_ok else "-")
            pdf.set_x(indent)
            pdf.set_font(pdf.base, "", 10.5)
            pdf.set_text_color(*QUIET)
            pdf.cell(6, 5.6, pdf.clean(marker))
            pdf.set_left_margin(indent + 6)
            pdf.set_x(indent + 6)
            pdf.inline(m[3])
            pdf.ln(0.6)
        else:
            pdf.inline(line.strip())
            pdf.ln(1)
        i += 1
    return bytes(pdf.output())
