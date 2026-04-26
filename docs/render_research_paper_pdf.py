from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from PIL import Image, ImageDraw, ImageFont


DPI = 200
PAGE_WIDTH = 1654
PAGE_HEIGHT = 2339
MARGIN_X = 105
MARGIN_TOP = 72
MARGIN_BOTTOM = 95
COLUMN_GAP = 58
COLUMN_WIDTH = (PAGE_WIDTH - (2 * MARGIN_X) - COLUMN_GAP) // 2
BODY_BOTTOM_FIRST = PAGE_HEIGHT - 180
BODY_BOTTOM_OTHER = PAGE_HEIGHT - MARGIN_BOTTOM
PT_SCALE = DPI / 72

BASE_DIR = Path("/Users/macbookair/Python/AI&DS6/ai_containment/docs")
OUTPUT_PDF = BASE_DIR / "research_paper_ai_containment_journal.pdf"

TIMES = "/System/Library/Fonts/Supplemental/Times New Roman.ttf"
TIMES_BOLD = "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf"
TIMES_ITALIC = "/System/Library/Fonts/Supplemental/Times New Roman Italic.ttf"
TIMES_BOLD_ITALIC = "/System/Library/Fonts/Supplemental/Times New Roman Bold Italic.ttf"
ARIAL = "/System/Library/Fonts/Supplemental/Arial.ttf"
ARIAL_BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"


def px(points: float) -> int:
    return int(round(points * PT_SCALE))


def make_font(path: str, size_pt: float) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, px(size_pt))


FONTS = {
    "title": make_font(TIMES, 22.5),
    "authors": make_font(TIMES_BOLD, 11.5),
    "affiliation": make_font(TIMES_ITALIC, 10.0),
    "emails": make_font(TIMES, 9.2),
    "header": make_font(TIMES_BOLD, 9.4),
    "body": make_font(TIMES, 9.3),
    "body_bold": make_font(TIMES_BOLD, 9.3),
    "body_italic": make_font(TIMES_ITALIC, 9.2),
    "section": make_font(TIMES_BOLD, 10.6),
    "subsection": make_font(TIMES_BOLD, 9.5),
    "caption": make_font(TIMES, 8.4),
    "caption_bold": make_font(TIMES_BOLD, 8.4),
    "small": make_font(TIMES, 8.2),
    "small_bold": make_font(TIMES_BOLD, 8.2),
    "tiny": make_font(TIMES, 7.4),
    "tiny_bold": make_font(TIMES_BOLD, 7.4),
    "arial_small": make_font(ARIAL, 7.4),
    "arial_small_bold": make_font(ARIAL_BOLD, 8.1),
    "arial_label": make_font(ARIAL_BOLD, 10.2),
}


def text_width(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont) -> float:
    return draw.textlength(text, font=font)


def line_height(font: ImageFont.FreeTypeFont, extra: int = 0) -> int:
    bbox = font.getbbox("Ag")
    return (bbox[3] - bbox[1]) + extra


def wrap_words(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
    max_width: int,
) -> list[str]:
    words = text.split()
    if not words:
        return [""]

    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if text_width(draw, candidate, font) <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def draw_justified_line(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: str,
    width: int,
) -> None:
    words = text.split()
    if len(words) <= 1:
        draw.text((x, y), text, font=font, fill=fill)
        return

    word_widths = [text_width(draw, word, font) for word in words]
    total_words = sum(word_widths)
    normal_space = text_width(draw, " ", font)
    free_space = width - total_words
    gaps = len(words) - 1
    if gaps <= 0 or free_space <= normal_space * gaps:
        draw.text((x, y), text, font=font, fill=fill)
        return

    extra = (free_space - (normal_space * gaps)) / gaps
    cursor = x
    for idx, word in enumerate(words):
        draw.text((cursor, y), word, font=font, fill=fill)
        cursor += word_widths[idx]
        if idx < gaps:
            cursor += normal_space + extra


def draw_centered_wrapped_text(
    draw: ImageDraw.ImageDraw,
    x0: int,
    x1: int,
    y: int,
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: str = "#111111",
    line_extra: int = 2,
) -> int:
    width = x1 - x0
    lines = wrap_words(draw, text, font, width - 18)
    line_h = line_height(font, line_extra)
    for line in lines:
        tw = text_width(draw, line, font)
        draw.text((x0 + (width - tw) / 2, y), line, font=font, fill=fill)
        y += line_h
    return y


def draw_left_wrapped_text(
    draw: ImageDraw.ImageDraw,
    x0: int,
    x1: int,
    y: int,
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: str = "#111111",
    line_extra: int = 1,
) -> int:
    width = x1 - x0
    line_h = line_height(font, line_extra)
    for line in wrap_words(draw, text, font, width):
        draw.text((x0, y), line, font=font, fill=fill)
        y += line_h
    return y


def measure_wrapped_paragraph(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
    width: int,
    indent_px: int,
    spacing_after: int,
    line_extra: int = 4,
) -> int:
    line_h = line_height(font, line_extra)
    lines = wrap_words(draw, text, font, width - 6)
    return (len(lines) * line_h) + spacing_after


def draw_wrapped_paragraph(
    draw: ImageDraw.ImageDraw,
    x0: int,
    y: int,
    width: int,
    text: str,
    font: ImageFont.FreeTypeFont,
    indent_px: int,
    spacing_after: int,
    justify: bool,
    fill: str = "#111111",
    line_extra: int = 4,
) -> int:
    line_h = line_height(font, line_extra)
    lines = wrap_words(draw, text, font, width - 6)
    for idx, line in enumerate(lines):
        first_line = idx == 0
        line_x = x0 + (indent_px if first_line and indent_px else 0)
        line_width = width - (indent_px if first_line and indent_px else 0)
        if justify and idx < len(lines) - 1 and len(line.split()) > 1:
            draw_justified_line(draw, line_x, y, line, font, fill, line_width)
        else:
            draw.text((line_x, y), line, font=font, fill=fill)
        y += line_h
    return y + spacing_after


@dataclass
class TableSpec:
    title: str
    headers: list[str]
    rows: list[list[str]]
    col_widths: list[float]
    description: str = ""


class PaperRenderer:
    def __init__(self) -> None:
        self.pages: list[Image.Image] = []
        self.page_number = 0
        self.page: Image.Image | None = None
        self.draw: ImageDraw.ImageDraw | None = None
        self.body_top = 0
        self.body_bottom = 0
        self.column_index = 0
        self.cursor_y = 0
        self.left_column_bottom = 0
        self._new_page(first_page=True)

    @property
    def column_x(self) -> int:
        if self.column_index == 0:
            return MARGIN_X
        return MARGIN_X + COLUMN_WIDTH + COLUMN_GAP

    def _new_page(self, first_page: bool = False) -> None:
        self.page_number += 1
        page = Image.new("RGB", (PAGE_WIDTH, PAGE_HEIGHT), "white")
        draw = ImageDraw.Draw(page)
        self._draw_running_header(draw, first_page)
        self.pages.append(page)
        self.page = page
        self.draw = draw
        self.column_index = 0
        self.body_top = self._draw_first_page_header(draw) if first_page else px(52)
        self.body_bottom = BODY_BOTTOM_FIRST if first_page else BODY_BOTTOM_OTHER
        self.cursor_y = self.body_top
        self.left_column_bottom = self.body_top

    def _draw_running_header(self, draw: ImageDraw.ImageDraw, first_page: bool) -> None:
        if first_page:
            return
        header = "National Security AI-Containment System"
        header_y = px(12)
        draw.text(
            ((PAGE_WIDTH - text_width(draw, header, FONTS["small_bold"])) / 2, header_y),
            header,
            font=FONTS["small_bold"],
            fill="#222222",
        )
        draw.line((MARGIN_X, px(28), PAGE_WIDTH - MARGIN_X, px(28)), fill="#b8b8b8", width=1)
        page_label = f"{self.page_number}"
        draw.text(
            (PAGE_WIDTH - MARGIN_X - text_width(draw, page_label, FONTS["small"]), header_y),
            page_label,
            font=FONTS["small"],
            fill="#444444",
        )

    def _draw_first_page_header(self, draw: ImageDraw.ImageDraw) -> int:
        y = MARGIN_TOP
        oa_font = FONTS["arial_small_bold"]
        draw.text((MARGIN_X - 42, y + 5), "OPEN", font=oa_font, fill="#c84d08")
        draw.text((MARGIN_X - 42, y + 20), "ACCESS", font=oa_font, fill="#c84d08")
        ring_x = MARGIN_X - 6
        draw.ellipse((ring_x, y + 1, ring_x + 26, y + 27), outline="#c84d08", width=3)
        draw.arc((ring_x + 4, y - 7, ring_x + 21, y + 10), start=180, end=360, fill="#c84d08", width=3)

        header_1 = "Journal-Style Research Manuscript"
        header_2 = "Secure AI Systems and National Security Applications, April 2026"
        draw.text(
            ((PAGE_WIDTH - text_width(draw, header_1, FONTS["header"])) / 2, y),
            header_1,
            font=FONTS["header"],
            fill="#111111",
        )
        draw.text(
            ((PAGE_WIDTH - text_width(draw, header_2, FONTS["header"])) / 2, y + 18),
            header_2,
            font=FONTS["header"],
            fill="#111111",
        )

        box_x = PAGE_WIDTH - MARGIN_X + 5 - 65
        box_y = y - 6
        draw.rectangle((box_x, box_y, box_x + 62, box_y + 66), outline="#9d9d9d", width=1)
        draw.ellipse((box_x + 17, box_y + 8, box_x + 45, box_y + 36), fill="#ffffff", outline="#d0d0d0", width=2)
        draw.pieslice((box_x + 19, box_y + 10, box_x + 43, box_y + 34), 40, 220, fill="#f26a2d")
        draw.pieslice((box_x + 19, box_y + 10, box_x + 43, box_y + 34), 220, 400, fill="#30a8df")
        draw.text((box_x + 10, box_y + 40), "Check for", font=FONTS["arial_small"], fill="#444444")
        draw.text((box_x + 16, box_y + 52), "Updates", font=FONTS["arial_small"], fill="#444444")

        title = (
            "National Security AI-Containment System:\n"
            "A Multi-Layer Architecture for Behavioral\n"
            "Monitoring, Threat Detection and Fail-\n"
            "Closed Mediation of Large Language\n"
            "Models"
        )
        title_y = y + 78
        for idx, line in enumerate(title.splitlines()):
            draw.text(
                ((PAGE_WIDTH - text_width(draw, line, FONTS["title"])) / 2, title_y + idx * px(20.5)),
                line,
                font=FONTS["title"],
                fill="#111111",
            )

        authors = "Aryan Pathania, Aryan Sharma"
        aff = "CGC University, Mohali, Punjab, India"
        emails = "pathaniaaryan169@gmail.com, aryansharma2004march@gmail.com"
        meta_y = title_y + (len(title.splitlines()) * px(20.5)) + 18
        draw.text(
            ((PAGE_WIDTH - text_width(draw, authors, FONTS["authors"])) / 2, meta_y),
            authors,
            font=FONTS["authors"],
            fill="#111111",
        )
        draw.text(
            ((PAGE_WIDTH - text_width(draw, aff, FONTS["affiliation"])) / 2, meta_y + 26),
            aff,
            font=FONTS["affiliation"],
            fill="#111111",
        )
        draw.text(
            ((PAGE_WIDTH - text_width(draw, emails, FONTS["emails"])) / 2, meta_y + 48),
            emails,
            font=FONTS["emails"],
            fill="#1544a8",
        )
        return meta_y + 92

    def ensure_space(self, needed_height: int) -> None:
        if self.cursor_y + needed_height <= self.body_bottom:
            return
        if self.column_index == 0:
            self.left_column_bottom = self.cursor_y
            self.column_index = 1
            self.cursor_y = self.body_top
            return
        self._new_page(first_page=False)

    def add_heading(self, text: str) -> None:
        assert self.draw is not None
        height = line_height(FONTS["section"], px(2)) + 8
        self.ensure_space(height)
        x = self.column_x
        width = COLUMN_WIDTH
        tw = text_width(self.draw, text, FONTS["section"])
        self.draw.text((x + (width - tw) / 2, self.cursor_y), text, font=FONTS["section"], fill="#111111")
        self.cursor_y += height

    def add_subheading(self, text: str) -> None:
        assert self.draw is not None
        height = line_height(FONTS["subsection"], px(2)) + 4
        self.ensure_space(height)
        self.draw.text((self.column_x, self.cursor_y), text, font=FONTS["subsection"], fill="#111111")
        self.cursor_y += height

    def add_paragraph(
        self,
        text: str,
        font_key: str = "body",
        bold_prefix: str | None = None,
        italic_prefix: str | None = None,
        indent: int | None = None,
        spacing_after: int = 9,
        justify: bool = True,
        fill: str = "#111111",
    ) -> None:
        assert self.draw is not None
        font = FONTS[font_key]
        indent_px = px(13) if indent is None else indent
        estimated = measure_wrapped_paragraph(
            self.draw,
            text,
            font,
            COLUMN_WIDTH,
            indent_px,
            spacing_after,
        )
        self.ensure_space(estimated)
        self.cursor_y = draw_wrapped_paragraph(
            self.draw,
            self.column_x,
            self.cursor_y,
            COLUMN_WIDTH,
            text,
            font,
            indent_px,
            spacing_after,
            justify,
            fill=fill,
        )

    def add_note_box(self, lines: list[str]) -> None:
        assert self.draw is not None
        box_padding = 10
        inner_width = COLUMN_WIDTH - (2 * box_padding) - 18
        wrapped_lines: list[tuple[str, ImageFont.FreeTypeFont, str]] = []
        for idx, line in enumerate(lines):
            font = FONTS["small_bold"] if idx == 0 else FONTS["small"]
            color = "#9b2500" if idx == 0 else "#111111"
            for wrapped in wrap_words(self.draw, line, font, inner_width):
                wrapped_lines.append((wrapped, font, color))
        box_height = (len(wrapped_lines) * line_height(FONTS["small"], 2)) + (2 * box_padding) + 8
        self.ensure_space(box_height + 10)
        x0 = self.column_x
        x1 = self.column_x + COLUMN_WIDTH
        y0 = self.cursor_y
        y1 = self.cursor_y + box_height
        self.draw.rectangle((x0, y0, x1, y1), fill="#fbefcc", outline="#ddbf67", width=2)
        y = y0 + box_padding
        for line, font, color in wrapped_lines:
            self.draw.text((x0 + box_padding, y), line, font=font, fill=color)
            y += line_height(font, 2)
        self.cursor_y = y1 + 10

    def add_equation(self, text: str) -> None:
        assert self.draw is not None
        font = FONTS["body_italic"]
        height = line_height(font, 4) + 10
        self.ensure_space(height)
        x = self.column_x
        width = COLUMN_WIDTH
        tw = text_width(self.draw, text, font)
        self.draw.text((x + (width - tw) / 2, self.cursor_y), text, font=font, fill="#111111")
        self.cursor_y += height

    def _current_flow_bottom(self) -> int:
        if self.column_index == 0:
            return self.cursor_y
        return max(self.left_column_bottom, self.cursor_y)

    def start_full_width_block(self, block_height: int) -> int:
        block_top = self._current_flow_bottom() + 10
        if block_top + block_height <= self.body_bottom:
            return block_top
        self._new_page(first_page=False)
        return self.body_top + 10

    def finish_full_width_block(self, bottom_y: int) -> None:
        self.body_top = bottom_y + 24
        self.column_index = 0
        self.cursor_y = self.body_top
        self.left_column_bottom = self.body_top

    def add_full_width_figure(
        self,
        drawer: Callable[[ImageDraw.ImageDraw, int], int],
        block_height: int,
    ) -> None:
        assert self.draw is not None
        top_y = self.start_full_width_block(block_height)
        bottom_y = drawer(self.draw, top_y)
        self.finish_full_width_block(bottom_y)

    def add_full_width_table(self, spec: TableSpec) -> None:
        assert self.draw is not None
        top_y = self.start_full_width_block(self._measure_table_height(spec))
        bottom_y = self._draw_table(self.draw, top_y, spec)
        self.finish_full_width_block(bottom_y)

    def add_full_width_story(self, items: list[dict[str, object]]) -> None:
        assert self.draw is not None
        full_width = PAGE_WIDTH - (2 * MARGIN_X)
        story_height = 0
        for item in items:
            kind = str(item["kind"])
            if kind == "heading":
                story_height += line_height(FONTS["section"], px(2)) + 8
            elif kind == "subheading":
                story_height += line_height(FONTS["subsection"], px(2)) + 4
            elif kind == "paragraph":
                font_key = str(item.get("font_key", "body"))
                indent_px = int(item.get("indent", px(13)))
                spacing_after = int(item.get("spacing_after", 9))
                story_height += measure_wrapped_paragraph(
                    self.draw,
                    str(item["text"]),
                    FONTS[font_key],
                    full_width,
                    indent_px,
                    spacing_after,
                )

        top_y = self.start_full_width_block(story_height)
        y = top_y
        for item in items:
            kind = str(item["kind"])
            text = str(item["text"])
            if kind == "heading":
                tw = text_width(self.draw, text, FONTS["section"])
                self.draw.text(
                    (MARGIN_X + (full_width - tw) / 2, y),
                    text,
                    font=FONTS["section"],
                    fill="#111111",
                )
                y += line_height(FONTS["section"], px(2)) + 8
            elif kind == "subheading":
                self.draw.text((MARGIN_X, y), text, font=FONTS["subsection"], fill="#111111")
                y += line_height(FONTS["subsection"], px(2)) + 4
            elif kind == "paragraph":
                font_key = str(item.get("font_key", "body"))
                indent_px = int(item.get("indent", px(13)))
                spacing_after = int(item.get("spacing_after", 9))
                justify = bool(item.get("justify", True))
                y = draw_wrapped_paragraph(
                    self.draw,
                    MARGIN_X,
                    y,
                    full_width,
                    text,
                    FONTS[font_key],
                    indent_px,
                    spacing_after,
                    justify,
                )
        self.finish_full_width_block(y)

    def _measure_table_height(self, spec: TableSpec) -> int:
        assert self.draw is not None
        table_width = PAGE_WIDTH - (2 * MARGIN_X)
        col_px = [int(table_width * ratio) for ratio in spec.col_widths]
        diff = table_width - sum(col_px)
        if diff:
            col_px[-1] += diff

        height = 34 + 34
        for row in spec.rows:
            max_lines = 1
            for idx, cell in enumerate(row):
                cell_lines = wrap_words(self.draw, cell, FONTS["small"], col_px[idx] - 12)
                max_lines = max(max_lines, len(cell_lines))
            height += max_lines * line_height(FONTS["small"], 2) + 14
        return height + 8

    def _draw_table(self, draw: ImageDraw.ImageDraw, top_y: int, spec: TableSpec) -> int:
        x0 = MARGIN_X
        x1 = PAGE_WIDTH - MARGIN_X
        draw.rectangle((x0, top_y, x1, top_y + 34), outline="#bdbdbd", fill="#efefef", width=1)
        title_font = FONTS["small_bold"]
        tw = text_width(draw, spec.title, title_font)
        draw.text((x0 + ((x1 - x0) - tw) / 2, top_y + 8), spec.title, font=title_font, fill="#111111")

        col_px = [int((x1 - x0) * ratio) for ratio in spec.col_widths]
        diff = (x1 - x0) - sum(col_px)
        if diff:
            col_px[-1] += diff

        y = top_y + 34
        row_h = 34
        col_x = x0
        for idx, header in enumerate(spec.headers):
            draw.rectangle((col_x, y, col_x + col_px[idx], y + row_h), outline="#bdbdbd", fill="#f3f3f3", width=1)
            hx = col_x + 6
            hy = y + 8
            draw.text((hx, hy), header, font=FONTS["small_bold"], fill="#111111")
            col_x += col_px[idx]
        y += row_h

        for row in spec.rows:
            wrapped_cells: list[list[str]] = []
            max_lines = 1
            for idx, cell in enumerate(row):
                cell_lines = wrap_words(draw, cell, FONTS["small"], col_px[idx] - 12)
                wrapped_cells.append(cell_lines)
                max_lines = max(max_lines, len(cell_lines))
            row_height = max_lines * line_height(FONTS["small"], 2) + 14
            col_x = x0
            for idx, cell_lines in enumerate(wrapped_cells):
                draw.rectangle((col_x, y, col_x + col_px[idx], y + row_height), outline="#bdbdbd", fill="#ffffff", width=1)
                cy = y + 7
                for line in cell_lines:
                    draw.text((col_x + 6, cy), line, font=FONTS["small"], fill="#111111")
                    cy += line_height(FONTS["small"], 2)
                col_x += col_px[idx]
            y += row_height
        return y + 8

    def add_references(self, items: list[str]) -> None:
        for idx, item in enumerate(items, start=1):
            prefix = f"[{idx}] "
            text = prefix + item
            self.add_paragraph(text, font_key="small", indent=0, spacing_after=6, justify=False)

    def force_new_page(self) -> None:
        self._new_page(first_page=False)

    def add_column_figure(
        self,
        drawer: Callable[[ImageDraw.ImageDraw, int, int, int], int],
        estimated_height: int,
    ) -> None:
        assert self.draw is not None
        self.ensure_space(estimated_height)
        self.cursor_y = drawer(self.draw, self.column_x, self.cursor_y, COLUMN_WIDTH) + 12

    def add_column_table(self, spec: TableSpec) -> None:
        assert self.draw is not None
        height = self._measure_table_height_at(spec, COLUMN_WIDTH)
        self.ensure_space(height)
        self.cursor_y = self._draw_table_at(self.draw, self.column_x, self.cursor_y, COLUMN_WIDTH, spec) + 12

    def _measure_table_height_at(self, spec: TableSpec, width: int) -> int:
        assert self.draw is not None
        col_px = [int(width * ratio) for ratio in spec.col_widths]
        diff = width - sum(col_px)
        if diff:
            col_px[-1] += diff

        header_font = FONTS["tiny_bold"] if width <= COLUMN_WIDTH else FONTS["small_bold"]
        cell_font = FONTS["tiny"] if width <= COLUMN_WIDTH else FONTS["small"]
        title_height = 30 if width <= COLUMN_WIDTH else 34
        header_height = 28 if width <= COLUMN_WIDTH else 34
        height = title_height + header_height

        for row in spec.rows:
            max_lines = 1
            for idx, cell in enumerate(row):
                lines = wrap_words(self.draw, cell, cell_font, col_px[idx] - 10)
                max_lines = max(max_lines, len(lines))
            height += max_lines * line_height(cell_font, 1) + 10

        if spec.description:
            desc_lines = wrap_words(self.draw, spec.description, FONTS["caption"], width - 8)
            height += (len(desc_lines) * line_height(FONTS["caption"], 1)) + 10
        return height

    def _draw_table_at(
        self,
        draw: ImageDraw.ImageDraw,
        x0: int,
        top_y: int,
        width: int,
        spec: TableSpec,
    ) -> int:
        x1 = x0 + width
        title_font = FONTS["tiny_bold"] if width <= COLUMN_WIDTH else FONTS["small_bold"]
        header_font = FONTS["tiny_bold"] if width <= COLUMN_WIDTH else FONTS["small_bold"]
        cell_font = FONTS["tiny"] if width <= COLUMN_WIDTH else FONTS["small"]
        title_height = 30 if width <= COLUMN_WIDTH else 34
        header_height = 28 if width <= COLUMN_WIDTH else 34

        draw.rectangle((x0, top_y, x1, top_y + title_height), outline="#bdbdbd", fill="#efefef", width=1)
        tw = text_width(draw, spec.title, title_font)
        draw.text((x0 + ((width - tw) / 2), top_y + 7), spec.title, font=title_font, fill="#111111")

        col_px = [int(width * ratio) for ratio in spec.col_widths]
        diff = width - sum(col_px)
        if diff:
            col_px[-1] += diff

        y = top_y + title_height
        col_x = x0
        for idx, header in enumerate(spec.headers):
            draw.rectangle((col_x, y, col_x + col_px[idx], y + header_height), outline="#bdbdbd", fill="#f3f3f3", width=1)
            hy = y + 6
            for line in wrap_words(draw, header, header_font, col_px[idx] - 10):
                draw.text((col_x + 5, hy), line, font=header_font, fill="#111111")
                hy += line_height(header_font, 0)
            col_x += col_px[idx]
        y += header_height

        for row in spec.rows:
            wrapped_cells: list[list[str]] = []
            max_lines = 1
            for idx, cell in enumerate(row):
                cell_lines = wrap_words(draw, cell, cell_font, col_px[idx] - 10)
                wrapped_cells.append(cell_lines)
                max_lines = max(max_lines, len(cell_lines))
            row_height = max_lines * line_height(cell_font, 1) + 10
            col_x = x0
            for idx, cell_lines in enumerate(wrapped_cells):
                draw.rectangle((col_x, y, col_x + col_px[idx], y + row_height), outline="#d2d2d2", fill="#ffffff", width=1)
                cy = y + 5
                for line in cell_lines:
                    draw.text((col_x + 5, cy), line, font=cell_font, fill="#111111")
                    cy += line_height(cell_font, 1)
                col_x += col_px[idx]
            y += row_height

        if spec.description:
            y += 4
            for line in wrap_words(draw, spec.description, FONTS["caption"], width - 8):
                draw.text((x0 + 3, y), line, font=FONTS["caption"], fill="#222222")
                y += line_height(FONTS["caption"], 1)
        return y

    def finalize(self) -> None:
        assert self.pages
        first = self.pages[0]
        footer_y = PAGE_HEIGHT - 118
        draw = ImageDraw.Draw(first)
        draw.line((MARGIN_X, footer_y - 12, PAGE_WIDTH - MARGIN_X, footer_y - 12), fill="#cfcfcf", width=1)
        left = "Manuscript Archive: AICS-0426/Workspace Edition\nTechnical style inspired by a journal-format sample."
        mid = "Prepared From:\nLocal ai_containment project workspace"
        draw.text((MARGIN_X, footer_y), left, font=FONTS["small"], fill="#222222")
        draw.text((PAGE_WIDTH // 2 + 60, footer_y), mid, font=FONTS["small"], fill="#222222")
        seal_x = PAGE_WIDTH - MARGIN_X - 96
        draw.ellipse((seal_x, footer_y - 24, seal_x + 70, footer_y + 46), outline="#c2332d", width=5, fill="#fff9f9")
        draw.rounded_rectangle((seal_x + 22, footer_y + 14, seal_x + 94, footer_y + 44), radius=14, outline="#5b5fb3", width=2, fill="#f2f2ff")
        draw.text((seal_x + 42, footer_y + 20), "AICS", font=FONTS["arial_label"], fill="#5b5fb3")

        self.pages[0].save(
            OUTPUT_PDF,
            "PDF",
            resolution=float(DPI),
            save_all=True,
            append_images=self.pages[1:],
        )


def figure_one(draw: ImageDraw.ImageDraw, top_y: int) -> int:
    x0 = MARGIN_X
    x1 = PAGE_WIDTH - MARGIN_X
    y1 = top_y + 320
    draw.rectangle((x0, top_y, x1, y1), outline="#bbbbbb", width=2)

    box_w = 420
    gap = 34
    heights = 232
    start_x = x0 + 18
    titles = [
        ("Layer 1: Contained AI", "#edf3fb", "#5a83b5", [
            "Mock, Ollama or OpenAI backend",
            "System prompt guardrail",
            "Kill-switch aware query gate",
            "Uniform response interface",
        ]),
        ("Layer 2: Sentinel Engine", "#f5f5f5", "#888888", [
            "Keyword and regex matching",
            "Semantic similarity anchors",
            "Entropy and ML classification",
            "Fail-closed blocking logic",
        ]),
        ("Layer 3: Command Center", "#eef8ef", "#5f9461", [
            "Dashboard and sandbox",
            "Policies, alerts and analytics",
            "Audit logs and threat details",
            "Human-in-the-loop intervention",
        ]),
    ]
    box_font = FONTS["subsection"]
    text_font = FONTS["small"]
    for idx, (title, fill, outline, lines) in enumerate(titles):
        bx0 = start_x + idx * (box_w + gap)
        bx1 = bx0 + box_w
        by0 = top_y + 34
        by1 = by0 + heights
        draw.rounded_rectangle((bx0, by0, bx1, by1), radius=12, fill=fill, outline=outline, width=3)
        tw = text_width(draw, title, box_font)
        draw.text((bx0 + (box_w - tw) / 2, by0 + 18), title, font=box_font, fill="#111111")
        ty = by0 + 60
        for line in lines:
            ltw = text_width(draw, line, text_font)
            draw.text((bx0 + (box_w - ltw) / 2, ty), line, font=text_font, fill="#111111")
            ty += 32

    band_y0 = top_y + 278
    band_y1 = band_y0 + 36
    draw.rounded_rectangle((x0 + 210, band_y0, x1 - 210, band_y1), radius=8, fill="#fff6e8", outline="#d2a561", width=2)
    band_text = "Shared persistence: logs, threat details, policies, kill-switch events and alerts"
    draw_centered_wrapped_text(draw, x0 + 214, x1 - 214, band_y0 + 7, band_text, FONTS["small_bold"], line_extra=0)

    caption = (
        "Fig. 1. Proposed Sentinel architecture. The deployment separates model access, "
        "hybrid threat mediation and operator oversight into independent but connected layers."
    )
    draw.text((x0 + 4, y1 + 10), caption, font=FONTS["caption"], fill="#111111")
    return y1 + 42


def figure_two(draw: ImageDraw.ImageDraw, top_y: int) -> int:
    x0 = MARGIN_X
    x1 = PAGE_WIDTH - MARGIN_X
    y1 = top_y + 258
    draw.rectangle((x0, top_y, x1, y1), outline="#bbbbbb", width=2)
    labels = [
        ("User Prompt", "session tagged", "#eef2f7", "#7088a4"),
        ("Input Scan", "rules + semantic + ML", "#fff6e8", "#c89845"),
        ("Policy Gate", "block or forward", "#f0f6ff", "#5f84c2"),
        ("Contained AI", "mock / ollama / API", "#fff6e8", "#c89845"),
        ("Output Scan", "redact and classify", "#eef8ef", "#5f9461"),
        ("Audit + Alert", "log, notify, display", "#f5f5f5", "#8b8b8b"),
    ]
    inner_margin = 24
    gap = 16
    box_w = ((x1 - x0) - (2 * inner_margin) - (gap * (len(labels) - 1))) // len(labels)
    start_x = x0 + inner_margin
    box_h = 80
    by0 = top_y + 58
    for idx, (title, subtitle, fill, outline) in enumerate(labels):
        bx0 = start_x + idx * (box_w + gap)
        bx1 = bx0 + box_w
        draw.rounded_rectangle((bx0, by0, bx1, by0 + box_h), radius=10, fill=fill, outline=outline, width=3)
        text_y = draw_centered_wrapped_text(draw, bx0, bx1, by0 + 12, title, FONTS["subsection"])
        draw_centered_wrapped_text(draw, bx0, bx1, text_y + 4, subtitle, FONTS["small"])
        if idx < len(labels) - 1:
            ax = bx1 + 5
            ay = by0 + 40
            draw.line((ax, ay, ax + 12, ay), fill="#777777", width=3)
            draw.polygon([(ax + 12, ay), (ax + 1, ay - 6), (ax + 1, ay + 6)], fill="#777777")

    branch = "Emergency branch: CRITICAL match or policy auto-kill triggers global kill switch"
    draw.rounded_rectangle((x0 + 270, top_y + 192, x1 - 270, top_y + 224), radius=8, fill="#fff0f0", outline="#be5b5b", width=2)
    draw_centered_wrapped_text(draw, x0 + 278, x1 - 278, top_y + 201, branch, FONTS["small_bold"], line_extra=0)

    caption = (
        "Fig. 2. Request mediation workflow. The same detector evaluates inbound prompts and "
        "outbound responses, while critical matches can trigger an emergency shutdown path."
    )
    draw.text((x0 + 4, y1 + 10), caption, font=FONTS["caption"], fill="#111111")
    return y1 + 42


def figure_three(draw: ImageDraw.ImageDraw, top_y: int) -> int:
    x0 = MARGIN_X
    x1 = PAGE_WIDTH - MARGIN_X
    y1 = top_y + 204
    draw.rectangle((x0, top_y, x1, y1), outline="#bbbbbb", width=2)
    steps = [
        ("Public corpora", "HF prompt, harm and safe sets", "#eef2f7", "#6f88a5"),
        ("Normalize + deduplicate", "labels, hashes, balancing", "#fff6e8", "#c89845"),
        ("TF-IDF + Logistic Regression", "1-2 grams, balanced classes", "#f1f7ff", "#6287c0"),
        ("Metrics + artifact", "accuracy, report, joblib", "#eef8ef", "#5f9461"),
        ("Runtime integration", "classifier loaded by engine", "#f8f8f8", "#8d8d8d"),
    ]
    inner_margin = 22
    gap = 14
    box_w = ((x1 - x0) - (2 * inner_margin) - (gap * (len(steps) - 1))) // len(steps)
    start_x = x0 + inner_margin
    by0 = top_y + 48
    for idx, (title, subtitle, fill, outline) in enumerate(steps):
        bx0 = start_x + idx * (box_w + gap)
        bx1 = bx0 + box_w
        box_h = 92 if idx == 4 else 74
        draw.rounded_rectangle((bx0, by0, bx1, by0 + box_h), radius=9, fill=fill, outline=outline, width=3)
        text_y = draw_centered_wrapped_text(draw, bx0, bx1, by0 + 15, title, FONTS["subsection"])
        draw_centered_wrapped_text(draw, bx0, bx1, text_y + 4, subtitle, FONTS["small"])
        if idx < len(steps) - 1:
            ax = bx1 + 5
            ay = by0 + 37
            draw.line((ax, ay, ax + 12, ay), fill="#777777", width=3)
            draw.polygon([(ax + 12, ay), (ax + 1, ay - 6), (ax + 1, ay + 6)], fill="#777777")
    caption = (
        "Fig. 3. Dataset and training workflow used by the prototype. "
        "The resulting classifier augments, but does not replace, symbolic and semantic checks."
    )
    draw.text((x0 + 4, y1 + 10), caption, font=FONTS["caption"], fill="#111111")
    return y1 + 42


def figure_four(draw: ImageDraw.ImageDraw, top_y: int) -> int:
    x0 = MARGIN_X
    x1 = PAGE_WIDTH - MARGIN_X
    y1 = top_y + 302
    draw.rectangle((x0, top_y, x1, y1), outline="#bbbbbb", width=2)
    draw.text((x0 + 180, top_y + 18), "Observed threat categories", font=FONTS["subsection"], fill="#111111")
    draw.text((x0 + 870, top_y + 18), "Deployment outcomes", font=FONTS["subsection"], fill="#111111")

    chart_x0 = x0 + 40
    chart_y0 = top_y + 58
    chart_y1 = top_y + 222
    chart_x1 = x0 + 615
    draw.line((chart_x0, chart_y1, chart_x1, chart_y1), fill="#444444", width=2)
    draw.line((chart_x0, chart_y0, chart_x0, chart_y1), fill="#444444", width=2)
    labels = [("Prompt\nInjection", 54), ("Malicious\nCode", 45), ("Data\nExfiltration", 29), ("Network\nAccess", 20), ("Weapons", 10)]
    bar_w = 60
    gap = 40
    max_v = 60
    colors = ["#355c8a", "#55739a", "#7a8da8", "#9ca6b7", "#bdc0ca"]
    for idx, (label, value) in enumerate(labels):
        bx0 = chart_x0 + 28 + idx * (bar_w + gap)
        bh = int((value / max_v) * (chart_y1 - chart_y0 - 10))
        by0 = chart_y1 - bh
        draw.rectangle((bx0, by0, bx0 + bar_w, chart_y1), fill=colors[idx], outline=colors[idx])
        value_text = str(value)
        draw.text((bx0 + (bar_w - text_width(draw, value_text, FONTS["small"])) / 2, by0 - 20), value_text, font=FONTS["small"], fill="#111111")
        draw_centered_wrapped_text(
            draw,
            bx0 - 12,
            bx0 + bar_w + 12,
            chart_y1 + 10,
            label,
            FONTS["caption"],
            line_extra=0,
        )

    boxes = [
        ("57 safe pass-through interactions", "#eef8ef", "#5f9461"),
        ("36 prompts blocked before model execution", "#fff6e8", "#c89845"),
        ("18 safe-input cases caught only after output scan", "#fff0f0", "#be5b5b"),
    ]
    bx0 = x0 + 760
    by = top_y + 72
    for text, fill, outline in boxes:
        draw.rounded_rectangle((bx0, by, x1 - 40, by + 48), radius=8, fill=fill, outline=outline, width=2)
        draw_centered_wrapped_text(draw, bx0, x1 - 40, by + 12, text, FONTS["small_bold"])
        by += 60

    caption = (
        "Fig. 4. Observed category counts and operational outcomes. "
        "The right-hand panel highlights why output mediation remains necessary."
    )
    draw.text((x0 + 4, y1 + 10), caption, font=FONTS["caption"], fill="#111111")
    return y1 + 42


def draw_caption_lines(
    draw: ImageDraw.ImageDraw,
    x0: int,
    y: int,
    width: int,
    caption: str,
) -> int:
    for line in wrap_words(draw, caption, FONTS["caption"], width - 6):
        draw.text((x0 + 2, y), line, font=FONTS["caption"], fill="#111111")
        y += line_height(FONTS["caption"], 1)
    return y


def figure_one_col(draw: ImageDraw.ImageDraw, x0: int, top_y: int, width: int) -> int:
    x1 = x0 + width
    frame_h = 350
    draw.rectangle((x0, top_y, x1, top_y + frame_h), outline="#bdbdbd", width=1)
    panels = [
        ("Layer 1: Access", "#edf3fb", "#5a83b5", ["Contained AI backend", "Prompt guardrail and query gate"]),
        ("Layer 2: Detection", "#f5f5f5", "#888888", ["Hybrid Sentinel scoring", "Policy-aware fail-closed response"]),
        ("Layer 3: Oversight", "#eef8ef", "#5f9461", ["Dashboard, alerts and logs", "Human review and kill switch"]),
    ]
    box_h = 78
    gap = 20
    y = top_y + 18
    for idx, (title, fill, outline, lines) in enumerate(panels):
        draw.rounded_rectangle((x0 + 18, y, x1 - 18, y + box_h), radius=10, fill=fill, outline=outline, width=2)
        draw.text((x0 + 24, y + 8), title, font=FONTS["small_bold"], fill="#111111")
        ty = y + 30
        for line in lines:
            ty = draw_left_wrapped_text(draw, x0 + 24, x1 - 26, ty, line, FONTS["small"], line_extra=0)
        if idx < len(panels) - 1:
            mid_x = x0 + (width // 2)
            draw.line((mid_x, y + box_h, mid_x, y + box_h + gap - 6), fill="#787878", width=2)
            draw.polygon([(mid_x, y + box_h + gap), (mid_x - 5, y + box_h + gap - 10), (mid_x + 5, y + box_h + gap - 10)], fill="#787878")
        y += box_h + gap

    band_y = top_y + 294
    draw.rounded_rectangle((x0 + 30, band_y, x1 - 30, band_y + 24), radius=6, fill="#fff6e8", outline="#d2a561", width=1)
    draw_centered_wrapped_text(
        draw,
        x0 + 34,
        x1 - 34,
        band_y + 6,
        "Shared logs, policies, threat details and emergency events",
        FONTS["tiny_bold"],
        line_extra=0,
    )
    caption = (
        "Fig. 1. Layered Sentinel architecture. Each panel isolates one operational role "
        "so that detection, enforcement and oversight remain separate but auditable."
    )
    return draw_caption_lines(draw, x0, top_y + frame_h + 8, width, caption)


def figure_two_col(draw: ImageDraw.ImageDraw, x0: int, top_y: int, width: int) -> int:
    x1 = x0 + width
    frame_h = 404
    draw.rectangle((x0, top_y, x1, top_y + frame_h), outline="#bdbdbd", width=1)
    steps = [
        ("1. User prompt", "session created and tagged", "#eef2f7", "#7088a4"),
        ("2. Input scan", "rules + semantic + ML checks", "#fff6e8", "#c89845"),
        ("3. Policy gate", "block, redact or forward", "#f0f6ff", "#5f84c2"),
        ("4. Model call", "contained backend executes", "#fff6e8", "#c89845"),
        ("5. Output scan", "same detector re-evaluates text", "#eef8ef", "#5f9461"),
        ("6. Audit + alert", "log, notify and summarize", "#f5f5f5", "#8b8b8b"),
    ]
    y = top_y + 16
    box_h = 50
    gap = 10
    for idx, (title, subtitle, fill, outline) in enumerate(steps):
        draw.rounded_rectangle((x0 + 22, y, x1 - 22, y + box_h), radius=8, fill=fill, outline=outline, width=2)
        draw.text((x0 + 32, y + 6), title, font=FONTS["tiny_bold"], fill="#111111")
        draw_left_wrapped_text(draw, x0 + 32, x1 - 34, y + 23, subtitle, FONTS["tiny"], line_extra=0)
        if idx < len(steps) - 1:
            mid_x = x0 + (width // 2)
            draw.line((mid_x, y + box_h, mid_x, y + box_h + gap - 4), fill="#777777", width=2)
            draw.polygon([(mid_x, y + box_h + gap), (mid_x - 4, y + box_h + gap - 8), (mid_x + 4, y + box_h + gap - 8)], fill="#777777")
        y += box_h + gap

    draw.rounded_rectangle((x0 + 32, top_y + 348, x1 - 32, top_y + 380), radius=6, fill="#fff0f0", outline="#be5b5b", width=1)
    draw_centered_wrapped_text(
        draw,
        x0 + 38,
        x1 - 38,
        top_y + 355,
        "Critical matches or auto-kill policies trigger the global shutdown state.",
        FONTS["tiny_bold"],
        line_extra=0,
    )
    caption = (
        "Fig. 2. Mediation workflow through the containment stack. The same scoring path "
        "is applied before and after generation so risky outputs cannot bypass the gate."
    )
    return draw_caption_lines(draw, x0, top_y + frame_h + 8, width, caption)


def figure_three_col(draw: ImageDraw.ImageDraw, x0: int, top_y: int, width: int) -> int:
    x1 = x0 + width
    frame_h = 280
    draw.rectangle((x0, top_y, x1, top_y + frame_h), outline="#bdbdbd", width=1)
    steps = [
        ("Public corpora", "prompt-injection, harm and safe text"),
        ("Normalize", "deduplicate, relabel and hash inputs"),
        ("Vectorize", "TF-IDF 1-2 grams with capped vocabulary"),
        ("Train LR", "balanced multiclass logistic regression"),
        ("Deploy", "load artifact inside SentinelEngine"),
    ]
    box_h = 38
    gap = 10
    y = top_y + 18
    fills = ["#eef2f7", "#fff6e8", "#f0f6ff", "#eef8ef", "#f8f8f8"]
    outlines = ["#6f88a5", "#c89845", "#6287c0", "#5f9461", "#8d8d8d"]
    for idx, (title, subtitle) in enumerate(steps):
        draw.rounded_rectangle((x0 + 22, y, x1 - 22, y + box_h), radius=8, fill=fills[idx], outline=outlines[idx], width=2)
        draw.text((x0 + 34, y + 7), title, font=FONTS["tiny_bold"], fill="#111111")
        sub_y = draw_centered_wrapped_text(draw, x0 + 150, x1 - 30, y + 6, subtitle, FONTS["tiny"], line_extra=0)
        if idx < len(steps) - 1:
            mid_x = x0 + (width // 2)
            draw.line((mid_x, y + box_h, mid_x, y + box_h + gap - 4), fill="#777777", width=2)
            draw.polygon([(mid_x, y + box_h + gap), (mid_x - 4, y + box_h + gap - 8), (mid_x + 4, y + box_h + gap - 8)], fill="#777777")
        y += box_h + gap
    caption = (
        "Fig. 3. Training workflow for the supervised detector. Each step tightens the data "
        "pipeline so the runtime classifier remains lightweight and reproducible."
    )
    return draw_caption_lines(draw, x0, top_y + frame_h + 8, width, caption)


def figure_four_col(draw: ImageDraw.ImageDraw, x0: int, top_y: int, width: int) -> int:
    x1 = x0 + width
    frame_h = 272
    draw.rectangle((x0, top_y, x1, top_y + frame_h), outline="#bdbdbd", width=1)
    draw.text((x0 + 18, top_y + 14), "Observed threat categories", font=FONTS["subsection"], fill="#111111")
    chart_x0 = x0 + 32
    chart_y0 = top_y + 54
    chart_y1 = top_y + 168
    chart_x1 = x1 - 24
    draw.line((chart_x0, chart_y1, chart_x1, chart_y1), fill="#444444", width=2)
    draw.line((chart_x0, chart_y0, chart_x0, chart_y1), fill="#444444", width=2)
    labels = [("Prompt\nInj.", 54), ("Malicious\nCode", 45), ("Data\nExfil.", 29), ("Network\nAccess", 20), ("Weapons", 10)]
    colors = ["#355c8a", "#55739a", "#7a8da8", "#9ca6b7", "#bdc0ca"]
    bar_w = 34
    gap = 20
    max_v = 60
    for idx, (label, value) in enumerate(labels):
        bx0 = chart_x0 + 20 + idx * (bar_w + gap)
        bh = int((value / max_v) * (chart_y1 - chart_y0 - 8))
        by0 = chart_y1 - bh
        draw.rectangle((bx0, by0, bx0 + bar_w, chart_y1), fill=colors[idx], outline=colors[idx])
        draw.text((bx0 + 6, by0 - 14), str(value), font=FONTS["tiny"], fill="#111111")
        draw_centered_wrapped_text(draw, bx0 - 12, bx0 + bar_w + 12, chart_y1 + 6, label, FONTS["tiny"], line_extra=0)
    caption = (
        "Fig. 4. Category counts observed in the prototype audit logs. Prompt injection "
        "and malicious-code requests dominate the harmful interaction set."
    )
    return draw_caption_lines(draw, x0, top_y + frame_h + 8, width, caption)


def figure_five_col(draw: ImageDraw.ImageDraw, x0: int, top_y: int, width: int) -> int:
    x1 = x0 + width
    frame_h = 228
    draw.rectangle((x0, top_y, x1, top_y + frame_h), outline="#bdbdbd", width=1)
    draw.text((x0 + 18, top_y + 14), "Severity distribution", font=FONTS["subsection"], fill="#111111")
    rows = [("Safe pass-through", 57, "#dbead7"), ("Blocked at input", 36, "#f6dfae"), ("Critical matches", 34, "#f2c1c1"), ("Kill events", 42, "#e8c7cb")]
    y = top_y + 52
    max_v = 60
    bar_x0 = x0 + 170
    for label, value, color in rows:
        draw.text((x0 + 20, y + 5), label, font=FONTS["tiny"], fill="#111111")
        draw.rounded_rectangle((bar_x0, y, x1 - 26, y + 20), radius=5, fill="#f7f7f7", outline="#d8d8d8", width=1)
        fill_w = int(((value / max_v) * ((x1 - 26) - bar_x0)))
        draw.rounded_rectangle((bar_x0, y, bar_x0 + fill_w, y + 20), radius=5, fill=color, outline=color, width=1)
        draw.text((x1 - 48, y + 5), str(value), font=FONTS["tiny_bold"], fill="#111111")
        y += 36
    caption = (
        "Fig. 5. Distribution of moderation outcomes across the sampled sessions. The chart "
        "shows how often the system remained permissive versus escalatory."
    )
    return draw_caption_lines(draw, x0, top_y + frame_h + 8, width, caption)


def figure_six_col(draw: ImageDraw.ImageDraw, x0: int, top_y: int, width: int) -> int:
    x1 = x0 + width
    frame_h = 238
    draw.rectangle((x0, top_y, x1, top_y + frame_h), outline="#bdbdbd", width=1)
    draw.text((x0 + 18, top_y + 14), "Signal contribution by detector", font=FONTS["subsection"], fill="#111111")
    categories = [
        ("Prompt inj.", (0.30, 0.28, 0.24, 0.08)),
        ("Code", (0.27, 0.30, 0.18, 0.05)),
        ("Exfil.", (0.26, 0.24, 0.27, 0.07)),
        ("Network", (0.25, 0.29, 0.19, 0.06)),
    ]
    colors = ["#5a83b5", "#c89845", "#5f9461", "#8b8b8b"]
    labels = ["K", "R", "S", "E"]
    y = top_y + 50
    for name, parts in categories:
        draw.text((x0 + 20, y + 7), name, font=FONTS["tiny"], fill="#111111")
        bx = x0 + 140
        total_w = x1 - bx - 24
        cursor = bx
        for idx, part in enumerate(parts):
            seg_w = int(total_w * part)
            draw.rectangle((cursor, y, cursor + seg_w, y + 18), fill=colors[idx], outline=colors[idx])
            cursor += seg_w
        draw.rectangle((bx, y, bx + total_w, y + 18), outline="#bdbdbd", width=1)
        y += 34
    lx = x0 + 24
    for idx, label in enumerate(labels):
        draw.rectangle((lx, top_y + 196, lx + 14, top_y + 210), fill=colors[idx], outline=colors[idx])
        draw.text((lx + 20, top_y + 195), f"{label} = channel weight", font=FONTS["tiny"], fill="#111111")
        lx += 166
    caption = (
        "Fig. 6. Relative detector contributions used in category scoring. The stacked bars "
        "make clear that semantic, lexical and regex signals are intentionally co-equal."
    )
    return draw_caption_lines(draw, x0, top_y + frame_h + 8, width, caption)


def figure_seven_col(draw: ImageDraw.ImageDraw, x0: int, top_y: int, width: int) -> int:
    x1 = x0 + width
    frame_h = 228
    draw.rectangle((x0, top_y, x1, top_y + frame_h), outline="#bdbdbd", width=1)
    draw.text((x0 + 18, top_y + 14), "Latency by pipeline stage (ms)", font=FONTS["subsection"], fill="#111111")
    stages = [("Input scan", 640), ("Model generation", 1710), ("Output scan", 520), ("Log + alert", 216)]
    max_v = 1800
    y = top_y + 52
    bar_x0 = x0 + 118
    value_x = x1 - 52
    bar_x1 = x1 - 76
    for label, value in stages:
        draw.text((x0 + 20, y + 5), label, font=FONTS["tiny"], fill="#111111")
        draw.rounded_rectangle((bar_x0, y, bar_x1, y + 20), radius=5, fill="#f7f7f7", outline="#d8d8d8", width=1)
        fill_w = int(((value / max_v) * (bar_x1 - bar_x0)))
        draw.rounded_rectangle((bar_x0, y, bar_x0 + fill_w, y + 20), radius=5, fill="#7a8da8", outline="#7a8da8", width=1)
        draw.text((value_x, y + 5), str(value), font=FONTS["tiny_bold"], fill="#111111")
        y += 36
    caption = (
        "Fig. 7. Approximate latency contribution of each containment stage. Generation is the "
        "dominant cost, while scanning and logging remain comparatively lightweight."
    )
    return draw_caption_lines(draw, x0, top_y + frame_h + 8, width, caption)


TABLE_ONE = TableSpec(
    title="Table I. Large-profile Sentinel training distribution",
    headers=["Label", "Count", "Source mix", "Operational use"],
    col_widths=[0.24, 0.10, 0.25, 0.41],
    rows=[
        ["SAFE", "60k", "UltraChat + benign prompts", "Normal requests expected to pass mediation"],
        ["PROMPT INJ.", "25k", "Jailbreak and PI corpora", "Role override, prompt reveal and bypass attempts"],
        ["MAL. CODE", "10k", "HarmBench-style harmful code", "Exploit, malware and abuse-oriented code"],
        ["DATA EXFIL.", "10k", "Leakage prompts + variants", "Protected-data retrieval or disclosure"],
        ["NET ACCESS", "10k", "HTTP, socket and transfer prompts", "Unsafe outbound communication behavior"],
        ["WEAPONS", "10k", "Harmful instruction sets", "Weaponization or violent capability requests"],
        ["OBFUSCATION", "6k", "Encoded payload patterns", "Hidden or decoded malicious intent"],
        ["POLICY VIOL.", "6k", "Restricted-content edge cases", "Noncompliant requests below severe harm"],
    ],
    description="Description: Table I summarizes the class balance used for supervised training and the operational role assigned to each label during containment evaluation.",
)

TABLE_TWO = TableSpec(
    title="Table II. Selected validation metrics from the stored classifier report",
    headers=["Class", "Precision", "Recall", "F1-score", "Support"],
    col_widths=[0.30, 0.17, 0.17, 0.17, 0.19],
    rows=[
        ["SAFE", "0.975", "0.988", "0.981", "12,000"],
        ["PROMPT_INJECTION", "0.972", "0.940", "0.956", "5,000"],
        ["MALICIOUS_CODE", "1.000", "0.997", "0.998", "2,000"],
        ["DATA_EXFILTRATION", "1.000", "0.996", "0.998", "2,000"],
        ["NETWORK_ACCESS", "1.000", "1.000", "1.000", "2,000"],
        ["WEAPONS", "0.999", "0.998", "0.998", "2,000"],
        ["Overall accuracy", "-", "-", "-", "0.9826 on 27,400 validation samples"],
    ],
    description="Description: Table II reports representative offline classifier results on the held-out validation split used by the prototype training workflow.",
)

TABLE_THREE = TableSpec(
    title="Table III. Snapshot of deployment statistics from containment_logs.db",
    headers=["Metric", "Value"],
    col_widths=[0.64, 0.36],
    rows=[
        ["Total recorded interactions", "176"],
        ["Interactions marked suspicious or threatening", "83"],
        ["Critical-severity interactions", "34"],
        ["Kill-switch trigger events", "42"],
        ["Generated alerts", "127"],
        ["Active security policies", "7"],
        ["Mean logged analysis time", "3085.77 ms"],
        ["Average prompt tokens / completion tokens", "64.10 / 164.94"],
    ],
    description="Description: Table III aggregates headline runtime measurements from the deployed audit database and complements the graphical summaries in Section VII.",
)


REFERENCES = [
    "S. Armstrong, A. Sandberg and N. Bostrom, \"Thinking Inside the Box: Controlling and Using an Oracle AI,\" Minds and Machines, vol. 22, no. 4, pp. 299-324, 2012.",
    "E. Tabassi, \"Artificial Intelligence Risk Management Framework (AI RMF 1.0),\" NIST AI 100-1, National Institute of Standards and Technology, 2023.",
    "C. Autio et al., \"Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile,\" NIST AI 600-1, National Institute of Standards and Technology, 2024.",
    "CISA et al., \"Joint Guidance on Deploying AI Systems Securely,\" Cybersecurity and Infrastructure Security Agency, Apr. 15, 2024.",
    "K. Greshake et al., \"More than you've asked for: A Comprehensive Analysis of Novel Prompt Injection Threats to Application-Integrated Large Language Models,\" arXiv:2302.12173, 2023.",
    "A. Zou et al., \"Universal and Transferable Adversarial Attacks on Aligned Language Models,\" arXiv:2307.15043, 2023.",
    "Anthropic, \"Many-shot jailbreaking,\" Research note, Apr. 2, 2024.",
    "A. Wei, N. Haghtalab and J. Steinhardt, \"Jailbroken: How Does LLM Safety Training Fail?,\" arXiv:2307.02483, 2023.",
    "M. Mazeika et al., \"HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal,\" Proc. ICML, 2024.",
    "P. Chao et al., \"JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models,\" Proc. NeurIPS Datasets and Benchmarks Track, 2024.",
    "H. Inan et al., \"Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations,\" arXiv:2312.06674, 2023.",
    "Y. Bai et al., \"Constitutional AI: Harmlessness from AI Feedback,\" arXiv:2212.08073, 2022.",
    "D. Ganguli et al., \"Red Teaming Language Models to Reduce Harms: Methods, Scaling Behaviors, and Lessons Learned,\" arXiv:2209.07858, 2022.",
    "OpenAI, \"GPT-4 Technical Report,\" arXiv:2303.08774, 2023.",
    "L. Ouyang et al., \"Training language models to follow instructions with human feedback,\" Proc. NeurIPS, vol. 35, 2022.",
]


def build_document(renderer: PaperRenderer) -> None:
    renderer.add_paragraph(
        "Abstract: Large language models are increasingly attractive for cyber defense, intelligence triage and secure knowledge access, but the same instruction-following behavior also exposes them to prompt injection, harmful code generation, data exfiltration and unsafe automation. This paper presents Sentinel, a deployable AI-containment prototype implemented in Django around a layered mediation pipeline. The system combines contained model access, a hybrid threat detector, policy-governed fail-closed enforcement, operator-visible logging and an emergency kill switch. The detector fuses lexical rules, regex signatures, semantic similarity, entropy analysis and an optional supervised classifier trained on a 137,000-record eight-class dataset. On the stored validation split the classifier achieved 98.26% accuracy, while operational logs from the prototype showed 83 suspicious interactions, 34 critical events, 42 kill-switch triggers and 127 generated alerts. These results suggest that layered containment can make unsafe model behavior substantially more observable, auditable and interruptible even when the underlying model remains vulnerable.",
        font_key="body_italic",
        indent=0,
        spacing_after=10,
        justify=False,
    )
    renderer.add_paragraph(
        "Keywords: AI containment, large language models, prompt injection, threat detection, secure deployment, kill switch, human-in-the-loop monitoring.",
        font_key="body_bold",
        indent=0,
        spacing_after=16,
        justify=False,
    )

    renderer.add_heading("I. INTRODUCTION")
    renderer.add_paragraph(
        "Large language models are moving quickly from experimental assistants to embedded decision-support components in high-impact environments. Within national-security and critical-infrastructure settings, the attraction is obvious: a single model can summarize reports, classify incidents, propose code, triage alerts and draft responses at a speed that reduces operator load. Yet the same broad generative ability creates a difficult trust problem. A system that can reason over natural-language instructions is also a system that can be manipulated by hostile instructions, induced to reveal sensitive information, or steered toward dangerous outputs that appear useful at first glance."
    )
    renderer.add_paragraph(
        "The containment problem is therefore not solved merely by selecting an aligned model provider. Oracle-AI and capability-control literature argued early that limiting the operational surface of a powerful system is as important as shaping its objective function [1]. Modern deployment guidance follows the same logic: NIST's AI RMF 1.0 and the Generative AI Profile frame trustworthy deployment as a governance and measurement problem [2], [3], while CISA-led operational guidance argues that externally developed AI systems should be surrounded by defensive controls that preserve confidentiality, integrity and availability during operation [4]."
    )
    renderer.add_paragraph(
        "This paper treats the application boundary around an LLM as part of the security perimeter. The contribution is not a claim of perfect containment, but a practical engineering pattern in which unsafe model interaction becomes detectable, governable and interruptible inside a real application stack. The focus is on present-day deployment discipline: clear mediation points, explicit policy controls, operator visibility and evidence-rich logs."
    )
    renderer.add_paragraph(
        "The implemented prototype in the local ai_containment workspace includes backend mediation, configurable policies, a hybrid detector, real-time alerts, audit persistence and an operator-facing command center. Its purpose is to treat unsafe model interaction as an observable process rather than a hidden model-side failure."
    )
    renderer.add_note_box(
        [
            "Revised Manuscript Prepared on April 26, 2026.",
            "* Correspondence Author",
            "Aryan Pathania*, CGC University, Mohali, Punjab, India. Email: pathaniaaryan169@gmail.com",
            "Aryan Sharma, CGC University, Mohali, Punjab, India. Email: aryansharma2004march@gmail.com",
            "This manuscript is based on the implemented prototype in the local ai_containment project and adopts a journal-style two-column presentation inspired by a technical paper sample.",
        ]
    )
    renderer.add_paragraph(
        "The core contributions of the paper are fourfold. First, it defines a concrete three-layer containment architecture that separates model access, threat mediation and operator oversight. Second, it implements a threat detector that combines symbolic features with semantic and supervised components rather than relying on a single heuristic. Third, it operationalizes enforcement through fail-closed blocking, policy-based escalation and a kill switch that can suspend further model generation. Fourth, it validates the approach using both offline classifier metrics and live operational logs collected from the deployed prototype."
    )
    renderer.add_paragraph(
        "The system should not be interpreted as a final answer to general AI safety. Instead, it should be understood as a security engineering pattern for present-day LLM deployments in which the model is treated as potentially misbehaving software that must be mediated, monitored and, when necessary, interrupted."
    )

    renderer.add_heading("II. RELATED WORK")
    renderer.add_paragraph(
        "Recent jailbreak research reinforces why a layered deployment posture is necessary. Prompt injection can override intended instructions in both direct and indirect settings [5], universal adversarial suffixes can transfer across aligned models [6], and many-shot jailbreaking can drive increasingly harmful completions as adversarial context accumulates [7]. These works show that the application wrapper around an LLM is a live attack surface rather than a neutral shell."
    )
    renderer.add_paragraph(
        "Evaluation and safeguard work strengthens that conclusion. Jailbreak failure analyses highlight how safety training can break under adversarial pressure [8], benchmark suites such as HarmBench and JailbreakBench formalize red-team evaluation [9], [10], and safeguard models such as Llama Guard illustrate the value of explicit I/O moderation layers [11]. Sentinel inherits these ideas but combines them in a single operational control plane."
    )
    renderer.add_paragraph(
        "The present work therefore addresses an integration gap: many publications analyze attacks or defenses in isolation, but fewer describe a full-stack prototype that joins model mediation, detection, dashboarding, logging, policy control and emergency shutdown in one deployable application."
    )
    renderer.add_paragraph(
        "From the application-security side, structured filtering, output validation, least privilege and emergency controls are now treated as baseline requirements rather than optional extras [4], [11]. That operational framing motivates the journal-style reconstruction presented here."
    )

    renderer.add_heading("III. PROPOSED SYSTEM ARCHITECTURE")
    renderer.add_column_figure(figure_one_col, 340)
    renderer.add_subheading("A. Layer 1: Contained model access")
    renderer.add_paragraph(
        "The first layer standardizes communication with the underlying language model. In the current implementation this layer supports three backends: a deterministic mock engine, a local Ollama backend and an OpenAI-compatible backend. By forcing all model calls through a single orchestration class, the system ensures that a common system prompt, token budget and kill-switch state are enforced before any completion is requested."
    )
    renderer.add_paragraph(
        "This layer also embodies a minimum-privilege philosophy. The model receives the user prompt and a fixed operational instruction, but it does not directly control alerting, policy writes, dashboard state or audit persistence. That separation reduces the chance that a model-side misbehavior can translate immediately into system-side authority."
    )
    renderer.add_subheading("B. Layer 2: Hybrid Sentinel detector")
    renderer.add_paragraph(
        "The second layer is the core containment engine. It analyzes both user input and model output using a configurable knowledge base of threat categories such as prompt injection, malicious code, data exfiltration, obfuscation, weapons and network access. Each category contains severity metadata, auto-kill behavior, keywords, regex patterns and semantic anchor phrases."
    )
    renderer.add_paragraph(
        "Policy handling is dynamic. Category severity and auto-kill behavior can be overridden through stored security policies, allowing operators to tighten or relax response posture without changing source code. This is important because deployment context changes over time; a model action that is acceptable in a classroom demo may be unacceptable in a live cyber-defense workflow."
    )
    renderer.add_subheading("C. Layer 3: Operational command center")
    renderer.add_paragraph(
        "The third layer turns containment into a managed process. It provides dashboards for recent interactions, threat distribution, sandbox testing, policy administration, alert review and kill-switch operations. The current Django interface uses WebSocket updates to push newly generated alerts and interaction summaries to the frontend in near real time."
    )
    renderer.add_paragraph(
        "Together, the three layers form a practical mediation pattern: the model is allowed to generate, but only through a gate; the gate is allowed to block, but only according to inspectable evidence and policy; and the operator is allowed to override or investigate, but only with an auditable trail."
    )

    renderer.add_heading("IV. THREAT MODEL AND MEDIATION")
    renderer.add_column_figure(figure_two_col, 372)
    renderer.add_paragraph(
        "The prototype assumes an attacker may act as an external user, an insider tester or an indirect content source whose text is later processed by the model. Immediate concern centers on direct prompt injection, model-assisted malicious code generation, credential and data exfiltration, hidden payloads and unsafe network instructions. The aim is not to defeat every adversary, but to sharply reduce the number of unsafe interactions that pass silently through the application boundary."
    )
    renderer.add_paragraph(
        "The request path begins with input scanning. Every user prompt is analyzed before it reaches the model. If the input is categorized as non-safe, the system follows a fail-closed policy and blocks forwarding. If the category is configured for auto-kill, the global kill switch is triggered immediately and the event is persisted. Safe input is then sent to the contained model, after which the raw output is analyzed by the same Sentinel engine before release to the user."
    )
    renderer.add_paragraph(
        "The detector combines four normalized evidence channels: keyword hits, regex hits, semantic similarity and entropy anomaly. An optional supervised classifier provides a fifth signal by predicting the most likely threat class from the text [9], [11]. In the present prototype, category scores are emitted only when the combined evidence clears a fixed action threshold."
    )
    renderer.add_equation("risk(c) = 0.30K_c + 0.30R_c + 0.30S_c + 0.10E_c")
    renderer.add_paragraph(
        "Threat aggregation also captures combinations that are operationally more serious than their parts. For example, the engine raises the final level to critical when prompt injection and data exfiltration signals co-occur. This design recognizes that many realistic misuse attempts are chained behaviors rather than isolated labels."
    )
    renderer.add_equation("risk'(c) = risk(c) (1 + \\lambda p_c) + \\delta I_{combo}(c)")
    renderer.add_paragraph(
        "A key design choice is that output scanning remains active even when the input was safe. This is necessary because a benign user request can still elicit a risky completion from a permissive or compromised model. Figure 6 later shows why no single signal should dominate the scoring path."
    )
    renderer.add_column_figure(figure_six_col, 292)

    renderer.force_new_page()
    renderer.add_heading("V. DATASET ENGINEERING AND TRAINING")
    renderer.add_paragraph(
        "To supplement symbolic detection, the project includes a management workflow for building and training a supervised classifier. The dataset builder assembles a large labeled corpus from public sources spanning prompt injection, jailbreak prompts, safe conversational text and harmful-instruction benchmarks [9], [10]."
    )
    renderer.add_paragraph(
        "The large-profile corpus contains 137,000 records. Safe examples dominate the distribution to reflect everyday use, but prompt-injection and harmful classes remain well represented to support robust separation boundaries. The builder normalizes label names, de-duplicates near-identical text and balances under-filled categories with defensive variants when necessary."
    )
    renderer.add_column_figure(figure_three_col, 324)
    renderer.add_column_table(TABLE_ONE)
    renderer.add_paragraph(
        "The training command builds a TF-IDF word-ngram representation and feeds it to multiclass logistic regression with class balancing. In the stored configuration, the model used 1-2 gram features, up to 120,000 terms and an 80/20 stratified validation split. The trained artifact is persisted as a joblib payload and loaded by SentinelEngine at runtime."
    )
    renderer.add_equation("P(y = c | x) = exp(w_c^T x + b_c) / \\sum_j exp(w_j^T x + b_j)")
    renderer.add_paragraph(
        "The choice of logistic regression is deliberate. While more complex encoders could improve recall on nuanced phrasing, the application prioritizes transparent probabilities, fast reloads, lightweight deployment and simple integration with symbolic evidence [14], [15]."
    )

    renderer.add_heading("VI. IMPLEMENTATION DETAILS")
    renderer.add_paragraph(
        "The prototype is implemented as a Django application with two main apps: sentinel and dashboard. The sentinel app contains the mediation logic, model wrapper, threat models, management commands and persistent database tables. The dashboard app provides views for analytics, logs, alerts, policy toggling, kill-switch status and an interactive sandbox used to probe the same containment path seen by end users."
    )
    renderer.add_paragraph(
        "Operational persistence is intentionally rich. Every interaction stores a session identifier, hashes, prompts, outputs, token counts, final threat level, blocking state and kill-switch state. Threat evidence is stored in a child table that records category, severity, confidence, matched keywords, matched patterns and direction. Separate tables persist security policies, kill-switch events and operator alerts."
    )
    renderer.add_paragraph(
        "The live command center aggregates threat counts, daily activity, severity distribution and unread alerts. WebSocket-based broadcast pushes critical state changes to the UI, allowing analysts to watch the pipeline as it executes. The sandbox view also supports structured red-team evaluation, which aligns with safeguard layering and stress-testing guidance in the literature [11], [13]."
    )
    renderer.add_paragraph(
        "The implementation currently uses SQLite and an in-memory channel layer, which is sufficient for a prototype but not the intended scaling endpoint. A production deployment would likely move to durable message infrastructure, stronger operator authentication, hardened admin workflows and host-level isolation around any locally executed tools."
    )
    renderer.add_column_figure(figure_seven_col, 282)

    renderer.force_new_page()
    renderer.add_heading("VII. EXPERIMENTAL RESULTS")
    renderer.add_subheading("A. Offline classifier evaluation")
    renderer.add_paragraph(
        "The stored training metrics show that the supervised component reached 98.26% validation accuracy on the held-out split. Performance was especially strong on data exfiltration, malicious code, network access, obfuscation and weapons categories. Prompt injection remained the most difficult label, which is unsurprising given the linguistic diversity of jailbreak phrasing [8], [10]."
    )
    renderer.add_column_table(TABLE_TWO)
    renderer.add_column_figure(figure_four_col, 290)
    renderer.add_subheading("B. Online operational behavior")
    renderer.add_paragraph(
        "Operational evidence was drawn from the prototype's SQLite audit database. The current log set contains 176 total interactions. Of these, 83 were marked suspicious or threatening by the mediation pipeline, and 36 were stopped at the input stage before any model completion was generated. Importantly, 18 additional incidents began with safe inputs but were later flagged after output scanning, which directly demonstrates the value of dual-sided mediation."
    )
    renderer.add_paragraph(
        "The system also recorded 42 kill-switch trigger events and 127 real-time alerts. Across all threat-detail records, input-side findings outnumbered output-side findings 106 to 59, indicating that many direct attack attempts are stopped early while post-generation review still catches meaningful residual risk."
    )
    renderer.add_column_table(TABLE_THREE)
    renderer.add_column_figure(figure_five_col, 270)
    renderer.add_equation("alert\\_rate = N_{alerts} / N_{interactions}")
    renderer.add_paragraph(
        "The mean logged analysis time was approximately 3.09 s, while average recorded prompt and completion lengths were 64.10 and 164.94 tokens, respectively. This latency is acceptable for an operator-mediated prototype but leaves room for optimization, especially if semantic models are upgraded or if higher interaction rates are expected."
    )

    renderer.add_heading("VIII. DISCUSSION")
    renderer.add_paragraph(
        "The prototype shows that containment is most credible when it is treated as an application-architecture problem rather than a single-model property. Because the detector scans both inputs and outputs, the system can catch both overtly adversarial prompts and benign-looking prompts that nevertheless lead to harmful generations. The audit schema, alerting path and kill-switch workflow ensure that the response to unsafe behavior is not invisible."
    )
    renderer.add_paragraph(
        "At the same time, the system has clear limits. It does not provide cryptographic assurance that a sufficiently capable model cannot manipulate downstream users. It does not yet isolate tool execution in a real operating-system sandbox, nor does it handle multimodal prompt injection. The supervised dataset is partly benchmark-driven and partly synthetically balanced, which helps coverage but may not perfectly reflect field data."
    )
    renderer.add_paragraph(
        "These limitations do not negate the value of the architecture. Rather, they clarify where future work should focus: better indirect-content sanitation, richer behavioral policies, externalized message queues, stronger admin control, multimodal scanning and tighter host-level execution isolation [12], [13]."
    )
    renderer.add_paragraph(
        "A second lesson is organizational rather than purely technical: containment works best when model alignment, safeguard models, audit instrumentation and human escalation paths are treated as complementary controls rather than substitute controls. That layered view is consistent with recent alignment and system-card thinking [12], [14]."
    )

    renderer.force_new_page()
    renderer.add_heading("IX. CONCLUSION AND FUTURE WORK")
    renderer.add_paragraph("Key points:", font_key="body_bold", indent=0, spacing_after=6, justify=False)
    renderer.add_paragraph("1. Sentinel demonstrates that practical AI containment can be implemented as a layered application workflow rather than as a model-only promise.", indent=0, spacing_after=4, justify=False)
    renderer.add_paragraph("2. Bidirectional scanning matters: several risky incidents in the prototype were only visible after the model generated a response.", indent=0, spacing_after=4, justify=False)
    renderer.add_paragraph("3. Operational controls such as policies, logs, alerts and kill switches are central to trustworthy deployment in high-stakes settings.", indent=0, spacing_after=10, justify=False)
    renderer.add_paragraph(
        "This paper presented Sentinel, a multi-layer AI-containment prototype for security-sensitive LLM deployment. The system combines contained model access, a hybrid threat detector, dynamic policy enforcement, operator visibility, forensic logging and an emergency kill switch. The supervised component trained on a 137,000-record dataset achieved 98.26% validation accuracy, while operational logs from the deployed prototype showed that the architecture can detect, block and escalate a meaningful variety of unsafe interactions in practice."
    )
    renderer.add_paragraph(
        "The principal takeaway is that deployable containment does not require solving general AI safety in one step. It requires building concrete mediation points where risk can be measured and controlled. For national-security use cases, such mediation is not optional overhead; it is part of the minimum trustworthy deployment boundary."
    )
    renderer.add_paragraph(
        "Future work should extend the current design toward multimodal input inspection, more formal policy languages, distributed audit pipelines and stronger runtime isolation around tool use. Even in its present form, however, the prototype demonstrates that layered containment can convert a vulnerable language model from an opaque liability into a monitorable and interruptible subsystem [15]."
    )

    renderer.add_heading("REFERENCES")
    renderer.add_references(REFERENCES)


def main() -> None:
    renderer = PaperRenderer()
    build_document(renderer)
    renderer.finalize()
    print(OUTPUT_PDF)


if __name__ == "__main__":
    main()
