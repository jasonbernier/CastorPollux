"""Small, inert HTML reader for the application's local help pages.

This deliberately supports only text formatting. It never loads remote content,
executes scripts, or asks Tk to interpret arbitrary HTML.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser


class _PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def plain_text(source: str) -> str:
    parser = _PlainText()
    parser.feed(source)
    return " ".join(" ".join(parser.parts).split())


def help_sections(source: str) -> dict[str, str]:
    """Return named help sections, with a complete-guide entry first."""
    sections = {"All topics": source}
    pattern = re.compile(r'<section\s+data-title="([^"]+)"[^>]*>(.*?)</section>', re.I | re.S)
    for match in pattern.finditer(source):
        title = plain_text(match.group(1))[:100]
        if title:
            sections[title] = match.group(2)
    return sections


class _TextRenderer(HTMLParser):
    BLOCKS = {"h1", "h2", "h3", "p", "ul", "ol", "pre", "section", "div"}

    def __init__(self, widget):
        super().__init__(convert_charrefs=True)
        self.widget = widget
        self.stack = []
        self.skip = 0
        self.link_count = 0

    def _newline(self, count=1):
        content = self.widget.get("1.0", "end-1c")
        if content and not content.endswith("\n" * count):
            self.widget.insert("end", "\n" * (count - len(content) + len(content.rstrip("\n"))))

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in {"head", "script", "style", "iframe", "object", "svg"}:
            self.skip += 1
            return
        if self.skip:
            return
        attrs = dict(attrs)
        if tag in self.BLOCKS:
            self._newline(2 if tag in {"h1", "h2", "section"} else 1)
        elif tag == "li":
            self._newline()
            self.widget.insert("end", "  •  ", ("muted",))
        elif tag == "br":
            self._newline()
        self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"head", "script", "style", "iframe", "object", "svg"}:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break
        if tag in self.BLOCKS or tag == "li":
            self._newline(2 if tag in {"h1", "h2", "p", "section"} else 1)

    def handle_data(self, data):
        if self.skip or not data or not data.strip():
            return
        tags = []
        for tag, attrs in self.stack:
            if tag in {"h1", "h2", "h3", "strong", "b", "code", "pre"}:
                tags.append(tag)
            if tag == "a":
                href = attrs.get("href", "")
                if href.startswith(("https://", "http://")):
                    link_tag = "link_" + str(self.link_count)
                    self.link_count += 1
                    self.widget.tag_configure(link_tag, foreground="#53CFE0", underline=True)
                    self.widget.tag_bind(link_tag, "<Button-1>", lambda _event, url=href: __import__("webbrowser").open(url))
                    self.widget.tag_bind(link_tag, "<Enter>", lambda _event: self.widget.configure(cursor="hand2"))
                    self.widget.tag_bind(link_tag, "<Leave>", lambda _event: self.widget.configure(cursor="xterm"))
                    tags.append(link_tag)
        self.widget.insert("end", re.sub(r"\s+", " ", data) if "pre" not in tags else data, tuple(tags))


def render_html(box, source: str, font, colors: dict):
    """Render a safe text subset of HTML into a CTkTextbox."""
    widget = box._textbox
    box.configure(state="normal")
    box.delete("1.0", "end")
    widget.configure(padx=22, pady=18, spacing1=2, spacing3=5)
    widget.tag_configure("h1", foreground=colors["accent"], font=font(24, True))
    widget.tag_configure("h2", foreground=colors["secondary"], font=font(18, True))
    widget.tag_configure("h3", foreground=colors["text"], font=font(15, True))
    widget.tag_configure("strong", foreground=colors["text"], font=font(13, True))
    widget.tag_configure("b", foreground=colors["text"], font=font(13, True))
    widget.tag_configure("code", foreground=colors["accent"], font=font(12, False, True))
    widget.tag_configure("pre", foreground=colors["accent"], font=font(12, False, True))
    widget.tag_configure("muted", foreground=colors["muted"])
    renderer = _TextRenderer(widget)
    renderer.feed(source)
    widget.configure(state="disabled")
