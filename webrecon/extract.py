"""Extract Web page clues without making network requests."""
from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


INVENTORY_CATEGORIES = (
    "emails", "links", "external_files", "js_files", "form_fields",
    "images", "videos", "audio", "comments",
)
EXTERNAL_EXTENSIONS = {
    ".css", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".sql", ".json",
    ".txt", ".csv", ".xml", ".yaml", ".yml", ".bak", ".conf", ".config",
}
JS_EXTENSIONS = {".js", ".mjs"}
IMAGE_EXTENSIONS = {".avif", ".bmp", ".gif", ".ico", ".jpeg", ".jpg",
                    ".png", ".svg", ".tif", ".tiff", ".webp"}
VIDEO_EXTENSIONS = {".avi", ".m4v", ".mov", ".mp4", ".mpeg", ".mpg", ".webm"}
AUDIO_EXTENSIONS = {".aac", ".flac", ".m4a", ".mp3", ".oga", ".opus", ".wav"}
EMAIL_PATTERN = re.compile(r"(?<![\w.+%-])[\w.+%-]+@[\w.-]+\.[a-zA-Z]{2,}(?![\w.-])", re.I)


def empty_inventory() -> dict[str, list[dict]]:
    return {category: [] for category in INVENTORY_CATEGORIES}


def clean_url(url: str, base: str) -> str | None:
    """Resolve an HTTP(S) reference and remove its fragment."""
    try:
        candidate = urljoin(base, url.strip())
        parts = urlsplit(candidate)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        if parts.username or parts.password:
            return None
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    except ValueError:
        return None


def _extension(url: str) -> str:
    path = urlsplit(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def _srcset(value: str) -> list[str]:
    return [item.strip().split()[0] for item in value.split(",") if item.strip()]


class LinkParser(HTMLParser):
    """Keep the crawl interface and record references for grouped extraction."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.comments: list[str] = []
        self.fields: list[dict] = []
        self.title = ""
        self._in_title = False
        self._text: list[str] = []
        self._references: list[tuple[str, str, str, str, str]] = []
        self._media_context: list[str] = []
        self._form_context: list[dict] = []
        self._field_context: list[dict] = []
        self.base_href: str | None = None

    def _reference(self, raw: str | None, tag: str, attribute: str,
                   mime: str = "") -> None:
        if raw:
            context = self._media_context[-1] if self._media_context else ""
            self._references.append((raw, tag, attribute, context, mime))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        data = {key.lower(): value for key, value in attrs if value is not None}
        if tag == "title":
            self._in_title = True
        if tag == "base" and self.base_href is None and data.get("href"):
            self.base_href = data["href"]
        if tag in ("video", "audio", "picture"):
            self._media_context.append(tag)
        if tag in ("a", "area", "link", "iframe") and data.get("href"):
            self.links.append((data["href"], tag))
            self._reference(data["href"], tag, "href", data.get("type", ""))
        if tag == "iframe" and data.get("src"):
            self.links.append((data["src"], tag))
            self._reference(data["src"], tag, "src", data.get("type", ""))
        if tag == "script" and data.get("src"):
            self.scripts.append(data["src"])
        if tag in ("script", "img", "video", "audio", "source", "embed"):
            self._reference(data.get("src"), tag, "src", data.get("type", ""))
        if tag == "object":
            self._reference(data.get("data"), tag, "data", data.get("type", ""))
        if tag in ("img", "source") and data.get("srcset"):
            for src in _srcset(data["srcset"]):
                self._reference(src, tag, "srcset", data.get("type", ""))
        if tag == "video":
            self._reference(data.get("poster"), tag, "poster")
        if tag == "meta" and data.get("content"):
            name = (data.get("property") or data.get("name") or "").lower()
            if name in ("og:image", "twitter:image", "og:video", "og:audio"):
                self._reference(data["content"], tag, name)
        if tag == "form":
            form = {key: data.get(key) for key in ("action", "method")}
            self.forms.append(form)
            self._form_context.append(form)
        if tag in ("input", "select", "textarea") and data.get("name"):
            self.fields.append({"tag": tag, "name": data["name"], "type": data.get("type")})
            self._field_context.append(self._form_context[-1].copy() if self._form_context else {})

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag == "form" and self._form_context:
            self._form_context.pop()
        if tag in ("video", "audio", "picture") and tag in self._media_context:
            index = len(self._media_context) - 1 - self._media_context[::-1].index(tag)
            del self._media_context[index:]

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data[:500]
        self._text.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)

    def reference_base(self, page_url: str) -> str:
        """Use the document's first valid base href for relative references."""
        if self.base_href:
            return clean_url(self.base_href, page_url) or page_url
        return page_url

    def inventory(self, page_url: str, prefix: str | None = None) -> dict[str, list[dict]]:
        grouped = empty_inventory()
        seen: dict[str, set[object]] = {category: set() for category in INVENTORY_CATEGORIES}
        reference_base = self.reference_base(page_url)

        def add(category: str, value: str, **metadata: str | None) -> None:
            identity = ((value, metadata.get("action"), metadata.get("method"))
                        if category == "form_fields" else value)
            if not value or identity in seen[category]:
                return
            seen[category].add(identity)
            grouped[category].append({"value": value, "source_url": page_url,
                                      "prefix": prefix, **metadata})

        # Parsed text and comments cover visible addresses; references cover mailto.
        for value in EMAIL_PATTERN.findall(unescape(" ".join(self._text + self.comments))):
            add("emails", value)
        for raw, tag, attribute, context, mime in self._references:
            try:
                credential_url = urlsplit(raw).username is not None
            except ValueError:
                credential_url = False
            if not credential_url:
                for value in EMAIL_PATTERN.findall(unescape(raw)):
                    add("emails", value)
            target = clean_url(raw, reference_base)
            if target is None:
                continue
            extension = _extension(target)
            metadata = {"tag": tag, "attribute": attribute}
            if tag in ("a", "area", "link", "iframe"):
                add("links", target, **metadata)
            if extension in EXTERNAL_EXTENSIONS:
                add("external_files", target, **metadata)
            if tag == "script" or extension in JS_EXTENSIONS:
                add("js_files", target, **metadata)
            if (tag == "img" or attribute in ("poster", "og:image", "twitter:image")
                    or context == "picture" or extension in IMAGE_EXTENSIONS):
                add("images", target, **metadata)
            if ((tag == "video" and attribute != "poster") or
                    (context == "video" and attribute != "poster") or
                    attribute == "og:video" or mime.startswith("video/") or
                    extension in VIDEO_EXTENSIONS):
                add("videos", target, **metadata)
            if tag == "audio" or context == "audio" or attribute == "og:audio" or mime.startswith("audio/") or extension in AUDIO_EXTENSIONS:
                add("audio", target, **metadata)
            if extension == ".ogg":
                if context == "video" or mime.startswith("video/"):
                    add("videos", target, **metadata)
                elif context == "audio" or mime.startswith("audio/"):
                    add("audio", target, **metadata)
        for field, form in zip(self.fields, self._field_context):
            metadata = {"tag": field["tag"], "type": field["type"]}
            if form:
                metadata["method"] = (form.get("method") or "get").lower()
                # An empty action submits to the document URL, regardless of base href.
                action = (clean_url(form["action"], reference_base)
                          if form.get("action") else page_url)
                if action:
                    metadata["action"] = action
            add("form_fields", field["name"], **metadata)
        for comment in self.comments:
            if comment.strip():
                add("comments", f"<!--{comment}-->")
        return grouped


def parse_html(body: bytes) -> LinkParser:
    parser = LinkParser()
    parser.feed(body.decode("utf-8", "replace"))
    parser.close()
    return parser


def extract_inventory(page_url: str, body: bytes,
                      prefix: str | None = None) -> dict[str, list[dict]]:
    """Return nine stable, per-page clue lists with their saved-response source."""
    return parse_html(body).inventory(page_url, prefix)
