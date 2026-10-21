from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import zlib
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit


MAX_URLS = 2
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 2_000_000
MAX_DECODED_BYTES = 6_000_000
MAX_PAGE_CHARS = 12_000
MAX_TOTAL_CHARS = 20_000
ALLOWED_PORTS = {80, 443}
ALLOWED_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "text/plain",
}
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class PublicWebError(RuntimeError):
    pass


def normalize_public_url(value: object) -> str | None:
    raw = str(value or "").strip().rstrip(".,;:!?)]}")
    if not raw or len(raw) > 2048:
        return None
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname.rstrip(".").lower()
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
            return None
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            return None
        if port not in ALLOWED_PORTS:
            return None
        host_ascii = host.encode("idna").decode("ascii")
        netloc = host_ascii
        if ":" in host_ascii and not host_ascii.startswith("["):
            netloc = f"[{host_ascii}]"
        if port != (443 if scheme == "https" else 80):
            netloc = f"{netloc}:{port}"
        return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    except (UnicodeError, ValueError):
        return None


def extract_public_urls(*values: object, limit: int = MAX_URLS) -> list[str]:
    found: list[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            candidates: Iterable[object] = value
        else:
            candidates = URL_RE.findall(str(value or ""))
        for candidate in candidates:
            normalized = normalize_public_url(candidate)
            if normalized and normalized not in found:
                found.append(normalized)
                if len(found) >= limit:
                    return found
    return found


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _resolve_public(host: str, port: int) -> str:
    try:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PublicWebError(f"DNS lookup failed: {exc}") from exc
    addresses = list(dict.fromkeys(row[4][0] for row in rows))
    if not addresses or any(not _is_public_ip(address) for address in addresses):
        raise PublicWebError("URL resolves to a non-public address")
    addresses.sort(key=lambda address: ipaddress.ip_address(address).version)
    return addresses[0]


def _request_headers(host: str) -> dict[str, str]:
    headers = {
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8",
        "Accept-Encoding": "gzip",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
        "Connection": "close",
        "User-Agent": "MydexPublicReader/1.0",
    }
    if host == "mp.weixin.qq.com":
        headers.update({
            "Referer": "https://mp.weixin.qq.com/",
            "User-Agent": (
                "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro Build/TQ3A.230805.001; wv) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
                "Chrome/112.0.0.0 Mobile Safari/537.36 "
                "MicroMessenger/8.0.49.2600 WeChat/arm64 Weixin "
                "NetType/WIFI Language/zh_CN ABI/arm64"
            ),
        })
    return headers


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _decode_body(data: bytes, content_type: str) -> str:
    charset_match = re.search(r"charset\s*=\s*['\"]?([^;'\"\s]+)", content_type, re.I)
    charsets = [charset_match.group(1)] if charset_match else []
    charsets.extend(["utf-8", "gb18030"])
    for charset in charsets:
        try:
            return data.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _request_once(url: str, timeout: float) -> tuple[int, dict[str, str], bytes]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    address = _resolve_public(host, port)
    conn_type = _PinnedHTTPSConnection if parts.scheme == "https" else _PinnedHTTPConnection
    conn = conn_type(host, port, address, timeout)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    host_header = host if port in {80, 443} else f"{host}:{port}"
    headers = _request_headers(host)
    headers["Host"] = host_header
    try:
        conn.request("GET", target, headers=headers)
        response = conn.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        length = response_headers.get("content-length")
        if length and int(length) > MAX_RESPONSE_BYTES:
            raise PublicWebError("Response is too large")
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise PublicWebError("Response is too large")
        if response_headers.get("content-encoding", "").lower() == "gzip":
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = decoder.decompress(data, MAX_DECODED_BYTES + 1)
            if len(data) > MAX_DECODED_BYTES or decoder.unconsumed_tail:
                raise PublicWebError("Decoded response is too large")
        return response.status, response_headers, data
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise PublicWebError(f"Request failed: {exc}") from exc
    finally:
        conn.close()


class _ReadableHTML(HTMLParser):
    BLOCKED = {"script", "style", "noscript", "svg", "form", "iframe"}
    FALLBACK_BLOCKED = BLOCKED | {"nav", "header", "footer", "aside"}
    BREAKS = {"p", "br", "li", "div", "section", "article", "h1", "h2", "h3", "h4"}
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: list[str] = []
        self.description = ""
        self.focused: list[str] = []
        self.fallback: list[str] = []
        self._stack: list[str] = []
        self._focus_starts: list[bool] = []
        self._focus_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_map = {str(k).lower(): str(v or "") for k, v in attrs}
        marker = " ".join((attrs_map.get("id", ""), attrs_map.get("class", ""))).lower()
        starts_focus = tag == "article" or "js_content" in marker or "rich_media_content" in marker
        if starts_focus:
            self._focus_depth += 1
        if tag == "meta":
            meta_name = (attrs_map.get("name") or attrs_map.get("property") or "").lower()
            if meta_name in {"description", "og:description"}:
                self.description = attrs_map.get("content", "")[:1000]
            if meta_name == "og:title" and not self.title:
                self.title.append(attrs_map.get("content", "")[:300])
        if tag in self.BREAKS:
            self._append("\n")
        if tag not in self.VOID:
            self._stack.append(tag)
            self._focus_starts.append(starts_focus)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.BREAKS:
            self._append("\n")
        if tag in self._stack:
            index = len(self._stack) - 1 - self._stack[::-1].index(tag)
            removed = self._focus_starts[index:]
            self._focus_depth = max(0, self._focus_depth - sum(removed))
            del self._stack[index:]
            del self._focus_starts[index:]

    def handle_data(self, data: str) -> None:
        if not data.strip() or any(tag in self.BLOCKED for tag in self._stack):
            return
        if self._stack and self._stack[-1] == "title":
            self.title.append(data)
            return
        self._append(data)

    def _append(self, value: str) -> None:
        if self._focus_depth:
            self.focused.append(value)
        if not any(tag in self.FALLBACK_BLOCKED for tag in self._stack):
            self.fallback.append(value)


def _clean_text(value: str, limit: int = MAX_PAGE_CHARS) -> str:
    lines = []
    for raw in value.replace("\r", "\n").split("\n"):
        line = re.sub(r"[ \t\f\v]+", " ", raw).strip()
        if line and (not lines or lines[-1] != line):
            lines.append(line)
    return "\n".join(lines)[:limit]


def extract_readable_text(html: str) -> dict[str, str]:
    parser = _ReadableHTML()
    parser.feed(html)
    focused = _clean_text("".join(parser.focused))
    fallback = _clean_text("".join(parser.fallback))
    return {
        "title": _clean_text(" ".join(parser.title), 300),
        "description": _clean_text(parser.description, 1000),
        "text": focused if len(focused) >= 120 else fallback,
    }


def read_public_page(url: str, timeout: float = 8.0) -> dict[str, object]:
    current = normalize_public_url(url)
    if not current:
        raise PublicWebError("Unsupported or invalid URL")
    for redirect_count in range(MAX_REDIRECTS + 1):
        status, headers, data = _request_once(current, timeout)
        if status in {301, 302, 303, 307, 308}:
            if redirect_count >= MAX_REDIRECTS:
                raise PublicWebError("Too many redirects")
            location = headers.get("location", "")
            current = normalize_public_url(urljoin(current, location))
            if not current:
                raise PublicWebError("Redirect target is not public HTTP(S)")
            continue
        if status < 200 or status >= 300:
            raise PublicWebError(f"HTTP {status}")
        content_type = headers.get("content-type", "text/html").lower()
        media_type = content_type.split(";", 1)[0].strip()
        if media_type not in ALLOWED_CONTENT_TYPES:
            raise PublicWebError(f"Unsupported content type: {media_type}")
        decoded = _decode_body(data, content_type)
        if media_type == "text/plain":
            parsed = {"title": "", "description": "", "text": _clean_text(decoded)}
        else:
            parsed = extract_readable_text(decoded)
        if urlsplit(current).hostname == "mp.weixin.qq.com" and (
            "/mp/wappoc_appmsgcaptcha" in urlsplit(current).path
            or "当前环境异常" in parsed["text"]
            or "完成验证后即可继续访问" in parsed["text"]
        ):
            raise PublicWebError("WeChat article requires interactive verification")
        if not parsed["text"]:
            raise PublicWebError("No readable text found")
        return {"url": current, **parsed}
    raise PublicWebError("Too many redirects")


def read_public_pages(urls: Iterable[str], timeout: float = 8.0) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    remaining = MAX_TOTAL_CHARS
    for url in extract_public_urls(list(urls), limit=MAX_URLS):
        try:
            page = read_public_page(url, timeout=timeout)
            page["text"] = str(page["text"])[:remaining]
            remaining -= len(str(page["text"]))
            results.append(page)
        except PublicWebError as exc:
            results.append({"url": url, "error": str(exc)[:300]})
        if remaining <= 0:
            break
    return results
