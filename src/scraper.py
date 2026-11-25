"""
Login-free asynchronous scraper for public Telegram channels (https://t.me/s/<channel>)
and public GitHub raw proxy repositories.
"""

import asyncio
import base64
import html
import logging
import re
from typing import Iterable

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger("us-harvester.scraper")

URI_PATTERN = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic|wg|wireguard)://[^s<>"'\)\]\\]+",
    re.IGNORECASE,
)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)


def try_decode_base64_blob(text: str) -> str:
    """Decode base64-encoded subscription payloads if applicable."""
    stripped = text.strip()
    if "://" in stripped or len(stripped) < 32:
        return stripped
    compact = re.sub(r"s+", "", stripped)
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return stripped
    try:
        padded = compact + "=" * ((4 - len(compact) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return stripped


def extract_uris_from_text(text: str, allowed_protocols: set[str]) -> list[str]:
    decoded = try_decode_base64_blob(html.unescape(text))
    found: list[str] = []
    for match in URI_PATTERN.findall(decoded):
        cleaned = match.strip().rstrip(",.;")
        scheme = cleaned.split("://", 1)[0].lower()
        normalized = (
            "hysteria2"
            if scheme in ("hy2", "hysteria2")
            else "wireguard"
            if scheme in ("wg", "wireguard")
            else "ss"
            if scheme in ("ss", "ssr")
            else scheme
        )
        if normalized in allowed_protocols:
            found.append(cleaned)
    return found


async def fetch_telegram_channel(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    channel: str,
    allowed_protocols: set[str],
) -> list[str]:
    """Scrapes the public web preview of a Telegram channel without any account login."""
    handle = channel.lstrip("@").strip()
    url = f"https://t.me/s/{handle}"
    async with semaphore:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return []
                body = await resp.text()
        except Exception as exc:
            logger.debug("Telegram channel @%s failed: %s", handle, exc)
            return []

    soup = BeautifulSoup(body, "html.parser")
    text_blocks = [
        el.get_text("
", strip=True)
        for el in soup.select(".tgme_widget_message_text, code, pre")
    ]
    combined = "
".join(text_blocks)
    return extract_uris_from_text(combined, allowed_protocols)


async def fetch_github_source(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    url: str,
    allowed_protocols: set[str],
) -> list[str]:
    async with semaphore:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return []
                body = await resp.text()
        except Exception as exc:
            logger.debug("GitHub source %s failed: %s", url, exc)
            return []

    return extract_uris_from_text(body, allowed_protocols)


async def collect_all_raw_uris(
    telegram_channels: Iterable[str],
    github_urls: Iterable[str],
    allowed_protocols: set[str],
) -> list[str]:
    semaphore = asyncio.Semaphore(20)
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    connector = aiohttp.TCPConnector(limit=30, ssl=False)

    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        tasks = [
            fetch_telegram_channel(session, semaphore, ch, allowed_protocols)
            for ch in telegram_channels
        ] + [
            fetch_github_source(session, semaphore, url, allowed_protocols)
            for url in github_urls
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_uris: list[str] = []
    for item in results:
        if isinstance(item, list):
            all_uris.extend(item)
    return all_uris
