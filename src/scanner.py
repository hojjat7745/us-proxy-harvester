"""
Real Connectivity, US Exit-IP Geo-Verification, Low-Ping Latency, and Min Download Speed Scanner.
Prioritizes US-hinted & TCP-alive nodes, then runs isolated local Xray-core SOCKS5 tunnels.
"""

import asyncio
import json
import logging
import os
import re
import socket
import tempfile
import time
from pathlib import Path

import aiohttp
from aiohttp_socks import ProxyConnector

from src.parser import ProxyNode

logger = logging.getLogger("us-harvester.scanner")

US_HINT_RE = re.compile(r"(?:\bUS\b|\bUSA\b|United\s*States|🇺🇸|America|Ashburn|Dallas|New\s*York|Los\s*Angeles|Seattle|Miami|Chicago|San\s*Jose|Atlanta)", re.IGNORECASE)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _tcp_precheck(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def _build_xray_outbound(node: ProxyNode) -> dict | None:
    """Translates a parsed ProxyNode into an Xray-core outbound configuration."""
    if node.protocol == "vless":
        net = node.params.get("type", "tcp")
        security = node.params.get("security", "none")
        stream: dict = {"network": net, "security": security}
        if security == "tls":
            stream["tlsSettings"] = {
                "serverName": node.params.get("sni") or node.server,
                "allowInsecure": True,
            }
        elif security == "reality":
            stream["realitySettings"] = {
                "serverName": node.params.get("sni") or node.server,
                "fingerprint": node.params.get("fp", "chrome"),
                "publicKey": node.params.get("pbk", ""),
                "shortId": node.params.get("sid", ""),
            }
        if net == "ws":
            stream["wsSettings"] = {
                "path": node.params.get("path", "/"),
                "headers": {"Host": node.params.get("host") or node.params.get("sni") or node.server},
            }
        elif net == "grpc":
            stream["grpcSettings"] = {
                "serviceName": node.params.get("serviceName", ""),
            }
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node.server,
                    "port": node.port,
                    "users": [{
                        "id": node.params.get("user", ""),
                        "encryption": node.params.get("encryption", "none"),
                        "flow": node.params.get("flow", ""),
                    }],
                }]
            },
            "streamSettings": stream,
        }

    if node.protocol == "vmess":
        net = node.params.get("net", "tcp")
        tls = "tls" if node.params.get("tls") == "tls" else "none"
        stream = {"network": net, "security": tls}
        if tls == "tls":
            stream["tlsSettings"] = {
                "serverName": node.params.get("sni") or node.server,
                "allowInsecure": True,
            }
        if net == "ws":
            stream["wsSettings"] = {
                "path": node.params.get("path", "/"),
                "headers": {"Host": node.params.get("host") or node.server},
            }
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": node.server,
                    "port": node.port,
                    "users": [{
                        "id": node.params.get("uuid", ""),
                        "alterId": int(node.params.get("aid", 0) or 0),
                        "security": node.params.get("cipher", "auto"),
                    }],
                }]
            },
            "streamSettings": stream,
        }

    if node.protocol == "trojan":
        net = node.params.get("type", "tcp")
        stream = {
            "network": net,
            "security": "tls",
            "tlsSettings": {
                "serverName": node.params.get("sni") or node.server,
                "allowInsecure": True,
            },
        }
        if net == "ws":
            stream["wsSettings"] = {
                "path": node.params.get("path", "/"),
                "headers": {"Host": node.params.get("host") or node.params.get("sni") or node.server},
            }
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": node.server,
                    "port": node.port,
                    "password": node.params.get("user", ""),
                }]
            },
            "streamSettings": stream,
        }

    if node.protocol == "ss":
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": node.server,
                    "port": node.port,
                    "method": node.params.get("cipher", "aes-256-gcm"),
                    "password": node.params.get("password", ""),
                }]
            },
        }

    return None


async def _detect_exit_geo(
    session: aiohttp.ClientSession,
    urls: list[str],
    timeout_sec: float,
) -> tuple[str, str, str] | None:
    for url in urls:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout_sec)) as resp:
                if resp.status != 200:
                    continue
                data = await resp.json(content_type=None)
                code = str(
                    data.get("country_code")
                    or data.get("country")
                    or ""
                ).upper()
                if len(code) == 2:
                    city = str(data.get("city") or "US")
                    ip = str(data.get("ip") or "")
                    return code, city, ip
        except Exception:
            continue
    return None


async def verify_single_node(
    node: ProxyNode,
    cfg: dict,
    semaphore: asyncio.Semaphore,
    xray_bin: str,
) -> ProxyNode | None:
    timeout_sec = float(cfg["scanner"]["connect_timeout_sec"])
    max_ping_ms = int(cfg["filters"]["max_ping_ms"])
    min_download_mbps = float(cfg["filters"]["min_download_mbps"])
    target_country = cfg["target_country"].upper()
    geo_urls = cfg["scanner"].get(
        "exit_ip_check_urls",
        [cfg["scanner"].get("exit_ip_check_url", "https://ipwho.is/?fields=ip,country_code,city")],
    )

    outbound = _build_xray_outbound(node)
    if outbound is None or not Path(xray_bin).exists():
        return None

    async with semaphore:
        if not await _tcp_precheck(node.server, node.port, min(timeout_sec, 2.5)):
            return None

        local_port = _find_free_port()
        xray_cfg = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "socks",
                "settings": {"udp": True},
            }],
            "outbounds": [outbound],
        }

        proc = None
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
                json.dump(xray_cfg, tmp)
                tmp_path = tmp.name

            proc = await asyncio.create_subprocess_exec(
                xray_bin,
                "run",
                "-c",
                tmp_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.sleep(0.35)

            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{local_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                # Step 1: Real HTTP latency (ping) through the proxy tunnel
                t0 = time.perf_counter()
                async with session.get(
                    cfg["scanner"]["ping_test_url"],
                    timeout=aiohttp.ClientTimeout(total=timeout_sec),
                ) as ping_resp:
                    if ping_resp.status not in (200, 204):
                        return None
                ping_ms = int((time.perf_counter() - t0) * 1000)
                if ping_ms > max_ping_ms:
                    return None

                # Step 2: Strict Exit-IP US Geolocation verification through the tunnel
                geo = await _detect_exit_geo(session, geo_urls, timeout_sec)
                if not geo:
                    return None
                country_code, city, exit_ip = geo
                if country_code != target_country:
                    return None
                node.country = country_code
                node.city = city
                node.exit_ip = exit_ip

                # Step 3: Real download speed test (Mbps) through the proxy tunnel
                dl_start = time.perf_counter()
                total_bytes = 0
                async with session.get(
                    cfg["scanner"]["speed_test_url"],
                    timeout=aiohttp.ClientTimeout(total=max(timeout_sec * 2, 15.0)),
                ) as dl_resp:
                    if dl_resp.status != 200:
                        return None
                    async for chunk in dl_resp.content.iter_chunked(65536):
                        total_bytes += len(chunk)
                elapsed = max(time.perf_counter() - dl_start, 0.05)
                download_mbps = round((total_bytes * 8) / (elapsed * 1_000_000), 2)

                if download_mbps < min_download_mbps:
                    return None

                node.ping_ms = ping_ms
                node.download_mbps = download_mbps
                return node

        except Exception:
            return None
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except Exception:
                    proc.kill()
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)


async def scan_and_filter_nodes(
    nodes: list[ProxyNode],
    cfg: dict,
) -> tuple[list[ProxyNode], dict]:
    xray_bin = os.environ.get("XRAY_BIN", "bin/xray")
    max_candidates = int(cfg["scanner"].get("max_candidates_to_test", 600))

    # Prioritize nodes whose label mentions US so we find working US nodes quickly within CI time budgets
    prioritized = sorted(
        nodes,
        key=lambda n: 0 if US_HINT_RE.search(n.name) else 1,
    )
    candidates = prioritized[:max_candidates]
    logger.info(
        "Testing %d prioritized candidates (out of %d unique parsed nodes)...",
        len(candidates),
        len(nodes),
    )

    semaphore = asyncio.Semaphore(int(cfg["scanner"]["max_workers"]))
    tasks = [verify_single_node(n, cfg, semaphore, xray_bin) for n in candidates]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    verified = [r for r in results if isinstance(r, ProxyNode)]
    if cfg["filters"].get("sort_by_lowest_ping", True):
        verified.sort(key=lambda n: (n.ping_ms, -n.download_mbps))

    limit = int(cfg["filters"]["max_output_configs"])
    verified = verified[:limit]

    stats = {
        "total_candidates": len(nodes),
        "tested_candidates": len(candidates),
        "verified_us_count": len(verified),
        "max_ping_ms_filter": cfg["filters"]["max_ping_ms"],
        "min_download_mbps_filter": cfg["filters"]["min_download_mbps"],
        "avg_ping_ms": round(sum(n.ping_ms for n in verified) / len(verified), 1) if verified else 0,
        "avg_download_mbps": round(sum(n.download_mbps for n in verified) / len(verified), 2) if verified else 0,
    }
    return verified, stats
