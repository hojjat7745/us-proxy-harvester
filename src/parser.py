"""
Normalizes, parses, and deduplicates proxy URIs across VLESS, VMess, Trojan,
Shadowsocks, Hysteria2, TUIC, and WireGuard.
"""

import base64
import json
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse


@dataclass
class ProxyNode:
    protocol: str
    server: str
    port: int
    name: str
    raw_uri: str
    params: dict = field(default_factory=dict)
    country: str = ""
    city: str = ""
    exit_ip: str = ""
    ping_ms: int = 9999
    download_mbps: float = 0.0

    @property
    def dedup_key(self) -> tuple:
        secret = (
            self.params.get("uuid")
            or self.params.get("password")
            or self.params.get("user")
            or ""
        )
        return (self.protocol, self.server.lower(), self.port, secret)


def _b64_decode(data: str) -> str:
    clean = data.strip()
    padded = clean + "=" * ((4 - len(clean) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="ignore")


def _safe_int(val, default: int = 0) -> int:
    try:
        return int(str(val).strip())
    except Exception:
        return default


def parse_single_uri(uri: str) -> ProxyNode | None:
    uri = uri.strip()
    if "://" not in uri:
        return None
    scheme = uri.split("://", 1)[0].lower()

    try:
        if scheme == "vmess":
            obj = json.loads(_b64_decode(uri[8:]))
            server = str(obj.get("add", "")).strip()
            port = _safe_int(obj.get("port", 0), 0)
            if not server or port <= 0:
                return None
            return ProxyNode(
                protocol="vmess",
                server=server,
                port=port,
                name=str(obj.get("ps") or f"VMess-{server}"),
                raw_uri=uri,
                params={
                    "uuid": str(obj.get("id", "")),
                    "aid": _safe_int(obj.get("aid", 0), 0),
                    "net": str(obj.get("net") or "tcp"),
                    "tls": str(obj.get("tls") or ""),
                    "sni": str(obj.get("sni") or obj.get("host") or ""),
                    "host": str(obj.get("host") or ""),
                    "path": str(obj.get("path") or "/"),
                    "cipher": str(obj.get("scy") or "auto"),
                },
            )

        if scheme in ("ss", "ssr"):
            body = uri.split("://", 1)[1]
            main_part, _, tag = body.partition("#")
            name = unquote(tag) if tag else "SS-Node"
            main_part = main_part.split("?", 1)[0]
            if "@" in main_part:
                cred_part, host_part = main_part.rsplit("@", 1)
                decoded_cred = cred_part if ":" in cred_part else _b64_decode(cred_part)
            else:
                decoded_all = _b64_decode(main_part)
                if "@" not in decoded_all:
                    return None
                decoded_cred, host_part = decoded_all.rsplit("@", 1)

            cipher, _, password = decoded_cred.partition(":")
            host_clean = host_part.split("/", 1)[0]
            server, _, port_str = host_clean.rpartition(":")
            server = server.strip("[]")
            port = _safe_int(port_str, 0)
            if not server or port <= 0 or not cipher:
                return None
            return ProxyNode(
                protocol="ss",
                server=server,
                port=port,
                name=name,
                raw_uri=uri,
                params={"cipher": cipher, "password": password},
            )

        protocol = (
            "hysteria2"
            if scheme in ("hy2", "hysteria2")
            else "wireguard"
            if scheme in ("wg", "wireguard")
            else scheme
        )
        parsed = urlparse("https://" + uri.split("://", 1)[1])
        server = (parsed.hostname or "").strip("[]")
        port = parsed.port or 443
        if not server or port <= 0:
            return None

        qs = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}
        params = {
            "user": unquote(parsed.username or ""),
            "password": unquote(parsed.password or ""),
            **qs,
        }
        name = unquote(parsed.fragment) if parsed.fragment else f"{protocol.upper()}-{server}"
        return ProxyNode(
            protocol=protocol,
            server=server,
            port=port,
            name=name,
            raw_uri=uri,
            params=params,
        )
    except Exception:
        return None


def parse_and_deduplicate(raw_uris: list[str], allowed_protocols: set[str]) -> list[ProxyNode]:
    seen: set[tuple] = set()
    nodes: list[ProxyNode] = []
    for uri in raw_uris:
        node = parse_single_uri(uri)
        if not node or node.protocol not in allowed_protocols:
            continue
        if node.dedup_key in seen:
            continue
        seen.add(node.dedup_key)
        nodes.append(node)
    return nodes
