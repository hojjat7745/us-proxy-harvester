"""
Exports verified US proxy nodes to:
- output/us_configs.txt (plain URI lines)
- output/us_configs_base64.txt (Base64 subscription)
- output/us_clash.yaml (full Clash / Mihomo Meta configuration)
- output/protocols/<proto>.txt (per-protocol splits)
- output/report.json (scan statistics)
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from src.parser import ProxyNode


def _node_to_clash_dict(node: ProxyNode, index: int) -> dict | None:
    safe_city = (node.city or "US").replace(" ", "")
    name = f"US-{safe_city}-{node.protocol.upper()}-{index + 1} [{node.ping_ms}ms | {node.download_mbps}Mbps]"

    if node.protocol == "vless":
        net = node.params.get("type", "tcp")
        sec = node.params.get("security", "none")
        entry = {
            "name": name,
            "type": "vless",
            "server": node.server,
            "port": node.port,
            "uuid": node.params.get("user", ""),
            "udp": True,
            "tls": sec in ("tls", "reality"),
            "network": net,
        }
        if node.params.get("sni"):
            entry["servername"] = node.params["sni"]
        if node.params.get("fp"):
            entry["client-fingerprint"] = node.params["fp"]
        if sec == "reality" and node.params.get("pbk"):
            entry["reality-opts"] = {
                "public-key": node.params["pbk"],
                "short-id": node.params.get("sid", ""),
            }
        if net == "ws":
            entry["ws-opts"] = {
                "path": node.params.get("path", "/"),
                "headers": {"Host": node.params.get("host") or node.params.get("sni") or node.server},
            }
        return entry

    if node.protocol == "vmess":
        net = node.params.get("net", "tcp")
        entry = {
            "name": name,
            "type": "vmess",
            "server": node.server,
            "port": node.port,
            "uuid": node.params.get("uuid", ""),
            "alterId": int(node.params.get("aid", 0) or 0),
            "cipher": node.params.get("cipher", "auto"),
            "udp": True,
            "tls": node.params.get("tls") == "tls",
            "network": net,
        }
        if node.params.get("sni"):
            entry["servername"] = node.params["sni"]
        if net == "ws":
            entry["ws-opts"] = {"path": node.params.get("path", "/")}
        return entry

    if node.protocol == "trojan":
        return {
            "name": name,
            "type": "trojan",
            "server": node.server,
            "port": node.port,
            "password": node.params.get("user", ""),
            "udp": True,
            "sni": node.params.get("sni") or node.server,
            "skip-cert-verify": False,
        }

    if node.protocol == "ss":
        return {
            "name": name,
            "type": "ss",
            "server": node.server,
            "port": node.port,
            "cipher": node.params.get("cipher", "aes-256-gcm"),
            "password": node.params.get("password", ""),
            "udp": True,
        }

    return None


def export_outputs(nodes: list[ProxyNode], stats: dict, cfg: dict) -> None:
    out_dir = Path(cfg["outputs"]["directory"])
    out_dir.mkdir(parents=True, exist_ok=True)

    plain_lines = [n.raw_uri for n in nodes]
    plain_text = "\n".join(plain_lines) + ("\n" if plain_lines else "")

    if cfg["outputs"].get("plain_txt", True):
        (out_dir / "us_configs.txt").write_text(plain_text, encoding="utf-8")

    if cfg["outputs"].get("base64_txt", True):
        encoded = base64.b64encode(plain_text.encode("utf-8")).decode("ascii")
        (out_dir / "us_configs_base64.txt").write_text(encoded + "\n", encoding="utf-8")

    if cfg["outputs"].get("clash_yaml", True):
        proxies = [p for i, n in enumerate(nodes) if (p := _node_to_clash_dict(n, i))]
        names = [p["name"] for p in proxies]
        clash_doc = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "ipv6": False,
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "nameserver": ["1.1.1.1", "8.8.8.8"],
            },
            "proxies": proxies,
            "proxy-groups": [
                {
                    "name": "US-Select",
                    "type": "select",
                    "proxies": ["US-Fastest-Auto", "US-Fallback", *names],
                },
                {
                    "name": "US-Fastest-Auto",
                    "type": "url-test",
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 300,
                    "tolerance": 50,
                    "proxies": names or ["DIRECT"],
                },
                {
                    "name": "US-Fallback",
                    "type": "fallback",
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 300,
                    "proxies": names or ["DIRECT"],
                },
            ],
            "rules": [
                "GEOIP,LAN,DIRECT",
                "GEOIP,IR,DIRECT",
                "MATCH,US-Select",
            ],
        }
        yaml_text = yaml.safe_dump(clash_doc, sort_keys=False, allow_unicode=True)
        (out_dir / "us_clash.yaml").write_text(yaml_text, encoding="utf-8")

    if cfg["outputs"].get("split_by_protocol", True):
        proto_dir = out_dir / "protocols"
        proto_dir.mkdir(parents=True, exist_ok=True)
        grouped: dict[str, list[str]] = {}
        for n in nodes:
            grouped.setdefault(n.protocol, []).append(n.raw_uri)
        for proto, uris in grouped.items():
            (proto_dir / f"{proto}.txt").write_text("\n".join(uris) + "\n", encoding="utf-8")

    report = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        **stats,
    }
    (out_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
