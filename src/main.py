"""
Main pipeline entry point for US Proxy Harvester.
1. Scrapes ~100 login-free public Telegram web channels (t.me/s/<channel>) and public GitHub repos.
2. Extracts and deduplicates all proxy protocols (vless, vmess, trojan, ss, hy2, tuic, wg).
3. Performs fast TCP + GeoIP pre-check, then spawns local Xray-core tunnels to verify:
   - Real active connectivity
   - Actual exit IP country == US (strict mode)
   - Real HTTP latency <= max_ping_ms
   - Real download throughput >= min_download_mbps
4. Exports verified configs to Clash YAML, plain TXT, Base64 TXT, protocol-split files, and report.json.
"""

import asyncio
import json
import logging
from pathlib import Path

from src.scraper import collect_all_raw_uris
from src.parser import parse_and_deduplicate
from src.scanner import scan_and_filter_nodes
from src.exporter import export_outputs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("us-harvester")


def load_config(path: Path = Path("config.json")) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_source_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        clean = raw.strip()
        if clean and not clean.startswith("#"):
            lines.append(clean)
    return lines


async def run_pipeline() -> None:
    cfg = load_config()
    tg_channels = load_source_lines(Path(cfg["sources"]["telegram_file"]))
    gh_repos = load_source_lines(Path(cfg["sources"]["github_file"]))
    allowed_protocols = set(cfg["protocols"])

    logger.info(
        "Loaded %d Telegram channels (no-login web preview) and %d GitHub sources.",
        len(tg_channels),
        len(gh_repos),
    )

    raw_uris = await collect_all_raw_uris(tg_channels, gh_repos, allowed_protocols)
    logger.info("Extracted %d raw proxy URI candidates.", len(raw_uris))

    parsed_nodes = parse_and_deduplicate(raw_uris, allowed_protocols)
    logger.info("Parsed %d unique normalized proxy nodes.", len(parsed_nodes))

    verified_nodes, stats = await scan_and_filter_nodes(parsed_nodes, cfg)
    logger.info(
        "Verified %d US nodes passing Ping <= %dms & Download >= %s Mbps.",
        len(verified_nodes),
        cfg["filters"]["max_ping_ms"],
        cfg["filters"]["min_download_mbps"],
    )

    export_outputs(verified_nodes, stats, cfg)
    logger.info("All YAML and TXT outputs written to %s/.", cfg["outputs"]["directory"])


if __name__ == "__main__":
    asyncio.run(run_pipeline())
