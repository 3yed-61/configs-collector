"""
Output utilities — file writing and statistics generation.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

from .config import LITE_MAX
from .models import ConfigEntry

log = logging.getLogger(__name__)


def save_list_to_file(items: Iterable[str], path: str | Path) -> None:
    """Write an iterable of strings to a file, one per line."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as fh:
        for item in items:
            fh.write(str(item) + "\n")

    log.info("Written: %s", path)


def _pick_top_entries(
    entries: List[ConfigEntry],
    limit: int,
    only_secure: bool = False,
) -> List[ConfigEntry]:
    """
    Select the top *limit* entries, prioritising secure configs first.

    Secure entries come before insecure ones; within each group the
    original collection order is preserved.
    """
    pool = [e for e in entries if not only_secure or e.secure]

    # Stable sort: secure first (True > False, so negate for ascending)
    ranked = sorted(pool, key=lambda e: (not e.secure,))
    return ranked[:limit]


def save_lite_files(
    classified: Dict[str, List[ConfigEntry]],
    outdir: str | Path,
    lite_max: int = LITE_MAX,
    only_secure: bool = False,
) -> Dict[str, int]:
    """
    For every protocol bucket, write a ``<proto>_lite.txt`` containing
    at most *lite_max* of the best configs (secure ones first).

    Returns a dict of ``{protocol: count}`` for the lite files.
    """
    outdir = Path(outdir)
    lite_dir = outdir / "lite"
    lite_dir.mkdir(parents=True, exist_ok=True)
    lite_counts: Dict[str, int] = {}

    for proto, entries in classified.items():
        top = _pick_top_entries(entries, lite_max, only_secure)
        uris = [e.uri for e in top]
        save_list_to_file(uris, lite_dir / f"{proto}.txt")
        lite_counts[proto] = len(uris)

    # Also write an aggregated lite file with all protocols
    all_top: List[str] = []
    for proto, entries in classified.items():
        top = _pick_top_entries(entries, lite_max, only_secure)
        all_top.extend(e.uri for e in top)
    save_list_to_file(all_top, lite_dir / "all.txt")

    log.info(
        "Lite files saved (%d max per protocol): %s",
        lite_max,
        lite_dir,
    )
    return lite_counts


def generate_stats(
    classified: Dict[str, List[ConfigEntry]],
    outdir: str | Path,
    lite_counts: Dict[str, int] | None = None,
) -> dict:
    """
    Generate and save a stats.json with per-protocol counts.

    Returns the stats dict.
    """
    outdir = Path(outdir)

    stats = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": 0,
        "total_secure": 0,
        "total_lite": 0,
        "protocols": {},
    }

    for proto, entries in classified.items():
        total = len(entries)
        secure = sum(1 for e in entries if e.secure)
        lite = lite_counts.get(proto, 0) if lite_counts else 0
        stats["protocols"][proto] = {
            "total": total,
            "secure": secure,
            "lite": lite,
        }
        stats["total"] += total
        stats["total_secure"] += secure
        stats["total_lite"] += lite

    stats_path = outdir / "stats.json"
    stats_path.parent.mkdir(parents=True, exist_ok=True)

    with open(stats_path, "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2, ensure_ascii=False)

    log.info("Stats saved: %s", stats_path)
    return stats
