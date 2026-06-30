"""
CLI entry point for configs-collector.

Usage:
    python -m collector [OPTIONS]
    configs-collector [OPTIONS]      (after pip install)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .config import DEFAULT_OUTDIR, DEFAULT_TAG, LITE_MAX, PROTOCOLS, load_sources
from .network import fetch_all, fetch_url
from .output import generate_stats, save_list_to_file, save_lite_files
from .pipeline import process_text

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="configs-collector",
        description="Collect, validate, and classify V2Ray proxy configs.",
    )
    p.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    p.add_argument(
        "--url", "-u",
        action="append",
        help="Source URL(s) to fetch. Can be repeated. Defaults to sources.txt.",
    )
    p.add_argument(
        "--infile", "-i",
        help="Read configs from a local file instead of (or in addition to) URLs.",
    )
    p.add_argument(
        "--outdir", "-o",
        default=str(DEFAULT_OUTDIR),
        help=f"Output directory (default: {DEFAULT_OUTDIR}).",
    )
    p.add_argument(
        "--tag", "-t",
        default=DEFAULT_TAG,
        help=f"Tag to inject into config names (default: {DEFAULT_TAG}).",
    )
    p.add_argument(
        "--only-secure",
        action="store_true",
        help="Only output configs that pass security checks.",
    )
    p.add_argument(
        "--live-check",
        action="store_true",
        help="Perform live TLS handshake checks on secure configs.",
    )
    p.add_argument(
        "--no-stats",
        action="store_true",
        help="Skip generating stats.json.",
    )
    p.add_argument(
        "--no-lite",
        action="store_true",
        help="Skip generating lite (top-N) output files.",
    )
    p.add_argument(
        "--lite-max",
        type=int,
        default=LITE_MAX,
        help=f"Max configs per protocol in lite files (default: {LITE_MAX}).",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    urls = args.url or load_sources()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Initialize buckets
    classified: dict[str, list] = {proto: [] for proto in PROTOCOLS}
    seen: dict[str, set] = {proto: set() for proto in PROTOCOLS}

    jsonl_path = outdir / "classified.jsonl"

    with open(jsonl_path, "w", encoding="utf-8") as jsonl_fh:

        # Process local file if provided
        if args.infile:
            log.info("Reading local file: %s", args.infile)
            text = Path(args.infile).read_text(encoding="utf-8")
            process_text(
                text, args.tag, classified, seen, jsonl_fh,
                only_secure=args.only_secure,
                do_live_check=args.live_check,
            )

        # Fetch and process URLs in parallel
        if urls:
            log.info("Fetching %d source(s) in parallel...", len(urls))
            downloaded = fetch_all(urls)

            for url in urls:  # preserve order
                text = downloaded.get(url, "")
                if text:
                    process_text(
                        text, args.tag, classified, seen, jsonl_fh,
                        only_secure=args.only_secure,
                        do_live_check=args.live_check,
                    )

    # Write per-protocol output files
    for proto, entries in classified.items():
        uris = sorted({
            e.uri for e in entries
            if not args.only_secure or e.secure
        })
        save_list_to_file(uris, outdir / f"{proto}.txt")

    # Generate lite files (top-N per protocol, secure first)
    lite_counts = None
    if not args.no_lite:
        lite_counts = save_lite_files(
            classified,
            outdir,
            lite_max=args.lite_max,
            only_secure=args.only_secure,
        )
        log.info(
            "Lite: %d configs total (max %d per protocol)",
            sum(lite_counts.values()),
            args.lite_max,
        )

    # Generate stats
    if not args.no_stats:
        stats = generate_stats(classified, outdir, lite_counts=lite_counts)
        log.info(
            "Total: %d configs (%d secure, %d lite)",
            stats["total"],
            stats["total_secure"],
            stats["total_lite"],
        )

    log.info("✅ Done. Output in: %s", outdir)


if __name__ == "__main__":
    main()
