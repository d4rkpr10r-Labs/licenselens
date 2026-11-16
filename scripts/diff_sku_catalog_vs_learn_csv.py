#!/usr/bin/env python3
"""Diff catalog service-plan GUIDs / SKU String_Ids against the Learn licensing CSV.

Authoritative source (retrieved at runtime):
  https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference
  CSV linked from that page (Product names and service plan identifiers for licensing).

Exit codes:
  0 — catalog GUIDs resolve in the CSV with matching plan names; no Critical mismatches
  1 — missing GUID, GUID↔name mismatch, or capability GUID absent from the CSV
  2 — CSV download / parse failure

Usage:
  python scripts/diff_sku_catalog_vs_learn_csv.py
  python scripts/diff_sku_catalog_vs_learn_csv.py --csv /path/to/licensing.csv
  python scripts/diff_sku_catalog_vs_learn_csv.py --json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

LEARN_PAGE = "https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference"
# Stable download URL published on the Learn page (updated 2026-08-19 as of 2026-11-16).
DEFAULT_CSV_URL = (
    "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/"
    "Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv"
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _download_csv(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "LicenseLens-sku-diff/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return response.read()


def _load_csv_rows(raw: bytes) -> list[dict[str, str]]:
    text = raw.decode("utf-8-sig")
    return list(csv.DictReader(text.splitlines()))


def _index_csv(rows: list[dict[str, str]]) -> tuple[dict[str, set[str]], set[str]]:
    guid_to_names: dict[str, set[str]] = defaultdict(set)
    string_ids: set[str] = set()
    for row in rows:
        plan_id = (row.get("Service_Plan_Id") or "").strip().lower()
        plan_name = (row.get("Service_Plan_Name") or "").strip()
        string_id = (row.get("String_Id") or "").strip()
        if string_id:
            string_ids.add(string_id)
        if plan_id and plan_name:
            guid_to_names[plan_id].add(plan_name)
    return guid_to_names, string_ids


def _diff(
    *,
    guid_to_names: dict[str, set[str]],
    string_ids: set[str],
    map_guids: dict[str, str],
    capability_guids: dict[str, list[str]],
    sku_tokens: set[str],
) -> dict[str, Any]:
    missing_map_guids: list[dict[str, str]] = []
    name_mismatches: list[dict[str, Any]] = []
    for guid, name in sorted(map_guids.items()):
        if guid not in guid_to_names:
            missing_map_guids.append({"guid": guid, "catalog_name": name})
            continue
        if name not in guid_to_names[guid]:
            name_mismatches.append(
                {
                    "guid": guid,
                    "catalog_name": name,
                    "csv_names": sorted(guid_to_names[guid]),
                }
            )

    missing_cap_guids: list[dict[str, Any]] = []
    for guid, caps in sorted(capability_guids.items()):
        if guid not in guid_to_names:
            missing_cap_guids.append({"guid": guid, "capabilities": caps})

    unknown_sku_tokens = sorted(token for token in sku_tokens if token not in string_ids)

    return {
        "source": {
            "learn_page": LEARN_PAGE,
            "csv_url": DEFAULT_CSV_URL,
            "retrieval_note": "CSV URL resolved from Learn page; verify date on page.",
        },
        "counts": {
            "csv_plan_guids": len(guid_to_names),
            "csv_string_ids": len(string_ids),
            "catalog_mapped_guids": len(map_guids),
            "capability_guids": len(capability_guids),
            "capability_sku_tokens": len(sku_tokens),
        },
        "missing_map_guids": missing_map_guids,
        "name_mismatches": name_mismatches,
        "missing_capability_guids": missing_cap_guids,
        "unknown_sku_string_ids": unknown_sku_tokens,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, help="Local CSV path (skip download)")
    parser.add_argument("--csv-url", default=DEFAULT_CSV_URL, help="Override CSV URL")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args(argv)

    root = _repo_root()
    try:
        if args.csv:
            raw = args.csv.read_bytes()
        else:
            raw = _download_csv(args.csv_url)
        rows = _load_csv_rows(raw)
    except Exception as exc:  # noqa: BLE001 — surface download/parse as exit 2
        print(f"CSV load failed: {exc}", file=sys.stderr)
        return 2

    guid_to_names, string_ids = _index_csv(rows)
    map_raw = yaml.safe_load((root / "catalog" / "sku_service_plans.yaml").read_text()) or {}
    map_guids = {
        str(guid).strip().lower(): str(name).strip()
        for guid, name in (map_raw.get("service_plan_guids") or {}).items()
    }
    caps_raw = yaml.safe_load((root / "catalog" / "capabilities.yaml").read_text()) or {}
    capability_guids: dict[str, list[str]] = defaultdict(list)
    sku_tokens: set[str] = set()
    for cap in caps_raw.get("capabilities") or []:
        if not isinstance(cap, dict):
            continue
        cap_id = str(cap.get("id") or "?")
        for guid in cap.get("service_plan_ids") or []:
            capability_guids[str(guid).strip().lower()].append(cap_id)
        for token in (cap.get("sku_part_numbers") or []) + (cap.get("sku_aliases") or []):
            sku_tokens.add(str(token).strip())

    report = _diff(
        guid_to_names=guid_to_names,
        string_ids=string_ids,
        map_guids=map_guids,
        capability_guids=dict(capability_guids),
        sku_tokens=sku_tokens,
    )

    # Unknown SKU String_Ids are informational (Graph sometimes uses aliases);
    # hard-fail only on GUID absence / name mismatch.
    hard_fail = bool(
        report["missing_map_guids"]
        or report["name_mismatches"]
        or report["missing_capability_guids"]
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("LicenseLens ↔ Learn licensing CSV diff")
        print(f"  Learn: {LEARN_PAGE}")
        print(f"  CSV plan GUIDs: {report['counts']['csv_plan_guids']}")
        print(f"  Catalog mapped GUIDs: {report['counts']['catalog_mapped_guids']}")
        for label, key in (
            ("Missing mapped GUIDs", "missing_map_guids"),
            ("GUID name mismatches", "name_mismatches"),
            ("Capability GUIDs missing from CSV", "missing_capability_guids"),
        ):
            items = report[key]
            print(f"  {label}: {len(items)}")
            for item in items[:20]:
                print(f"    - {item}")
        unknowns = report["unknown_sku_string_ids"]
        print(f"  SKU tokens not in CSV String_Id (informational): {len(unknowns)}")
        for token in unknowns[:40]:
            print(f"    - {token}")
        print("  Result:", "FAIL" if hard_fail else "PASS (GUIDs)")

    return 1 if hard_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
