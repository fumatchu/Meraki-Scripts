#!/usr/bin/env python3
#MJG-Write 11-5
"""
find_uuid_clients.py

Find Meraki clients that are using UUID-style names (default) or, optionally,
"suspicious" hostnames (UUID OR long hex-only OR blank).

Usage examples:
  # Interactive: choose mode and org via menus
  python find_uuid_clients.py

  # Explicit UUID-only (no mode menu)
  python find_uuid_clients.py --mode uuid

  # UUID + lazy hex + blank/missing names
  python find_uuid_clients.py --mode suspicious

  # With explicit API key and org name
  python find_uuid_clients.py --api-key <KEY> --org "My Org" --mode suspicious
"""

from __future__ import annotations
import os
import sys
import time
import re
import csv
import argparse
import requests
from typing import List, Dict, Optional

BASE = "https://api.meraki.com/api/v1"

# Strict UUID with dashes: 8-4-4-4-12
UUID_WITH_DASHES_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# "Lazy hex" strings: long hex-only values, no dashes.
# 24–64 chars is a reasonable window for GUIDs-without-dashes and similar IDs.
LONG_HEX_RE = re.compile(r"^[0-9a-fA-F]{24,64}$")


# Basic backoff for Meraki API
def request_with_retries(
    method: str,
    url: str,
    headers: dict,
    params: dict = None,
    json: dict = None,
    max_retries: int = 6,
):
    backoff = 1
    for attempt in range(1, max_retries + 1):
        r = requests.request(
            method, url, headers=headers, params=params, json=json, timeout=30
        )
        if r.status_code == 200:
            return r
        if r.status_code in (429, 500, 502, 503, 504):
            retry_after = r.headers.get("Retry-After")
            wait = int(retry_after) if (retry_after and retry_after.isdigit()) else backoff
            print(
                f"[{r.status_code}] Rate/Server error. retry {attempt}/{max_retries} after {wait}s...",
                file=sys.stderr,
            )
            time.sleep(wait)
            backoff = min(backoff * 2, 60)
            continue
        r.raise_for_status()
    r.raise_for_status()


def get_orgs(api_key: str) -> List[Dict]:
    headers = {"X-Cisco-Meraki-API-Key": api_key}
    url = f"{BASE}/organizations"
    r = request_with_retries("GET", url, headers)
    return r.json()


def get_networks(api_key: str, org_id: str) -> List[Dict]:
    headers = {"X-Cisco-Meraki-API-Key": api_key}
    url = f"{BASE}/organizations/{org_id}/networks"
    r = request_with_retries("GET", url, headers)
    return r.json()


def get_clients(api_key: str, network_id: str, timespan: int) -> List[Dict]:
    headers = {"X-Cisco-Meraki-API-Key": api_key}
    params = {"timespan": timespan, "perPage": 1000}
    url = f"{BASE}/networks/{network_id}/clients"
    r = request_with_retries("GET", url, headers, params=params)
    return r.json()


def is_uuid_name(name: Optional[str]) -> bool:
    """
    Strict UUID-only check (for 'uuid' mode).
    Does NOT treat blank names as UUID; those are only included in 'suspicious' mode.
    """
    if not name:
        return False
    name = name.strip()
    if not name:
        return False
    return bool(UUID_WITH_DASHES_RE.match(name))


def is_suspicious_name(name: Optional[str]) -> bool:
    """
    "Suspicious" hostname:
      - blank / missing, OR
      - strict UUID with dashes, OR
      - long hex-only string (lazy GUID-style ID).
    """
    if not name:
        return True
    name = name.strip()
    if not name:
        return True

    if UUID_WITH_DASHES_RE.match(name):
        return True

    if LONG_HEX_RE.match(name):
        return True

    return False


def choose_from_list(prompt: str, items: List[Dict], label_key: str = "name") -> Dict:
    if not items:
        raise SystemExit("No items to choose from.")
    if len(items) == 1:
        return items[0]

    print(prompt)
    for i, it in enumerate(items, start=1):
        print(f" {i}) {it.get(label_key) or it.get('id')}")

    while True:
        sel = input(f"Choose 1-{len(items)}: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(items):
            return items[int(sel) - 1]
        print("Invalid selection")


def choose_mode_interactive() -> str:
    """
    Interactive mode picker, same style as org list:
      1) UUID only
      2) UUID + suspicious
    """
    print("Select detection mode:")
    print(" 1) UUID only (strict UUID hostnames)")
    print(" 2) UUID + suspicious (UUID, long hex, blank names)")
    while True:
        sel = input("Choose 1-2: ").strip()
        if sel == "1":
            return "uuid"
        if sel == "2":
            return "suspicious"
        print("Invalid selection")


def main():
    parser = argparse.ArgumentParser(
        description="Find Meraki clients with UUID-style or suspicious hostnames"
    )
    parser.add_argument("--api-key", help="Meraki API key (or set MERAKI_API_KEY)")
    parser.add_argument(
        "--org", help="Organization name to target (if omitted will prompt if multiple)"
    )
    parser.add_argument(
        "--timespan",
        type=int,
        help="Timespan in seconds to look back for clients (default 7 days)",
        default=7 * 24 * 3600,
    )
    parser.add_argument(
        "--out", help="CSV output filename", default="meraki_uuid_clients.csv"
    )
    parser.add_argument(
        "--mode",
        choices=["uuid", "suspicious"],
        default=None,
        help="Detection mode. If omitted, you'll be prompted after entering the API key.",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Fail for ambiguous org, and default to UUID-only mode if --mode not supplied",
    )
    args = parser.parse_args()

    # --- API key ---
    api_key = args.api_key or os.getenv("MERAKI_API_KEY")
    if not api_key:
        api_key = input("Meraki API Key: ").strip()
    if not api_key:
        print("API key required", file=sys.stderr)
        sys.exit(1)

    # --- Detection mode (after API key) ---
    if args.mode:
        mode = args.mode
    elif args.no_interactive:
        mode = "uuid"
    else:
        mode = choose_mode_interactive()

    print(f"Detection mode: {mode}")

    # --- Organizations ---
    orgs = get_orgs(api_key)
    if not orgs:
        print("No organizations found for that API key.", file=sys.stderr)
        sys.exit(1)

    if args.org:
        matches = [o for o in orgs if o.get("name") == args.org]
        if not matches:
            print(f"No org named '{args.org}' found. Available orgs:", file=sys.stderr)
            for o in orgs:
                print(" -", o.get("name"))
            sys.exit(2)
        chosen_org = matches[0]
    else:
        if len(orgs) == 1 or args.no_interactive:
            chosen_org = orgs[0]
        else:
            chosen_org = choose_from_list("Select an organization:", orgs, label_key="name")

    org_id = chosen_org["id"]
    org_name = chosen_org.get("name")
    print(f"Working on org: {org_name} (id: {org_id})")

    # --- Networks ---
    networks = get_networks(api_key, org_id)
    if not networks:
        print("No networks found in this org.", file=sys.stderr)
        sys.exit(4)

    results = []
    total_networks = len(networks)
    print(
        f"Found {total_networks} networks. Scanning clients (timespan {args.timespan}s)..."
    )

    for idx, net in enumerate(networks, start=1):
        net_id = net.get("id")
        net_name = net.get("name")
        print(f"[{idx}/{total_networks}] Network: {net_name} ({net_id}) ...", end=" ")
        sys.stdout.flush()

        try:
            clients = get_clients(api_key, net_id, args.timespan)
        except Exception as e:
            print(f"ERROR getting clients: {e}", file=sys.stderr)
            continue

        net_count = 0
        for c in clients:
            # Candidate name fields
            name_fields = [
                c.get("description"),
                c.get("dhcpHostname"),
                c.get("hostname"),
            ]
            chosen_name = next((n for n in name_fields if n), "") or ""

            if mode == "uuid":
                match = is_uuid_name(chosen_name)
            else:  # mode == "suspicious"
                match = is_suspicious_name(chosen_name)

            if not match:
                continue

            results.append(
                {
                    "org_id": org_id,
                    "org_name": org_name,
                    "network_id": net_id,
                    "network_name": net_name,
                    "client_mac": c.get("mac"),
                    "client_ip": c.get("ip"),
                    "name": chosen_name,
                    "seenAt": c.get("seenAt") or c.get("lastSeen") or "",
                    "client_description": c.get("description") or "",
                    "dhcpHostname": c.get("dhcpHostname") or "",
                    "os": c.get("os") or c.get("deviceType") or "",
                }
            )
            net_count += 1

        label = "UUID" if mode == "uuid" else "suspicious"
        print(f"found {net_count} {label} clients")

    # --- CSV output ---
    if results:
        fieldnames = [
            "org_name",
            "network_name",
            "network_id",
            "client_mac",
            "client_ip",
            "name",
            "dhcpHostname",
            "client_description",
            "os",
            "seenAt",
        ]
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(
                    {
                        "org_name": r.get("org_name", ""),
                        "network_name": r.get("network_name", ""),
                        "network_id": r.get("network_id", ""),
                        "client_mac": r.get("client_mac", ""),
                        "client_ip": r.get("client_ip", ""),
                        "name": r.get("name", ""),
                        "dhcpHostname": r.get("dhcpHostname", ""),
                        "client_description": r.get("client_description", ""),
                        "os": r.get("os", ""),
                        "seenAt": r.get("seenAt", ""),
                    }
                )
        print(f"\nWrote {len(results)} {mode} clients to {args.out}")
    else:
        print(f"\nNo {mode} clients found in the requested timespan.")


if __name__ == "__main__":
    main()
