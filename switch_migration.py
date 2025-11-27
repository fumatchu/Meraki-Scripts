#!/usr/bin/env python3
"""
Move a Meraki (or Cloud-managed Catalyst) switch or switch stack
from one network to another and preserve its switch-port config.

Features:
  - Login via API key (prompt or MERAKI_DASHBOARD_API_KEY)
  - Select source org, network, and switch
  - Detect if the switch is in a stack
      * If yes, option to move the entire stack:
        - Backup all stack members
        - Break stack in source network
        - Move all members to destination network
        - Restore ports + link aggregation groups
        - Recreate stack in destination network (or detect auto-created stack)
      * If not, just move the single switch
  - Batch mode:
      * Select multiple switches in a source network
      * Detect stacks automatically and move full stacks if any member is selected
      * Use a single destination org/network for the entire batch
  - Backup switch config (device + ports + link aggregations) to JSON
  - Select destination org
  - Either select an existing destination network OR create a new switch-only network
  - Move the switch/stack to the destination network
  - Restore:
      * Device metadata (name, tags, physical address, notes, lat/lng)
      * Switch port configuration
      * Link aggregation groups
  - Colorized console output + mirrored logs to ./logs/move_YYYY-MM-DD_HH-MM-SS.log

Prereqs:
    pip install meraki

Usage:
    python3 switch_migration.py
"""

import os
import sys
import json
import time
import re
import builtins
from datetime import datetime, timezone
from getpass import getpass

import meraki
from meraki.exceptions import APIError


# ─────────────────────────────────────────────────────────────────────────────
# Logging: mirror all prints to a log file (strip ANSI in log)
# ─────────────────────────────────────────────────────────────────────────────

LOG_FILE = None


def init_log_file():
    """Initialize a new log file in ./logs/ with a timestamped name."""
    global LOG_FILE
    os.makedirs("logs", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    LOG_FILE = f"logs/move_{ts}.log"
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"Meraki Switch Move Log - {ts}\n")
        f.write("=====================================================\n")


def remove_ansi(text: str) -> str:
    """Strip ANSI escape sequences for clean logs."""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_escape.sub("", text)


def log_print(*args, **kwargs):
    """
    Drop-in replacement for print():
      - prints to stdout (with colors)
      - writes a stripped version to LOG_FILE (if initialized)
    """
    sep = kwargs.get("sep", " ")
    end = kwargs.get("end", "\n")
    text = sep.join(str(a) for a in args)

    # Console output (keep color)
    builtins.print(text, end=end)

    # Log file output (strip color)
    if LOG_FILE:
        stripped = remove_ansi(text)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(stripped + ("\n" if not end or end.endswith("\n") else end))


# Replace built-in print in this module with our logger
print = log_print  # noqa: E305,E402


# ─────────────────────────────────────────────────────────────────────────────
# Colors / formatting
# ─────────────────────────────────────────────────────────────────────────────

USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def _c(code: str) -> str:
    return code if USE_COLOR else ""


RESET   = _c("\033[0m")
BOLD    = _c("\033[1m")
RED     = _c("\033[31m")
GREEN   = _c("\033[32m")
YELLOW  = _c("\033[33m")
BLUE    = _c("\033[34m")
MAGENTA = _c("\033[35m")
CYAN    = _c("\033[36m")


def info(msg: str):
    print(f"{CYAN}{msg}{RESET}")


def success(msg: str):
    print(f"{GREEN}{msg}{RESET}")


def warn(msg: str):
    print(f"{YELLOW}{msg}{RESET}")


def error(msg: str):
    print(f"{RED}{msg}{RESET}")


def header(msg: str):
    print(f"\n{BOLD}{CYAN}=== {msg} ==={RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# API key handling
# ─────────────────────────────────────────────────────────────────────────────

def prompt_api_key() -> str:
    api_key = os.getenv("MERAKI_DASHBOARD_API_KEY")
    if api_key:
        ans = input(f"{YELLOW}Use MERAKI_DASHBOARD_API_KEY from environment? [Y/n]: {RESET}").strip().lower()
        if ans in ("", "y", "yes"):
            return api_key

    api_key = getpass(f"{CYAN}Enter Meraki Dashboard API key (input hidden): {RESET}").strip()
    if not api_key:
        error("No API key provided, exiting.")
        sys.exit(1)
    return api_key


# ─────────────────────────────────────────────────────────────────────────────
# Generic selection helpers
# ─────────────────────────────────────────────────────────────────────────────

def choose_from_list(items, label_fn, prompt="Choose an option"):
    if not items:
        error("No options available.")
        sys.exit(1)

    while True:
        header(prompt)
        for idx, item in enumerate(items, start=1):
            print(f"  [{idx}] {label_fn(item)}")
        choice = input(f"{YELLOW}Enter number (or q to quit): {RESET}").strip().lower()
        if choice in ("q", "quit", "exit"):
            warn("Aborted by user.")
            sys.exit(0)
        if not choice.isdigit():
            warn("Please enter a valid number.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(items):
            return items[idx - 1]
        warn("Out of range, try again.")


def select_organization(dashboard):
    orgs = dashboard.organizations.getOrganizations()
    return choose_from_list(
        orgs,
        lambda o: f"{o.get('name')} (id={o.get('id')})",
        "Select an organization",
    )


def select_network(dashboard, org_id, prompt="Select a network"):
    networks = dashboard.organizations.getOrganizationNetworks(
        org_id,
        perPage=1000,
    )

    def net_score(n):
        types = n.get("productTypes", [])
        return 0 if "switch" in types else 1

    networks.sort(key=net_score)

    return choose_from_list(
        networks,
        lambda n: f"{n.get('name')} (id={n.get('id')}, products={','.join(n.get('productTypes', []))})",
        prompt,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Switch / stack selection logic
# ─────────────────────────────────────────────────────────────────────────────

def is_movable_switch(device: dict) -> bool:
    """
    Decide whether a device can be moved by this tool.

    - Always allow Meraki MS switches.
    - Allow Cloud-managed Catalyst switches (C92/C93/C94/...) whose firmware
      does NOT contain "IOS XE".
    """
    model = (device.get("model") or "").upper()
    ptype = (device.get("productType") or "").lower()
    firmware = (device.get("firmware") or device.get("firmwareVersion") or "").upper().strip()

    # Meraki MS – always OK
    if model.startswith("MS"):
        return True

    # Is it "switch-ish" at all?
    is_switch_family = (
        ptype == "switch"
        or model.startswith(("C92", "C93", "C94", "C95", "C96"))
    )
    if not is_switch_family:
        return False

    # Exclude IOS XE monitoring-only devices
    if "IOS XE" in firmware:
        return False

    # Everything else in this family is considered movable
    return True


def select_switch_in_network(dashboard, network_id):
    devices = dashboard.networks.getNetworkDevices(network_id)

    if not devices:
        error("No devices found in this network at all.")
        sys.exit(1)

    switches = [d for d in devices if is_movable_switch(d)]

    if not switches:
        warn("\nNo eligible switch devices found in this network.")
        print("Devices present (for reference):")
        for d in devices:
            print(
                f"  name={d.get('name')!r}, "
                f"serial={d.get('serial')}, "
                f"model={d.get('model')}, "
                f"productType={d.get('productType')}, "
                f"firmware={d.get('firmware') or d.get('firmwareVersion')}"
            )
        print(f"\n{YELLOW}Note: This tool only moves:{RESET}")
        print("  - Meraki MS switches, or")
        print("  - Cloud-managed Catalyst switches NOT running IOS-XE.")
        sys.exit(1)

    return choose_from_list(
        switches,
        lambda d: (
            f"{d.get('name') or '(no name)'} | "
            f"serial={d.get('serial')} | "
            f"model={d.get('model')} | "
            f"firmware={d.get('firmware') or d.get('firmwareVersion')} | "
            f"productType={d.get('productType')}"
        ),
        "Select a switch (MS or CS, not IOS-XE)",
    )


def select_multiple_switches_in_network(dashboard, network_id):
    """
    Let the user pick multiple switches from a network (by index, ranges, or 'all').
    Returns a list of device dicts.
    """
    devices = dashboard.networks.getNetworkDevices(network_id)

    if not devices:
        error("No devices found in this network at all.")
        sys.exit(1)

    switches = [d for d in devices if is_movable_switch(d)]

    if not switches:
        warn("\nNo eligible switch devices found in this network.")
        print("Devices present (for reference):")
        for d in devices:
            print(
                f"  name={d.get('name')!r}, "
                f"serial={d.get('serial')}, "
                f"model={d.get('model')}, "
                f"productType={d.get('productType')}, "
                f"firmware={d.get('firmware') or d.get('firmwareVersion')}"
            )
        print(f"\n{YELLOW}Note: This tool only moves:{RESET}")
        print("  - Meraki MS switches, or")
        print("  - Cloud-managed Catalyst switches NOT running IOS-XE.")
        sys.exit(1)

    header("Select one or more switches (batch mode)")
    for idx, d in enumerate(switches, start=1):
        print(
            f"  [{idx}] {d.get('name') or '(no name)'} | "
            f"serial={d.get('serial')} | model={d.get('model')}"
        )

    while True:
        raw = input(
            f"{YELLOW}Enter numbers (e.g. 1,2,5-7), 'all' for all, or 'q' to quit: {RESET}"
        ).strip().lower()

        if raw in ("q", "quit", "exit"):
            warn("Aborted by user.")
            sys.exit(0)

        if raw == "all":
            return switches

        try:
            indices = parse_index_list(raw, len(switches))
        except ValueError as e:
            warn(str(e))
            continue

        if not indices:
            warn("No valid selections parsed; try again.")
            continue

        return [switches[i - 1] for i in sorted(indices)]


def parse_index_list(s: str, max_index: int):
    """
    Parse a string like "1,2,5-7" into a set of 1-based indices.
    Raises ValueError for invalid input.
    """
    indices = set()
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        raise ValueError("Empty selection.")

    for part in parts:
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            if not (start_str.isdigit() and end_str.isdigit()):
                raise ValueError(f"Invalid range: {part}")
            start = int(start_str)
            end = int(end_str)
            if start > end:
                raise ValueError(f"Invalid range (start > end): {part}")
            if start < 1 or end > max_index:
                raise ValueError(f"Range out of bounds: {part}")
            for i in range(start, end + 1):
                indices.add(i)
        else:
            if not part.isdigit():
                raise ValueError(f"Invalid index: {part}")
            idx = int(part)
            if idx < 1 or idx > max_index:
                raise ValueError(f"Index out of bounds: {part}")
            indices.add(idx)

    return indices


def detect_switch_stack(dashboard, network_id: str, serial: str):
    """
    Return the switch stack dict the serial belongs to, or None.
    """
    try:
        stacks = dashboard.switch.getNetworkSwitchStacks(network_id)
    except APIError as e:
        warn(f"Failed to query switch stacks: {e}")
        return None

    for stack in stacks:
        serials = stack.get("serials") or []
        if serial in serials:
            return stack

    return None


def build_move_plan_for_selection(dashboard, network_id: str, devices):
    """
    Given a set of selected devices in a network, decide which stacks
    and which standalone switches will be moved.

    Returns:
        stacks_to_move:  [stack_dict, ...]
        singles_to_move: [device_dict, ...]
    """
    selected_serials = {d["serial"] for d in devices}
    handled_serials = set()
    stacks_to_move = []
    singles_to_move = []

    for d in devices:
        serial = d["serial"]
        if serial in handled_serials:
            continue

        stack = detect_switch_stack(dashboard, network_id, serial)
        if stack:
            stack_serials = set(stack.get("serials") or [])
            # Mark all members as handled
            handled_serials.update(stack_serials)
            stacks_to_move.append(stack)

            # If some stack members weren't in the explicit selection, let the user know.
            missing = stack_serials - selected_serials
            if missing:
                warn(
                    f"Stack '{stack.get('name')}' has additional members not explicitly "
                    f"selected: {', '.join(sorted(missing))}. Moving the full stack."
                )
        else:
            singles_to_move.append(d)
            handled_serials.add(serial)

    return stacks_to_move, singles_to_move


# ─────────────────────────────────────────────────────────────────────────────
# Backup / restore (ports + link aggregations)
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_PORT_FIELDS = {
    "name",
    "tags",
    "enabled",
    "poeEnabled",
    "type",
    "vlan",
    "voiceVlan",
    "allowedVlans",
    "isolationEnabled",
    "rstpEnabled",
    "stpGuard",
    "linkNegotiation",
    "portScheduleId",
    "udld",
    "accessPolicyType",
    "accessPolicyNumber",
    "macAllowList",
    "macWhitelistLimit",
    "stickyMacAllowList",
    "stickyMacAllowListLimit",
    "stormControlEnabled",
    "adaptivePolicyGroupId",
    "peerSgtCapable",
    "flexibleStackingEnabled",
    "daiTrusted",
    "profile",       # {enabled,id,name}
    "mirror",        # {mode}
    "dot3az",        # {enabled}
    "highSpeed",     # {enabled}
}


def backup_switch_config(dashboard, network_id: str, serial: str, backup_dir="backups"):
    """
    Fetch switch config (device + all ports + link aggregations touching this switch)
    and save to a JSON file. Returns (config_dict, path).
    """
    os.makedirs(backup_dir, exist_ok=True)

    header(f"Backing up config for switch {serial}")

    device = dashboard.devices.getDevice(serial)
    ports = dashboard.switch.getDeviceSwitchPorts(serial)

    # Network-level link aggregations; filter down to those involving this serial
    try:
        all_link_aggs = dashboard.switch.getNetworkSwitchLinkAggregations(network_id)
    except APIError as e:
        warn(f"Could not fetch link aggregations: {e}")
        all_link_aggs = []

    link_aggs = []
    for lag in all_link_aggs:
        for sp in lag.get("switchPorts", []):
            if sp.get("serial") == serial:
                link_aggs.append(lag)
                break

    now_utc = datetime.now(timezone.utc)
    backup = {
        "serial": serial,
        "networkId": network_id,
        "timestamp": now_utc.isoformat(),
        "device": device,
        "ports": ports,
        "linkAggregations": link_aggs,
    }

    ts = now_utc.strftime("%Y%m%d-%H%M%S")
    fname = os.path.join(backup_dir, f"{serial}_backup_{ts}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(backup, f, indent=2)

    success(f"Backup saved to {fname}")
    return backup, fname


def backup_stack_config(dashboard, network_id: str, stack: dict, backup_dir="backups"):
    """
    Backup ALL members of a stack plus all link aggregations
    that touch ANY member of the stack.
    """
    os.makedirs(backup_dir, exist_ok=True)
    serials = stack.get("serials") or []

    header(
        f"Backing up config for stack '{stack.get('name')}' "
        f"(id={stack.get('id')}) with members: {', '.join(serials)}"
    )

    # All network link aggregations once
    try:
        all_link_aggs = dashboard.switch.getNetworkSwitchLinkAggregations(network_id)
    except APIError as e:
        warn(f"Could not fetch link aggregations for stack: {e}")
        all_link_aggs = []

    member_set = set(serials)
    stack_link_aggs = []
    for lag in all_link_aggs:
        ports = lag.get("switchPorts") or []
        if any(sp.get("serial") in member_set for sp in ports):
            stack_link_aggs.append(lag)

    per_switch_backups = {}
    for serial in serials:
        backup, path = backup_switch_config(dashboard, network_id, serial, backup_dir)
        per_switch_backups[serial] = {"backup": backup, "file": path}

    now_utc = datetime.now(timezone.utc)
    ts = now_utc.strftime("%Y%m%d-%H%M%S")
    stack_backup = {
        "stackId": stack.get("id"),
        "name": stack.get("name"),
        "networkId": network_id,
        "serials": serials,
        "timestamp": now_utc.isoformat(),
        "linkAggregations": stack_link_aggs,
        "perSwitchFiles": {s: info_["file"] for s, info_ in per_switch_backups.items()},
    }
    stack_fname = os.path.join(backup_dir, f"stack_{stack['id']}_backup_{ts}.json")
    with open(stack_fname, "w", encoding="utf-8") as f:
        json.dump(stack_backup, f, indent=2)

    success(f"Stack backup metadata saved to {stack_fname}")
    return per_switch_backups, stack_link_aggs, stack_fname


def restore_switch_ports(dashboard, serial: str, ports_backup):
    header(f"Restoring {len(ports_backup)} ports on switch {serial}")
    success_count = 0
    failures = 0

    for port in ports_backup:
        port_id = str(port.get("portId"))
        if not port_id:
            warn("  Skipping a port with no portId in backup.")
            continue

        profile_name = (port.get("profile") or {}).get("name")
        label = profile_name or port.get("name") or port_id

        print(f"  Port {port_id} ({label}): ", end="")

        body = {k: v for k, v in port.items() if k in ALLOWED_PORT_FIELDS}

        try:
            dashboard.switch.updateDeviceSwitchPort(serial, port_id, **body)
            print(f"{GREEN}OK{RESET}")
            success_count += 1
        except APIError as e:
            print(f"{RED}FAILED -> {e}{RESET}")
            failures += 1

    print(
        f"\nPort restore complete on {serial}: "
        f"{GREEN}{success_count} success{RESET}, {RED}{failures} failed{RESET}."
    )


def restore_switch_link_aggregations(dashboard, network_id: str, label: str, link_aggs_backup):
    if not link_aggs_backup:
        info(f"No link aggregation groups to restore for {label}.")
        return

    header(f"Restoring {len(link_aggs_backup)} link aggregation groups for {label}")

    created = 0
    failures = 0
    for lag in link_aggs_backup:
        name = lag.get("name") or "(no name)"
        switch_ports = lag.get("switchPorts") or []
        try:
            dashboard.switch.createNetworkSwitchLinkAggregation(
                network_id,
                switchPorts=switch_ports,
                name=name,
            )
            print(f"  LAG '{name}' ({len(switch_ports)} ports): {GREEN}OK{RESET}")
            created += 1
        except APIError as e:
            print(f"  LAG '{name}': {RED}FAILED -> {e}{RESET}")
            failures += 1

    print(
        f"Link aggregation restore for {label}: "
        f"{GREEN}{created} created{RESET}, {RED}{failures} failed{RESET}."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Device metadata (name / tags / physical address / notes / lat/lng)
# ─────────────────────────────────────────────────────────────────────────────

DEVICE_META_FIELDS = ("name", "tags", "address", "notes", "lat", "lng")


def _get_common_dest_address(dashboard, network_id: str):
    """
    Look at all devices in the destination network and determine the
    most common non-empty address (and its lat/lng if present).

    Returns:
        {
          "address": "123 Main St, City, ST",
          "count": 5,
          "lat": 33.123,
          "lng": -84.55,
        }
        or None if no addresses were found.
    """
    try:
        devices = dashboard.networks.getNetworkDevices(network_id)
    except APIError as e:
        warn(f"Could not inspect destination network devices for address: {e}")
        return None

    addr_map = {}
    for d in devices:
        addr = (d.get("address") or "").strip()
        if not addr:
            continue
        key = addr.lower()
        if key not in addr_map:
            addr_map[key] = {
                "address": addr,
                "count": 0,
                "lat": d.get("lat"),
                "lng": d.get("lng"),
            }
        addr_map[key]["count"] += 1

    if not addr_map:
        return None

    # Pick the most common address
    return max(addr_map.values(), key=lambda x: x["count"])


def choose_address_for_device(
    dashboard,
    dst_net_id: str,
    backup_device: dict,
    addr_cache: dict | None = None,
):
    """
    Decide which physical (mailing) address to use for a device being moved:

      - Source address: from backup_device["address"]
      - Destination "standard" address: most common address among devices
        already in the destination network.

    For stacks, addr_cache is used to remember the first choice and
    apply it to all members without prompting again.
    """
    src_addr = (backup_device.get("address") or "").strip()

    # If the source device has no address, just return as-is.
    if not src_addr:
        return backup_device

    dest_common = _get_common_dest_address(dashboard, dst_net_id)
    if not dest_common:
        # No meaningful address pattern in destination network – keep source.
        return backup_device

    dest_addr = dest_common["address"].strip()

    # If they match (case-insensitive), nothing to decide.
    if dest_addr.lower() == src_addr.lower():
        return backup_device

    # If we have a cache and a mode, reuse it.
    if addr_cache is not None and "mode" in addr_cache:
        mode = addr_cache["mode"]
        if mode == "source":
            return backup_device
        # mode == "dest"
        new_dev = dict(backup_device)
        new_dev["address"] = addr_cache["dest_address"]
        if addr_cache.get("lat") is not None:
            new_dev["lat"] = addr_cache["lat"]
        if addr_cache.get("lng") is not None:
            new_dev["lng"] = addr_cache["lng"]
        return new_dev

    # Otherwise, prompt user which one to use.
    header("Physical address selection for moved device")
    print(f"  Source device address:      {src_addr}")
    print(f"  Common address in DEST net: {dest_addr} (on {dest_common['count']} device(s))")
    choice = input(
        f"{YELLOW}Use which address? [1] Source  [2] Destination (default): {RESET}"
    ).strip()

    if choice == "1":
        info("Keeping source device address.")
        if addr_cache is not None:
            addr_cache["mode"] = "source"
        return backup_device

    # Use destination network's common address (and its lat/lng if present)
    info("Using destination network's common address for this device.")
    new_dev = dict(backup_device)
    new_dev["address"] = dest_addr
    if dest_common.get("lat") is not None:
        new_dev["lat"] = dest_common["lat"]
    if dest_common.get("lng") is not None:
        new_dev["lng"] = dest_common["lng"]

    if addr_cache is not None:
        addr_cache["mode"] = "dest"
        addr_cache["dest_address"] = dest_addr
        addr_cache["lat"] = dest_common.get("lat")
        addr_cache["lng"] = dest_common.get("lng")

    return new_dev


def restore_device_metadata(dashboard, serial: str, device_obj: dict):
    """
    Restore high-level device metadata (name, tags, address, notes, lat/lng)
    onto a device in its *current* network.
    """
    body = {}
    for field in DEVICE_META_FIELDS:
        value = device_obj.get(field)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        body[field] = value

    if not body:
        return

    header(f"Restoring device metadata for {serial}")
    try:
        dashboard.devices.updateDevice(serial, **body)
        success(f"Device metadata updated for {serial}.")
    except APIError as e:
        warn(f"Could not update device metadata for {serial}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Network creation
# ─────────────────────────────────────────────────────────────────────────────

def create_switch_network(dashboard, org_id: str):
    header("Creating a new switch-only network in the selected organization")

    try:
        org = dashboard.organizations.getOrganization(org_id)
        org_tz = org.get("timeZone", "America/New_York")
    except Exception:
        org_tz = "America/New_York"

    default_name = f"Switch-move-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    name = input(f"{CYAN}Enter name for new network [{default_name}]: {RESET}").strip()
    if not name:
        name = default_name

    tz_in = input(f"{CYAN}Enter time zone for new network [{org_tz}]: {RESET}").strip()
    if not tz_in:
        tz_in = org_tz

    info(
        f"Creating network '{name}' "
        f"(time zone: {tz_in}, productTypes: ['switch']) ..."
    )
    try:
        net = dashboard.organizations.createOrganizationNetwork(
            org_id,
            name=name,
            productTypes=["switch"],
            timeZone=tz_in,
        )
    except APIError as e:
        error(f"Failed to create network: {e}")
        sys.exit(1)

    success(f"Created network: {net.get('name')} (id={net.get('id')})")
    return net


def choose_destination_org_and_network(dashboard, org_src: dict, net_src: dict):
    header("Destination organization")
    print("  [1] Same as source")
    print("  [2] Choose a different organization")
    choice = input(f"{YELLOW}Select option [1/2]: {RESET}").strip()
    if choice == "2":
        org_dst = select_organization(dashboard)
    else:
        org_dst = org_src

    header("Destination network")
    print("  [1] Use an existing network")
    print("  [2] Create a new switch-only network")
    n_choice = input(f"{YELLOW}Select option [1/2]: {RESET}").strip()

    if n_choice == "2":
        net_dst = create_switch_network(dashboard, org_dst["id"])
    else:
        net_dst = select_network(dashboard, org_dst["id"], prompt="Select DESTINATION network")

    if org_src["id"] == org_dst["id"] and net_src["id"] == net_dst["id"]:
        warn("Source and destination networks are the same. No move necessary.")
        sys.exit(0)

    return org_dst, net_dst


# ─────────────────────────────────────────────────────────────────────────────
# Move operations (single switch vs entire stack)
# ─────────────────────────────────────────────────────────────────────────────

def find_stack_by_serials(dashboard, network_id: str, serials):
    """
    Look for an existing stack in `network_id` whose member serials
    exactly match the given serial list (order-independent).
    """
    try:
        stacks = dashboard.switch.getNetworkSwitchStacks(network_id)
    except APIError as e:
        warn(f"Could not list stacks in destination network: {e}")
        return None

    desired = set(serials)
    for s in stacks:
        s_serials = set(s.get("serials") or [])
        if s_serials == desired:
            return s

    return None


def move_switch_between_networks(
    dashboard,
    org_src, net_src, device,
    org_dst, net_dst,
    backup,
):
    src_net_id = net_src["id"]
    dst_net_id = net_dst["id"]
    serial = device["serial"]

    header("Summary of SINGLE-SWITCH move")
    print(f"  Switch: {device.get('name') or '(no name)'} | serial={serial} | model={device.get('model')}")
    print(f"  From: org={org_src['name']} (id={org_src['id']}), network={net_src['name']} (id={src_net_id})")
    print(f"  To:   org={org_dst['name']} (id={org_dst['id']}), network={net_dst['name']} (id={dst_net_id})")

    confirm = input(f"{YELLOW}Proceed with move? Type 'yes' to continue: {RESET}").strip().lower()
    if confirm != "yes":
        warn("Move cancelled.")
        sys.exit(0)

    header("Removing device from source network")
    try:
        dashboard.networks.removeNetworkDevices(src_net_id, serial)
        success("Device removed from source network.")
    except APIError as e:
        error(f"Error removing device from source network: {e}")
        error("Aborting before claiming into destination network.")
        sys.exit(1)

    header("Claiming device into destination network")
    try:
        dashboard.networks.claimNetworkDevices(dst_net_id, serials=[serial])
        success("Device claimed into destination network.")
    except APIError as e:
        error(f"Error claiming device into destination network: {e}")
        error("Device has been removed from the source but not added to the destination.")
        sys.exit(1)

    info("Waiting a few seconds for the Dashboard to register the move...")
    time.sleep(5)

    # Decide physical address / metadata for this device
    chosen_device = choose_address_for_device(dashboard, dst_net_id, backup["device"], addr_cache=None)
    restore_device_metadata(dashboard, serial, chosen_device)

    # Ports + LAGs
    restore_switch_ports(dashboard, serial, backup["ports"])

    restore_switch_link_aggregations(
        dashboard,
        dst_net_id,
        label=serial,
        link_aggs_backup=backup.get("linkAggregations", []),
    )

    success("Done. Verify in Dashboard that the switch looks correct in its new network.")


def move_stack_between_networks(
    dashboard,
    org_src, net_src, stack,
    org_dst, net_dst,
    per_switch_backups,
    stack_link_aggs,
):
    src_net_id = net_src["id"]
    dst_net_id = net_dst["id"]
    serials = stack.get("serials") or []

    header("Summary of STACK move")
    print(f"  Stack: '{stack.get('name')}' (id={stack.get('id')})")
    for serial in serials:
        dev = per_switch_backups[serial]["backup"]["device"]
        print(f"    - {dev.get('name') or '(no name)'} | serial={serial} | model={dev.get('model')}")
    print(f"  From: org={org_src['name']} (id={org_src['id']}), network={net_src['name']} (id={src_net_id})")
    print(f"  To:   org={org_dst['name']} (id={org_dst['id']}), network={net_dst['name']} (id={dst_net_id})")

    confirm = input(f"{YELLOW}Proceed with STACK move? Type 'yes' to continue: {RESET}").strip().lower()
    if confirm != "yes":
        warn("Stack move cancelled.")
        sys.exit(0)

    header("Breaking stack in source network (deleting stack object)")
    try:
        dashboard.switch.deleteNetworkSwitchStack(src_net_id, stack["id"])
        success(f"Stack '{stack.get('name')}' deleted; members are now standalone switches.")
    except APIError as e:
        error(f"FAILED to delete stack: {e}")
        error("Aborting before moving devices.")
        sys.exit(1)

    header("Removing devices from source network")
    for serial in serials:
        try:
            dashboard.networks.removeNetworkDevices(src_net_id, serial)
            success(f"Removed {serial} from source network.")
        except APIError as e:
            error(f"FAILED to remove {serial} from source network: {e}")
            error("Aborting before claiming into destination.")
            sys.exit(1)

    header("Claiming devices into destination network")
    try:
        dashboard.networks.claimNetworkDevices(dst_net_id, serials=serials)
        success("All devices claimed into destination network.")
    except APIError as e:
        error(f"Error claiming devices into destination network: {e}")
        error("Devices are removed from the source but not added to the destination.")
        sys.exit(1)

    info("Waiting a few seconds for the Dashboard to register the move...")
    time.sleep(5)

    # Address / metadata choice — prompt ONCE, reuse for all stack members
    addr_cache: dict = {}
    header("Restoring device metadata on all stack members")
    for serial in serials:
        backup_dev = per_switch_backups[serial]["backup"]["device"]
        chosen_dev = choose_address_for_device(dashboard, dst_net_id, backup_dev, addr_cache=addr_cache)
        restore_device_metadata(dashboard, serial, chosen_dev)

    header("Restoring ports on all stack members")
    for serial in serials:
        backup = per_switch_backups[serial]["backup"]
        restore_switch_ports(dashboard, serial, backup["ports"])

    restore_switch_link_aggregations(
        dashboard,
        dst_net_id,
        label=f"stack {stack.get('name')}",
        link_aggs_backup=stack_link_aggs,
    )

    header("Ensuring stack exists in destination network")
    existing = find_stack_by_serials(dashboard, dst_net_id, serials)
    if existing:
        success(
            f"Stack already present in destination (likely auto-provisioned): "
            f"'{existing.get('name')}' (id={existing.get('id')})"
        )
        success("Stack move complete. Verify in Dashboard that the stack and ports look correct.")
        return

    try:
        dashboard.switch.createNetworkSwitchStack(
            dst_net_id,
            name=stack.get("name"),
            serials=serials,
        )
        success(f"Stack '{stack.get('name')}' recreated in destination network.")
    except APIError as e:
        msg = str(e)
        if "already part of a switch stack" in msg:
            warn("Stack creation failed because switches are already in a stack.")
            warn("Dashboard auto-provisioning likely created the stack; verify in the UI.")
        else:
            error(f"FAILED to recreate stack: {e}")

    success("Stack move complete. Verify in Dashboard that the stack and ports look correct.")


# ─────────────────────────────────────────────────────────────────────────────
# Single workflow run (one switch or one stack)
# ─────────────────────────────────────────────────────────────────────────────

def run_single_move(dashboard):
    header("Select SOURCE")
    org_src = select_organization(dashboard)
    net_src = select_network(dashboard, org_src["id"], prompt="Select SOURCE network")
    device = select_switch_in_network(dashboard, net_src["id"])
    serial = device["serial"]

    stack = detect_switch_stack(dashboard, net_src["id"], serial)

    if stack:
        header("Stack detected")
        print(f"  Stack name: {stack.get('name')}")
        print(f"  Stack id:   {stack.get('id')}")
        print(f"  Members:    {', '.join(stack.get('serials') or [])}")
        print(f"\n{YELLOW}Meraki requires breaking a stack before moving its switches.{RESET}")
        print("This tool can:")
        print("  - Break the stack in the SOURCE network")
        print("  - Move ALL stack members together")
        print("  - Restore configs and re-create the stack in the DESTINATION network")

        proceed = input(f"{YELLOW}Move the ENTIRE stack as a unit? [y/N]: {RESET}").strip().lower()
        if proceed not in ("y", "yes"):
            warn("No stack move performed. If you want to move a single member, "
                 "break the stack manually first and then re-run this tool.")
            return

        per_switch_backups, stack_link_aggs, stack_backup_path = backup_stack_config(
            dashboard, net_src["id"], stack
        )
        success(f"Stack backup metadata file: {stack_backup_path}")

        org_dst, net_dst = choose_destination_org_and_network(dashboard, org_src, net_src)

        move_stack_between_networks(
            dashboard,
            org_src, net_src, stack,
            org_dst, net_dst,
            per_switch_backups,
            stack_link_aggs,
        )

    else:
        backup, backup_path = backup_switch_config(dashboard, net_src["id"], serial)
        success(f"Backup file: {backup_path}")

        org_dst, net_dst = choose_destination_org_and_network(dashboard, org_src, net_src)

        move_switch_between_networks(
            dashboard,
            org_src, net_src, device,
            org_dst, net_dst,
            backup,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Batch workflow (multiple switches / stacks)
# ─────────────────────────────────────────────────────────────────────────────

def run_batch_move(dashboard):
    header("Select SOURCE (batch mode)")
    org_src = select_organization(dashboard)
    net_src = select_network(dashboard, org_src["id"], prompt="Select SOURCE network")

    selected_devices = select_multiple_switches_in_network(dashboard, net_src["id"])
    if not selected_devices:
        warn("No devices selected.")
        return

    stacks_to_move, singles_to_move = build_move_plan_for_selection(
        dashboard, net_src["id"], selected_devices
    )

    header("Batch move plan")
    if stacks_to_move:
        print("Stacks to move:")
        for s in stacks_to_move:
            print(
                f"  - {s.get('name')} (id={s.get('id')}), "
                f"members: {', '.join(s.get('serials') or [])}"
            )
    else:
        print("Stacks to move: (none)")

    if singles_to_move:
        print("Standalone switches to move:")
        for d in singles_to_move:
            print(
                f"  - {d.get('name') or '(no name)'} | "
                f"serial={d['serial']} | model={d['model']}"
            )
    else:
        print("Standalone switches to move: (none)")

    confirm = input(
        f"{YELLOW}Proceed with this batch move? Type 'yes' to continue: {RESET}"
    ).strip().lower()
    if confirm != "yes":
        warn("Batch move cancelled.")
        return

    org_dst, net_dst = choose_destination_org_and_network(dashboard, org_src, net_src)

    # Move stacks first
    for stack in stacks_to_move:
        per_switch_backups, stack_link_aggs, stack_backup_path = backup_stack_config(
            dashboard, net_src["id"], stack
        )
        success(f"Stack backup metadata file: {stack_backup_path}")
        move_stack_between_networks(
            dashboard,
            org_src, net_src, stack,
            org_dst, net_dst,
            per_switch_backups,
            stack_link_aggs,
        )

    # Then standalone switches
    for device in singles_to_move:
        serial = device["serial"]
        backup, backup_path = backup_switch_config(dashboard, net_src["id"], serial)
        success(f"Backup file: {backup_path}")
        move_switch_between_networks(
            dashboard,
            org_src, net_src, device,
            org_dst, net_dst,
            backup,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main loop with API key reuse
# ─────────────────────────────────────────────────────────────────────────────

def main():
    init_log_file()
    header("Meraki Switch / Stack Move Tool")
    if LOG_FILE:
        info(f"Logging to: {LOG_FILE}")
    cached_api_key = None

    while True:
        if cached_api_key is None:
            api_key = prompt_api_key()
        else:
            info("Reusing cached API key.")
            api_key = cached_api_key

        dashboard = meraki.DashboardAPI(
            api_key,
            output_log=False,
            print_console=False,
            suppress_logging=True,
        )

        # Mode selection
        header("Mode selection")
        print("  [1] Move a single switch or stack")
        print("  [2] Batch move multiple switches / stacks")
        mode = input(f"{YELLOW}Select mode [1/2]: {RESET}").strip()

        if mode == "2":
            run_batch_move(dashboard)
        else:
            run_single_move(dashboard)

        again = input(
            f"\n{YELLOW}Do you want to perform another move? [y/N]: {RESET}"
        ).strip().lower()
        if again not in ("y", "yes"):
            success("Exiting...")
            break

        reuse = input(f"{YELLOW}Reuse the same API key? [Y/n]: {RESET}").strip().lower()
        if reuse in ("", "y", "yes"):
            cached_api_key = api_key
        else:
            cached_api_key = None


if __name__ == "__main__":
    main()
