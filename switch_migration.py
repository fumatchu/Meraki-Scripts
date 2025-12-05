
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

import glob
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

# Track (source_net_id, dest_net_id) pairs where we moved switches,
# so we can do a final STP summary at exit.
STP_AUDIT_PAIRS: set[tuple[str, str]] = set()


def note_stp_pair(src_net_id: str, dst_net_id: str):
    """Remember that we moved switches from src_net_id → dst_net_id."""
    STP_AUDIT_PAIRS.add((src_net_id, dst_net_id))


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

# ──────────────────────────────────────────────────────────
# STP audit tracking (collect source→destination pairs)
# ──────────────────────────────────────────────────────────

# Keep track of (source_net_id, dest_net_id) pairs for a final STP report
STP_AUDIT_PAIRS: set[tuple[str, str]] = set()

def note_stp_pair(src_net_id: str, dst_net_id: str):
    """Remember that we moved switches from src_net_id → dst_net_id."""
    STP_AUDIT_PAIRS.add((src_net_id, dst_net_id))


# ─────────────────────────────────────────────────────────────────────────────
# Mull over each switch to detect if it's MS series. If it is look for storm control setting in SOURCE network and apply to DEST Network
# ─────────────────────────────────────────────────────────────────────────────
def align_storm_control_between_networks(dashboard, src_net_id: str, dst_net_id: str):
    """
    Make the destination network's storm control settings match the source network
    if possible.

    - If the source network has no storm control configured, we do nothing.
    - If the destination network returns "Storm control is not supported on this
      network", we log a friendly note instead of an error.
    - This can be called multiple times (e.g. after each switch/stack move) so
      that once an MS switch is present in the destination, the settings can be
      applied.
    """
    # Read storm control from SOURCE
    try:
        storm = dashboard.switch.getNetworkSwitchStormControl(src_net_id)
    except (APIError, AttributeError) as e:
        warn(f"  Could not read storm control settings from source: {e}")
        return

    if not storm:
        info("  Source network has no storm control settings; nothing to copy.")
        return

    # Normalize list-shaped responses if they ever appear
    if isinstance(storm, list):
        if storm and isinstance(storm[0], dict):
            storm = storm[0]
            info(
                "  Storm control settings returned as a list on source; "
                "using first entry."
            )
        else:
            warn(
                "  Storm control settings on source came back in an unexpected "
                "list format; skipping storm-control clone."
            )
            return

    # Try to apply to DEST
    try:
        dashboard.switch.updateNetworkSwitchStormControl(
            dst_net_id,
            **storm,
        )
        info("  Copied storm control settings.")
    except (APIError, AttributeError) as e:
        msg = str(e)
        if "Storm control is not supported on this network" in msg:
            info(
                "  Storm control is configured on the SOURCE network, but the "
                "destination network does not currently support storm control "
                "(likely because there are no MS switches in that network yet).\n"
                "  This tool will re-check storm control on each switch/stack "
                "move, and will apply the settings automatically once an MS "
                "switch is present in the destination network."
            )
        else:
            warn(f"  Failed to apply storm control settings: {e}")
# ─────────────────────────────────────────────────────────────────────────────
# Defer STP overrides until the switch is actually in the network and serial exists (pending)
# ─────────────────────────────────────────────────────────────────────────────
def restore_pending_stp_overrides(dashboard, dst_net_id: str):
    """
    Previously this tried to replay per-switch / per-stack STP bridge priorities
    from the source network.

    Meraki's STP JSON shape varies across orgs (sometimes dict, sometimes array),
    and trying to normalize all variants has caused intermittent 400s and now
    type errors. To keep the move workflow rock-solid, we *only* clone global
    STP (rstpEnabled + default bridge priority) and skip per-device overrides.

    This function is now a safe no-op that just clears any queued data.
    Why, Meraki? Fix your shit
    """
    pending = PENDING_STP_OVERRIDES.pop(dst_net_id, None)
    if not pending:
        return

    warn(
        "  Skipping per-switch/stack STP bridge priority overrides. "
        "Global STP (RSTP enable + default priority) was already copied "
        "when the destination network was created. If you rely on "
        "non-default priorities per switch/stack, please verify and adjust "
        "them manually in Dashboard after the move."
    )
def report_stp_diff(dashboard, src_net_id: str, dst_net_id: str):
    """
    Read STP config from source and destination networks and print a summary
    (RSTP, default priority, and count of per-switch/stack overrides).
    No writes – this is purely a sanity-check report.
    """
    header(f"STP comparison: source {src_net_id} → dest {dst_net_id}")

    try:
        src_stp = dashboard.switch.getNetworkSwitchStp(src_net_id)
    except APIError as e:
        warn(f"  Could not read STP from source {src_net_id}: {e}")
        return

    try:
        dst_stp = dashboard.switch.getNetworkSwitchStp(dst_net_id)
    except APIError as e:
        warn(f"  Could not read STP from dest {dst_net_id}: {e}")
        return

    def normalize_stp(obj):
        rstp = obj.get("rstpEnabled")
        bp   = obj.get("stpBridgePriority") or {}
        # bp can be a dict (old style) or a list (new style) – try to normalize
        default_pri = None
        sw_count = 0
        stack_count = 0

        if isinstance(bp, dict):
            default_pri = bp.get("default")
            sw_count    = len(bp.get("switches") or [])
            stack_count = len(bp.get("stacks") or [])
        elif isinstance(bp, list):
            # We don't fully understand Meraki's new schema reliably here,
            # just count entries and try to detect a "default" priority if present.
            default_candidates = []
            for item in bp:
                if not isinstance(item, dict):
                    continue
                pri = item.get("stpPriority")
                if pri is not None:
                    default_candidates.append(pri)
                if item.get("switches"):
                    sw_count += 1
                if item.get("stacks"):
                    stack_count += 1
            if default_candidates:
                # Pick the lowest as "default-ish"
                default_pri = min(default_candidates)

        return rstp, default_pri, sw_count, stack_count

    src_rstp, src_def, src_sw_cnt, src_stack_cnt = normalize_stp(src_stp)
    dst_rstp, dst_def, dst_sw_cnt, dst_stack_cnt = normalize_stp(dst_stp)

    print(f"  Source RSTP enabled: {src_rstp}")
    print(f"  Dest   RSTP enabled: {dst_rstp}")
    print(f"  Source default bridge priority: {src_def}")
    print(f"  Dest   default bridge priority: {dst_def}")
    print(
        f"  Source per-switch overrides: {src_sw_cnt}, per-stack overrides: {src_stack_cnt}"
    )
    print(
        f"  Dest   per-switch overrides: {dst_sw_cnt}, per-stack overrides: {dst_stack_cnt}"
    )

    # Non-fatal hints
    if src_def is not None and dst_def is not None and src_def != dst_def:
        warn(
            "  NOTE: default bridge priority differs between source and dest. "
            "You may want to align these in Dashboard if this network is meant to be a clone."
        )

    if src_sw_cnt and not dst_sw_cnt:
        warn(
            "  NOTE: source has per-switch STP priorities, dest does not. "
            "Review root / secondary bridges in Dashboard and adjust as needed."
        )

    if src_stack_cnt and not dst_stack_cnt:
        warn(
            "  NOTE: source has per-stack STP priorities, dest does not. "
            "Review stack root roles in Dashboard."
        )

    success("  STP comparison complete (no changes were made automatically).")

# ─────────────────────────────────────────────────────────────────────────────
# Wait for NM ports to appear after MOVE- without this, LAGS fail and NM Port config (helper)
# ─────────────────────────────────────────────────────────────────────────────

def wait_for_ports_to_exist(
    dashboard,
    serial: str,
    expected_port_ids: set[str],
    timeout: int = 240,
    poll_interval: int = 10,
) -> set[str]:
    """
    Poll getDeviceSwitchPorts(serial) until all expected portIds appear
    or timeout is hit.

    Returns the set of still-missing ports (empty set means success).
    """
    expected = {pid for pid in expected_port_ids if pid}
    if not expected:
        return set()

    missing = set(expected)
    deadline = time.time() + timeout

    while missing and time.time() < deadline:
        try:
            ports = dashboard.switch.getDeviceSwitchPorts(serial)
            seen = {p.get("portId") for p in ports}
            missing = {pid for pid in missing if pid not in seen}

            if not missing:
                break

            warn(
                f"  Still waiting for ports on {serial}: {sorted(missing)}; "
                f"retrying in {poll_interval}s..."
            )
        except Exception as e:
            warn(
                f"  Error checking ports on {serial} while waiting for ports: {e}. "
                f"Retrying in {poll_interval}s..."
            )

        time.sleep(poll_interval)

    if missing:
        warn(
            f"  Giving up waiting for some ports on {serial}: {sorted(missing)}. "
            "If this switch has a network module/uplink installed, verify its ports "
            "and LAGs manually in Dashboard."
        )
    else:
        info(f"  All expected ports are now visible on {serial}.")

    return missing
# ─────────────────────────────────────────────────────────────────────────────
# Firmware switch vlaidation checking for new network creation (helper)
# ─────────────────────────────────────────────────────────────────────────────
def clone_switch_firmware_tracks(dashboard, src_net_id: str, dst_net_id: str):
    """
    Ensure destination network uses the same switch firmware tracks
    as the source network for:
      - MS (Meraki)   -> product type 'switch'
      - CS (Catalyst) -> product type 'switchCatalyst'

    We only schedule a change if the version IDs differ. If they
    already match, we log and skip to avoid the
    "already on this version" 400.
    """
    try:
        src_fw = dashboard.networks.getNetworkFirmwareUpgrades(src_net_id)
    except APIError as e:
        warn(f"Could not read source firmware info: {e}")
        return

    try:
        dst_fw = dashboard.networks.getNetworkFirmwareUpgrades(dst_net_id)
    except APIError as e:
        warn(f"Could not read destination firmware info: {e}")
        return

    src_products = src_fw.get("products", {}) or {}
    dst_products = dst_fw.get("products", {}) or {}

    # Build up a products dict we’ll send in a single update call
    products_body = {}

    # (ptype, pretty name for logs)
    for ptype, label in (
        ("switch", "MS (Meraki)"),
        ("switchCatalyst", "CS (Catalyst)"),
    ):
        s = src_products.get(ptype)
        d = dst_products.get(ptype)

        # If either side doesn't have this product track, skip it
        if not s or not s.get("currentVersion") or not d:
            continue

        s_ver = s["currentVersion"]
        d_ver = (d.get("currentVersion") or {})

        s_id = s_ver.get("id")
        d_id = d_ver.get("id")

        s_name = s_ver.get("shortName") or s_ver.get("display") or s_ver.get("releaseChannel") or "unknown"
        d_name = d_ver.get("shortName") or d_ver.get("display") or d_ver.get("releaseChannel") or "unknown"

        if not s_id:
            continue

        # Log what the source is running
        print(f"  Source {label} firmware: {s_name} (id={s_id})")

        # If versions already match, don't try to "update" – Meraki will 400.
        if s_id == d_id:
            info(f"  Destination already on same {label} firmware ({d_name}); no change needed.")
            continue

        # Otherwise, schedule destination to match source
        products_body[ptype] = {
            "nextUpgrade": {
                "toVersion": {"id": s_id}
            }
        }
        info(
            f"  Will schedule destination {label} firmware from {d_name} "
            f"to {s_name}."
        )

    if not products_body:
        # Nothing to change
        return

    try:
        dashboard.networks.updateNetworkFirmwareUpgrades(
            dst_net_id,
            products=products_body,
        )
        success("  Scheduled destination switch firmware to match source (MS/CS tracks where applicable).")
    except APIError as e:
        warn(f"  Could not schedule destination switch firmware to match source: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Last Known Good for Meraki UPLINK FLags (uplink needs to be sepcified First, Otherwise SVI/Routing fails- wah wah)
# ─────────────────────────────────────────────────────────────────────────────
def stack_iface_has_uplink_flag(iface: dict) -> bool:
    """
    Decide if a stack L3 interface looks like an uplink in Meraki.
    We check both direct flags and nested ipv4 role (for future proofing).
    """
    if iface.get("uplinkV4") or iface.get("uplinkV6"):
        return True

    ipv4 = iface.get("ipv4") or {}
    if isinstance(ipv4, dict) and ipv4.get("role") == "uplink":
        return True

    return False


def find_last_good_stack_backup(stack_id: str, backup_dir: str = "backups"):
    """
    Look through all stack_<stackId>_backup_*.json files and return the
    newest one that has at least one L3 interface marked as an uplink.

    Returns:
      dict with backup JSON plus a '_backup_file' key, or None.
    """
    pattern = os.path.join(backup_dir, f"stack_{stack_id}_backup_*.json")
    candidates = sorted(glob.glob(pattern))
    if not candidates:
        return None

    # Newest first
    for path in reversed(candidates):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        if any(
            stack_iface_has_uplink_flag(i)
            for i in (data.get("stackL3Interfaces") or [])
        ):
            data["_backup_file"] = path
            return data

    return None


def apply_uplink_flags_from_history(
    current_ifaces: list[dict],
    historical_ifaces: list[dict],
) -> int:
    """
    For each current iface, look for a matching iface in historical_ifaces
    by (vlanId, subnet). If the historical one had an uplink flag, copy that
    uplink metadata onto the current iface.

    Returns:
      number of current interfaces that had uplink flags applied.
    """
    # Map "key" -> historical iface that is uplink
    hist_by_key = {}
    for hi in historical_ifaces:
        if not stack_iface_has_uplink_flag(hi):
            continue
        key = (hi.get("vlanId"), (hi.get("subnet") or "").strip())
        hist_by_key[key] = hi

    touched = 0
    for ci in current_ifaces:
        key = (ci.get("vlanId"), (ci.get("subnet") or "").strip())
        hi = hist_by_key.get(key)
        if not hi:
            continue

        # Copy simple uplinkV4/uplinkV6 flags if present
        if hi.get("uplinkV4"):
            ci["uplinkV4"] = True
        if hi.get("uplinkV6"):
            ci["uplinkV6"] = True

        # Copy ipv4.role = uplink if present
        hist_ipv4 = hi.get("ipv4") or {}
        if isinstance(hist_ipv4, dict) and hist_ipv4.get("role") == "uplink":
            cur_ipv4 = ci.get("ipv4") or {}
            if not isinstance(cur_ipv4, dict):
                cur_ipv4 = {}
            cur_ipv4["role"] = "uplink"
            ci["ipv4"] = cur_ipv4

        touched += 1

    return touched

# ─────────────────────────────────────────────────────────────────────────────
# Switch / stack selection logic
# ─────────────────────────────────────────────────────────────────────────────

def is_movable_switch(device: dict) -> bool:
    """
    Decide whether a device can be moved by this tool.

    Rules:
      - Always allow Meraki MS switches.
      - Allow Cloud-managed Catalyst (C92/C93/C94/C95/C96) that are on
        *CS* firmware (cs-17.x) – i.e. true cloud-managed persona.
      - Exclude Catalyst on pure IOS-XE persona (ios-xe-17.x), which are
        monitoring/hybrid only.
      - Everything else: not movable.
    """
    model    = (device.get("model") or "").upper()
    ptype    = (device.get("productType") or "").lower()
    firmware = (device.get("firmware") or device.get("firmwareVersion") or "").lower()
    serial   = device.get("serial")

    # Meraki MS – always OK
    if model.startswith("MS"):
        return True

    # Only treat Catalyst families as candidates at all
    is_catalyst_family = (
        model.startswith(("C92", "C93", "C94", "C95", "C96"))
        or ptype == "switchcatalyst"
    )
    if not is_catalyst_family:
        return False

    # Classic IOS-XE persona → monitored / hybrid, not movable
    if firmware.startswith("ios-xe-"):
        info(
            f"  Skipping Catalyst {serial} ({model}) – firmware '{firmware}' "
            "looks like IOS-XE/monitoring persona, not cloud-managed CS."
        )
        return False

    # CS firmware → cloud-managed Catalyst, OK to move
    if firmware.startswith("cs-"):
        return True

    # Anything else: be conservative
    warn(
        f"  Unknown Catalyst persona for {serial} ({model}), firmware='{firmware}'. "
        "Treating as NOT movable. Update is_movable_switch() if you confirm this "
        "should be migratable."
    )
    return False


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


def backup_switch_config(
    dashboard,
    network_id: str,
    serial: str,
    backup_dir="backups",
    skip_l3_and_static: bool = False,
):
    """
    Fetch switch config:

      - device metadata
      - all switch ports
      - link aggregations touching this switch
      - (optionally) device-level L3 interfaces + DHCP + static routes

    For stack members, Meraki does NOT support the device-level L3/static
    endpoints, so backup_stack_config() calls this with skip_l3_and_static=True
    and we rely on the stack-level APIs instead.
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

    # Always initialize these so backup structure is consistent
    l3_ifaces = []
    l3_dhcp = {}
    static_routes = []

    if not skip_l3_and_static:
        # ── Device-level L3 interfaces + DHCP ────────────────────────────────
        try:
            l3_ifaces = dashboard.switch.getDeviceSwitchRoutingInterfaces(serial)
            if l3_ifaces:
                header(f"Found {len(l3_ifaces)} L3 interface(s) on {serial}; backing up DHCP.")
            for iface in l3_ifaces:
                iface_id = iface.get("interfaceId")
                if not iface_id:
                    continue
                try:
                    dhcp_cfg = dashboard.switch.getDeviceSwitchRoutingInterfaceDhcp(
                        serial, iface_id
                    )
                except APIError as e:
                    warn(f"  Could not fetch DHCP for L3 interface {iface_id} on {serial}: {e}")
                    dhcp_cfg = None
                l3_dhcp[iface_id] = dhcp_cfg
        except APIError as e:
            warn(f"Could not fetch L3 interfaces for {serial}: {e}")

        # ── Device-level static routes ───────────────────────────────────────
        try:
            static_routes = dashboard.switch.getDeviceSwitchRoutingStaticRoutes(serial)
            if static_routes:
                header(f"Found {len(static_routes)} static route(s) on {serial}; backing them up.")
        except APIError as e:
            warn(f"Could not fetch static routes for {serial}: {e}")

    now_utc = datetime.now(timezone.utc)
    backup = {
        "serial": serial,
        "networkId": network_id,
        "timestamp": now_utc.isoformat(),
        "device": device,
        "ports": ports,
        "linkAggregations": link_aggs,
        "l3Interfaces": l3_ifaces,
        "l3Dhcp": l3_dhcp,
        "staticRoutes": static_routes,
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
    that touch ANY member of the stack, and any stack-level
    L3 interfaces + DHCP + static routes.
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

    # Per-member backups (ports + LAGs only; stack-level L3/static handled below)
    per_switch_backups = {}
    for serial in serials:
        backup, path = backup_switch_config(
            dashboard,
            network_id,
            serial,
            backup_dir=backup_dir,
            skip_l3_and_static=True,  # <- key change for stack members
        )
        per_switch_backups[serial] = {"backup": backup, "file": path}

    # ── Stack-level L3 interfaces + DHCP ─────────────────────────────────────
    stack_l3_ifaces = []
    stack_l3_dhcp = {}
    try:
        stack_l3_ifaces = dashboard.switch.getNetworkSwitchStackRoutingInterfaces(
            network_id, stack["id"]
        )
        if stack_l3_ifaces:
            header(
                f"Found {len(stack_l3_ifaces)} stack-level L3 interface(s) "
                f"on '{stack.get('name')}'. Backing up DHCP."
            )
        for iface in stack_l3_ifaces:
            iface_id = iface.get("interfaceId")
            if not iface_id:
                continue
            try:
                dhcp_cfg = dashboard.switch.getNetworkSwitchStackRoutingInterfaceDhcp(
                    network_id,
                    stack["id"],
                    iface_id,
                )
            except APIError as e:
                warn(
                    f"  Could not fetch DHCP for stack L3 interface {iface_id} "
                    f"on stack '{stack.get('name')}': {e}"
                )
                dhcp_cfg = None
            stack_l3_dhcp[iface_id] = dhcp_cfg
    except APIError as e:
        warn(
            f"Could not fetch stack-level L3 interfaces for stack '{stack.get('name')}': {e}"
        )

    # ── Stack-level static routes ────────────────────────────────────────────
    stack_static_routes = []
    try:
        stack_static_routes = dashboard.switch.getNetworkSwitchStackRoutingStaticRoutes(
            network_id, stack["id"]
        )
        if stack_static_routes:
            header(
                f"Found {len(stack_static_routes)} stack-level static route(s) "
                f"on '{stack.get('name')}'. Backing them up."
            )
    except APIError as e:
        warn(
            f"Could not fetch stack-level static routes for stack '{stack.get('name')}': {e}"
        )

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
        "stackL3Interfaces": stack_l3_ifaces,
        "stackL3Dhcp": stack_l3_dhcp,
        "stackStaticRoutes": stack_static_routes,
    }
    stack_fname = os.path.join(backup_dir, f"stack_{stack['id']}_backup_{ts}.json")
    with open(stack_fname, "w", encoding="utf-8") as f:
        json.dump(stack_backup, f, indent=2)

    success(f"Stack backup metadata saved to {stack_fname}")
    return (
        per_switch_backups,
        stack_link_aggs,
        stack_l3_ifaces,
        stack_l3_dhcp,
        stack_static_routes,
        stack_fname,
    )


DEFAULT_PORT_RE = re.compile(r"_DEFAULT_\d+$")

def restore_switch_ports(dashboard, serial: str, ports_backup):
    header(f"Restoring {len(ports_backup)} ports on switch {serial}")
    success_count = 0
    failures = 0
    skipped = 0

    # Discover current, valid port IDs on this device
    valid_port_ids = set()
    try:
        current_ports = dashboard.switch.getDeviceSwitchPorts(serial)
        for p in current_ports:
            pid = p.get("portId")
            if pid is not None:
                valid_port_ids.add(str(pid))
    except APIError as e:
        warn(
            f"Could not fetch current ports for {serial} to validate port IDs: {e}. "
            f"Will attempt to apply all ports from backup anyway."
        )

    for port in ports_backup:
        port_id = str(port.get("portId"))
        if not port_id:
            warn("  Skipping a port with no portId in backup.")
            skipped += 1
            continue

        # Skip *only* obvious template ports like 1_DEFAULT_1..8
        if DEFAULT_PORT_RE.search(port_id):
            warn(
                f"  Skipping backup port '{port_id}' – dashboard template/default port "
                f"(no real interface on the device)."
            )
            skipped += 1
            continue

        # If we successfully fetched valid IDs, skip any that don't exist
        if valid_port_ids and port_id not in valid_port_ids:
            warn(
                f"  Skipping backup port '{port_id}' – not present on current device "
                f"(likely a template/default module port)."
            )
            skipped += 1
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
        f"{GREEN}{success_count} success{RESET}, "
        f"{RED}{failures} failed{RESET}, "
        f"{YELLOW}{skipped} skipped (non-existent/template ports){RESET}."
    )

def restore_device_l3_and_dhcp(dashboard, serial: str, l3_ifaces, l3_dhcp_map):
    """
    Restore device-level L3 interfaces and DHCP to a *moved* switch.

    Key behavior:
      - Skip L3 interfaces whose IP == the switch management IP (CS rejects those).
      - Let the user choose *any* eligible VLAN as the uplink (not just mgmt).
      - Ensure the chosen uplink is created first and flagged as an uplink
        (uplinkV4 + ipv4.role='uplink') to satisfy Meraki's "uplink first" rule.
    """
    # Look up management IP(s) so we can avoid trying to create an L3
    # interface that uses the same address (Meraki will reject it).
    mgmt_ips = set()
    try:
        dev = dashboard.devices.getDevice(serial)
        for key in ("lanIp", "managementIp", "ip"):
            val = (dev.get(key) or "").strip()
            if val:
                mgmt_ips.add(val)
    except APIError as e:
        warn(f"Could not read device management IP for {serial}: {e}")
        mgmt_ips = set()

    if not l3_ifaces:
        info(f"No L3 interfaces in backup for {serial}. Skipping L3/DHCP restore.")
        return

    header(f"L3 / DHCP restore for {serial}")
    print(f"  {len(l3_ifaces)} L3 interface(s) were backed up.")

    choice = input(
        f"{YELLOW}Recreate these L3 interfaces and DHCP on the destination switch? [y/N]: {RESET}"
    ).strip().lower()
    if choice not in ("y", "yes"):
        warn("Skipping L3 / DHCP restore for this device.")
        return

    # Get current L3 interfaces on the destination device to avoid collisions
    try:
        existing = dashboard.switch.getDeviceSwitchRoutingInterfaces(serial)
    except APIError as e:
        warn(f"Could not inspect existing L3 interfaces on {serial}: {e}")
        existing = []

    existing_by_vlan = {}
    existing_by_subnet = {}
    for iface in existing:
        v = iface.get("vlanId")
        s = (iface.get("subnet") or "").strip()
        if v is not None:
            existing_by_vlan[v] = iface
        if s:
            existing_by_subnet[s] = iface

    # ── First pass: figure out which interfaces we can actually create ──────
    eligible_ifaces: list[dict] = []
    skipped = 0

    for src_iface in l3_ifaces:
        src_vlan = src_iface.get("vlanId")
        src_subnet = (src_iface.get("subnet") or "").strip()
        src_name = src_iface.get("name") or f"VLAN {src_vlan or '?'}"
        iface_ip = (src_iface.get("interfaceIp") or "").strip()

        # 1) VLAN conflict
        if src_vlan is not None and src_vlan in existing_by_vlan:
            warn(
                f"  Skipping L3 '{src_name}' (VLAN {src_vlan}) – dest already has an "
                f"interface on this VLAN."
            )
            skipped += 1
            continue

        # 2) Subnet conflict
        if src_subnet and src_subnet in existing_by_subnet:
            warn(
                f"  Skipping L3 '{src_name}' (subnet {src_subnet}) – dest already has an "
                f"interface on this subnet."
            )
            skipped += 1
            continue

        # 3) IP == management IP (CS mgmt VLAN case)
        if iface_ip and iface_ip in mgmt_ips:
            warn(
                f"  Skipping L3 '{src_name}' (VLAN {src_vlan}) – "
                f"interface IP {iface_ip} matches the switch management IP. "
                "On Cloud-managed Catalyst this is usually the management VLAN, "
                "which Dashboard handles via network settings, not L3 interfaces."
            )
            skipped += 1
            continue

        # If we got here, this interface is eligible to be created
        eligible_ifaces.append(src_iface)

    if not eligible_ifaces:
        warn(
            "All backed-up L3 interfaces were skipped due to conflicts or management-IP "
            "constraints. No L3 interfaces will be recreated on this device."
        )
        print(
            f"\nL3 restore summary for {serial}: "
            f"{GREEN}0 created{RESET}, {YELLOW}{skipped} skipped{RESET} "
            "(conflicts / mgmt-IP), DHCP: 0 OK, 0 failed."
        )
        return

    # ── Determine uplink candidate(s) *only* from eligible interfaces ───────
    uplink_interface_ids = {
        iface.get("interfaceId")
        for iface in eligible_ifaces
        if iface.get("uplinkV4") or iface.get("uplinkV6")
    }

    # If none were flagged as uplink (or the only uplink was the mgmt-IP iface
    # that we just skipped), let the user pick ANY eligible VLAN to be uplink.
    if not uplink_interface_ids:
        header("Select uplink for restored switch (required by Meraki)")
        print("Choose which VLAN will be treated as the uplink on this switch.")
        print("The uplink SVI will be created first and flagged as an uplink.\n")

        # Try to suggest a reasonable default (first interface with a defaultGateway)
        default_idx = None
        for idx, iface in enumerate(eligible_ifaces, start=1):
            if iface.get("defaultGateway"):
                default_idx = idx
                break
        if default_idx is None:
            default_idx = 1  # fall back to first eligible

        for idx, iface in enumerate(eligible_ifaces, start=1):
            v = iface.get("vlanId")
            s = (iface.get("subnet") or "").strip()
            n = iface.get("name") or f"VLAN {v or '?'}"
            gw = iface.get("defaultGateway") or "none"
            marker = " (default)" if idx == default_idx else ""
            print(f"  [{idx}] {n} (VLAN {v}, subnet {s or 'N/A'}, gw={gw}){marker}")

        while True:
            resp = input(
                f"{YELLOW}Which interface should be treated as the uplink? "
                f"[1-{len(eligible_ifaces)}, Enter for default]: {RESET}"
            ).strip()

            if resp == "":
                chosen_idx = default_idx
            else:
                if not resp.isdigit():
                    warn("Invalid input; please enter a number or press Enter for default.")
                    continue
                chosen_idx = int(resp)
                if chosen_idx < 1 or chosen_idx > len(eligible_ifaces):
                    warn("Out of range; try again.")
                    continue

            chosen = eligible_ifaces[chosen_idx - 1]
            cid = chosen.get("interfaceId")
            if not cid:
                warn(
                    "Selected interface has no interfaceId in backup; cannot flag as uplink. "
                    "Please pick another."
                )
                continue

            uplink_interface_ids.add(cid)
            info(
                f"Will treat '{chosen.get('name') or f'VLAN {chosen.get('vlanId') or '?'}'}' "
                f"as uplink when recreating."
            )
            break

    # ── Order creation: uplink first, then others with defaultGateway, then rest ──
    sorted_ifaces = sorted(
        eligible_ifaces,
        key=lambda iface: (
            0 if iface.get("interfaceId") in uplink_interface_ids else 1,
            0 if iface.get("defaultGateway") else 1,
        ),
    )

    created = 0
    dhcp_ok = 0
    dhcp_fail = 0

    for src_iface in sorted_ifaces:
        src_vlan = src_iface.get("vlanId")
        src_subnet = (src_iface.get("subnet") or "").strip()
        src_name = src_iface.get("name") or f"VLAN {src_vlan or '?'}"
        src_id = src_iface.get("interfaceId")

        # Build body for createDeviceSwitchRoutingInterface
        body: dict = {}
        for key in (
            "name",
            "mode",
            "subnet",
            "interfaceIp",
            "multicastRouting",
            "vlanId",
            "switchPortId",
            "defaultGateway",
            "ospfSettings",
            "ipv6",
            "vrf",
            "loopback",
            "uplinkV4",
            "uplinkV6",
        ):
            if key in src_iface and src_iface[key] is not None:
                body[key] = src_iface[key]

        # If this is the chosen uplink, force uplink flags
        if src_id in uplink_interface_ids:
            body["uplinkV4"] = True
            # Also ensure nested ipv4.role = "uplink" for newer APIs
            ipv4 = src_iface.get("ipv4") or {}
            if not isinstance(ipv4, dict):
                ipv4 = {}
            ipv4["role"] = "uplink"
            body["ipv4"] = ipv4

        print(
            f"  Creating L3 interface '{src_name}' (VLAN {src_vlan}, subnet {src_subnet})... ",
            end="",
        )
        try:
            created_iface = dashboard.switch.createDeviceSwitchRoutingInterface(
                serial,
                name=body.pop("name"),
                **body,
            )
            print(f"{GREEN}OK{RESET}")
            created += 1
        except APIError as e:
            msg = str(e)
            print(f"{RED}FAILED -> {e}{RESET}")
            if "matches the management IP of the switch" in msg:
                warn(
                    "  Meraki rejected this L3 interface because its IP equals the "
                    "management IP. For Cloud-managed Catalyst, keep that IP for "
                    "mgmt only and rely on the network switch management VLAN "
                    "setting cloned at the network level."
                )
            if (
                "Cannot create an L3 Interface without creating either an IPv4 or IPv6 Uplink"
                in msg
            ):
                warn(
                    "  Meraki still believes there is no uplink L3 interface. Double-check "
                    "in Dashboard that the first SVI you chose was created and marked as "
                    "uplink; if not, you may need to manually create an uplink SVI, then "
                    "re-run the script (you can answer 'n' for L3 restore next time)."
                )
            continue

        new_id = created_iface.get("interfaceId")
        if not new_id:
            continue

        # Re-apply DHCP if we have it in the backup
        dhcp_cfg = l3_dhcp_map.get(src_id)
        if not dhcp_cfg:
            continue

        dhcp_body: dict = {}
        for key in (
            "dhcpMode",
            "dhcpRelayServerIps",
            "dhcpLeaseTime",
            "dnsNameserversOption",
            "dnsCustomNameservers",
            "bootOptionsEnabled",
            "bootNextServer",
            "bootFileName",
            "dhcpOptions",
            "reservedIpRanges",
            "fixedIpAssignments",
            "dhcpDefaultRouterIps",
            "dhcpDomainName",
        ):
            if key in dhcp_cfg and dhcp_cfg[key] is not None:
                dhcp_body[key] = dhcp_cfg[key]

        if not dhcp_body:
            continue

        print(f"    Applying DHCP config to '{src_name}'... ", end="")
        try:
            dashboard.switch.updateDeviceSwitchRoutingInterfaceDhcp(
                serial,
                new_id,
                **dhcp_body,
            )
            print(f"{GREEN}OK{RESET}")
            dhcp_ok += 1
        except APIError as e:
            print(f"{RED}FAILED -> {e}{RESET}")
            dhcp_fail += 1

    total_skipped = skipped + (len(l3_ifaces) - len(eligible_ifaces))
    print(
        f"\nL3 restore summary for {serial}: "
        f"{GREEN}{created} created{RESET}, "
        f"{YELLOW}{total_skipped} skipped{RESET} "
        f"(conflicts / mgmt-IP), DHCP: {GREEN}{dhcp_ok} OK{RESET}, "
        f"{RED}{dhcp_fail} failed{RESET}."
    )
def restore_device_static_routes(dashboard, serial: str, static_routes):
    """
    Restore device-level static routes to a moved switch.

    - Reads existing static routes on the destination device
    - Skips any that would duplicate an existing (subnet, nextHopIp)
    - Detects management-subnet next hop and skips those routes with a clear message
    """
    if not static_routes:
        info(f"No static routes in backup for {serial}. Skipping static route restore.")
        return

    header(f"Static route restore for {serial}")
    print(f"  {len(static_routes)} static route(s) were backed up.")

    choice = input(
        f"{YELLOW}Recreate these static routes on the destination switch? [y/N]: {RESET}"
    ).strip().lower()
    if choice not in ("y", "yes"):
        warn("Skipping static route restore for this device.")
        return

    # Current routes on the destination device
    try:
        existing = dashboard.switch.getDeviceSwitchRoutingStaticRoutes(serial)
    except APIError as e:
        warn(f"Could not inspect existing static routes on {serial}: {e}")
        existing = []

    existing_keys = set()
    for r in existing:
        subnet = (r.get("subnet") or "").strip()
        nh = (r.get("nextHopIp") or "").strip()
        if subnet and nh:
            existing_keys.add((subnet, nh))

    # Discover management IP(s) for this device
    mgmt_ips = set()
    try:
        dev = dashboard.devices.getDevice(serial)
        for key in ("lanIp", "managementIp", "ip"):
            val = (dev.get(key) or "").strip()
            if val:
                mgmt_ips.add(val)
    except APIError as e:
        warn(f"Could not read device management IP for {serial}: {e}")
        mgmt_ips = set()

    # Discover L3 interfaces so we can infer mgmt subnet(s)
    try:
        existing_l3 = dashboard.switch.getDeviceSwitchRoutingInterfaces(serial)
    except APIError as e:
        warn(f"Could not inspect existing L3 interfaces on {serial}: {e}")
        existing_l3 = []

    from ipaddress import ip_network, ip_address

    mgmt_subnets = []
    for iface in existing_l3:
        try:
            subnet_str = (iface.get("subnet") or "").strip()
            iface_ip = (iface.get("interfaceIp") or "").strip()
            if not subnet_str or not iface_ip:
                continue
            net = ip_network(subnet_str, strict=False)
            if iface_ip in mgmt_ips:
                mgmt_subnets.append(net)
        except Exception:
            # Ignore malformed or unexpected data
            continue

    created = 0
    skipped = 0
    failed = 0

    for src_route in static_routes:
        subnet = (src_route.get("subnet") or "").strip()
        nh = (src_route.get("nextHopIp") or "").strip()
        name = src_route.get("name") or f"{subnet} via {nh}"

        if not subnet or not nh:
            warn(f"  Skipping static route '{name}' – missing subnet or nextHopIp in backup.")
            skipped += 1
            continue

        key = (subnet, nh)
        if key in existing_keys:
            warn(
                f"  Skipping static route '{name}' ({subnet} → {nh}) – "
                f"already exists on dest."
            )
            skipped += 1
            continue

        # NEW: if next hop is on a management subnet, skip with explicit message
        skip_for_mgmt = False
        if mgmt_subnets:
            try:
                nh_ip = ip_address(nh)
                for mgmt_net in mgmt_subnets:
                    if nh_ip in mgmt_net:
                        skip_for_mgmt = True
                        break
            except Exception:
                # If we can't parse the IP, just fall through and let the API decide
                pass

        if skip_for_mgmt:
            warn(
                f"  Skipping static route '{name}' ({subnet} → {nh}) – "
                "next hop is on the management subnet (not recreated via API). "
                "Please add manually in Dashboard."
            )
            skipped += 1
            continue

        body = {}
        for field in (
            "name",
            "subnet",
            "nextHopIp",
            "advertiseViaOspfEnabled",
            "preferOverOspfRoutesEnabled",
        ):
            if field in src_route and src_route[field] is not None:
                body[field] = src_route[field]

        print(f"  Creating static route '{name}' ({subnet} → {nh})... ", end="")
        try:
            dashboard.switch.createDeviceSwitchRoutingStaticRoute(serial, **body)
            print(f"{GREEN}OK{RESET}")
            created += 1
        except APIError as e:
            print(f"{RED}FAILED -> {e}{RESET}")
            failed += 1

    print(
        f"\nStatic route restore summary for {serial}: "
        f"{GREEN}{created} created{RESET}, "
        f"{YELLOW}{skipped} skipped{RESET}, "
        f"{RED}{failed} failed{RESET}."
    )
def restore_stack_l3_and_dhcp(
    dashboard,
    network_id: str,
    stack_id: str,
    stack_name: str,
    stack_l3_ifaces: list[dict],
    stack_l3_dhcp_map: dict,
    backup_dir: str = "backups",
) -> bool:
    """
    Restore stack-level L3 interfaces and DHCP.

    Returns:
      True if at least one L3 interface was created,
      False if we hit the "no uplink" wall and bailed.
    """
    if not stack_name:
        stack_name = stack_id

    if not stack_l3_ifaces:
        info(f"No stack-level L3 interfaces in backup for '{stack_name}'. Skipping.")
        return True  # nothing to do, but not an error

    header(f"L3 / DHCP restore for stack '{stack_name}'")
    print(f"  {len(stack_l3_ifaces)} L3 interface(s) were backed up.")

    choice = input(
        f"{YELLOW}Recreate these stack L3 interfaces and DHCP in the destination? [y/N]: {RESET}"
    ).strip().lower()
    if choice not in ("y", "yes"):
        warn(f"Skipping stack L3 / DHCP restore for '{stack_name}'.")
        return True

    # What already exists on the destination stack?
    try:
        existing = dashboard.switch.getNetworkSwitchStackRoutingInterfaces(
            network_id, stack_id
        )
    except APIError as e:
        warn(
            f"Could not inspect existing stack L3 interfaces on '{stack_name}': {e}"
        )
        existing = []

    existing_by_vlan = {}
    existing_by_subnet = {}
    for iface in existing:
        v = iface.get("vlanId")
        s = (iface.get("subnet") or "").strip()
        if v is not None:
            existing_by_vlan[v] = iface
        if s:
            existing_by_subnet[s] = iface

    # ── Step 1: check for uplink flags directly from current backup ────────
    uplink_interface_ids = {
        iface.get("interfaceId")
        for iface in stack_l3_ifaces
        if stack_iface_has_uplink_flag(iface)
    }

    # ── Step 2: if none, try "last known good" stack backup ────────────────
    if not uplink_interface_ids:
        last_good = find_last_good_stack_backup(stack_id, backup_dir)
        if last_good:
            hist_ifaces = last_good.get("stackL3Interfaces") or []
            touched = apply_uplink_flags_from_history(stack_l3_ifaces, hist_ifaces)
            if touched:
                info(
                    f"No uplink flags in current Dashboard stack L3 for '{stack_name}'. "
                    f"Borrowed uplink metadata for {touched} interface(s) from "
                    f"last-known-good backup "
                    f"{os.path.basename(last_good['_backup_file'])}."
                )
                uplink_interface_ids = {
                    iface.get("interfaceId")
                    for iface in stack_l3_ifaces
                    if stack_iface_has_uplink_flag(iface)
                }
            else:
                warn(
                    f"Found historical stack backups for '{stack_name}' but none of the "
                    "interfaces matched by VLAN/subnet for uplink promotion."
                )
        else:
            warn(
                f"No previous stack backups with uplink flags were found for '{stack_name}'."
            )

    # ── Step 3: if still none, prompt user (last resort) ───────────────────
    if not uplink_interface_ids:
        header("Select uplink for restored stack (no uplink flag in Dashboard or backups)")
        for idx, iface in enumerate(stack_l3_ifaces, start=1):
            v = iface.get("vlanId")
            s = (iface.get("subnet") or "").strip()
            n = iface.get("name") or f"VLAN {v or '?'}"
            print(f"  [{idx}] {n} (VLAN {v}, subnet {s or 'N/A'})")

        while True:
            resp = input(
                f"{YELLOW}Which interface should be treated as the uplink? "
                f"Enter number (or press Enter to skip): {RESET}"
            ).strip()
            if resp == "":
                warn(
                    "No uplink selected. Meraki may reject creating stack L3 interfaces "
                    "until an uplink exists. If restore fails, you may need to create "
                    "an uplink manually in Dashboard and re-run."
                )
                break
            if not resp.isdigit():
                warn("Invalid input; please enter a number or press Enter to skip.")
                continue
            index = int(resp)
            if index < 1 or index > len(stack_l3_ifaces):
                warn("Out of range; try again.")
                continue

            chosen = stack_l3_ifaces[index - 1]
            cid = chosen.get("interfaceId")
            if not cid:
                warn("Selected interface has no interfaceId in backup; cannot flag as uplink.")
                break

            uplink_interface_ids.add(cid)
            info(
                f"Will treat stack L3 '{chosen.get('name') or f'VLAN {chosen.get('vlanId') or '?'}'}' "
                f"as uplink when recreating."
            )
            break

    # ── Order: uplink first, then those with defaultGateway, then others ───
    sorted_ifaces = sorted(
        stack_l3_ifaces,
        key=lambda iface: (
            0 if iface.get("interfaceId") in uplink_interface_ids else 1,
            0 if iface.get("defaultGateway") else 1,
        ),
    )

    created = 0
    skipped = 0
    dhcp_ok = 0
    dhcp_fail = 0

    for src_iface in sorted_ifaces:
        src_vlan = src_iface.get("vlanId")
        src_subnet = (src_iface.get("subnet") or "").strip()
        src_name = src_iface.get("name") or f"VLAN {src_vlan or '?'}"
        src_id = src_iface.get("interfaceId")

        # Collision checks
        if src_vlan is not None and src_vlan in existing_by_vlan:
            warn(
                f"  Skipping stack L3 '{src_name}' (VLAN {src_vlan}) – dest already has "
                f"an interface on this VLAN."
            )
            skipped += 1
            continue
        if src_subnet and src_subnet in existing_by_subnet:
            warn(
                f"  Skipping stack L3 '{src_name}' (subnet {src_subnet}) – dest already "
                f"has an interface on this subnet."
            )
            skipped += 1
            continue

        body = {}
        for key in (
            "name",
            "subnet",
            "interfaceIp",
            "multicastRouting",
            "vlanId",
            "defaultGateway",
            "ospfSettings",
            "ipv6",
            "vrf",
            "loopback",
            "uplinkV4",
            "uplinkV6",
            "ipv4",  # include nested ipv4 object if present
        ):
            if key in src_iface and src_iface[key] is not None:
                body[key] = src_iface[key]

        # If this is an uplink candidate, force it to be treated as an uplink
        if src_id in uplink_interface_ids:
            # 1) Flat flag Meraki clearly understands
            body["uplinkV4"] = True

            # 2) Also nudge the nested ipv4 object
            ipv4 = body.get("ipv4") or {}
            if not isinstance(ipv4, dict):
                ipv4 = {}
            ipv4["role"] = "uplink"
            body["ipv4"] = ipv4

        print(
            f"  Creating stack L3 interface '{src_name}' "
            f"(VLAN {src_vlan}, subnet {src_subnet})... ",
            end="",
        )

        try:
            created_iface = dashboard.switch.createNetworkSwitchStackRoutingInterface(
                network_id,
                stack_id,
                **body,
            )
            print(f"{GREEN}OK{RESET}")
            created += 1
        except APIError as e:
            print(f"{RED}FAILED -> {e}{RESET}")
            msg = str(e)
            if (
                "Cannot create an L3 Interface without creating either an IPv4 or IPv6 Uplink L3 Interface first."
                in msg
            ):
                warn(
                    "Meraki refused to create the first stack L3 interface because it does "
                    "not see any IPv4/IPv6 uplink. This usually means neither the current "
                    "Dashboard state nor any previous backup contains a usable uplink flag.\n"
                    "Workaround: create that interface manually in Dashboard on this stack, "
                    "mark it as the uplink there, then re-run the script (you can skip the "
                    "stack L3 step and just restore static routes)."
                )
                # Bail out; caller should skip static routes in this case
                return False
            continue

        new_id = created_iface.get("interfaceId")
        if not new_id:
            continue

        # Re-apply DHCP if present in backup
        dhcp_cfg = stack_l3_dhcp_map.get(src_id)
        if not dhcp_cfg:
            continue

        dhcp_body = {}
        for key in (
            "dhcpMode",
            "dhcpRelayServerIps",
            "dhcpLeaseTime",
            "dnsNameserversOption",
            "dnsCustomNameservers",
            "bootOptionsEnabled",
            "bootNextServer",
            "bootFileName",
            "dhcpOptions",
            "reservedIpRanges",
            "fixedIpAssignments",
            "dhcpDefaultRouterIps",
            "dhcpDomainName",
        ):
            if key in dhcp_cfg and dhcp_cfg[key] is not None:
                dhcp_body[key] = dhcp_cfg[key]

        if not dhcp_body:
            continue

        print(f"    Applying DHCP config to stack L3 '{src_name}'... ", end="")
        try:
            dashboard.switch.updateNetworkSwitchStackRoutingInterfaceDhcp(
                network_id,
                stack_id,
                new_id,
                **dhcp_body,
            )
            print(f"{GREEN}OK{RESET}")
            dhcp_ok += 1
        except APIError as e:
            print(f"{RED}FAILED -> {e}{RESET}")
            dhcp_fail += 1

    print(
        f"\nStack L3 restore summary for '{stack_name}': "
        f"{GREEN}{created} created{RESET}, {YELLOW}{skipped} skipped{RESET} "
        f"(conflicts). DHCP: {GREEN}{dhcp_ok} OK{RESET}, {RED}{dhcp_fail} failed{RESET}."
    )
    return created > 0

def restore_stack_static_routes(
    dashboard,
    network_id: str,
    stack_id: str,
    stack_name: str,
    static_routes,
    stack_l3_ifaces_from_backup,
):
    """
    Restore stack-level static routes to a moved stack.

    - Skips any route whose next-hop lives on the management subnet
      (Meraki APIs currently reject those; user must add them manually).
    - Skips routes that already exist on the destination stack.
    """
    if not static_routes:
        info(f"No stack-level static routes in backup for '{stack_name}'. Skipping.")
        return

    header(f"Static route restore for stack '{stack_name}'")
    print(f"  {len(static_routes)} stack-level static route(s) were backed up.")

    choice = input(
        f"{YELLOW}Recreate these stack static routes in the destination? [y/N]: {RESET}"
    ).strip().lower()
    if choice not in ("y", "yes"):
        warn(f"Skipping stack static route restore for '{stack_name}'.")
        return

    # ── Discover management IPs for stack members ───────────────────────────
    import ipaddress

    mgmt_ips: set[str] = set()
    try:
        stack_obj = dashboard.switch.getNetworkSwitchStack(network_id, stack_id)
        serials = stack_obj.get("serials") or []
        for s in serials:
            try:
                dev = dashboard.devices.getDevice(s)
            except APIError as e:
                warn(f"  Could not read device info for stack member {s}: {e}")
                continue
            for key in ("lanIp", "managementIp", "ip"):
                val = (dev.get(key) or "").strip()
                if val:
                    mgmt_ips.add(val)
    except APIError as e:
        warn(
            f"  Could not read stack members for '{stack_name}' when determining "
            f"management IPs: {e}"
        )

    # ── Compute management subnets from backup stack L3 interfaces ──────────
    mgmt_subnets: list[ipaddress._BaseNetwork] = []
    if stack_l3_ifaces_from_backup:
        for iface in stack_l3_ifaces_from_backup:
            iface_ip = (iface.get("interfaceIp") or "").strip()
            subnet = (iface.get("subnet") or "").strip()
            if not iface_ip or not subnet:
                continue
            if iface_ip not in mgmt_ips:
                continue
            try:
                net = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                continue
            mgmt_subnets.append(net)

    # Existing static routes on dest stack
    try:
        existing = dashboard.switch.getNetworkSwitchStackRoutingStaticRoutes(
            network_id,
            stack_id,
        )
    except APIError as e:
        warn(
            f"Could not inspect existing stack static routes for '{stack_name}' "
            f"in destination: {e}"
        )
        existing = []

    existing_keys = set()
    for r in existing:
        subnet = (r.get("subnet") or "").strip()
        nh = (r.get("nextHopIp") or "").strip()
        if subnet and nh:
            existing_keys.add((subnet, nh))

    created = 0
    skipped = 0
    failed = 0

    for src_route in static_routes:
        subnet = (src_route.get("subnet") or "").strip()
        nh = (src_route.get("nextHopIp") or "").strip()
        name = src_route.get("name") or f"{subnet} via {nh}"

        if not subnet or not nh:
            warn(
                f"  Skipping stack static route '{name}' – missing subnet "
                f"or nextHopIp in backup."
            )
            skipped += 1
            continue

        # Skip if already present
        key = (subnet, nh)
        if key in existing_keys:
            warn(
                f"  Skipping stack static route '{name}' ({subnet} → {nh}) – "
                f"already exists on dest stack."
            )
            skipped += 1
            continue

        # Skip if next hop is on any management subnet
        if mgmt_subnets:
            try:
                nh_ip = ipaddress.ip_address(nh)
            except ValueError:
                nh_ip = None

            if nh_ip and any(nh_ip in net for net in mgmt_subnets):
                warn(
                    f"  Skipping stack static route '{name}' ({subnet} → {nh}) – "
                    "next hop is on management subnet (not recreated via API). "
                    "Please add manually."
                )
                skipped += 1
                continue

        body = {}
        for key_field in (
            "name",
            "subnet",
            "nextHopIp",
            "advertiseViaOspfEnabled",
            "preferOverOspfRoutesEnabled",
        ):
            if key_field in src_route and src_route[key_field] is not None:
                body[key_field] = src_route[key_field]

        print(f"  Creating stack static route '{name}' ({subnet} → {nh})... ", end="")
        try:
            dashboard.switch.createNetworkSwitchStackRoutingStaticRoute(
                network_id,
                stack_id,
                **body,
            )
            print(f"{GREEN}OK{RESET}")
            created += 1
        except APIError as e:
            print(f"{RED}FAILED -> {e}{RESET}")
            failed += 1

    print(
        f"\nStack static route restore summary for '{stack_name}': "
        f"{GREEN}{created} created{RESET}, "
        f"{YELLOW}{skipped} skipped{RESET}, "
        f"{RED}{failed} failed{RESET}."
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

    Behavior:
      * If source and destination addresses are the same (case-insensitive),
        no prompt, keep the source.
      * If they differ, prompt ONCE per destination network:
          [1] Keep source
          [2] Use destination common address
          [3] Enter a custom address
        The choice is cached in addr_cache and reused for later devices in
        the same move into this destination network.
    """
    src_addr = (backup_device.get("address") or "").strip()

    # Figure out "standard" address for DEST network (if any)
    dest_common = _get_common_dest_address(dashboard, dst_net_id)
    dest_addr = (
        dest_common["address"].strip()
        if dest_common and dest_common.get("address")
        else ""
    )

    # If BOTH are empty, nothing useful to do.
    if not src_addr and not dest_addr:
        return backup_device

    # If they match (case-insensitive), nothing to decide.
    if src_addr and dest_addr and src_addr.lower() == dest_addr.lower():
        return backup_device

    # If we have a cached decision, reuse it immediately.
    if addr_cache is not None and "mode" in addr_cache:
        mode = addr_cache["mode"]

        if mode == "source":
            # Always keep whatever was in the backup
            return backup_device

        if mode == "dest":
            # Always use the dest standard address
            new_dev = dict(backup_device)
            use_addr = addr_cache.get("dest_address", dest_addr)
            if use_addr:
                new_dev["address"] = use_addr
            if addr_cache.get("lat") is not None:
                new_dev["lat"] = addr_cache["lat"]
            if addr_cache.get("lng") is not None:
                new_dev["lng"] = addr_cache["lng"]
            return new_dev

        if mode == "manual":
            # Always use the user-supplied custom address
            manual_addr = (addr_cache.get("manual_address") or "").strip()
            if not manual_addr:
                return backup_device
            new_dev = dict(backup_device)
            new_dev["address"] = manual_addr
            return new_dev

        # Unknown mode - fall through as if no cache

    # At this point we know:
    #   - src_addr and dest_addr differ (one or both may be empty), OR
    #   - exactly one of them exists.
    header("Physical address selection for moved device")
    print(f"  Source device address:      {src_addr or '(none)'}")
    if dest_addr:
        cnt = dest_common.get("count", 0) if dest_common else 0
        print(
            f"  Common address in DEST net: {dest_addr} "
            f"(on {cnt} device(s))"
        )
    else:
        print("  Common address in DEST net: (none found)")

    print()
    print("  [1] Keep source device address")
    print("  [2] Use destination network common address")
    print("  [3] Enter a custom address")

    while True:
        prompt = f"{YELLOW}Select option [1/2/3]"
        if dest_addr:
            prompt += " (Enter for 2)"
        prompt += f": {RESET}"

        choice = input(prompt).strip()

        if choice == "" and dest_addr:
            choice = "2"

        if choice not in ("1", "2", "3"):
            warn("Please enter 1, 2, or 3.")
            continue

        # 1) Keep source
        if choice == "1":
            info("Keeping source device address.")
            if addr_cache is not None:
                addr_cache["mode"] = "source"
            return backup_device

        # 2) Use DEST standard address
        if choice == "2":
            if not dest_addr:
                warn("Destination network has no common address; keeping source.")
                if addr_cache is not None:
                    addr_cache["mode"] = "source"
                return backup_device

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

        # 3) Manual/custom address
        if choice == "3":
            while True:
                manual_addr = input(
                    f"{CYAN}Enter custom physical address for this device: {RESET}"
                ).strip()
                if manual_addr:
                    break
                warn("Address cannot be empty. Try again.")

            info(f"Using custom address: {manual_addr}")
            new_dev = dict(backup_device)
            new_dev["address"] = manual_addr

            if addr_cache is not None:
                addr_cache["mode"] = "manual"
                addr_cache["manual_address"] = manual_addr

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

def clone_network_switch_settings(dashboard, src_net_id: str, dst_net_id: str):
    """
    Clone basic network-level switch settings from src_net_id -> dst_net_id:

      - Switch firmware tracks (MS + CS)
      - Management VLAN
      - Global STP config (but NOT per-switch priorities that reference old serials)
      - QoS rules
      - Multicast routing
      - Storm control (via align_storm_control_between_networks)

    Any failures here are logged as non-fatal.
    """
    header("Cloning network-level switch settings to new destination network")
    print(f"  Source network: {src_net_id}")
    print(f"  Dest network:   {dst_net_id}")

    # ── Firmware alignment (MS + CS) ────────────────────────────────────────
    clone_switch_firmware_tracks(dashboard, src_net_id, dst_net_id)

    # ── Switch settings (for management VLAN) ───────────────────────────────
    try:
        src_settings = dashboard.switch.getNetworkSwitchSettings(src_net_id)
    except APIError as e:
        warn(f"Could not read source switch settings: {e}")
        warn("Skipping network-level switch settings clone.")
        return

    # Some orgs / library versions can return a list here, so normalize
    if isinstance(src_settings, list):
        if src_settings and isinstance(src_settings[0], dict):
            src_settings = src_settings[0]
        else:
            warn("  Source switch settings came back as an unexpected list; skipping.")
            src_settings = {}

    # Management VLAN: API usually uses 'vlan'
    mgmt_vlan = src_settings.get("vlan")
    if mgmt_vlan is None:
        mgmt_vlan = src_settings.get("managementVlan")

    if mgmt_vlan is None or mgmt_vlan == 0:
        info("  Source network has no management VLAN set; skipping.")
    else:
        try:
            dashboard.switch.updateNetworkSwitchSettings(
                dst_net_id,
                vlan=mgmt_vlan,
            )
            print(f"  Copied management VLAN (vlan={mgmt_vlan})")
        except APIError as e:
            warn(f"  Failed to apply management VLAN to dest: {e}")

        # ── STP (global only) ───────────────────────────────────────────────────
    try:
        stp = dashboard.switch.getNetworkSwitchStp(src_net_id)
    except APIError as e:
        warn(f"  Could not read STP settings from source: {e}")
        stp = None

    if stp:
        body = {}

        # Global RSTP toggle
        if "rstpEnabled" in stp:
            body["rstpEnabled"] = stp["rstpEnabled"]

        # stpBridgePriority may be:
        #   - dict: {"default": 32768, "switches": [...], "stacks": [...]}
        #   - list: [{"stpPriority": 28672, "switches": [...], "stacks": [...]}, ...]
        src_bp = stp.get("stpBridgePriority")
        default_pri = None

        if isinstance(src_bp, dict):
            default_pri = src_bp.get("default")
        elif isinstance(src_bp, list) and src_bp:
            # Take the first entry's stpPriority as the "default-ish" value
            default_pri = src_bp[0].get("stpPriority")

        if default_pri is not None:
            # Only clone a single global priority; do NOT try to bring over
            # per-switch/stack overrides here.
            body["stpBridgePriority"] = [
                {"stpPriority": default_pri}
            ]

        if body:
            try:
                dashboard.switch.updateNetworkSwitchStp(dst_net_id, **body)
                info(
                    "  Applied global STP settings to new network "
                    "(per-switch/stack overrides are NOT auto-cloned)."
                )
            except APIError as e:
                warn(
                    "  Could not apply global STP settings to new network: "
                    f"{e}"
                )
        else:
            info("  No global STP settings found to copy.")

    # ── QoS rules ───────────────────────────────────────────────────────────
    try:
        qos_rules = dashboard.switch.getNetworkSwitchQosRules(src_net_id)
    except APIError as e:
        warn(f"  Could not read QoS rules from source: {e}")
        qos_rules = []

    if qos_rules:
        created = 0
        for rule in qos_rules:
            rule_id = rule.get("id")
            # VLAN can be None => "ANY VLAN"
            vlan = rule.get("vlan", None)

            body = {}

            # Protocol + DSCP
            body["protocol"] = rule.get("protocol") or "ANY"
            if rule.get("dscp") is not None:
                body["dscp"] = rule["dscp"]
            else:
                body["dscp"] = 0

            # Optional port / range fields — convert ints to strings
            for field in ("srcPort", "dstPort", "srcPortRange", "dstPortRange"):
                val = rule.get(field)
                if val is None:
                    continue
                if isinstance(val, int):
                    val = str(val)
                body[field] = val

            try:
                # IMPORTANT: vlan stays as positional arg
                dashboard.switch.createNetworkSwitchQosRule(
                    dst_net_id,
                    vlan,  # may be None => ANY VLAN
                    **body,
                )
                created += 1
            except APIError as e:
                warn(f"  Failed to create QoS rule {rule_id}: {e}")

        print(f"  Copied {created} QoS rule(s).")
    else:
        info("  No QoS rules found to copy.")

    # ── Multicast routing settings ──────────────────────────────────────────
    try:
        mcast = dashboard.switch.getNetworkSwitchRoutingMulticast(src_net_id)
    except (APIError, AttributeError) as e:
        warn(f"  Could not read multicast routing settings from source: {e}")
        mcast = None

    if mcast:
        # Normalize list-shaped responses, if any
        if isinstance(mcast, list):
            if mcast and isinstance(mcast[0], dict):
                mcast = mcast[0]
                info(
                    "  Multicast routing settings returned as a list; "
                    "using first entry."
                )
            else:
                warn(
                    "  Multicast routing settings came back in an unexpected "
                    "list format; skipping multicast clone."
                )
                mcast = None

    if mcast:
        body = {}
        for key in (
            "defaultSettings",
            "overrides",
            "igmpSnooping",
            "floodUnknownMulticastTrafficEnabled",
        ):
            if key in mcast and mcast[key] is not None:
                body[key] = mcast[key]

        if body:
            try:
                dashboard.switch.updateNetworkSwitchRoutingMulticast(
                    dst_net_id,
                    **body,
                )
                info("  Copied multicast routing settings.")
            except (APIError, AttributeError) as e:
                warn(f"  Failed to apply multicast routing settings: {e}")
        else:
            info("  No multicast routing settings to copy.")

    # ── Storm control (deferred/validated) ──────────────────────────────────
    align_storm_control_between_networks(dashboard, src_net_id, dst_net_id)

    success("Finished cloning network-level switch settings.")
def _normalize_stp_obj(stp_raw):
    """
    Meraki STP API sometimes returns a dict, sometimes a list with one dict.
    Normalize to a single dict.
    """
    if isinstance(stp_raw, list):
        return stp_raw[0] if stp_raw else {}
    if isinstance(stp_raw, dict):
        return stp_raw
    return {}


def _extract_overrides(bp_val):
    """
    Return two dicts {switch_id: priority}, {stack_id: priority} for
    per-device STP overrides.

    IMPORTANT: we only treat entries that have an explicit
    stpPriority/priority as overrides. Objects that just carry the
    global 'default' value are ignored here – otherwise every switch
    would look like it has an override equal to the global default.
    """
    switch_map: dict[str, int | None] = {}
    stack_map: dict[str, int | None] = {}

    def _add_switch(entry, pri):
        if isinstance(entry, dict):
            ident = (
                entry.get("serial")
                or entry.get("id")
                or entry.get("name")
            )
        else:
            ident = str(entry)
        if ident:
            switch_map[ident] = pri

    def _add_stack(entry, pri):
        if isinstance(entry, dict):
            ident = (
                entry.get("stackId")
                or entry.get("id")
                or entry.get("name")
            )
        else:
            ident = str(entry)
        if ident:
            stack_map[ident] = pri

    # ── Legacy dict shape ────────────────────────────────────────────────
    if isinstance(bp_val, dict):
        # In this shape, bp_val itself is the override object and holds
        # stpPriority/priority plus lists of switches/stacks.
        base_pri = bp_val.get("stpPriority") or bp_val.get("priority")
        if base_pri is not None:
            for s in bp_val.get("switches") or []:
                _add_switch(s, base_pri)
            for st in bp_val.get("stacks") or []:
                _add_stack(st, base_pri)

    # ── Newer list-of-objects shape (what your org is using) ────────────
    elif isinstance(bp_val, list):
        for obj in bp_val:
            if not isinstance(obj, dict):
                continue

            # Only objects with an explicit per-device priority are overrides.
            pri = obj.get("stpPriority") or obj.get("priority")
            if pri is None:
                # This is likely just the "default" object; ignore it here.
                continue

            for s in obj.get("switches") or []:
                _add_switch(s, pri)
            for st in obj.get("stacks") or []:
                _add_stack(st, pri)

    return switch_map, stack_map

def summarize_stp_migrations(dashboard):
    """
    At the end of the session, show an actionable STP summary for each
    (source_net_id, dest_net_id) pair where we moved switches.

    We *don't* auto-change STP here; we just surface differences so you
    know exactly which switches / stacks to fix in Dashboard.
    """
    if not STP_AUDIT_PAIRS:
        info("No STP-related network moves recorded in this session.")
        return

    header("STP summary for networks touched in this session")

    def _default_pri(bp_val):
        """
        Try to extract the network-wide default bridge priority.
        We deliberately keep this separate from per-device overrides.
        """
        # Legacy dict style
        if isinstance(bp_val, dict):
            if "default" in bp_val:
                return bp_val.get("default")

            # Some shards may store default as stpPriority with no
            # switches/stacks attached.
            if (
                not bp_val.get("switches")
                and not bp_val.get("stacks")
                and bp_val.get("stpPriority") is not None
            ):
                return bp_val.get("stpPriority")

        # List-of-objects style
        if isinstance(bp_val, list):
            # First, look for an explicit "default" field.
            for obj in bp_val:
                if not isinstance(obj, dict):
                    continue
                if "default" in obj:
                    return obj.get("default")

            # Fallback: any object with no switches/stacks is probably
            # the default object; use its stpPriority/priority.
            for obj in bp_val:
                if not isinstance(obj, dict):
                    continue
                if not obj.get("switches") and not obj.get("stacks"):
                    pri = obj.get("stpPriority") or obj.get("priority")
                    if pri is not None:
                        return pri

        return None

    for idx, (src_net_id, dst_net_id) in enumerate(sorted(STP_AUDIT_PAIRS), start=1):
        # Grab network names for nicer output
        try:
            src_net = dashboard.networks.getNetwork(src_net_id)
            src_name = src_net.get("name", src_net_id)
        except Exception:
            src_name = src_net_id

        try:
            dst_net = dashboard.networks.getNetwork(dst_net_id)
            dst_name = dst_net.get("name", dst_net_id)
        except Exception:
            dst_name = dst_net_id

        print(
            f"\n{BOLD}Pair {idx}: {src_name} ({src_net_id}) → "
            f"{dst_name} ({dst_net_id}){RESET}"
        )

        # Pull raw STP configs
        try:
            src_stp_raw = dashboard.switch.getNetworkSwitchStp(src_net_id)
        except APIError as e:
            warn(f"  Could not read STP from SOURCE {src_net_id}: {e}")
            src_stp_raw = {}

        try:
            dst_stp_raw = dashboard.switch.getNetworkSwitchStp(dst_net_id)
        except APIError as e:
            warn(f"  Could not read STP from DEST {dst_net_id}: {e}")
            dst_stp_raw = {}

        src_stp = _normalize_stp_obj(src_stp_raw)
        dst_stp = _normalize_stp_obj(dst_stp_raw)

        src_rstp = src_stp.get("rstpEnabled")
        dst_rstp = dst_stp.get("rstpEnabled")

        src_bp = src_stp.get("stpBridgePriority") or {}
        dst_bp = dst_stp.get("stpBridgePriority") or {}

        src_default = _default_pri(src_bp)
        dst_default = _default_pri(dst_bp)

        # Per-device overrides (uses the updated _extract_overrides you added)
        src_sw_map, src_stack_map = _extract_overrides(src_bp)
        dst_sw_map, dst_stack_map = _extract_overrides(dst_bp)

        print(f"  RSTP enabled: source={src_rstp}, dest={dst_rstp}")
        print(f"  Default STP bridge priority: source={src_default}, dest={dst_default}")

        # ---- Per-switch overrides ----
        print("  Per-switch STP overrides (source vs dest):")
        all_serials = sorted(set(src_sw_map.keys()) | set(dst_sw_map.keys()))
        if not all_serials:
            print("    (none)")
        else:
            for serial in all_serials:
                s_pri = src_sw_map.get(serial)
                d_pri = dst_sw_map.get(serial)
                if s_pri == d_pri:
                    print(f"    - {serial}: source={s_pri}, dest={d_pri}")
                else:
                    msg = f"    - {serial}: source={s_pri}, dest={d_pri}"
                    if s_pri is not None and d_pri is None:
                        msg += "  ← MISSING ON DEST – set this priority in Switch Settings."
                    elif s_pri is None and d_pri is not None:
                        msg += "  ← EXTRA ON DEST (not present on source)."
                    else:
                        msg += "  ← MISMATCH – verify which value is correct."
                    print(msg)

        # ---- Per-stack overrides ----
        print("  Per-stack STP overrides (source vs dest):")
        all_stacks = sorted(set(src_stack_map.keys()) | set(dst_stack_map.keys()))
        if not all_stacks:
            print("    (none)")
        else:
            for stack_id in all_stacks:
                s_pri = src_stack_map.get(stack_id)
                d_pri = dst_stack_map.get(stack_id)
                if s_pri == d_pri:
                    print(f"    - {stack_id}: source={s_pri}, dest={d_pri}")
                else:
                    msg = f"    - {stack_id}: source={s_pri}, dest={d_pri}"
                    if s_pri is not None and d_pri is None:
                        msg += "  ← MISSING ON DEST – set this stack priority."
                    elif s_pri is None and d_pri is not None:
                        msg += "  ← EXTRA ON DEST (not present on source)."
                    else:
                        msg += "  ← MISMATCH – verify which value is correct."
                    print(msg)

        # High-level flag if anything differs
        if (
            src_rstp == dst_rstp
            and src_default == dst_default
            and src_sw_map == dst_sw_map
            and src_stack_map == dst_stack_map
        ):
            success("  STP settings match between source and dest for this pair.")
        else:
            warn("  STP differences detected – see details above for this pair.")
# ─────────────────────────────────────────────────────────────────────────────
# Network creation
# ─────────────────────────────────────────────────────────────────────────────

def create_switch_network(
    dashboard,
    org_id: str,
    src_net_for_settings: dict | None = None,
):
    """
    Create a new switch-only network in the given org.

    If src_net_for_settings is provided, we also clone key network-level
    switch settings (mgmt VLAN, STP, QoS, multicast, MTU, storm control)
    from that source network *after* creation.
    """
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

    # If we have a source network, immediately clone its switch settings
    if src_net_for_settings is not None:
        try:
            clone_network_switch_settings(
                dashboard,
                src_net_id=src_net_for_settings["id"],
                dst_net_id=net["id"],
            )
        except Exception as e:
            # Absolutely do not kill the workflow for a settings copy failure
            warn(f"Non-fatal: failed to clone network switch settings: {e}")

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
    print("  [2] Create a new switch-only network (clone switch settings from SOURCE)")
    n_choice = input(f"{YELLOW}Select option [1/2]: {RESET}").strip()

    if n_choice == "2":
        # IMPORTANT: pass net_src so we can clone its switch settings
        net_dst = create_switch_network(
            dashboard,
            org_dst["id"],
            src_net_for_settings=net_src,
        )
    else:
        net_dst = select_network(
            dashboard,
            org_dst["id"],
            prompt="Select DESTINATION network",
        )

    if org_src["id"] == org_dst["id"] and net_src["id"] == net_dst["id"]:
        warn("Source and destination networks are the same. No move necessary.")
        sys.exit(0)

    # Remember this mapping for a final STP audit after all moves
    note_stp_pair(net_src["id"], net_dst["id"])

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




def restore_switch_link_aggregations(
    dashboard,
    network_id: str,
    label: str,
    link_aggs_backup: list[dict] | None,
):
    """
    Restore switch or stack link aggregations from backup.

    Behavior:
      - Up to 3 create+verify rounds.
      - After each round we call getNetworkSwitchLinkAggregations() and verify
        that every backup member (serial/portId) appears in some LAG.
      - If the verification passes, we stop early and report success.
      - If the API for LAGs is not supported (404), we warn and return.
      - If after 3 rounds we still don't see matching LAG members, we warn
        that the user should verify LAGs manually in Dashboard.
    """

    if not link_aggs_backup:
        info(f"No link aggregation groups to restore for {label}.")
        return

    header(f"Restoring {len(link_aggs_backup)} link aggregation groups for {label}")

    # Helper to flatten backup members into (serial, portId) pairs
    def backup_member_keys() -> list[tuple[str, str]]:
        keys: list[tuple[str, str]] = []
        for lag in link_aggs_backup or []:
            for m in lag.get("switchPorts", []):
                s = m.get("serial")
                p = m.get("portId")
                if s and p:
                    keys.append((s, p))
        return keys

    backup_members = backup_member_keys()
    if not backup_members:
        warn(
            f"  Backup for {label} has no switchPorts in its LAG definitions. "
            "Nothing to restore."
        )
        return

    max_rounds = 3

    for attempt in range(1, max_rounds + 1):
        info(
            f"Attempt {attempt}/{max_rounds} to create and verify link "
            f"aggregations for {label}..."
        )

        # ── Create/refresh LAGs for this attempt ────────────────────────────
        created_this_round = 0
        failed_this_round = 0

        for lag in link_aggs_backup or []:
            members = lag.get("switchPorts") or []
            payload = {"switchPorts": members}

            member_desc = ", ".join(
                f"{m.get('serial')}/{m.get('portId')}" for m in members
            ) or "(no members)"

            try:
                dashboard.switch.createNetworkSwitchLinkAggregation(
                    network_id,
                    **payload,
                )
                success(
                    f"  [round {attempt}] LAG '(no name)' "
                    f"({len(members)} ports: {member_desc}): create call OK"
                )
                created_this_round += 1
            except APIError as e:
                msg = str(e)
                # Common case on retries: "port is already part of a link aggregation"
                if "already part of" in msg or "already member" in msg:
                    info(
                        f"  [round {attempt}] LAG '(no name)' "
                        f"({member_desc}): ports already in a LAG according to API."
                    )
                else:
                    failed_this_round += 1
                    error(
                        f"  [round {attempt}] LAG '(no name)' "
                        f"({member_desc}): FAILED -> {e}"
                    )

        info(
            f"  [round {attempt}] create calls: "
            f"{created_this_round} OK, {failed_this_round} failed."
        )

        # Small settle delay for eventual consistency before verification
        time.sleep(5)

        # ── Verification phase for this attempt ─────────────────────────────
        try:
            current = dashboard.switch.getNetworkSwitchLinkAggregations(network_id)
        except APIError as e:
            msg = str(e)
            if "404" in msg or "Not Found" in msg:
                warn(
                    "  WARNING: getNetworkSwitchLinkAggregations is not supported on "
                    f"this network (likely a Cloud-monitored Catalyst limitation). "
                    "The tool cannot verify LAGs. Please confirm uplink/LAG config "
                    "manually in Dashboard."
                )
                return
            else:
                warn(
                    f"  WARNING: Error while verifying link aggregations on {label}: "
                    f"{e}. Please confirm LAGs manually in Dashboard."
                )
                return

        if not current:
            warn(
                f"  [round {attempt}] No LAGs returned by "
                "getNetworkSwitchLinkAggregations()."
            )
            if attempt < max_rounds:
                warn("  Retrying LAG creation/verification...")
                continue
            else:
                warn(
                    "  After multiple attempts, no LAGs are visible via the API. "
                    "Please verify NM/uplink LAGs manually in Dashboard."
                )
                return

        # Build map of (serial, portId) -> LAG id from current config
        member_to_lag: dict[tuple[str, str], str] = {}
        for lag in current:
            lag_id = lag.get("id") or "unknown"
            for m in lag.get("switchPorts", []):
                key = (m.get("serial"), m.get("portId"))
                member_to_lag[key] = lag_id

        missing_members: list[str] = []
        for key in backup_members:
            if key not in member_to_lag:
                missing_members.append(f"{key[0]}/{key[1]}")

        if not missing_members:
            info(
                f"  Verified: all backup LAG member ports for {label} appear in "
                f"current LAG configuration after attempt {attempt}."
            )
            return

        # Some members still not in any LAG
        warn(
            f"  [round {attempt}] One or more backup LAG members do not appear in "
            f"any current LAG on {label}: {', '.join(missing_members)}"
        )

        if attempt < max_rounds:
            warn("  Will retry LAG creation/verification again...")
        else:
            warn(
                "  After multiple attempts, some backup LAG member ports still do "
                "not appear in any LAG. Please inspect and fix uplink/LAGs "
                "manually in Dashboard."
            )
            return

def move_stack_between_networks(
    dashboard,
    org_src,
    net_src,
    stack,
    org_dst,
    net_dst,
    per_switch_backups,
    stack_link_aggs,
    stack_l3_ifaces,
    stack_l3_dhcp,
    stack_static_routes,
    addr_cache: dict | None = None,
):
    src_net_id = net_src["id"]
    dst_net_id = net_dst["id"]
    serials = stack.get("serials") or []
    stack_name = stack.get("name") or "(unnamed stack)"

    header("Summary of STACK move")
    print(f"  Stack: '{stack_name}' (id={stack.get('id')})")
    for serial in serials:
        dev = per_switch_backups[serial]["backup"]["device"]
        print(f"    - {dev.get('name') or '(no name)'} | "
              f"serial={serial} | model={dev.get('model')}")
    print(f"  From: org={org_src['name']} (id={org_src['id']}), "
          f"network={net_src['name']} (id={src_net_id})")
    print(f"  To:   org={org_dst['name']} (id={org_dst['id']}), "
          f"network={net_dst['name']} (id={dst_net_id})")

    confirm = input(
        f"{YELLOW}Proceed with STACK move? Type 'yes' to continue: {RESET}"
    ).strip().lower()
    if confirm != "yes":
        warn("Stack move cancelled.")
        sys.exit(0)

    header("Breaking stack in source network (deleting stack object)")
    try:
        dashboard.switch.deleteNetworkSwitchStack(src_net_id, stack["id"])
        success(
            f"Stack '{stack_name}' deleted; members are now standalone switches."
        )
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

    # Build a map of serial -> set(portIds) that participate in LAGs.
    # These are the ports we especially care about being present (often NM/uplink ports).
    lag_ports_by_serial: dict[str, set[str]] = {}
    for lag in stack_link_aggs or []:
        for member in lag.get("switchPorts", []):
            m_serial = member.get("serial")
            m_port   = member.get("portId")
            if not m_serial or not m_port:
                continue
            lag_ports_by_serial.setdefault(m_serial, set()).add(m_port)
    # Address / metadata choice — reuse addr_cache if provided
    if addr_cache is None:
        addr_cache = {}

    header("Restoring device metadata on all stack members")
    for serial in serials:
        backup_dev = per_switch_backups[serial]["backup"]["device"]
        chosen_dev = choose_address_for_device(
            dashboard,
            dst_net_id,
            backup_dev,
            addr_cache=addr_cache,
        )
        restore_device_metadata(dashboard, serial, chosen_dev)
    # Before restoring ports, wait for any LAG/NM ports from the backup
    # to appear on each switch (handles NM cards taking a bit to show up).
    if lag_ports_by_serial:
        info(
    "Note: In lab testing, a 2-switch stack took ~80 seconds for NM (network "
    "module) ports to appear after moving into a new network. Larger stacks or "
    "busier Meraki shards may take longer.\n"
    "The Meraki Dashboard provisions stack members in parallel, but uplink/"
    "module ports can still take time to materialize.\n"
    "We will wait up to 10 minutes for required NM/LAG ports to appear before "
    "continuing. This is normal behavior on Catalyst stacks after a network move."
)
        header("Waiting for LAG / NM ports to appear on stack members")
        for serial in serials:
            expected = lag_ports_by_serial.get(serial)
            if not expected:
                continue  # this member had no LAG ports in the backup
            wait_for_ports_to_exist(
                dashboard,
                serial,
                expected_port_ids=expected,
                timeout=480,
                poll_interval=10,
            )
    header("Restoring ports on all stack members")
    for serial in serials:
        b = per_switch_backups[serial]["backup"]
        restore_switch_ports(dashboard, serial, b["ports"])

    restore_switch_link_aggregations(
        dashboard,
        dst_net_id,
        label=f"stack {stack_name}",
        link_aggs_backup=stack_link_aggs,
    )

    # ── Ensure stack exists in destination, capture its ID ───────────────────
    header("Ensuring stack exists in destination network")
    dest_stack_id = None

    existing = find_stack_by_serials(dashboard, dst_net_id, serials)
    if existing:
        dest_stack_id = existing.get("id")
        success(
            f"Stack already present in destination (likely auto-provisioned): "
            f"'{existing.get('name')}' (id={dest_stack_id})"
        )
    else:
        try:
            created_stack = dashboard.switch.createNetworkSwitchStack(
                dst_net_id,
                name=stack_name,
                serials=serials,
            )
            dest_stack_id = created_stack.get("id")
            success(
                f"Stack '{stack_name}' recreated in destination network "
                f"(id={dest_stack_id})."
            )
        except APIError as e:
            msg = str(e)
            if "already part of a switch stack" in msg:
                warn(
                    "Stack creation failed because switches are already in a stack."
                )
                warn(
                    "Dashboard auto-provisioning likely created the stack; verifying..."
                )
                existing = find_stack_by_serials(dashboard, dst_net_id, serials)
                if existing:
                    dest_stack_id = existing.get("id")
                    success(
                        f"Confirmed existing stack in destination: "
                        f"'{existing.get('name')}' (id={dest_stack_id})"
                    )
                else:
                    error(
                        "Could not locate the auto-created stack in destination "
                        "after error. Skipping stack-level L3/static restore."
                    )
            else:
                error(f"FAILED to recreate stack: {e}")
                error("Skipping stack-level L3/static restore.")
                dest_stack_id = None

    # ── Stack-level L3 + DHCP + static routes on the destination stack ──────
    if dest_stack_id:
        ok = restore_stack_l3_and_dhcp(
            dashboard,
            dst_net_id,
            dest_stack_id,
            stack_name,
            stack_l3_ifaces,
            stack_l3_dhcp,
            backup_dir="backups",  # adjust if needed
        )

        if ok:
            restore_stack_static_routes(
                dashboard,
                dst_net_id,
                dest_stack_id,
                stack_name,
                stack_static_routes,
                stack_l3_ifaces,
            )
        else:
            warn(
                "Skipping stack static routes because no stack L3 interface could be "
                "created (uplink requirement not satisfied)."
            )

    # Re-check storm control alignment after each stack move as well.
    align_storm_control_between_networks(dashboard, net_src["id"], dst_net_id)

    # Now that the stack exists in the DEST network, we no longer try to
    # auto-apply per-switch STP overrides here.

    # Remember this src→dst pair for a final STP summary.
    note_stp_pair(src_net_id, dst_net_id)

    success(
        "Stack move complete. Verify in Dashboard that per-member ports, "
        "stack L3, DHCP, static routes, and STP look correct."
    )

def move_switch_between_networks(
    dashboard,
    org_src,
    net_src,
    device,
    org_dst,
    net_dst,
    backup,
    addr_cache: dict | None = None,
):
    """
    Move a single switch from net_src to net_dst and restore its config
    from 'backup' (created by backup_switch_config).
    """
    src_net_id = net_src["id"]
    dst_net_id = net_dst["id"]
    serial = device["serial"]
    name = device.get("name") or "(no name)"

    header("Summary of SINGLE SWITCH move")
    print(f"  Switch: {name} | serial={serial} | model={device.get('model')}")
    print(f"  From: org={org_src['name']} (id={org_src['id']}), "
          f"network={net_src['name']} (id={src_net_id})")
    print(f"  To:   org={org_dst['name']} (id={org_dst['id']}), "
          f"network={net_dst['name']} (id={dst_net_id})")

    confirm = input(
        f"{YELLOW}Proceed with this switch move? "
        f"Type 'yes' to continue: {RESET}"
    ).strip().lower()
    if confirm != "yes":
        warn("Switch move cancelled.")
        return

    header("Removing device from source network")
    try:
        dashboard.networks.removeNetworkDevices(src_net_id, serial)
        success(f"Removed {serial} from source network.")
    except APIError as e:
        error(f"FAILED to remove {serial} from source network: {e}")
        error("Aborting before claiming into destination.")
        sys.exit(1)

    header("Claiming device into destination network")
    try:
        dashboard.networks.claimNetworkDevices(dst_net_id, serials=[serial])
        success(f"Device {serial} claimed into destination network.")
    except APIError as e:
        error(f"Error claiming device into destination network: {e}")
        error("Device is removed from the source but not added to the destination.")
        sys.exit(1)

    info("Waiting a few seconds for the Dashboard to register the move...")
    time.sleep(5)

    # Address / metadata decision – reuse addr_cache if provided
    if addr_cache is None:
        addr_cache = {}

    header("Restoring device metadata")
    backup_dev = backup["device"]
    chosen_dev = choose_address_for_device(
        dashboard,
        dst_net_id,
        backup_dev,
        addr_cache=addr_cache,
    )
    restore_device_metadata(dashboard, serial, chosen_dev)

    # ── LAG / NM port handling for single switch ────────────────────────────
    # Figure out which ports participate in LAGs in the backup (usually NM/uplink).
    switch_link_aggs = backup.get("linkAggregations") or []
    expected_lag_ports: set[str] = set()
    for lag in switch_link_aggs:
        for member in lag.get("switchPorts", []):
            if member.get("serial") == serial and member.get("portId"):
                expected_lag_ports.add(member["portId"])

    if expected_lag_ports:
        header("Waiting for LAG / NM ports to appear on destination switch")
        info(
            "Note: in lab testing, NM (network module) ports on single "
            "Catalyst switches could take close to a minute to appear "
            "after a network move. We will wait up to 10 minutes for "
            f"these ports: {sorted(expected_lag_ports)}"
        )
        wait_for_ports_to_exist(
            dashboard,
            serial,
            expected_port_ids=expected_lag_ports,
            timeout=600,       # 10 minutes
            poll_interval=10,  # every 10 seconds
        )

    header("Restoring switch ports")
    restore_switch_ports(dashboard, serial, backup["ports"])

    header("Restoring link aggregations (if any)")
    restore_switch_link_aggregations(
        dashboard,
        dst_net_id,
        label=f"switch {serial}",
        link_aggs_backup=switch_link_aggs,
    )

    # L3 + DHCP restore (device-level)
    restore_device_l3_and_dhcp(
        dashboard,
        serial,
        backup.get("l3Interfaces") or [],
        backup.get("l3Dhcp") or {},
    )

    # Static route restore (device-level)
    restore_device_static_routes(
        dashboard,
        serial,
        backup.get("staticRoutes") or [],
    )

    # Re-check storm control alignment on every move – once an MS switch
    # exists in the destination, this will be able to apply the source
    # storm control template.
    align_storm_control_between_networks(dashboard, net_src["id"], dst_net_id)

    # Remember this src→dst pair for a final STP summary.
    note_stp_pair(src_net_id, dst_net_id)

    success(
        "Single switch move complete. Verify in Dashboard that ports, "
        "L3, DHCP, static routes, STP, and storm control look correct."
    )
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
        (
            per_switch_backups,
            stack_link_aggs,
            stack_l3_ifaces,
            stack_l3_dhcp,
            stack_static_routes,
            stack_backup_path,
        ) = backup_stack_config(dashboard, net_src["id"], stack)
        success(f"Stack backup metadata file: {stack_backup_path}")

        org_dst, net_dst = choose_destination_org_and_network(
            dashboard, org_src, net_src
        )

        # One address decision cache per single move
        addr_cache = {}

        move_stack_between_networks(
            dashboard,
            org_src,
            net_src,
            stack,
            org_dst,
            net_dst,
            per_switch_backups,
            stack_link_aggs,
            stack_l3_ifaces,
            stack_l3_dhcp,
            stack_static_routes,
            addr_cache=addr_cache,
        )

    else:
        backup, backup_path = backup_switch_config(dashboard, net_src["id"], serial)
        success(f"Backup file: {backup_path}")

        org_dst, net_dst = choose_destination_org_and_network(
            dashboard, org_src, net_src
        )

        # One address decision cache per single move
        addr_cache = {}

        move_switch_between_networks(
            dashboard,
            org_src,
            net_src,
            device,
            org_dst,
            net_dst,
            backup,
            addr_cache=addr_cache,
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

    # One address decision cache per batch into this dest network
    addr_cache = {}

    # Move stacks first
    for stack in stacks_to_move:
        (
            per_switch_backups,
            stack_link_aggs,
            stack_l3_ifaces,
            stack_l3_dhcp,
            stack_static_routes,
            stack_backup_path,
        ) = backup_stack_config(dashboard, net_src["id"], stack)
        success(f"Stack backup metadata file: {stack_backup_path}")
        move_stack_between_networks(
            dashboard,
            org_src,
            net_src,
            stack,
            org_dst,
            net_dst,
            per_switch_backups,
            stack_link_aggs,
            stack_l3_ifaces,
            stack_l3_dhcp,
            stack_static_routes,
            addr_cache=addr_cache,
        )

    # Then standalone switches
    for device in singles_to_move:
        serial = device["serial"]
        backup, backup_path = backup_switch_config(dashboard, net_src["id"], serial)
        success(f"Backup file: {backup_path}")
        move_switch_between_networks(
            dashboard,
            org_src,
            net_src,
            device,
            org_dst,
            net_dst,
            backup,
            addr_cache=addr_cache,
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
            # Final STP summary for all src→dst pairs we touched this session
            summarize_stp_migrations(dashboard)
            success("Exiting...")
            break

        reuse = input(
            f"{YELLOW}Reuse the same API key? [Y/n]: {RESET}"
        ).strip().lower()

        if reuse in ("", "y", "yes"):
            cached_api_key = api_key
        else:
            cached_api_key = None


if __name__ == "__main__":
    main()
