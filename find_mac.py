import meraki
import os
import time
from datetime import datetime

# === Format timestamps ===
def format_timestamp(ts):
    if not ts:
        return "Unknown"
    try:
        if isinstance(ts, str) and "T" in ts:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").strftime('%Y-%m-%d %H:%M:%S')
        ts = int(ts)
        if ts > 1_000_000_000_000:
            ts = ts // 1000
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)

# === Select Organization ===
def get_org(dashboard):
    try:
        orgs = dashboard.organizations.getOrganizations()
    except Exception as e:
        print(f"❌ Error retrieving organizations: {e}")
        return None, None

    if not orgs:
        print("❌ No organizations found.")
        return None, None

    print("\nAvailable Organizations:")
    for idx, org in enumerate(orgs):
        print(f"{idx+1}. {org['name']} (ID: {org['id']})")

    while True:
        choice = input("Select the organization number to use: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(orgs)):
            print("❌ Invalid selection. Please enter a valid number.")
            continue
        return orgs[int(choice) - 1]['id'], orgs[int(choice) - 1]['name']

# === Search all networks ===
def find_mac_in_networks(dashboard, org_id, target_mac):
    networks = dashboard.organizations.getOrganizationNetworks(org_id)
    print(f"\n🔍 Searching for MAC {target_mac} across all networks...")

    for net in networks:
        net_id = net['id']
        net_name = net['name']
        print(f"→ Searching in network: {net_name}...")

        try:
            clients = dashboard.networks.getNetworkClients(net_id, total_pages='all')
        except Exception as e:
            print(f"⚠️  Failed to fetch clients from {net_name}: {e}")
            continue

        for client in clients:
            if client.get('mac', '').lower() == target_mac.lower():
                print("\n🎯 MAC Address Found!")
                print(f"Network: {net_name}")
                print(f"Description: {client.get('description', 'No description')}")
                print(f"Manufacturer: {client.get('manufacturer', 'Unknown')}")
                print(f"MAC: {client.get('mac')}")
                print(f"IP: {client.get('ip', 'N/A')}")
                print(f"VLAN: {client.get('vlan', 'N/A')}")
                print(f"SSID: {client.get('ssid', 'N/A')}")
                print(f"Last Seen: {format_timestamp(client.get('lastSeen'))}")
                return net_id
    print("MAC address not found.")
    return None

# === Search all devices (MR, CW, MS, CS) ===
def enrich_with_device_context(dashboard, client_mac, org_id, net_id):
    print("\n🔎 Looking for the AP or switch that saw the MAC...")

    try:
        network_clients = dashboard.networks.getNetworkClients(net_id, total_pages='all')
    except Exception as e:
        print(f"⚠️ Could not fetch network clients: {e}")
        return

    matched_client = None
    device_serial = None

    # 🔍 **Step 1: Find the client and determine its connected device**
    for client in network_clients:
        if client.get('mac', '').lower() == client_mac.lower():
            matched_client = client
            device_serial = client.get('recentDeviceSerial')
            device_name = client.get('recentDeviceName')
            device_mac = client.get('recentDeviceMac')
            connection_type = client.get('recentDeviceConnection')

            print("\n🎯 MAC Address Found!")
            print(f"SSID: {client.get('ssid', 'N/A')}")
            print(f"Description: {client.get('description', 'N/A')}")
            print(f"MAC: {client_mac}")
            print(f"IP: {client.get('ip', 'N/A')}")
            print(f"VLAN: {client.get('vlan', 'N/A')}")
            print(f"Last Seen: {format_timestamp(client.get('lastSeen'))}")

            if device_serial:
                print(f"\n📡 Client is connected to: {device_name} (Serial: {device_serial})")
                print(f"🔗 Connection Type: {connection_type}")
                break

    if not device_serial:
        print("⚠️ No connected AP or switch found in network client data.")
        return

    # 🔍 **Step 2: Fetch Device Details**
    try:
        device_details = dashboard.devices.getDevice(device_serial)
        device_model = device_details.get('model', 'Unknown')

        # **Updated to detect CW APs**
        if device_model.startswith("MR") or device_model.startswith("CW"):
            device_type = "Access Point (MR/CW)"
        elif device_model.startswith("MS") or device_model.startswith("CS"):
            device_type = "Switch (MS/CS)"
        else:
            device_type = "Unknown Device"

        print(f"\n📡 Device Details:")
        print(f"Device Name: {device_details.get('name', 'Unknown')}")
        print(f"Model: {device_model}")
        print(f"MAC: {device_mac}")
        print(f"IP: {device_details.get('lanIp', 'N/A')}")
        print(f"Serial: {device_details.get('serial')}")
        print(f"📍 Location: {device_details.get('address', 'Unknown')}")
        print(f"🆔 Device Type: {device_type}")

        # **AP Handling (`MR` and `CW`)**
        if device_model.startswith("MR") or device_model.startswith("CW"):
            try:
                ap_status = dashboard.wireless.getDeviceWirelessStatus(device_serial)
                print(f"📶 Signal Strength: {ap_status.get('signalStrength', 'N/A')} dBm")
                print(f"📡 Channel: {ap_status.get('channel', 'N/A')}")
            except Exception as e:
                print(f"⚠️ Could not fetch AP wireless details: {e}")

    except Exception as e:
        print(f"⚠️ Could not fetch device details: {e}")

# === Main Function ===
def main():
    print("🔐 Meraki MAC Address Finder")
    API_KEY = os.getenv("MERAKI_API_KEY") or input("Enter your Meraki API Key: ").strip()
    dashboard = meraki.DashboardAPI(API_KEY, suppress_logging=True)
    org_id, org_name = get_org(dashboard)
    if not org_id:
        return

    while True:
        mac = input("\nEnter the MAC address to search (format must be aa:bb:cc:11:22:33):").strip().lower()
        if not mac:
            print("❌ Invalid MAC address. Please enter a valid one.")
            continue
        
        net_id = find_mac_in_networks(dashboard, org_id, mac)
        if net_id:
            enrich_with_device_context(dashboard, mac, org_id, net_id)
        
        # **Ask if the user wants to search again**
        search_again = input("\n🔄 Would you like to search for another MAC address? (y/n): ").strip().lower()
        if search_again != 'y':
            print("👋 Exiting. Have a great day!")
            break

if __name__ == "__main__":
    main()
