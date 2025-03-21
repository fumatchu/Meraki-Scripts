import csv
import requests
import json

# Constants for API access
API_KEY = 'YOUR_API_KEY_HERE'  # Replace with your actual API key
BASE_URL = 'https://api.meraki.com/api/v1'
HEADERS = {
    'X-Cisco-Meraki-API-Key': API_KEY,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

def get_organizations():
    """Fetch all organizations."""
    url = f"{BASE_URL}/organizations"
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def get_networks(organization_id):
    """Fetch networks for a given organization."""
    url = f"{BASE_URL}/organizations/{organization_id}/networks"
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def get_switch_routing_interfaces(serial):
    """Fetch routing interfaces for a given MS switch."""
    url = f"{BASE_URL}/devices/{serial}/switch/routing/interfaces"
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def update_dhcp_settings(serial, interface_Id, dhcp_settings):
    """Update DHCP settings for a given interface of an MS switch."""
    url = f"{BASE_URL}/devices/{serial}/switch/routing/interfaces/{interface_Id}/dhcp"
    response = requests.put(url, headers=HEADERS, json=dhcp_settings)
    response.raise_for_status()
    return response.json()

def parse_reserved_ip_ranges(reserved_ip_ranges_str):
    """Parse reserved IP ranges with comments from CSV format."""
    reserved_ip_ranges = []
    if reserved_ip_ranges_str:
        for range_comment in reserved_ip_ranges_str.split(","):
            try:
                start_end, comment = range_comment.split(":")
                start, end = start_end.split("-")
                reserved_ip_ranges.append({
                    "start": start.strip(),
                    "end": end.strip(),
                    "comment": comment.strip()
                })
                print(f"Reserved IP Range: {start.strip()} to {end.strip()}, Comment: {comment.strip()}")
            except ValueError:
                print(f"Error parsing reserved IP range: {range_comment}")
    return reserved_ip_ranges

def parse_client_reservations(client_reservations):
    """Parse client reservations from CSV format."""
    reservations = []
    if client_reservations:
        for reservation in client_reservations.split(","):
            try:
                name_mac_ip = reservation.split("-")
                if len(name_mac_ip) == 3:
                    name, mac, ip = name_mac_ip
                    reservations.append({"name": name.strip(), "mac": mac.strip(), "ip": ip.strip()})
                else:
                    print(f"Error parsing client reservation: {reservation}")
            except ValueError:
                print(f"Error parsing client reservation: {reservation}")
    return reservations

def main():
    # Fetch and select an organization once
    organizations = get_organizations()
    print("Select an Organization:")
    for index, org in enumerate(organizations, start=1):
        print(f"{index}: {org['name']}")
    org_choice = int(input("Enter number: ")) - 1
    organization_id = organizations[org_choice]['id']

    # Fetch and select a network once
    networks = get_networks(organization_id)
    print("Select a Network:")
    for index, net in enumerate(networks, start=1):
        print(f"{index}: {net['name']}")
    net_choice = int(input("Enter number: ")) - 1
    network_id = networks[net_choice]['id']

    # Read DHCP options and serial numbers from CSV
    csv_file_path = 'YOUR_LOCAL_DIRECTORY_HERE'  # Replace with your actual CSV file path
    with open(csv_file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            # Check if the row is empty and continue to the next row
            if not row:
                print("No more lines to process.")
                break

            serial_number = row['serial_number']
            target_subnet = row['subnet']
            reserved_ip_ranges = parse_reserved_ip_ranges(row.get('reservedIpRanges', ''))
            fixed_ip_assignments = parse_client_reservations(row.get('clientReservations', ''))

            # Construct the scope_data dictionary conditionally
            scope_data = {}

            if row.get('dhcpMode'):
                scope_data["dhcpMode"] = row['dhcpMode']
            if row.get('dnsNameserversOption'):
                scope_data["dnsNameserversOption"] = row['dnsNameserversOption']
            if row.get('dhcpRelayServerIps'):
                # Convert to a list of IPs
                scope_data["dhcpRelayServerIps"] = row['dhcpRelayServerIps'].split(",")
            if row.get('dnsServers'):
                scope_data["dnsCustomNameservers"] = row['dnsServers'].split(",")
            if reserved_ip_ranges:
                scope_data["reservedIpRanges"] = reserved_ip_ranges
            if fixed_ip_assignments:
                scope_data["fixedIpAssignments"] = fixed_ip_assignments

            # Construct the dhcpOptions if all related fields are present
            dhcp_options = []
            dhcpoption_number = row.get('dhcpoption_number')
            dhcpoption_type = row.get('dhcpoption_type')
            dhcpoption_value = row.get('dhcpoption_value')

            if dhcpoption_number and dhcpoption_type and dhcpoption_value:
                dhcp_options.append({
                    "code": dhcpoption_number,
                    "type": dhcpoption_type,
                    "value": dhcpoption_value
                })

            if dhcp_options:
                scope_data["dhcpOptions"] = dhcp_options

            # Print the scope_data in JSON format
            print("JSON Payload for Update:")
            print(json.dumps(scope_data, indent=2))

            interfaces = get_switch_routing_interfaces(serial_number)
            for interface in interfaces:
                if interface['subnet'] == target_subnet:
                    interface_Id = interface['interfaceId']
                    print(f"Updating DHCP settings for serial: {serial_number}, interface: {interface_Id}")
                    update_dhcp_settings(serial_number, interface_Id, scope_data)
                    break

if __name__ == "__main__":
    main()
