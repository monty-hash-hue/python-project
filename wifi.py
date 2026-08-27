import subprocess
import json
import csv
from datetime import datetime


# STEP 1 — RUN SYSTEM COMMAND

def run_command(command):
    """
    Run a Windows command and return its output.
    """

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if result.returncode != 0:
            return ""

        return result.stdout

    except Exception as e:
        print(f"Command Error: {e}")
        return ""


# STEP 2 — SCAN AVAILABLE WIFI NETWORKS

def scan_wifi_networks():

    output = run_command(
        ["netsh", "wlan", "show", "networks"]
    )

    wifi_networks = {}

    if not output:
        return wifi_networks

    ssid = None

    for line in output.splitlines():

        line = line.strip()

        # SSID
        if line.startswith("SSID"):

            parts = line.split(":", 1)

            if len(parts) == 2:

                ssid = parts[1].strip()

                if ssid:
                    wifi_networks[ssid] = {}

        # Network Type
        elif line.startswith("Network type") and ssid:

            wifi_networks[ssid]["Network Type"] = (
                line.split(":", 1)[1].strip()
            )

        # Authentication
        elif line.startswith("Authentication") and ssid:

            wifi_networks[ssid]["Authentication"] = (
                line.split(":", 1)[1].strip()
            )

        # Encryption
        elif line.startswith("Encryption") and ssid:

            wifi_networks[ssid]["Encryption"] = (
                line.split(":", 1)[1].strip()
            )

        # Signal
        elif line.startswith("Signal") and ssid:

            wifi_networks[ssid]["Signal"] = (
                line.split(":", 1)[1].strip()
            )

        # Channel
        elif line.startswith("Channel") and ssid:

            wifi_networks[ssid]["Channel"] = (
                line.split(":", 1)[1].strip()
            )

    return wifi_networks


# ============================================================
# STEP 3 — GET CURRENT NETWORK INFORMATION
# ============================================================

def get_network_info():

    output = run_command(["ipconfig"])

    network_info = {}

    if not output:
        return network_info

    gateway_found = False

    for line in output.splitlines():

        line = line.strip()

        # IPv4
        if line.startswith("IPv4 Address"):

            network_info["IPv4"] = (
                line.split(":", 1)[1].strip()
            )

        # Subnet Mask
        elif line.startswith("Subnet Mask"):

            network_info["Subnet Mask"] = (
                line.split(":", 1)[1].strip()
            )

        # Default Gateway
        elif line.startswith("Default Gateway"):

            gateway = line.split(":", 1)[1].strip()

            # IPv4 gateway
            if "." in gateway:

                network_info["Gateway"] = gateway
                gateway_found = False

            else:

                # Gateway may be on next line
                gateway_found = True

        # Gateway continuation line
        elif gateway_found and "." in line:

            network_info["Gateway"] = line
            gateway_found = False

    return network_info


# STEP 4 — SECURITY ANALYZER

def analyze_network(details):

    authentication = details.get(
        "Authentication", ""
    ).lower()

    encryption = details.get(
        "Encryption", ""
    ).lower()

    # Open network
    if authentication == "open":

        return {
            "Status": "WARNING",
            "Message": "Open Network - No Authentication"
        }

    # WPA3
    elif "wpa3" in authentication:

        return {
            "Status": "Excellent",
            "Message": "WPA3 Protected Network"
        }

    # WPA2
    elif "wpa2" in authentication:

        if encryption:

            return {
                "Status": "Good",
                "Message": f"WPA2 with {encryption.upper()}"
            }

        return {
            "Status": "Good",
            "Message": "WPA2 Protected Network"
        }

    # WPA
    elif "wpa" in authentication:

        return {
            "Status": "Moderate",
            "Message": "WPA Protected Network"
        }

    # WEP
    elif "wep" in authentication:

        return {
            "Status": "WARNING",
            "Message": "WEP is an outdated security method"
        }

    else:

        return {
            "Status": "Unknown",
            "Message": "Security information unavailable"
        }


# STEP 5 — DISPLAY ALL WIFI NETWORKS

def display_wifi_networks(wifi_networks):

    print("\n========================================")
    print("        AVAILABLE WIFI NETWORKS")
    print("========================================")

    if not wifi_networks:

        print("\nNo WiFi networks found.")
        return

    for number, (ssid, details) in enumerate(
        wifi_networks.items(),
        start=1
    ):

        print(f"\n[{number}] {ssid}")

        for key, value in details.items():

            print(
                f"    {key:<18}: {value}"
            )

        security = analyze_network(details)

        print(
            f"    {'Security Status':<18}: "
            f"{security['Status']}"
        )

        print(
            f"    {'Security Info':<18}: "
            f"{security['Message']}"
        )


# STEP 6 — DISPLAY CURRENT NETWORK

def display_network_info(network_info):

    print("\n========================================")
    print("        CURRENT NETWORK INFO")
    print("========================================")

    if not network_info:

        print("\nNetwork information unavailable.")
        return

    for key, value in network_info.items():

        print(
            f"{key:<18}: {value}"
        )


# STEP 7 — SELECT WIFI NETWORK

def select_network(wifi_networks):

    if not wifi_networks:

        print("\nNo networks available.")
        return None

    network_list = list(
        wifi_networks.keys()
    )

    print("\n========================================")
    print("        SELECT WIFI NETWORK")
    print("========================================")

    for number, ssid in enumerate(
        network_list,
        start=1
    ):

        print(
            f"[{number}] {ssid}"
        )

    try:

        choice = int(
            input("\nEnter network number: ")
        )

        if choice < 1 or choice > len(network_list):

            print("\nInvalid network number.")
            return None

        selected_ssid = network_list[
            choice - 1
        ]

        selected_details = (
            wifi_networks[selected_ssid]
        )

        print("\n========================================")
        print("        SELECTED NETWORK")
        print("========================================")

        print(
            f"SSID               : {selected_ssid}"
        )

        for key, value in selected_details.items():

            print(
                f"{key:<18}: {value}"
            )

        security = analyze_network(
            selected_details
        )

        print(
            f"{'Security Status':<18}: "
            f"{security['Status']}"
        )

        print(
            f"{'Security Info':<18}: "
            f"{security['Message']}"
        )

        return selected_ssid

    except ValueError:

        print("\nPlease enter a valid number.")
        return None


# STEP 8 — CREATE JSON REPORT

def export_json(wifi_networks, network_info):

    report = {

        "scan_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "wifi_networks": wifi_networks,

        "current_network": network_info
    }

    try:

        with open(
            "wifi_report.json",
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )

        print(
            "\nJSON report created successfully:"
        )

        print("wifi_report.json")

    except Exception as e:

        print(
            f"\nJSON export error: {e}"
        )


# STEP 9 — CREATE CSV REPORT

def export_csv(wifi_networks):

    try:

        with open(
            "wifi_report.csv",
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "SSID",
                "Network Type",
                "Authentication",
                "Encryption",
                "Signal",
                "Channel",
                "Security Status"
            ])

            for ssid, details in (
                wifi_networks.items()
            ):

                security = analyze_network(
                    details
                )

                writer.writerow([

                    ssid,

                    details.get(
                        "Network Type",
                        "N/A"
                    ),

                    details.get(
                        "Authentication",
                        "N/A"
                    ),

                    details.get(
                        "Encryption",
                        "N/A"
                    ),

                    details.get(
                        "Signal",
                        "N/A"
                    ),

                    details.get(
                        "Channel",
                        "N/A"
                    ),

                    security["Status"]
                ])

        print(
            "\nCSV report created successfully:"
        )

        print("wifi_report.csv")

    except Exception as e:

        print(
            f"\nCSV export error: {e}"
        )


# STEP 10 — BASIC NETWORK DIAGNOSTICS

def ping_gateway(network_info):

    gateway = network_info.get(
        "Gateway"
    )

    if not gateway:

        print(
            "\nGateway address not available."
        )

        return

    print(
        f"\nTesting gateway: {gateway}"
    )

    result = subprocess.run(

        [
            "ping",
            "-n",
            "4",
            gateway
        ],

        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    print("\nPing Result:")
    print(result.stdout)


# STEP 11 — REFRESH SCAN

def refresh_scan():

    print(
        "\nScanning WiFi networks..."
    )

    wifi_networks = scan_wifi_networks()

    if wifi_networks:

        print(
            f"\n{len(wifi_networks)} "
            "network(s) found."
        )

    else:

        print(
            "\nNo networks found."
        )

    return wifi_networks


# STEP 12 — MENU

def show_menu():

    print("\n")
    print("========================================")
    print("        WIFI MANAGEMENT SYSTEM")
    print("========================================")

    print("1. Scan WiFi Networks")
    print("2. Show Current Network Information")
    print("3. Select & Analyze Network")
    print("4. Export JSON Report")
    print("5. Export CSV Report")
    print("6. Ping Gateway")
    print("7. Refresh WiFi Scan")
    print("8. Exit")

    print("========================================")


# ============================================================
# STEP 13 — MAIN PROGRAM
# ============================================================

def main():

    print("========================================")
    print("      WIFI MANAGEMENT & ANALYZER")
    print("========================================")

    print(
        "\nInitializing WiFi Scanner..."
    )

    wifi_networks = scan_wifi_networks()

    network_info = get_network_info()

    while True:

        show_menu()

        choice = input(
            "\nEnter your choice: "
        ).strip()

        # --------------------------------
        # Option 1
        # --------------------------------

        if choice == "1":

            display_wifi_networks(
                wifi_networks
            )

        # Option 2
   

        elif choice == "2":

            display_network_info(
                network_info
            )

        
        # Option 3
        

        elif choice == "3":

            select_network(
                wifi_networks
            )

        
        # Option 4

        elif choice == "4":

            export_json(
                wifi_networks,
                network_info
            )

        # Option 5

        elif choice == "5":

            export_csv(
                wifi_networks
            )

        # Option 6


        elif choice == "6":

            ping_gateway(
                network_info
            )

        # Option 7

        elif choice == "7":

            wifi_networks = refresh_scan()

        # Option 8

        elif choice == "8":

            print(
                "\nThank you for using "
                "WiFi Management System."
            )

            break

        # Invalid Choice

        else:

            print(
                "\nInvalid choice. "
                "Please select 1-8."
            )

# PROGRAM START


if __name__ == "__main__":

    main()