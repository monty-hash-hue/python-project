import subprocess
import json
from datetime import datetime

# scan wifi 
def scan_wifi():
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks"],
        capture_output=True, text=True, errors="ignore"
    )

    networks = {}
    ssid = None

    for line in result.stdout.splitlines():
        line = line.strip()

        if line.startswith("SSID"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                ssid = parts[1].strip()
                if ssid:
                    networks[ssid] = {}

        elif ssid and ":" in line:
            key, value = line.split(":", 1)

            if key in ["Network type", "Authentication",
                       "Encryption", "Signal", "Channel"]:
                networks[ssid][key] = value.strip()

    return networks

# analyze security
def analyze(details):
    auth = details.get("Authentication", "").lower()

    if auth == "open":
        return "WARNING - Open Network"
    if "wpa3" in auth:
        return "Excellent - WPA3"
    if "wpa2" in auth:
        return "Good - WPA2"
    if "wpa" in auth:
        return "Moderate - WPA"
    if "wep" in auth:
        return "WARNING - WEP"

    return "Unknown"

# show network (Display )
def show_wifi(networks):
    print("\n========== WIFI NETWORKS ==========")

    if not networks:
        print("No networks found.")
        return

    for i, (ssid, data) in enumerate(networks.items(), 1):
        print(f"\n[{i}] {ssid}")
        print("Authentication:", data.get("Authentication", "N/A"))
        print("Encryption    :", data.get("Encryption", "N/A"))
        print("Signal        :", data.get("Signal", "N/A"))
        print("Channel       :", data.get("Channel", "N/A"))
        print("Security      :", analyze(data))

# network incormation 
def network_info():
    result = subprocess.run(
        ["ipconfig"],
        capture_output=True, text=True, errors="ignore"
    )

    info = {}

    for line in result.stdout.splitlines():
        line = line.strip()

        if line.startswith("IPv4 Address"):
            info["IPv4"] = line.split(":", 1)[1].strip()

        elif line.startswith("Subnet Mask"):
            info["Subnet Mask"] = line.split(":", 1)[1].strip()

        elif line.startswith("Default Gateway"):
            gateway = line.split(":", 1)[1].strip()
            if gateway:
                info["Gateway"] = gateway

    return info


def save_report(networks, info):
    report = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "wifi_networks": networks,
        "current_network": info
    }

    with open("wifi_report.json", "w") as file:
        json.dump(report, file, indent=4)

    print("\nReport saved: wifi_report.json")


def main():
    print("\n==============================")
    print("      WIFI SECURITY ANALYZER")
    print("==============================")

    networks = scan_wifi()

    while True:
        print("\n1. Show WiFi Networks")
        print("2. Current Network Info")
        print("3. Save JSON Report")
        print("4. Refresh Scan")
        print("5. Exit")

        choice = input("\nEnter choice: ")

        if choice == "1":
            show_wifi(networks)

        elif choice == "2":
            info = network_info()
            print("\n====== CURRENT NETWORK ======")

            if info:
                for key, value in info.items():
                    print(f"{key}: {value}")
            else:
                print("Information unavailable.")

        elif choice == "3":
            save_report(networks, network_info())

        elif choice == "4":
            print("\nScanning...")
            networks = scan_wifi()
            print(f"{len(networks)} network(s) found.")

        elif choice == "5":
            print("\nThank you!")
            break

        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
