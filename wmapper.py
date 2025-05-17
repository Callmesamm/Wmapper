import subprocess
import csv
import platform
import re

def scan_wifi():
    os_name = platform.system()
    print(f"Detected operating system: {os_name}")
    
    if os_name == "Windows":
        result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], capture_output=True, text=True)
        print("Raw netsh output:")
        print(result.stdout)
        return result.stdout, os_name, "netsh"
    elif os_name == "Linux":
        # First try nmcli
        try:
            result = subprocess.run(['nmcli', '--terse', '--fields', 'SSID,CHAN,SIGNAL,SECURITY', 'device', 'wifi'], capture_output=True, text=True)
            print("Raw nmcli output:")
            print(result.stdout)
            if result.stdout.strip():  # Check if there's meaningful output
                return result.stdout, os_name, "nmcli"
            else:
                print("nmcli returned no output, falling back to iwlist...")
        except FileNotFoundError:
            print("nmcli not found, falling back to iwlist...")
        
        # Fallback to iwlist
        try:
            # Find the wireless interface (e.g., wlan0)
            interfaces = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            interface = None
            for line in interfaces.stdout.splitlines():
                if "Interface" in line:
                    interface = line.split()[-1]
                    break
            if not interface:
                raise Exception("No wireless interface found. Ensure a Wi-Fi adapter is available.")
            
            result = subprocess.run(['iwlist', interface, 'scan'], capture_output=True, text=True)
            print("Raw iwlist output:")
            print(result.stdout)
            return result.stdout, os_name, "iwlist"
        except FileNotFoundError:
            raise Exception("iwlist not found. Please install wireless-tools (e.g., sudo apt install wireless-tools).")
        except Exception as e:
            raise Exception(f"Failed to scan Wi-Fi networks: {str(e)}")
    else:
        raise Exception(f"Unsupported operating system: {os_name}")

def parse_wifi_data(wifi_output, os_name, scan_method):
    networks = []
    
    if os_name == "Windows":
        current_network = {}
        for line in wifi_output.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                if current_network and "SSID" in current_network:
                    networks.append(current_network)
                current_network = {"SSID": line.split(":")[1].strip() if ":" in line else "Unknown"}
            elif line.startswith("Signal"):
                current_network["Signal"] = line.split(":")[1].strip() if ":" in line else "Unknown"
            elif line.startswith("Authentication"):
                current_network["Encryption"] = line.split(":")[1].strip() if ":" in line else "Unknown"
            elif line.startswith("Channel"):
                channel_value = line.split(":")[1].strip() if ":" in line else "Unknown"
                try:
                    int(channel_value)
                    current_network["Channel"] = channel_value
                except ValueError:
                    current_network["Channel"] = "Unknown"
        if current_network and "SSID" in current_network:
            current_network.setdefault("Signal", "Unknown")
            current_network.setdefault("Encryption", "Unknown")
            current_network.setdefault("Channel", "Unknown")
            networks.append(current_network)
    
    elif os_name == "Linux" and scan_method == "nmcli":
        for line in wifi_output.splitlines():
            if line.strip():
                parts = line.split(":")
                if len(parts) >= 4:
                    ssid = parts[0] if parts[0] else "Unknown"
                    channel = parts[1] if parts[1] else "Unknown"
                    signal = f"{parts[2]}%" if parts[2] else "Unknown"
                    encryption = parts[3] if parts[3] else "Unknown"
                    networks.append({
                        "SSID": ssid,
                        "Signal": signal,
                        "Encryption": encryption,
                        "Channel": channel
                    })
    
    elif os_name == "Linux" and scan_method == "iwlist":
        current_network = {}
        for line in wifi_output.splitlines():
            line = line.strip()
            if "ESSID:" in line:
                if current_network and "SSID" in current_network:
                    networks.append(current_network)
                current_network = {"SSID": line.split("ESSID:")[1].strip('"') if "ESSID:" in line else "Unknown"}
            elif "Channel:" in line:
                channel_value = line.split("Channel:")[1].strip()
                try:
                    int(channel_value)
                    current_network["Channel"] = channel_value
                except ValueError:
                    current_network["Channel"] = "Unknown"
            elif "Quality=" in line:
                # Quality=XX/70 or similar, extract signal level
                signal_match = re.search(r"Signal level=(-?\d+)", line)
                if signal_match:
                    current_network["Signal"] = f"{signal_match.group(1)} dBm"
                else:
                    current_network["Signal"] = "Unknown"
            elif "Encryption key:" in line:
                if "on" in line:
                    # Look for the encryption type in subsequent lines
                    enc_type = "Unknown"
                    for next_line in wifi_output.splitlines()[wifi_output.splitlines().index(line)+1:]:
                        next_line = next_line.strip()
                        if "Authentication Suites" in next_line or "WPA" in next_line or "WEP" in next_line:
                            enc_type = next_line.split(":")[-1].strip() if ":" in next_line else next_line
                            break
                    current_network["Encryption"] = enc_type
                else:
                    current_network["Encryption"] = "None"
        if current_network and "SSID" in current_network:
            current_network.setdefault("Signal", "Unknown")
            current_network.setdefault("Encryption", "Unknown")
            current_network.setdefault("Channel", "Unknown")
            networks.append(current_network)
    
    print("Parsed networks:", networks)
    return networks

#ali

def analyze_interference(networks):
    interference_report = []
    for i, net1 in enumerate(networks):
        for j, net2 in enumerate(networks):
            if i < j:
                try:
                    ch1 = int(net1.get("Channel", "1"))
                except (ValueError, TypeError):
                    ch1 = 1
                try:
                    ch2 = int(net2.get("Channel", "1"))
                except (ValueError, TypeError):
                    ch2 = 1
                if abs(ch1 - ch2) < 5 and ch1 <= 14 and ch2 <= 14:
                    interference_report.append(f"Interference detected between {net1['SSID']} (Channel {ch1}) and {net2['SSID']} (Channel {ch2})")
    return interference_report

def main():
    print("Scanning for Wi-Fi networks...")
    try:
        wifi_data, os_name, scan_method = scan_wifi()
    except Exception as e:
        print(f"Error: {e}")
        return
    
    if not wifi_data.strip():
        print("Error: No output from Wi-Fi scan. Ensure Wi-Fi is enabled and run as administrator.")
        return
    
    networks = parse_wifi_data(wifi_data, os_name, scan_method)
    
    if networks:
        for network in networks:
            print(f"SSID: {network['SSID']}, Signal: {network['Signal']}, Encryption: {network['Encryption']}, Channel: {network['Channel']}")
    else:
        print("No Wi-Fi networks found or unable to parse data.")
    
    if networks:
        print("\nChannel Usage Report")
        print("-------------------")
        channel_counts = {}
        for network in networks:
            channel = network["Channel"]
            channel_counts[channel] = channel_counts.get(channel, 0) + 1
        for channel, count in channel_counts.items():
            print(f"Channel {channel}: {count} network(s)")
        
        interference = analyze_interference(networks)
        if interference:
            print("\nInterference Report")
            print("------------------")
            for note in interference:
                print(note)
        else:
            print("\nNo significant interference detected.")
    
    with open("wifi_report.txt", "w") as file:
        file.write("Wi-Fi Network Report\n")
        file.write("--------------------\n")
        if networks:
            for network in networks:
                file.write(f"SSID: {network['SSID']}, Signal: {network['Signal']}, Encryption: {network['Encryption']}, Channel: {network['Channel']}\n")
        else:
            file.write("No Wi-Fi networks found or unable to parse data.\n")
        file.write("\nChannel Usage Report\n")
        file.write("-------------------\n")
        if networks:
            for channel, count in channel_counts.items():
                file.write(f"Channel {channel}: {count} network(s)\n")
        file.write("\nInterference Report\n")
        file.write("------------------\n")
        if interference:
            for note in interference:
                file.write(f"{note}\n")
        else:
            file.write("No significant interference detected.\n")
    
    if networks:
        with open("wifi_report.csv", "w", newline='') as csvfile:
            fieldnames = ["SSID", "Signal", "Encryption", "Channel"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for network in networks:
                writer.writerow(network)
        print("Report also saved to wifi_report.csv")
    else:
        print("No data to save to wifi_report.csv")



if __name__ == "__main__":
    main()