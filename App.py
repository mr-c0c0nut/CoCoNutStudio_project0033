import os
import sys
import time
import subprocess
import threading
import shutil
import re
import socket
from datetime import datetime

# =====================================================================
# AUTOMATIC DEPENDENCY MANAGEMENT
# =====================================================================
REQUIRED_PACKAGES = ["psutil", "colorama"]

def auto_install_packages():
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[*] Installing required Python packages: {', '.join(missing)}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print("[+] Dependencies installed successfully.\n")
        except Exception as e:
            print(f"[-] Failed to install dependencies automatically: {e}")
            print("Please run: pip install " + " ".join(missing))
            sys.exit(1)

auto_install_packages()

import psutil
from colorama import init, Fore, Style

init(autoreset=True)

# =====================================================================
# GLOBAL STATE & DATA STRUCTURES
# =====================================================================
class AppState:
    def __init__(self):
        self.mode = "PERSONAL"  # "PERSONAL" or "LAB_ADMIN"
        self.is_lab_authorized = False
        self.local_ip = "127.0.0.1"
        self.local_subnet = "127.0.0.1/32"
        self.net_interface_name = "Ethernet"
        self.tshark_path = None
        self.discovered_devices = {}  # IP -> {"mac": str, "hostname": str, "last_seen": str}
        self.network_activities = []  # List of ActivityRecord
        self.device_stats = {}        # IP -> Stats
        self.capture_thread = None
        self.stop_capture_event = threading.Event()
        self.remote_traffic_detected = False
        self.hide_unknown_domains = False
        self.selected_device_filter = None  # None for All, or specific IP

class ActivityRecord:
    def __init__(self, timestamp, src_ip, src_device, domain, dest_ip, protocol, confidence, bytes_len=0):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.src_device = src_device
        self.domain = domain
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.confidence = confidence  # "HIGH", "MEDIUM", "LOW"
        self.bytes_len = bytes_len

state = AppState()

# =====================================================================
# NETWORK UTILITIES & DISCOVERY
# =====================================================================
def get_local_net_info():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        state.local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        state.local_ip = "127.0.0.1"

    ip_parts = state.local_ip.split(".")
    if len(ip_parts) == 4:
        state.local_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    else:
        state.local_subnet = "127.0.0.1/32"

    # Identify primary network interface
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.address == state.local_ip:
                state.net_interface_name = iface
                break

    # Add local machine to discovered devices
    state.discovered_devices[state.local_ip] = {
        "mac": get_local_mac(),
        "hostname": socket.gethostname(),
        "last_seen": datetime.now().strftime("%H:%M:%S")
    }

def get_local_mac():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                return addr.address
    return "00:00:00:00:00:00"

def run_nmap_discovery():
    print(f"\n{Fore.CYAN}[*] Discovering LAN Subnet ({state.local_subnet}) via ARP / Nmap Ping...")
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        try:
            cmd = [nmap_bin, "-sn", state.local_subnet]
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=15)
            parse_nmap_output(out)
            print(f"{Fore.GREEN}[+] Nmap scan complete. Discovered {len(state.discovered_devices)} devices.")
            return
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Nmap scan failed or timed out ({e}). Falling back to ARP cache.")
    else:
        print(f"{Fore.YELLOW}[!] Nmap executable not found in PATH. Reading system ARP cache...")

    read_system_arp_table()

def parse_nmap_output(output):
    current_ip = None
    current_host = "Unknown"
    for line in output.splitlines():
        line = line.strip()
        if "Nmap scan report for" in line:
            parts = line.split()
            if len(parts) == 5:
                current_host = parts[4].strip("()")
                current_ip = parts[4].strip("()")
            elif len(parts) >= 6:
                current_host = parts[4]
                current_ip = parts[5].strip("()")
        elif "MAC Address:" in line and current_ip:
            mac_part = line.split("MAC Address:")[1].split()[0]
            state.discovered_devices[current_ip] = {
                "mac": mac_part,
                "hostname": current_host,
                "last_seen": datetime.now().strftime("%H:%M:%S")
            }
            current_ip = None

def read_system_arp_table():
    try:
        out = subprocess.check_output(["arp", "-a"], text=True)
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fa-f\-]{17})\s+(\w+)", line)
            if m:
                ip, mac, arp_type = m.group(1), m.group(2).replace("-", ":"), m.group(3)
                if ip != state.local_ip and not ip.startswith("224.") and not ip.endswith(".255"):
                    try:
                        host = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        host = f"PC-{ip.split('.')[-1]}"
                    state.discovered_devices[ip] = {
                        "mac": mac,
                        "hostname": host,
                        "last_seen": datetime.now().strftime("%H:%M:%S")
                    }
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to read ARP table: {e}")

def resolve_device_name(ip):
    if ip == state.local_ip:
        return f"{socket.gethostname()} (Local)"
    if ip in state.discovered_devices:
        return state.discovered_devices[ip]["hostname"]
    return "Unknown Device"

# =====================================================================
# TSHARK ENVIRONMENT CHECK & INSTALLATION
# =====================================================================
def check_and_setup_tshark():
    tshark = shutil.which("tshark")
    if not tshark:
        standard_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
        ]
        for p in standard_paths:
            if os.path.exists(p):
                tshark = p
                break

    if tshark:
        state.tshark_path = tshark
        return True

    print(f"\n{Fore.RED}============================================================")
    print(f"{Fore.RED}               TSHARK DEPENDENCY MISSING")
    print(f"{Fore.RED}============================================================")
    print("TShark (Wireshark packet analysis CLI) is required for Network Activity monitoring.")
    print("Official Download Page: https://www.wireshark.org/download.html\n")
    
    ans = input("Would you like to open the official Wireshark download page now? (Y/N): ").strip().upper()
    if ans == "Y":
        import webbrowser
        webbrowser.open("https://www.wireshark.org/download.html")
        print("\nPlease install Wireshark / TShark and restart App.py.")
    
    return False

def verify_tshark_version():
    if not state.tshark_path:
        return False
    try:
        res = subprocess.run([state.tshark_path, "--version"], capture_output=True, text=True, check=True)
        first_line = res.stdout.splitlines()[0] if res.stdout else "TShark active"
        print(f"{Fore.GREEN}[+] Verified: {first_line}")
        return True
    except Exception as e:
        print(f"{Fore.RED}[-] TShark verification failed: {e}")
        return False

# =====================================================================
# LIVE CAPTURE & METADATA PARSING ENGINE
# =====================================================================
def start_tshark_capture():
    if not state.tshark_path or state.capture_thread is not None:
        return

    state.stop_capture_event.clear()
    state.capture_thread = threading.Thread(target=_tshark_capture_worker, daemon=True)
    state.capture_thread.start()

def stop_tshark_capture():
    if state.capture_thread:
        state.stop_capture_event.set()
        state.capture_thread = None

def _tshark_capture_worker():
    # TShark display filter to capture DNS query names and TLS Client Hello SNI
    # Fields: frame.time_clock, ip.src, ip.dst, dns.qry.name, tls.handshake.extensions_server_name, frame.len, _ws.col.Protocol
    cmd = [
        state.tshark_path,
        "-i", state.net_interface_name,
        "-l",
        "-n",
        "-Y", "dns.flags.response == 0 or tls.handshake.type == 1",
        "-T", "fields",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "dns.qry.name",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol"
    ]

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Failed to launch TShark process: {e}")
        return

    while not state.stop_capture_event.is_set():
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                break
            continue

        parts = line.strip().split("\t")
        if len(parts) < 7:
            continue

        raw_time, src_ip, dst_ip, dns_name, tls_sni, length_str, proto = parts[:7]

        if not src_ip or src_ip == state.local_ip and state.mode == "PERSONAL":
            pass # Handle personal mode routing
        elif src_ip != state.local_ip:
            state.remote_traffic_detected = True

        # Mode enforcement: Skip remote devices if in PERSONAL mode
        if state.mode == "PERSONAL" and src_ip != state.local_ip:
            continue

        domain = "Unknown"
        confidence = "LOW"

        if dns_name:
            domain = sanitize_domain(dns_name)
            confidence = "HIGH"
        elif tls_sni:
            domain = sanitize_domain(tls_sni)
            confidence = "HIGH"
        elif dst_ip:
            domain = "Unknown"
            confidence = "LOW"

        # Filter out local broadcast or invalid entries
        if not src_ip or dst_ip.startswith("255.255.255") or dst_ip.startswith("224."):
            continue

        try:
            pkt_bytes = int(length_str) if length_str.isdigit() else 64
        except ValueError:
            pkt_bytes = 64

        t_stamp = datetime.now().strftime("%H:%M:%S")
        device_name = resolve_device_name(src_ip)

        rec = ActivityRecord(
            timestamp=t_stamp,
            src_ip=src_ip,
            src_device=device_name,
            domain=domain,
            dest_ip=dst_ip,
            protocol=proto if proto else "TCP/UDP",
            confidence=confidence,
            bytes_len=pkt_bytes
        )

        state.network_activities.append(rec)
        if len(state.network_activities) > 500:
            state.network_activities.pop(0)

        # Update Device Statistics
        if src_ip not in state.device_stats:
            state.device_stats[src_ip] = {
                "domains": set(),
                "connections": 0,
                "bytes": 0,
                "first_seen": t_stamp,
                "last_seen": t_stamp
            }
        st = state.device_stats[src_ip]
        st["connections"] += 1
        st["bytes"] += pkt_bytes
        st["last_seen"] = t_stamp
        if domain != "Unknown":
            st["domains"].add(domain)

    process.terminate()

def sanitize_domain(domain_raw):
    # Sanitize domain string to extract apex/registered domain, removing subpaths or query params
    clean = domain_raw.split(",")[0].strip().lower()
    clean = re.sub(r"^[^\w\.-]+", "", clean)
    parts = clean.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean

# =====================================================================
# UI RENDERING MODULES
# =====================================================================
def print_header():
    os.system("cls" if os.name == "nt" else "clear")
    print(f"{Fore.CYAN}===============================================================")
    print(f"{Fore.CYAN}        LAN MONITOR & COMPUTER LAB ADMIN TOOL")
    print(f"{Fore.CYAN}===============================================================")
    print(f" Connection: {Fore.YELLOW}{state.net_interface_name}")
    
    if state.mode == "LAB_ADMIN":
        print(f" Mode: {Fore.GREEN}LAB / ADMIN MODE {Style.DIM}(Authorized Administration)")
    else:
        print(f" Mode: {Fore.BLUE}PERSONAL / LOCAL DEVICE MODE")

    print(f" Local IP: {Fore.WHITE}{state.local_ip}")
    print(f" Subnet: {Fore.WHITE}{state.local_subnet}")
    print(f"{Fore.CYAN}---------------------------------------------------------------\n")

def show_privacy_notice():
    print(f"{Fore.YELLOW}[PRIVACY & AUDIT NOTICE]")
    print(" - Network metadata only (DNS queries, TLS SNI headers).")
    print(" - HTTPS contents are NOT inspected or decrypted.")
    print(" - No passwords, cookies, auth tokens, or private payloads are collected.")
    print(" - Operating strictly within administrative metadata analysis bounds.\n")

def render_main_menu():
    print_header()
    print(" MAIN MENU:\n")
    print(" [1] Scan LAN Subnet")
    print(" [2] View Discovered Devices")
    print(" [3] Website / Network Activity")
    print(" [4] Traffic Statistics")
    print(" [5] View Device Details")
    print(" [6] Local Computer Info")
    print(" [7] Refresh Network Detection")
    print(" [0] Exit\n")

def mode_switch_prompt():
    print_header()
    print(f"{Fore.YELLOW}LAB / ADMIN MODE PERMISSION CHECK")
    print("---------------------------------------------------------------")
    print("Authorized Lab Mode allows inspecting network metadata from remote PCs")
    print("connected to the physical network TAP/SPAN port or router mirror.\n")
    ans = input("Is this a computer lab network that you are authorized to manage? (Y/N): ").strip().upper()
    
    if ans == "Y":
        state.mode = "LAB_ADMIN"
        state.is_lab_authorized = True
        print(f"\n{Fore.GREEN}[+] Switched to Authorized Lab Administration Mode.")
    else:
        state.mode = "PERSONAL"
        state.is_lab_authorized = False
        print(f"\n{Fore.BLUE}[*] Remaining in Personal / Local Device Mode.")
    time.sleep(1.5)

# =====================================================================
# FEATURE MODULES
# =====================================================================
def feature_website_activity():
    if not check_and_setup_tshark():
        input("\nPress Enter to return to main menu...")
        return

    start_tshark_capture()
    
    print_header()
    show_privacy_notice()
    
    if state.mode == "PERSONAL":
        print(f"{Fore.BLUE}[PERSONAL MODE ACTIVE] Monitoring activity for LOCAL DEVICE ONLY.\n")

    print(f"{Fore.GREEN}Monitoring network metadata... (Press CTRL+C or 'Q' to control)")
    print("-----------------------------------------------------------------------------------------------")
    print(f"{'TIME':<10} {'DEVICE':<18} {'SRC IP':<16} {'DOMAIN':<22} {'DEST IP':<16} {'PROTO':<8} {'CONFIDENCE'}")
    print("-----------------------------------------------------------------------------------------------")

    try:
        last_check_time = time.time()
        while True:
            # Check for remote traffic warning in Lab Mode after 5 seconds of capturing
            if state.mode == "LAB_ADMIN" and not state.remote_traffic_detected and (time.time() - last_check_time > 5):
                render_visibility_warning()
                last_check_time = time.time() + 9999  # Render once

            # Print recent activities
            display_list = list(state.network_activities)
            if state.hide_unknown_domains:
                display_list = [r for r in display_list if r.domain != "Unknown"]
            if state.selected_device_filter:
                display_list = [r for r in display_list if r.src_ip == state.selected_device_filter]

            os.system("cls" if os.name == "nt" else "clear")
            print_header()
            print(f" [A] All Devices | [D] Filter Device | [H] Toggle Hide Unknown ({state.hide_unknown_domains}) | [Q] Return\n")
            print(f"{'TIME':<10} {'DEVICE':<18} {'SRC IP':<16} {'DOMAIN':<22} {'DEST IP':<16} {'PROTO':<8} {'CONFIDENCE'}")
            print("-----------------------------------------------------------------------------------------------")

            if not display_list:
                if state.mode == "LAB_ADMIN" and not state.remote_traffic_detected:
                    print(f"{Fore.YELLOW} No traffic from remote devices detected.")
                    print(" Ensure SPAN/Port Mirroring is configured on the switch.")
                else:
                    print(" Listening for active network metadata...")
            else:
                for rec in display_list[-15:]:
                    conf_color = Fore.GREEN if rec.confidence == "HIGH" else (Fore.YELLOW if rec.confidence == "MEDIUM" else Fore.RED)
                    print(f" {rec.timestamp:<9} {rec.src_device[:17]:<18} {rec.src_ip:<16} {rec.domain[:21]:<22} {rec.dest_ip:<16} {rec.protocol:<8} {conf_color}{rec.confidence}")

            time.sleep(1.5)

    except KeyboardInterrupt:
        pass

def render_visibility_warning():
    print(f"\n{Fore.RED}============================================================")
    print(f"{Fore.RED}               TRAFFIC VISIBILITY WARNING")
    print(f"{Fore.RED}============================================================")
    print("App is running in LAB MODE on PC Admin, but NO packets")
    print("from other LAN devices have been observed.\n")
    print("Possible Causes:")
    print(" - Switch is unmanaged (does not forward unicast frames to Admin port).")
    print(" - SPAN / Port Mirroring is NOT enabled on the network switch.")
    print(" - Wi-Fi AP Isolation is enabled on the wireless access point.")
    print(" - PC Admin is on a separate VLAN / Subnet from client PCs.\n")
    print("Action Plan for Administrator:")
    print(" 1. Enable SPAN / Port Mirroring on switch pointing to Admin port.")
    print(" 2. Use a dedicated Network TAP hardware between Router & Switch.")
    print(" 3. Export NetFlow / IPFIX telemetry directly from Gateway Router.")
    print("============================================================\n")

def feature_traffic_statistics():
    print_header()
    print("============================================================")
    print("                   TRAFFIC STATISTICS")
    print("============================================================")

    if not state.device_stats:
        print("\n No traffic statistics captured yet.")
        input("\nPress Enter to return...")
        return

    for ip, st in state.device_stats.items():
        dev_name = resolve_device_name(ip)
        mb_str = f"{st['bytes'] / (1024*1024):.2f} MB"
        print(f"\n Device: {Fore.GREEN}{dev_name}{Style.RESET_ALL} ({ip})")
        print(f"   Connections : {st['connections']}")
        print(f"   Data Volume : {mb_str}")
        print(f"   First Seen  : {st['first_seen']}")
        print(f"   Last Seen   : {st['last_seen']}")
        print("   Domains Contacted:")
        if st["domains"]:
            for d in list(st["domains"])[:10]:
                print(f"     -> {d}")
        else:
            print("     -> None (IP only metadata)")

    input("\nPress Enter to return...")

def feature_device_details():
    print_header()
    print("DISCOVERED LAN DEVICES:")
    if not state.discovered_devices:
        print(" No devices discovered yet. Please run Scan LAN Subnet first.")
    else:
        for ip, info in state.discovered_devices.items():
            print(f" - {info['hostname']:<20} | IP: {ip:<15} | MAC: {info['mac']}")
    input("\nPress Enter to return...")

def feature_local_info():
    print_header()
    print("LOCAL COMPUTER INFO:")
    print(f" Hostname     : {socket.gethostname()}")
    print(f" Primary IP   : {state.local_ip}")
    print(f" MAC Address  : {get_local_mac()}")
    print(f" OS           : {os.name.upper()} ({sys.platform})")
    print(f" TShark Path  : {state.tshark_path if state.tshark_path else 'Not Installed'}")
    input("\nPress Enter to return...")

# =====================================================================
# MAIN ENTRY POINT & LOOP
# =====================================================================
def main():
    get_local_net_info()
    mode_switch_prompt()

    while True:
        try:
            render_main_menu()
            choice = input("Select option [0-7]: ").strip()

            if choice == "1":
                run_nmap_discovery()
                input("\nPress Enter to return...")
            elif choice == "2":
                feature_device_details()
            elif choice == "3":
                feature_website_activity()
            elif choice == "4":
                feature_traffic_statistics()
            elif choice == "5":
                feature_device_details()
            elif choice == "6":
                feature_local_info()
            elif choice == "7":
                get_local_net_info()
                print(f"{Fore.GREEN}[+] Network interface refreshed.")
                time.sleep(1)
            elif choice == "0":
                stop_tshark_capture()
                print(f"\n{Fore.CYAN}[*] Exiting LAN Monitor Tool. Goodbye!")
                sys.exit(0)
            else:
                print(f"{Fore.RED}[!] Invalid selection. Try again.")
                time.sleep(1)

        except Exception as e:
            print(f"\n{Fore.RED}[-] Unexpected Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()
