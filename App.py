# App.py - LAN Monitor & Computer Lab Admin Tool (Windows)
# Complete single-file application. No external requirements.txt needed.

import os
import sys
import time
import socket
import re
import subprocess
import platform
import threading
import shutil
import urllib.request
import tempfile
from pathlib import Path
import re
import socket
from datetime import datetime

# ==============================================================================
# 1. AUTO-SETUP & DEPENDENCY MANAGER
# ==============================================================================
# =====================================================================
# AUTOMATIC DEPENDENCY MANAGEMENT
# =====================================================================
REQUIRED_PACKAGES = ["psutil", "colorama"]

def check_and_install_python_packages():
    """Tự động kiểm tra và cài đặt các package Python thiếu."""
    required = ["psutil"]
def auto_install_packages():
missing = []
    
    for pkg in required:
    for pkg in REQUIRED_PACKAGES:
try:
__import__(pkg)
except ImportError:
missing.append(pkg)
            
if missing:
        print(f"[!] Phát hiện thiếu Python package: {', '.join(missing)}")
        print("[*] Đang tiến hành tự động cài đặt qua pip...")
        for pkg in missing:
            try:
                cmd = [sys.executable, "-m", "pip", "install", pkg]
                subprocess.check_call(cmd)
                print(f"[+] Cài đặt thành công package: {pkg}")
            except Exception as e:
                print(f"[-] Lỗi khi cài đặt {pkg}: {e}")
                print("[!] Vui lòng chạy lệnh CMD dưới quyền Admin: python -m pip install " + pkg)
                sys.exit(1)

# Kiểm tra package ngay khi khởi chạy
check_and_install_python_packages()
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

class SystemPaths:
    """Tự động tìm kiếm đường dẫn phần mềm trên Windows."""
    
    @staticmethod
    def find_executable(exe_name, common_locations):
        # 1. Kiểm tra PATH hệ thống
        found = shutil.which(exe_name)
        if found:
            return found
        
        # 2. Kiểm tra các thư mục cài đặt mặc định trên Windows
        for loc in common_locations:
            p = Path(loc)
            if p.is_file():
                return str(p)
        return None

    @classmethod
    def get_nmap_path(cls):
        locations = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe")
        ]
        return cls.find_executable("nmap.exe", locations)

    @classmethod
    def get_tshark_path(cls):
        locations = [
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
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe")
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
]
        return cls.find_executable("tshark.exe", locations)


class OfficialInstaller:
    """Quản lý việc tải và kích hoạt trình cài đặt chính thức."""
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

    NMAP_DOWNLOAD_URL = "https://nmap.org/dist/nmap-7.95-setup.exe"
    WIRESHARK_DOWNLOAD_URL = "https://www.wireshark.org/download/win64/Wireshark-latest-x64.exe"
    ans = input("Would you like to open the official Wireshark download page now? (Y/N): ").strip().upper()
    if ans == "Y":
        import webbrowser
        webbrowser.open("https://www.wireshark.org/download.html")
        print("\nPlease install Wireshark / TShark and restart App.py.")

    NMAP_OFFICIAL_PAGE = "https://nmap.org/download.html"
    WIRESHARK_OFFICIAL_PAGE = "https://www.wireshark.org/download.html"
    return False

    @staticmethod
    def download_file(url, target_path):
        """Tải file từ Internet với thanh tiến trình đơn giản."""
        try:
            print(f"[*] Đang kết nối tới server chính thức:\n    {url}")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response, open(target_path, 'wb') as out_file:
                total_size = int(response.info().get('Content-Length', 0))
                bytes_downloaded = 0
                block_size = 8192
                
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    bytes_downloaded += len(buffer)
                    out_file.write(buffer)
                    
                    if total_size > 0:
                        percent = (bytes_downloaded / total_size) * 100
                        mb_curr = bytes_downloaded / (1024 * 1024)
                        mb_total = total_size / (1024 * 1024)
                        sys.stdout.write(f"\r    Đã tải: {percent:.1f}% ({mb_curr:.2f}/{mb_total:.2f} MB)")
                        sys.stdout.flush()
                print("\n[+] Tải file hoàn tất thành công.")
                return True
        except Exception as e:
            print(f"\n[-] Lỗi trong quá trình tải file: {e}")
            return False

    @staticmethod
    def run_installer_with_uac(installer_path):
        """Khởi chạy installer yêu cầu UAC chuẩn từ Windows."""
        print("[*] Yêu cầu quyền Administrator để mở installer...")
        try:
            # Sử dụng PowerShell Start-Process -Verb RunAs để kích hoạt popup UAC
            ps_cmd = f"Start-Process '{installer_path}' -Verb RunAs -Wait"
            res = subprocess.run(["powershell", "-Command", ps_cmd], check=True)
            return res.returncode == 0
        except Exception as e:
            print(f"[-] Lỗi khi kích hoạt installer: {e}")
            return False

    @classmethod
    def setup_nmap(cls):
        print("\n" + "="*60)
        print(" NMAP CHƯA ĐƯỢC CÀI ĐẶT")
        print("="*60)
        print("Nmap cần thiết cho các chức năng:")
        print(" [1] Scan LAN Subnet")
        print(" [2] View Discovered Devices\n")
        
        ans = input("Bạn có muốn tải và cài Nmap từ trang chính thức không? [Y/n]: ").strip().lower()
        if ans not in ['y', 'yes', '']:
            print("[!] Bỏ qua cài đặt Nmap. Chức năng Scan LAN sẽ bị vô hiệu hóa.")
            return False

        temp_dir = tempfile.gettempdir()
        installer_file = os.path.join(temp_dir, "nmap_setup.exe")
        
        if cls.download_file(cls.NMAP_DOWNLOAD_URL, installer_file):
            print("[*] Đang khởi chạy Nmap Setup...")
            cls.run_installer_with_uac(installer_file)
            
            # Xóa installer tạm
            if os.path.exists(installer_file):
                try: os.remove(installer_file)
                except: pass

            # Kiểm tra lại sau khi cài
            nmap_path = SystemPaths.get_nmap_path()
            if nmap_path:
                try:
                    out = subprocess.check_output([nmap_path, "--version"], text=True, errors="ignore")
                    version_line = out.splitlines()[0] if out else "Unknown"
                    print(f"[+] Nmap installation successful ({version_line}).")
                    return True
                except: pass
        
        print("[-] Không thể tự động cài đặt Nmap.")
        print(f"    Vui lòng tải và cài thủ công từ: {cls.NMAP_OFFICIAL_PAGE}")
def verify_tshark_version():
    if not state.tshark_path:
return False

    @classmethod
    def setup_tshark(cls):
        print("\n" + "="*60)
        print(" WIRESHARK / TSHARK CHƯA ĐƯỢC CÀI ĐẶT")
        print("="*60)
        print("TShark cần thiết cho các chức năng:")
        print(" [1] Traffic Statistics")
        print(" [2] Website / Network Activity Metadata\n")

        ans = input("Bạn có muốn tải và cài Wireshark/TShark từ trang chính thức không? [Y/n]: ").strip().lower()
        if ans not in ['y', 'yes', '']:
            print("[!] Bỏ qua cài đặt Wireshark. Chức năng phân tích Traffic sẽ bị vô hiệu hóa.")
            return False

        temp_dir = tempfile.gettempdir()
        installer_file = os.path.join(temp_dir, "wireshark_setup.exe")

        if cls.download_file(cls.WIRESHARK_DOWNLOAD_URL, installer_file):
            print("[*] Đang khởi chạy Wireshark Setup...")
            cls.run_installer_with_uac(installer_file)

            if os.path.exists(installer_file):
                try: os.remove(installer_file)
                except: pass

            tshark_path = SystemPaths.get_tshark_path()
            if tshark_path:
                try:
                    out = subprocess.check_output([tshark_path, "--version"], text=True, errors="ignore")
                    version_line = out.splitlines()[0] if out else "Unknown"
                    print(f"[+] Wireshark/TShark installation successful ({version_line}).")
                    return True
                except: pass

        print("[-] Không thể tự động cài đặt Wireshark.")
        print(f"    Vui lòng tải và cài thủ công từ: {cls.WIRESHARK_OFFICIAL_PAGE}")
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

def setup_dependencies():
    """Kiểm tra toàn bộ hệ thống và chuẩn bị môi trường."""
    print("============================================================")
    print("              KIỂM TRA HỆ THỐNG & DEPENDENCY               ")
    print("============================================================")
    
    nmap_status = "OK" if SystemPaths.get_nmap_path() else "MISSING"
    tshark_status = "OK" if SystemPaths.get_tshark_path() else "MISSING"

    if nmap_status == "MISSING":
        if OfficialInstaller.setup_nmap():
            nmap_status = "OK"

    if tshark_status == "MISSING":
        if OfficialInstaller.setup_tshark():
            tshark_status = "OK"

    print("\n==============================")
    print(" SYSTEM CHECK RESULT")
    print("==============================")
    print(f" Python        : OK ({platform.python_version()})")
    print(f" psutil        : OK")
    print(f" Nmap          : {nmap_status}")
    print(f" TShark        : {tshark_status}")
    print("==============================\n")
    time.sleep(1)

# ==============================================================================
# 2. NETWORK DETECTION & CONFIGURATION
# ==============================================================================

class NetworkDetector:
    @staticmethod
    def get_active_connection():
        """Phát hiện Interface mạng đang kết nối."""
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        active_ifaces = []
        for iface_name, iface_stats in stats.items():
            if iface_stats.isup and iface_name in addrs:
                if "loopback" in iface_name.lower() or "vethernet" in iface_name.lower():
                    continue
                for addr in addrs[iface_name]:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        active_ifaces.append((iface_name, addr.address, addr.netmask))

        if not active_ifaces:
            return "NONE", "No Interface", "0.0.0.0", "0.0.0.0", "0.0.0.0/0"

        # Ưu tiên tìm Wi-Fi hoặc Ethernet
        for iface_name, ip, mask in active_ifaces:
            name_lower = iface_name.lower()
            subnet = NetworkDetector.calculate_subnet(ip, mask)
            if "wi-fi" in name_lower or "wireless" in name_lower or "wlan" in name_lower:
                return "WIFI", iface_name, ip, mask, subnet
            elif "ethernet" in name_lower or "eth" in name_lower or "local area" in name_lower:
                return "ETHERNET", iface_name, ip, mask, subnet

        first = active_ifaces[0]
        return "UNKNOWN", first[0], first[1], first[2], NetworkDetector.calculate_subnet(first[1], first[2])

    @staticmethod
    def calculate_subnet(ip, mask):
        if not ip or not mask or ip == "0.0.0.0":
            return "127.0.0.1/32"
        try:
            ip_parts = [int(x) for x in ip.split('.')]
            mask_parts = [int(x) for x in mask.split('.')]
            net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            cidr = sum(bin(x).count('1') for x in mask_parts)
            return f"{net_parts[0]}.{net_parts[1]}.{net_parts[2]}.{net_parts[3]}/{cidr}"
        except:
            return "192.168.1.0/24"

# ==============================================================================
# 3. LAN DISCOVERY & TRAFFIC METADATA
# ==============================================================================

class LANScanner:
    def __init__(self, subnet):
        self.subnet = subnet
        self.devices = []

    def scan_subnet(self):
        """Thực hiện scan Nmap Host Discovery (-sn)."""
        nmap_path = SystemPaths.get_nmap_path()
        self.devices = []

        if not nmap_path:
            print("[!] Nmap chưa được cài đặt. Không thể thực hiện Nmap Scan Subnet.")
            print("[*] Chuyển sang đọc ARP Table thiết bị local...")
            return self._fallback_arp_scan()

        print(f"[*] Đang thực hiện Nmap Ping Scan trên subnet: {self.subnet}")
        try:
            cmd = [nmap_path, "-sn", self.subnet]
            out = subprocess.check_output(cmd, text=True, errors="ignore", timeout=60)
            
            current = {}
            for line in out.splitlines():
                line = line.strip()
                if "Nmap scan report for" in line:
                    if current and "ip" in current:
                        self.devices.append(current)
                    current = {"hostname": "Unknown", "status": "ONLINE", "mac": "--", "latency": "<10ms"}
                    parts = line.replace("Nmap scan report for ", "").split()
                    if len(parts) == 1:
                        current["ip"] = parts[0]
                    else:
                        current["hostname"] = parts[0]
                        current["ip"] = parts[1].strip("()")
                elif "MAC Address:" in line:
                    mac_part = line.split("MAC Address: ")[1].split()
                    current["mac"] = mac_part[0]

            if current and "ip" in current:
                self.devices.append(current)

            print(f"[+] Quét hoàn tất. Tìm thấy {len(self.devices)} máy hoạt động.")
        except Exception as e:
            print(f"[-] Lỗi khi thực hiện Nmap scan: {e}")
        return self.devices

    def _fallback_arp_scan(self):
        try:
            out = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ip, mac = parts[0], parts[1]
                    if not ip.startswith("224.") and not ip.startswith("255."):
                        self.devices.append({
                            "ip": ip,
                            "mac": mac.upper(),
                            "hostname": "ARP Discovery",
                            "status": "ONLINE",
                            "latency": "N/A"
                        })
        except Exception as e:
            print(f"[-] Lỗi đọc ARP table: {e}")
        return self.devices


class TrafficAnalyzer:
    @staticmethod
    def capture_metadata(duration=5):
        """Bắt thông số Traffic Metadata ngắn hạn qua TShark."""
        tshark_path = SystemPaths.get_tshark_path()
        if not tshark_path:
            return " [!] TShark/Wireshark chưa cài đặt. Không thể thu thập Traffic Metadata."
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

        print(f"[*] Đang thu thập Traffic Metadata trong {duration} giây...")
try:
            cmd = [
                tshark_path,
                "-a", f"duration:{duration}",
                "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "_ws.col.Protocol",
                "-e", "frame.len"
            ]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore")
            stdout, _ = process.communicate(timeout=duration + 5)
            
            lines = stdout.splitlines()
            total_bytes = 0
            proto_counts = {}

            for line in lines:
                parts = line.split("\t")
                if len(parts) >= 5:
                    proto = parts[3]
                    try:
                        total_bytes += int(parts[4])
                    except: pass
                    proto_counts[proto] = proto_counts.get(proto, 0) + 1

            res = f" Tổng gói tin phân tích : {len(lines)}\n"
            res += f" Dung lượng metadata   : {total_bytes / 1024:.2f} KB\n"
            res += " Giao thức phát hiện:\n"
            for pr, cnt in proto_counts.items():
                res += f"   - {pr}: {cnt} packets\n"
            return res
        except Exception as e:
            return f" [-] Lỗi phân tích Traffic: {e}"
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

    @staticmethod
    def capture_website_activity(duration=5):
        """Lấy metadata kết nối domain/hostname an toàn (SNI/DNS metadata)."""
        tshark_path = SystemPaths.get_tshark_path()
        if not tshark_path:
            print(" [!] TShark chưa cài đặt. Đang lấy danh sách Remote IP từ psutil connection metadata...\n")
            return TrafficAnalyzer._fallback_psutil_activity()
    print(f"{Fore.GREEN}Monitoring network metadata... (Press CTRL+C or 'Q' to control)")
    print("-----------------------------------------------------------------------------------------------")
    print(f"{'TIME':<10} {'DEVICE':<18} {'SRC IP':<16} {'DOMAIN':<22} {'DEST IP':<16} {'PROTO':<8} {'CONFIDENCE'}")
    print("-----------------------------------------------------------------------------------------------")

        print(f"[*] Đang theo dõi DNS/SNI domain metadata trong {duration} giây...")
        try:
            cmd = [
                tshark_path,
                "-a", f"duration:{duration}",
                "-Y", "tls.handshake.extensions_server_name or dns.flags.response == 1",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "tls.handshake.extensions_server_name",
                "-e", "dns.qry.name"
            ]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore")
            stdout, _ = process.communicate(timeout=duration + 5)

            activities = []
            for line in stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    src_ip = parts[0] if parts[0] else "Local Machine"
                    domain = parts[1] if parts[1] else (parts[2] if len(parts) > 2 else "")
                    if domain and domain not in activities:
                        activities.append(f" {src_ip:<18} ->  {domain}")

            if not activities:
                return " [i] Không phát hiện domain lookup mới trong thời gian qua. Đang dùng fallback connection list:\n" + TrafficAnalyzer._fallback_psutil_activity()
            return "\n".join(activities)
        except Exception as e:
            return f" [-] Lỗi khi theo dõi Website Activity: {e}"
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

    @staticmethod
    def _fallback_psutil_activity():
        output = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.status == 'ESTABLISHED':
                    ip = conn.raddr.ip
                    try:
                        host = socket.gethostbyaddr(ip)[0]
                    except:
                        host = ip
                    output.append(f" Local Machine      ->  {host} ({ip}:{conn.raddr.port})")
        except Exception as e:
            output.append(f" [-] Lỗi đọc kết nối local: {e}")
        return "\n".join(output[:10]) if output else " Không có kết nối mạng ngoại vi đang mở."
            time.sleep(1.5)

# ==============================================================================
# 4. MAIN APPLICATION DASHBOARD
# ==============================================================================
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

class LANMonitorApp:
    def __init__(self):
        self.conn_type = "NONE"
        self.iface = ""
        self.local_ip = "0.0.0.0"
        self.netmask = "0.0.0.0"
        self.subnet = "0.0.0.0/0"
        self.mode = "UNDETERMINED"
        self.scanner = None

    def initialize_network(self):
        os.system("cls" if os.name == "nt" else "clear")
        self.conn_type, self.iface, self.local_ip, self.netmask, self.subnet = NetworkDetector.get_active_connection()

        print("===============================================================")
        print("           LAN MONITOR & COMPUTER LAB ADMIN TOOL               ")
        print("===============================================================\n")

        print(f" Loai ket noi : {self.conn_type}")
        print(f" Interface    : {self.iface}")
        print(f" Local IP     : {self.local_ip}")
        print(f" Subnet       : {self.subnet}\n")

        if self.conn_type == "WIFI":
            print("=============================================================")
            print(" CANH BAO: BAN DANG SU DUNG MANG KHONG DAY (WI-FI).")
            print("=============================================================")
            ans = input("\nDay co phai mang phong may ma ban DUOC PHEU QUAN TRI khong? (y/N): ").strip().lower()
            if ans == 'y':
                self.mode = "LAB / ADMIN MODE"
            else:
                self.mode = "PERSONAL / LOCAL DEVICE MODE"
        else:
            ans = input("Ban co muon vao LAB / ADMIN MODE de quan tri khong? [Y/n]: ").strip().lower()
            if ans in ['y', 'yes', '']:
                self.mode = "LAB / ADMIN MODE"
            else:
                self.mode = "PERSONAL / LOCAL DEVICE MODE"

        if self.mode == "LAB / ADMIN MODE":
            self.scanner = LANScanner(self.subnet)

    def print_menu(self):
        os.system("cls" if os.name == "nt" else "clear")
        print("===============================================================")
        print("           LAN MONITOR & COMPUTER LAB ADMIN TOOL               ")
        print("===============================================================")
        print(f" Connection : {self.conn_type}")
        print(f" Mode       : {self.mode}")
        print(f" Local IP   : {self.local_ip}")
        print(f" Subnet     : {self.subnet}")
        print("===============================================================\n")
        print(" MAIN MENU:\n")
        
        if self.mode == "LAB / ADMIN MODE":
            print(" [1] Scan LAN Subnet")
            print(" [2] View Discovered Devices")
            print(" [3] Website / Network Activity")
            print(" [4] Traffic Statistics")
            print(" [5] View Device Details")
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
            print(" [1] Scan LAN Subnet (Disabled in Personal Mode)")
            print(" [2] View Discovered Devices (Disabled in Personal Mode)")
            print(" [3] Website / Network Activity (Disabled in Personal Mode)")
            print(" [4] Traffic Statistics (Disabled in Personal Mode)")
            print(" [5] View Device Details (Disabled in Personal Mode)")

        print(" [6] Local Computer Info")
        print(" [7] Refresh Network Detection")
        print(" [0] Exit\n")

    def show_local_info(self):
        print("\n---------------------------------------------------------------")
        print(" LOCAL COMPUTER INFORMATION")
        print("---------------------------------------------------------------")
        print(f" Hostname      : {socket.gethostname()}")
        print(f" IP Address    : {self.local_ip}")
        print(f" Subnet Mask   : {self.netmask}")
        
        io = psutil.net_io_counters()
        print(f" Sent Bytes    : {io.bytes_sent / (1024*1024):.2f} MB")
        print(f" Recv Bytes    : {io.bytes_recv / (1024*1024):.2f} MB")
        
        print("\n Connections Metadata (Top 8 Active):")
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
            conns = [c for c in psutil.net_connections(kind='inet') if c.status == 'ESTABLISHED']
            for c in conns[:8]:
                r = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "--"
                print(f"  - Local Port {c.laddr.port:<5} -> Remote {r:<22} (PID: {c.pid})")
        except Exception as e:
            print(f"  [-] Error reading active connections: {e}")
        input("\nNhan Enter de tiep tuc...")

    def run(self):
        setup_dependencies()
        self.initialize_network()

        while True:
            self.print_menu()
            choice = input("Chon chuc nang [0-7]: ").strip()
            render_main_menu()
            choice = input("Select option [0-7]: ").strip()

if choice == "1":
                if self.mode == "LAB / ADMIN MODE":
                    self.scanner.scan_subnet()
                else:
                    print("\n[!] Chuc nang nay bi khoi o Personal Mode.")
                input("\nNhan Enter de tiep tuc...")

                run_nmap_discovery()
                input("\nPress Enter to return...")
elif choice == "2":
                if self.mode == "LAB / ADMIN MODE":
                    print("\n---------------------------------------------------------------")
                    print(" DISCOVERED DEVICES IN LAN")
                    print("---------------------------------------------------------------")
                    print(f" {'IP Address':<16} {'MAC Address':<20} {'Hostname':<20} {'Status'}")
                    print(" " + "-"*65)
                    for d in self.scanner.devices:
                        print(f" {d.get('ip','--'):<16} {d.get('mac','--'):<20} {d.get('hostname','--'):<20} {d.get('status','--')}")
                else:
                    print("\n[!] Chuc nang nay bi khoi o Personal Mode.")
                input("\nNhan Enter de tiep tuc...")

                feature_device_details()
elif choice == "3":
                if self.mode == "LAB / ADMIN MODE":
                    print("\n---------------------------------------------------------------")
                    print(" WEBSITE / NETWORK ACTIVITY (DOMAIN METADATA)")
                    print("---------------------------------------------------------------")
                    res = TrafficAnalyzer.capture_website_activity(duration=5)
                    print(res)
                else:
                    print("\n[!] Chuc nang nay bi khoi o Personal Mode.")
                input("\nNhan Enter de tiep tuc...")

                feature_website_activity()
elif choice == "4":
                if self.mode == "LAB / ADMIN MODE":
                    print("\n---------------------------------------------------------------")
                    print(" TRAFFIC STATISTICS METADATA")
                    print("---------------------------------------------------------------")
                    res = TrafficAnalyzer.capture_metadata(duration=5)
                    print(res)
                else:
                    print("\n[!] Chuc nang nay bi khoi o Personal Mode.")
                input("\nNhan Enter de tiep tuc...")

                feature_traffic_statistics()
elif choice == "5":
                if self.mode == "LAB / ADMIN MODE":
                    target = input("\nNhap IP thiet bi can xem chi tiet: ").strip()
                    dev = next((d for d in self.scanner.devices if d.get('ip') == target), None)
                    if dev:
                        print(f"\n Details for {target}:")
                        print(f"  - Hostname : {dev.get('hostname')}")
                        print(f"  - MAC      : {dev.get('mac')}")
                        print(f"  - Latency  : {dev.get('latency')}")
                        print(f"  - Status   : {dev.get('status')}")
                    else:
                        print(" [!] Khong tim thay IP trong danh sach da scan. Hay chay Scan LAN truoc.")
                else:
                    print("\n[!] Chuc nang nay bi khoi o Personal Mode.")
                input("\nNhan Enter de tiep tuc...")

                feature_device_details()
elif choice == "6":
                self.show_local_info()

                feature_local_info()
elif choice == "7":
                self.initialize_network()

                get_local_net_info()
                print(f"{Fore.GREEN}[+] Network interface refreshed.")
                time.sleep(1)
elif choice == "0":
                print("\nDang thoat ung dung...")
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
    try:
        app = LANMonitorApp()
        app.run()
    except KeyboardInterrupt:
        print("\n[!] Dung boi nguoi dung.")
        sys.exit(0)
    main()
