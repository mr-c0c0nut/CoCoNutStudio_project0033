# App.py - LAN Monitor & Computer Lab Admin Tool (Windows)
# Complete single-file application. No external requirements.txt needed.

import os
import sys
import time
import socket
import re
import subprocess
import platform
import shutil
import urllib.request
import tempfile
from pathlib import Path

# ==============================================================================
# 1. AUTO-SETUP & DEPENDENCY MANAGER
# ==============================================================================

def check_and_install_python_packages():
    """Tự động kiểm tra và cài đặt các package Python thiếu."""
    required = ["psutil"]
    missing = []
    
    for pkg in required:
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

import psutil


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
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe")
        ]
        return cls.find_executable("tshark.exe", locations)


class OfficialInstaller:
    """Quản lý việc tải và kích hoạt trình cài đặt chính thức."""
    
    NMAP_DOWNLOAD_URL = "https://nmap.org/dist/nmap-7.95-setup.exe"
    WIRESHARK_DOWNLOAD_URL = "https://www.wireshark.org/download/win64/Wireshark-latest-x64.exe"
    
    NMAP_OFFICIAL_PAGE = "https://nmap.org/download.html"
    WIRESHARK_OFFICIAL_PAGE = "https://www.wireshark.org/download.html"

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
        return False


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

    @staticmethod
    def capture_website_activity(duration=5):
        """Lấy metadata kết nối domain/hostname an toàn (SNI/DNS metadata)."""
        tshark_path = SystemPaths.get_tshark_path()
        if not tshark_path:
            print(" [!] TShark chưa cài đặt. Đang lấy danh sách Remote IP từ psutil connection metadata...\n")
            return TrafficAnalyzer._fallback_psutil_activity()

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

# ==============================================================================
# 4. MAIN APPLICATION DASHBOARD
# ==============================================================================

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

            if choice == "1":
                if self.mode == "LAB / ADMIN MODE":
                    self.scanner.scan_subnet()
                else:
                    print("\n[!] Chuc nang nay bi khoi o Personal Mode.")
                input("\nNhan Enter de tiep tuc...")

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

            elif choice == "6":
                self.show_local_info()

            elif choice == "7":
                self.initialize_network()

            elif choice == "0":
                print("\nDang thoat ung dung...")
                sys.exit(0)


if __name__ == "__main__":
    try:
        app = LANMonitorApp()
        app.run()
    except KeyboardInterrupt:
        print("\n[!] Dung boi nguoi dung.")
        sys.exit(0)
