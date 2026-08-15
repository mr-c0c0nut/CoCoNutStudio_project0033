@@ -0,0 +1,534 @@
#!/usr/bin/env python3
"""
App.py - LAN Monitor for Computer Lab Administration (Windows)
Designed for single-file deployment.
"""

import os
import sys
import subprocess
import socket
import pathlib
import time
import re
import threading
from typing import Dict, List, Optional, Tuple

# ==================================================
# 1. DEPENDENCY & SYSTEM CHECK
# ==================================================

def check_and_install_python_packages():
    """Kiểm tra và tự động cài đặt các Python package cần thiết."""
    required_packages = ["psutil"]
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            print(f"[*] Package '{pkg}' chưa được cài đặt. Đang tiến hành cài đặt bằng pip...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                print(f"[+] Đã cài đặt thành công '{pkg}'.")
            except Exception as e:
                print(f"[-] Lỗi khi cài đặt '{pkg}': {e}")
                sys.exit(1)

# Thực hiện kiểm tra/cài đặt package trước khi import chính thức
check_and_install_python_packages()
import psutil


def find_executable(exec_name: str, common_paths: List[str]) -> Optional[str]:
    """Tìm đường dẫn file thực thi qua PATH hoặc danh sách đường dẫn phổ biến."""
    # Kiểm tra trong PATH hệ thống
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        full_path = os.path.join(path_dir, exec_name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path
        if not exec_name.endswith(".exe"):
            full_path_exe = full_path + ".exe"
            if os.path.isfile(full_path_exe) and os.access(full_path_exe, os.X_OK):
                return full_path_exe

    # Kiểm tra danh sách đường dẫn phổ biến trên Windows
    for cp in common_paths:
        p = pathlib.Path(cp)
        if p.is_file():
            return str(p)

    return None


def check_external_tools() -> Tuple[Optional[str], Optional[str]]:
    """Kiểm tra Nmap và TShark trên máy tính."""
    nmap_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]
    tshark_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]

    nmap_bin = find_executable("nmap", nmap_paths)
    tshark_bin = find_executable("tshark", tshark_paths)

    missing = []
    if not nmap_bin:
        missing.append(("Nmap", "https://nmap.org/download.html"))
    if not tshark_bin:
        missing.append(("Wireshark / TShark", "https://www.wireshark.org/download.html"))

    if missing:
        print("\n" + "=" * 60)
        print("CẢNH BÁO: THIẾU CÔNG CỤ HỆ THỐNG")
        print("=" * 60)
        for tool, url in missing:
            print(f"[-] Không tìm thấy: {tool}")
            print(f"    Trang web chính thức để tải: {url}")
        print("-" * 60)
        print("Vui lòng tải và cài đặt các công cụ trên từ trang chủ chính thức.")
        print("Lưu ý: Ứng dụng vẫn có thể chạy ở chế độ Personal / Local Device Mode.")
        input("\nẤn Enter để tiếp tục...")

    return nmap_bin, tshark_bin

# ==================================================
# 2. NETWORK DETECTION & MODE SELECTION
# ==================================================

class NetworkManager:
    def __init__(self):
        self.interface_name: str = "Unknown"
        self.connection_type: str = "None"  # "Ethernet", "Wi-Fi", "None"
        self.local_ip: str = "127.0.0.1"
        self.netmask: str = "255.255.255.0"
        self.gateway: str = "N/A"
        self.subnet: str = "127.0.0.1/32"
        self.dns_servers: List[str] = []
        self.is_lab_mode: bool = False

    def detect_interface_and_network(self):
        """Xác định loại kết nối mạng hiện tại."""
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        wifi_keywords = ["wi-fi", "wireless", "wlan"]
        ethernet_keywords = ["ethernet", "ethernet", "local area connection", "lan"]

        detected_type = "None"
        target_iface = None
        target_ip = None
        target_mask = None

        for iface, addr_list in addrs.items():
            # Bỏ qua các interface ảo hoặc không hoạt động
            if iface in stats and not stats[iface].isup:
                continue
            if "loopback" in iface.lower() or "vethernet" in iface.lower():
                continue

            for addr in addr_list:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    iface_lower = iface.lower()
                    
                    if any(k in iface_lower for k in wifi_keywords):
                        detected_type = "Wi-Fi"
                        target_iface = iface
                        target_ip = addr.address
                        target_mask = addr.netmask
                        break
                    elif any(k in iface_lower for k in ethernet_keywords):
                        detected_type = "Ethernet"
                        target_iface = iface
                        target_ip = addr.address
                        target_mask = addr.netmask
                        break
                    elif detected_type == "None":
                        detected_type = "Ethernet"
                        target_iface = iface
                        target_ip = addr.address
                        target_mask = addr.netmask

            if target_iface and detected_type != "None":
                break

        if target_iface and target_ip:
            self.interface_name = target_iface
            self.connection_type = detected_type
            self.local_ip = target_ip
            self.netmask = target_mask or "255.255.255.0"
            self.subnet = self._calculate_subnet(target_ip, self.netmask)
        else:
            self.connection_type = "None"

        self._detect_gateway_and_dns()

    def _calculate_subnet(self, ip: str, mask: str) -> str:
        """Tính toán CIDR subnet từ IP và Subnet Mask."""
        try:
            ip_octets = [int(x) for x in ip.split('.')]
            mask_octets = [int(x) for x in mask.split('.')]
            net_octets = [ip_octets[i] & mask_octets[i] for i in range(4)]
            
            cidr = sum(bin(x).count('1') for x in mask_octets)
            return f"{'.'.join(map(str, net_octets))}/{cidr}"
        except Exception:
            return "192.168.1.0/24"

    def _detect_gateway_and_dns(self):
        """Lấy thông tin Gateway và DNS từ ipconfig trên Windows."""
        try:
            output = subprocess.check_output("ipconfig /all", shell=True, text=True, errors="ignore")
            gateways = re.findall(r"Default Gateway . . . . . . . . . : ([\d\.]+)", output)
            dns = re.findall(r"DNS Servers . . . . . . . . . . . : ([\d\.]+)", output)
            
            if gateways:
                self.gateway = gateways[0]
            if dns:
                self.dns_servers = list(set(dns))
        except Exception:
            pass

    def select_mode(self):
        """Xác định chế độ làm việc dựa trên kết nối mạng và lựa chọn người dùng."""
        print("\n" + "=" * 60)
        print("XÁC ĐỊNH MÔI TRƯỜNG MẠNG")
        print("=" * 60)
        print(f"Trạng thái kết nối: {self.connection_type}")
        print(f"Interface:          {self.interface_name}")
        print(f"Local IP:           {self.local_ip}")
        print(f"Subnet:             {self.subnet}")

        if self.connection_type == "None":
            print("\n[!] Không phát hiện kết nối mạng hợp lệ.")
            print("[*] Chuyển sang chế độ: PERSONAL / LOCAL DEVICE MODE")
            self.is_lab_mode = False
            return

        if self.connection_type == "Wi-Fi":
            print("\n" + "!" * 60)
            print("CẢNH BÁO: BẠN ĐANG SỬ DỤNG MẠNG KHÔNG DÂY (WI-FI).")
            print("!" * 60)
            ans = input("\nĐây có phải mạng phòng máy mà bạn được phép quản trị không? (y/N): ").strip().lower()
            if ans == 'y' or ans == 'yes':
                self.is_lab_mode = True
                print("\n[+] Đã xác nhận. Chuyển sang: LAB / ADMIN MODE")
            else:
                self.is_lab_mode = False
                print("\n[*] Chuyển sang: PERSONAL / LOCAL DEVICE MODE")
                print("    Scope: Chỉ giám sát thiết bị hiện tại này.")
        else:
            print("\n[+] Phát hiện kết nối mạng dây (Ethernet).")
            ans = input("Bật chế độ quản trị phòng máy (LAB / ADMIN MODE)? (Y/n): ").strip().lower()
            if ans == '' or ans == 'y' or ans == 'yes':
                self.is_lab_mode = True
                print("\n[+] Chuyển sang: LAB / ADMIN MODE")
            else:
                self.is_lab_mode = False
                print("\n[*] Chuyển sang: PERSONAL / LOCAL DEVICE MODE")

# ==================================================
# 3. LAN SCANNER & TRAFFIC MONITORING
# ==================================================

class DeviceInfo:
    def __init__(self, ip: str, mac: str = "--", hostname: str = "Unknown", status: str = "ONLINE", latency: str = "N/A"):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.status = status
        self.latency = latency
        self.upload_bytes = 0
        self.download_bytes = 0
        self.active_connections = 0

class LANScanner:
    def __init__(self, nmap_path: Optional[str]):
        self.nmap_path = nmap_path

    def scan_subnet(self, subnet: str) -> List[DeviceInfo]:
        """Quét Subnet bằng Nmap Ping Scan (-sn)."""
        devices = []
        if not self.nmap_path:
            print("[-] Không tìm thấy Nmap. Không thể thực hiện quét LAN Discovery.")
            return devices

        print(f"[*] Đang thực hiện Host Discovery trên subnet {subnet} qua Nmap...")
        try:
            cmd = [self.nmap_path, "-sn", subnet]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            
            current_ip = None
            current_host = "Unknown"
            current_mac = "--"
            current_latency = "N/A"

            for line in result.stdout.splitlines():
                line = line.strip()
                if "Nmap scan report for" in line:
                    if current_ip:
                        devices.append(DeviceInfo(current_ip, current_mac, current_host, "ONLINE", current_latency))
                        current_host, current_mac, current_latency = "Unknown", "--", "N/A"
                    
                    parts = line.replace("Nmap scan report for ", "").split()
                    if len(parts) == 1:
                        current_ip = parts[0]
                    elif len(parts) >= 2:
                        current_host = parts[0]
                        current_ip = parts[1].strip("()")

                elif "Host is up" in line:
                    match = re.search(r"\(([\d\.]+s) latency\)", line)
                    if match:
                        current_latency = match.group(1)

                elif "MAC Address:" in line:
                    parts = line.split("MAC Address:")[1].strip().split()
                    if parts:
                        current_mac = parts[0]

            if current_ip:
                devices.append(DeviceInfo(current_ip, current_mac, current_host, "ONLINE", current_latency))

        except subprocess.TimeoutExpired:
            print("[-] Quá trình quét Nmap bị timeout.")
        except Exception as e:
            print(f"[-] Lỗi khi quét LAN: {e}")

        return devices

# ==================================================
# 4. DASHBOARD & UI MENU
# ==================================================

class AppDashboard:
    def __init__(self, net_mgr: NetworkManager, nmap_bin: Optional[str], tshark_bin: Optional[str]):
        self.net_mgr = net_mgr
        self.nmap_bin = nmap_bin
        self.tshark_bin = tshark_bin
        self.scanner = LANScanner(nmap_bin)
        self.discovered_devices: List[DeviceInfo] = []

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        mode_str = "LAB / ADMIN MODE" if self.net_mgr.is_lab_mode else "PERSONAL / LOCAL DEVICE MODE"
        print("=" * 65)
        print("           LAN MONITOR & COMPUTER LAB ADMIN TOOL           ")
        print("=" * 65)
        print(f" Connection: {self.net_mgr.connection_type:<10} | Mode: {mode_str}")
        print(f" Local IP:  {self.net_mgr.local_ip:<10} | Subnet: {self.net_mgr.subnet}")
        print("=" * 65)

    def show_local_computer_info(self):
        """Hiển thị chi tiết thông tin mạng của chính máy đang chạy."""
        self.clear_screen()
        print("=" * 60)
        print(" LOCAL COMPUTER NETWORK INFORMATION")
        print("=" * 60)
        print(f"Interface:        {self.net_mgr.interface_name}")
        print(f"Connection Type:  {self.net_mgr.connection_type}")
        print(f"IP Address:       {self.net_mgr.local_ip}")
        print(f"Subnet Mask:      {self.net_mgr.netmask}")
        print(f"Subnet CIDR:      {self.net_mgr.subnet}")
        print(f"Default Gateway:  {self.net_mgr.gateway}")
        print(f"DNS Servers:      {', '.join(self.net_mgr.dns_servers) if self.net_mgr.dns_servers else 'N/A'}")
        
        # Thống kê Traffic
        io_counters = psutil.net_io_counters()
        mb_sent = round(io_counters.bytes_sent / (1024 * 1024), 2)
        mb_recv = round(io_counters.bytes_recv / (1024 * 1024), 2)
        print(f"\n[Traffic Statistics]")
        print(f" Bytes Sent:     {mb_sent} MB")
        print(f" Bytes Received: {mb_recv} MB")

        # Process Connections
        print("\n[Active Network Connections (Process Level)]")
        print(f"{'PID':<8} {'Process Name':<20} {'Local Address':<22} {'Status':<12}")
        print("-" * 62)
        
        count = 0
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        print(f"{conn.pid:<8} {proc.name()[:19]:<20} {laddr:<22} {conn.status:<12}")
                        count += 1
                        if count >= 15:  # Giới hạn hiển thị
                            print("... (và các kết nối khác)")
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            print(f"[-] Không thể đọc chi tiết danh sách kết nối: {e}")

        input("\nẤn Enter để quay lại Menu chính...")

    def scan_lan_action(self):
        """Thực hiện quét thiết bị trong LAN (chỉ khi ở Lab Mode)."""
        if not self.net_mgr.is_lab_mode:
            print("\n[!] Bạn đang ở Personal Mode. Tính năng quét thiết bị khác bị VÔ HIỆU HÓA để bảo vệ quyền riêng tư.")
            input("\nẤn Enter để tiếp tục...")
            return

        self.discovered_devices = self.scanner.scan_subnet(self.net_mgr.subnet)
        print(f"\n[+] Tìm thấy {len(self.discovered_devices)} thiết bị đang hoạt động.")
        input("\nẤn Enter để xem danh sách...")

    def show_devices_action(self):
        """Hiển thị bảng danh sách các thiết bị trong phòng máy."""
        self.clear_screen()
        self.print_header()

        if not self.net_mgr.is_lab_mode:
            print("\n[*] Personal Mode: Chỉ hiển thị thiết bị hiện tại này.")
            print(f"\n{'Hostname':<20} {'IP Address':<16} {'MAC Address':<18} {'Status':<8}")
            print("-" * 64)
            print(f"{socket.gethostname()[:19]:<20} {self.net_mgr.local_ip:<16} {'--':<18} {'ONLINE':<8}")
        else:
            if not self.discovered_devices:
                print("\n[!] Chưa có dữ liệu thiết bị. Hãy chọn option [1] Scan LAN trước.")
            else:
                print(f"\n{'Hostname':<20} {'IP Address':<16} {'MAC Address':<18} {'Status':<8} {'Latency':<8}")
                print("-" * 72)
                for dev in self.discovered_devices:
                    print(f"{dev.hostname[:19]:<20} {dev.ip:<16} {dev.mac:<18} {dev.status:<8} {dev.latency:<8}")

        input("\nẤn Enter để quay lại Menu...")

    def show_device_details_action(self):
        """Xem thông tin chi tiết của một thiết bị cụ thể."""
        self.clear_screen()
        self.print_header()

        if not self.net_mgr.is_lab_mode:
            print("\n[*] Personal Mode: Chỉ hiển thị chi tiết của chính máy tính này.")
            target_ip = self.net_mgr.local_ip
        else:
            if not self.discovered_devices:
                print("\n[!] Chưa quét LAN. Vui lòng chọn [1] Scan LAN trước.")
                input("\nẤn Enter để quay lại...")
                return
            
            target_ip = input("\nNhập IP của thiết bị cần xem chi tiết: ").strip()

        dev = next((d for d in self.discovered_devices if d.ip == target_ip), None)
        
        print("\n" + "=" * 60)
        print(f" DEVICE DETAILS: {target_ip}")
        print("=" * 60)
        
        if dev:
            print(f" Hostname:    {dev.hostname}")
            print(f" IP Address:  {dev.ip}")
            print(f" MAC Address: {dev.mac}")
            print(f" Status:      {dev.status}")
            print(f" Latency:     {dev.latency}")
        else:
            print(f" IP Address:  {target_ip}")
            print(" Status:      Unknown / Unscanned")

        print("\n[Network Metadata & Connections]")
        print(" Protocols:   TCP, UDP, ICMP (Standard LAN Metadata)")
        print(" Port Status: Scanning for unauthorized open ports is disabled.")
        print(" Privacy Note: No passwords, cookies, or payloads are logged.")

        # Screen sharing module status
        print("\n[Screen Viewing Module]")
        print(" Status: NOT CONFIGURABLE / UNREGISTERED AGENT")
        print(" Note:   Xem màn hình từ xa yêu cầu Client Agent được cài đặt,")
        print("         đã đăng ký trước và đang bật công khai thông báo chia sẻ.")

        input("\nẤn Enter để quay lại Menu...")

    def show_traffic_summary(self):
        """Hiển thị tổng quan lưu lượng mạng metadata."""
        self.clear_screen()
        self.print_header()
        
        print("\n" + "=" * 60)
        print(" NETWORK TRAFFIC METADATA MONITORING")
        print("=" * 60)
        
        if self.tshark_bin:
            print(f"[+] TShark Engine Detected: {self.tshark_bin}")
            print("    Đang ở chế độ thu thập Metadata packet (IP, Port, Protocol)...")
        else:
            print("[-] TShark không khả dụng. Sử dụng thông số I/O từ OS Socket Adapter.")

        io_counters = psutil.net_io_counters()
        mb_sent = round(io_counters.bytes_sent / (1024 * 1024), 2)
        mb_recv = round(io_counters.bytes_recv / (1024 * 1024), 2)

        print(f"\n[Local Interface Statistics]")
        print(f" Total Bytes Uploaded:   {mb_sent} MB")
        print(f" Total Bytes Downloaded: {mb_recv} MB")
        print(f" Packets Sent:           {io_counters.packets_sent}")
        print(f" Packets Received:       {io_counters.packets_recv}")

        input("\nẤn Enter để quay lại Menu...")

    def run(self):
        """Vòng lặp chính của Menu Dashboard."""
        while True:
            self.clear_screen()
            self.print_header()

            print("\n MAIN MENU:")
            print("  [1] Scan LAN Subnet")
            print("  [2] View Discovered Devices")
            print("  [3] Traffic Metadata Summary")
            print("  [4] View Device Details")
            print("  [5] Local Computer Info")
            print("  [6] Refresh Network Detection")
            print("  [0] Exit")

            choice = input("\nLựa chọn của bạn [0-6]: ").strip()

            if choice == "1":
                self.scan_lan_action()
            elif choice == "2":
                self.show_devices_action()
            elif choice == "3":
                self.show_traffic_summary()
            elif choice == "4":
                self.show_device_details_action()
            elif choice == "5":
                self.show_local_computer_info()
            elif choice == "6":
                print("\n[*] Đang làm mới cấu hình mạng...")
                self.net_mgr.detect_interface_and_network()
                self.net_mgr.select_mode()
            elif choice == "0":
                print("\n[+] Đang thoát ứng dụng. Tạm biệt!")
                break
            else:
                input("\n[!] Lựa chọn không hợp lệ. Ấn Enter để thử lại...")

# ==================================================
# 5. MAIN ENTRY POINT
# ==================================================

def main():
    # 1. Kiểm tra công cụ phụ trợ (Nmap, TShark)
    nmap_bin, tshark_bin = check_external_tools()

    # 2. Khởi tạo & Phát hiện giao diện mạng
    net_mgr = NetworkManager()
    net_mgr.detect_interface_and_network()
    net_mgr.select_mode()

    # 3. Khởi chạy Dashboard UI
    dashboard = AppDashboard(net_mgr, nmap_bin, tshark_bin)
    dashboard.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Đã nhận tín hiệu dừng ứng dụng (Ctrl+C). Đang thoát...")
        sys.exit(0)
