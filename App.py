import os
import re
import sys
import time
import socket
import shutil
import subprocess
import threading
from collections import defaultdict, deque
from datetime import datetime

# ============================================================
# LAN MONITOR - AUTHORIZED ADMIN / LAB NETWORK METADATA ONLY
# ============================================================
# Records network metadata visible to the capture interface:
# source/destination IP, DNS names, TLS SNI and ports.
#
# Does NOT decrypt HTTPS or collect passwords/cookies/content.
# ============================================================

REQUIRED_PACKAGES = ["psutil", "colorama"]


def ensure_packages():
    missing = []

    for name in REQUIRED_PACKAGES:
        try:
            __import__(name)
        except ImportError:
            missing.append(name)

    if missing:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", *missing]
        )


ensure_packages()

import psutil
from colorama import Fore, init

init(autoreset=True)


# ============================================================
# DATA STRUCTURES
# ============================================================

class Activity:
    def __init__(
        self,
        timestamp,
        src,
        dst,
        domain,
        protocol,
        port,
        source
    ):
        self.timestamp = timestamp
        self.src = src
        self.dst = dst
        self.domain = domain or "-"
        self.protocol = protocol or "-"
        self.port = port or "-"
        self.source = source


class Monitor:
    def __init__(self):

        self.local_ip = "127.0.0.1"

        self.interface_name = None
        self.interface_id = None

        self.tshark = None
        self.nmap = shutil.which("nmap")

        self.running = False
        self.process = None

        self.lock = threading.Lock()

        self.activities = deque(maxlen=1500)

        self.devices = {}

        self.stats = defaultdict(
            lambda: {
                "domains": set(),
                "connections": 0,
                "last": "-"
            }
        )

        # destination IP -> (domain, timestamp)
        self.dns_cache = {}

        # Optional source-IP filter
        self.device_filter = None


    # ========================================================
    # NETWORK DETECTION
    # ========================================================

    def detect_local_network(self):

        try:

            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            s.connect(("1.1.1.1", 53))

            self.local_ip = s.getsockname()[0]

            s.close()

        except OSError:
            pass


        for name, addresses in psutil.net_if_addrs().items():

            for address in addresses:

                if address.address == self.local_ip:

                    self.interface_name = name

                    return


    # ========================================================
    # TSHARK
    # ========================================================

    def find_tshark(self):

        self.tshark = shutil.which("tshark")

        if self.tshark:
            return True


        candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]


        for path in candidates:

            if os.path.exists(path):

                self.tshark = path

                return True


        return False


    def list_capture_interfaces(self):

        if not self.tshark:
            return []


        try:

            output = subprocess.check_output(
                [self.tshark, "-D"],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10
            )

        except Exception:

            return []


        interfaces = []


        for line in output.splitlines():

            match = re.match(
                r"\s*(\d+)\.\s+(.*)",
                line.strip()
            )

            if match:

                interfaces.append(
                    (
                        match.group(1),
                        match.group(2)
                    )
                )


        return interfaces


    def choose_interface(self):

        interfaces = self.list_capture_interfaces()


        if not interfaces:

            return False


        # Try to match the interface detected by psutil
        if self.interface_name:

            needle = self.interface_name.lower()

            for interface_id, description in interfaces:

                if needle in description.lower():

                    self.interface_id = interface_id

                    return True


        # Only one interface
        if len(interfaces) == 1:

            self.interface_id = interfaces[0][0]
            self.interface_name = interfaces[0][1]

            return True


        print(
            f"\n{Fore.YELLOW}"
            "Capture interfaces:"
        )


        for interface_id, description in interfaces:

            print(
                f"  [{interface_id}] {description}"
            )


        choice = input(
            "\nChọn interface TShark "
            "(Enter = interface đầu tiên): "
        ).strip()


        if not choice:

            choice = interfaces[0][0]


        for interface_id, description in interfaces:

            if interface_id == choice:

                self.interface_id = interface_id
                self.interface_name = description

                return True


        return False


    # ========================================================
    # NMAP DISCOVERY
    # ========================================================

    def subnet(self):

        parts = self.local_ip.split(".")


        if len(parts) == 4:

            return (
                f"{parts[0]}."
                f"{parts[1]}."
                f"{parts[2]}.0/24"
            )


        return None


    def discover(self):

        if not self.nmap:

            print(
                f"{Fore.YELLOW}"
                "[!] Nmap chưa có trong PATH."
            )

            return


        network = self.subnet()


        if not network:

            return


        print(
            f"{Fore.CYAN}"
            f"[*] Nmap discovery: {network}"
        )


        try:

            output = subprocess.check_output(
                [
                    self.nmap,
                    "-sn",
                    network
                ],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30
            )

        except Exception as exc:

            print(
                f"{Fore.YELLOW}"
                f"[!] Nmap discovery lỗi: {exc}"
            )

            return


        current_ip = None
        current_host = "Unknown"


        for line in output.splitlines():

            match = re.search(
                r"Nmap scan report for (.+)",
                line
            )


            if match:

                value = match.group(1).strip()


                ip_match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)$",
                    value
                )


                if ip_match:

                    current_ip = ip_match.group(1)

                else:

                    current_ip = value


                current_host = value

                continue


            match = re.search(
                r"MAC Address:\s+"
                r"([0-9A-Fa-f:-]+)"
                r"(?:\s+\((.*?)\))?",
                line
            )


            if match and current_ip:

                self.devices[current_ip] = {

                    "hostname": current_host,

                    "mac": match.group(1),

                    "vendor": match.group(2) or "",

                    "last_seen":
                        datetime.now().strftime("%H:%M:%S")
                }


                current_ip = None


        print(
            f"{Fore.GREEN}"
            f"[+] Found {len(self.devices)} LAN devices."
        )


    # ========================================================
    # DOMAIN HANDLING
    # ========================================================

    @staticmethod
    def clean_domain(value):

        value = (
            value or ""
        ).strip().lower().rstrip(".")


        if not value:

            return None


        if value in {
            "-",
            "unknown"
        }:

            return None


        return value


    @staticmethod
    def split_fields(line):

        # TShark fields are tab separated.
        return line.rstrip(
            "\r\n"
        ).split("\t")


    # ========================================================
    # DNS CORRELATION
    # ========================================================

    def add_dns_cache(
        self,
        domain,
        ips
    ):

        domain = self.clean_domain(domain)


        if not domain:

            return


        now = time.time()


        for ip in ips:

            ip = ip.strip()


            if ip:

                self.dns_cache[ip] = (
                    domain,
                    now
                )


    def resolve_from_cache(self, ip):

        item = self.dns_cache.get(ip)


        if not item:

            return None


        domain, timestamp = item


        # DNS correlation lifetime:
        # 5 minutes.
        if time.time() - timestamp > 300:

            self.dns_cache.pop(
                ip,
                None
            )

            return None


        return domain


    # ========================================================
    # ACTIVITY RECORDING
    # ========================================================

    def record(
        self,
        src,
        dst,
        domain,
        protocol,
        port,
        source
    ):

        if not src or not dst:

            return


        # Ignore broadcast / multicast noise.
        if dst.startswith(
            (
                "224.",
                "239.",
                "255."
            )
        ):

            return


        # Optional source filter.
        if (
            self.device_filter
            and src != self.device_filter
        ):

            return


        timestamp = (
            datetime.now()
            .strftime("%H:%M:%S")
        )


        activity = Activity(
            timestamp,
            src,
            dst,
            domain,
            protocol,
            port,
            source
        )


        with self.lock:

            self.activities.appendleft(
                activity
            )


            stats = self.stats[src]

            stats["connections"] += 1

            stats["last"] = timestamp


            if domain:

                stats["domains"].add(
                    domain
                )


    # ========================================================
    # LIVE TSHARK CAPTURE
    # ========================================================

    def capture_worker(self):

        # Observe:
        #
        # DNS
        # TLS ClientHello / SNI
        # QUIC
        # TCP SYN
        #
        # Both IPv4 and IPv6 fields are included.

        display_filter = (
            "dns or "
            "tls.handshake.type == 1 or "
            "quic or "
            "tcp.flags.syn == 1 or "
            "udp.dstport == 443"
        )


        fields = [

            "frame.time_epoch",

            "ip.src",
            "ip.dst",

            "ipv6.src",
            "ipv6.dst",

            "tcp.dstport",
            "udp.dstport",

            "dns.flags.response",
            "dns.qry.name",
            "dns.a",
            "dns.aaaa",

            "tls.handshake.extensions_server_name",

            "_ws.col.Protocol",
        ]


        command = [

            self.tshark,

            "-i",
            self.interface_id,

            "-l",

            "-n",

            "-Y",
            display_filter,

            "-T",
            "fields"
        ]


        for field in fields:

            command += [
                "-e",
                field
            ]


        try:

            self.process = subprocess.Popen(

                command,

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                text=True,

                bufsize=1,

                errors="replace"
            )


        except Exception as exc:

            print(
                f"{Fore.RED}"
                f"[-] Không thể khởi động TShark: "
                f"{exc}"
            )

            self.running = False

            return


        while self.running:

            line = (
                self.process.stdout.readline()
            )


            if not line:

                if (
                    self.process.poll()
                    is not None
                ):

                    break

                continue


            parts = self.split_fields(line)


            if len(parts) < len(fields):

                parts += [
                    ""
                ] * (
                    len(fields)
                    - len(parts)
                )


            (

                _timestamp,

                ipv4_src,
                ipv4_dst,

                ipv6_src,
                ipv6_dst,

                tcp_port,
                udp_port,

                dns_response,

                dns_name,

                dns_a,

                dns_aaaa,

                tls_sni,

                protocol

            ) = parts[:13]


            # ------------------------------------------------
            # IPv4 OR IPv6
            # ------------------------------------------------

            src = (
                ipv4_src
                or ipv6_src
            )


            dst = (
                ipv4_dst
                or ipv6_dst
            )


            port = (
                tcp_port
                or udp_port
            )


            # ------------------------------------------------
            # DNS RESPONSE
            # ------------------------------------------------

            if (
                dns_response == "1"
                and dns_name
            ):

                ips = []


                if dns_a:

                    ips.extend(
                        x
                        for x in dns_a.split(",")
                        if x
                    )


                if dns_aaaa:

                    ips.extend(
                        x
                        for x in dns_aaaa.split(",")
                        if x
                    )


                self.add_dns_cache(
                    dns_name,
                    ips
                )


                self.record(
                    src,
                    dst,
                    self.clean_domain(
                        dns_name
                    ),
                    "DNS",
                    port,
                    "DNS"
                )


                continue


            # ------------------------------------------------
            # DNS REQUEST
            # ------------------------------------------------

            if (
                dns_name
                and dns_response != "1"
            ):

                self.record(
                    src,
                    dst,
                    self.clean_domain(
                        dns_name
                    ),
                    "DNS",
                    port,
                    "DNS"
                )


                continue


            # ------------------------------------------------
            # TLS SNI
            # ------------------------------------------------

            domain = self.clean_domain(
                tls_sni
            )


            if domain:

                self.record(
                    src,
                    dst,
                    domain,
                    protocol or "TLS",
                    port,
                    "TLS-SNI"
                )


                continue


            # ------------------------------------------------
            # IP CONNECTION + DNS CORRELATION
            # ------------------------------------------------

            if dst:

                domain = (
                    self.resolve_from_cache(
                        dst
                    )
                )


                if domain:

                    self.record(
                        src,
                        dst,
                        domain,
                        protocol or "TCP/UDP",
                        port,
                        "DNS-cache"
                    )


        try:

            self.process.terminate()

        except Exception:

            pass


        self.process = None


    # ========================================================
    # START / STOP
    # ========================================================

    def start(self):

        if self.running:

            print(
                f"{Fore.YELLOW}"
                "[!] Capture đang chạy."
            )

            return


        if not self.tshark:

            print(
                f"{Fore.RED}"
                "[-] Không tìm thấy TShark."
            )

            return


        if (
            not self.interface_id
            and not self.choose_interface()
        ):

            print(
                f"{Fore.RED}"
                "[-] Không chọn được capture interface."
            )

            return


        self.running = True


        thread = threading.Thread(
            target=self.capture_worker,
            daemon=True
        )


        thread.start()


        print(
            f"{Fore.GREEN}"
            "[+] Capture started"
        )


        print(
            f"    Interface: "
            f"[{self.interface_id}] "
            f"{self.interface_name}"
        )


    def stop(self):

        self.running = False


        if self.process:

            try:

                self.process.terminate()

            except Exception:

                pass


        print(
            f"{Fore.YELLOW}"
            "[*] Monitoring stopped."
        )


    # ========================================================
    # DISPLAY
    # ========================================================

    def print_activity(
        self,
        limit=40
    ):

        with self.lock:

            rows = list(
                self.activities
            )[:limit]


        print(
            f"\n{Fore.CYAN}"
            f"{'TIME':8} "
            f"{'SOURCE':18} "
            f"{'DESTINATION':42} "
            f"{'DOMAIN':38} "
            f"{'SOURCE TYPE':12}"
        )


        print(
            "-" * 125
        )


        for activity in rows:

            destination = (
                f"{activity.dst}:"
                f"{activity.port}"
                if activity.port != "-"
                else activity.dst
            )


            print(
                f"{activity.timestamp:8} "
                f"{activity.src:18} "
                f"{destination:42.42} "
                f"{activity.domain:38.38} "
                f"{activity.source:12}"
            )


    def print_devices(self):

        print(
            f"\n{Fore.CYAN}"
            "DISCOVERED LAN DEVICES"
        )


        print("-" * 90)


        if not self.devices:

            print(
                "No devices discovered yet."
            )


        for ip, info in sorted(
            self.devices.items()
        ):

            print(
                f"{ip:16} "
                f"{info['hostname'][:28]:28} "
                f"{info['mac']:18} "
                f"{info['vendor']}"
            )


    def print_summary(self):

        print(
            f"\n{Fore.CYAN}"
            "DOMAIN ACTIVITY BY SOURCE"
        )


        print("-" * 100)


        with self.lock:

            items = sorted(
                self.stats.items(),
                key=lambda item:
                    item[1]["connections"],
                reverse=True
            )


        if not items:

            print(
                "Chưa có activity."
            )

            return


        for ip, stats in items:

            domains = ", ".join(
                sorted(
                    stats["domains"]
                )
            )


            if not domains:

                domains = (
                    "(no domain observed)"
                )


            print(
                f"\n{Fore.GREEN}"
                f"{ip}"
            )


            print(
                f"  Connections: "
                f"{stats['connections']}"
            )


            print(
                f"  Last seen: "
                f"{stats['last']}"
            )


            print(
                f"  Domains:"
            )


            for domain in sorted(
                stats["domains"]
            ):

                print(
                    f"    - {domain}"
                )


    # ========================================================
    # CLEAR
    # ========================================================

    def clear_activity(self):

        with self.lock:

            self.activities.clear()

            self.stats.clear()

            self.dns_cache.clear()


# ============================================================
# UI
# ============================================================

def clear_screen():

    os.system(
        "cls"
        if os.name == "nt"
        else "clear"
    )


def main():

    monitor = Monitor()


    # --------------------------------------------------------
    # Detect network
    # --------------------------------------------------------

    monitor.detect_local_network()


    clear_screen()


    print(
        f"{Fore.CYAN}"
        "=============================================================="
    )


    print(
        f"{Fore.CYAN}"
        "          LAN DOMAIN MONITOR"
    )


    print(
        f"{Fore.CYAN}"
        "=============================================================="
    )


    print(
        f"Local IP : "
        f"{monitor.local_ip}"
    )


    print(
        f"Interface: "
        f"{monitor.interface_name or 'unknown'}"
    )


    print()


    print(
        "Network metadata only."
    )


    print(
        "HTTPS payloads are not decrypted."
    )


    print(
        "Use only on an authorized lab/network."
    )


    print()


    # --------------------------------------------------------
    # TShark
    # --------------------------------------------------------

    if not monitor.find_tshark():

        print(
            f"{Fore.RED}"
            "[-] TShark not found."
        )


        print(
            "Install Wireshark with TShark first."
        )


        input(
            "\nEnter để thoát..."
        )


        return


    print(
        f"{Fore.GREEN}"
        f"[+] TShark: "
        f"{monitor.tshark}"
    )


    # --------------------------------------------------------
    # Nmap
    # --------------------------------------------------------

    monitor.discover()


    # --------------------------------------------------------
    # Capture interface
    # --------------------------------------------------------

    if not monitor.choose_interface():

        print(
            f"{Fore.RED}"
            "[-] Không chọn được capture interface."
        )


        input(
            "\nEnter để thoát..."
        )


        return


    # ========================================================
    # MAIN LOOP
    # ========================================================

    while True:

        print()


        print(
            f"{Fore.CYAN}"
            "================ MENU ================"
        )


        print(
            "[1] Start live domain monitoring"
        )


        print(
            "[2] Stop monitoring"
        )


        print(
            "[3] Show recent activity"
        )


        print(
            "[4] Show domains by PC/IP"
        )


        print(
            "[5] Show discovered LAN devices"
        )


        print(
            "[6] Filter by source IP"
        )


        print(
            "[7] Clear activity"
        )


        print(
            "[8] Re-run Nmap discovery"
        )


        print(
            "[0] Exit"
        )


        choice = input(
            "\nChọn: "
        ).strip()


        # ----------------------------------------------------
        # START
        # ----------------------------------------------------

        if choice == "1":

            monitor.start()


        # ----------------------------------------------------
        # STOP
        # ----------------------------------------------------

        elif choice == "2":

            monitor.stop()


        # ----------------------------------------------------
        # ACTIVITY
        # ----------------------------------------------------

        elif choice == "3":

            clear_screen()

            monitor.print_activity()

            input(
                "\nEnter..."
            )


        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        elif choice == "4":

            clear_screen()

            monitor.print_summary()

            input(
                "\nEnter..."
            )


        # ----------------------------------------------------
        # DEVICES
        # ----------------------------------------------------

        elif choice == "5":

            clear_screen()

            monitor.print_devices()

            input(
                "\nEnter..."
            )


        # ----------------------------------------------------
        # FILTER
        # ----------------------------------------------------

        elif choice == "6":

            value = input(
                "Source IP "
                "(Enter = all): "
            ).strip()


            monitor.device_filter = (
                value
                if value
                else None
            )


            print(
                f"{Fore.GREEN}"
                "Filter: "
                f"{monitor.device_filter or 'ALL'}"
            )


        # ----------------------------------------------------
        # CLEAR
        # ----------------------------------------------------

        elif choice == "7":

            monitor.clear_activity()


            print(
                f"{Fore.GREEN}"
                "[+] Activity cleared."
            )


        # ----------------------------------------------------
        # NMAP REFRESH
        # ----------------------------------------------------

        elif choice == "8":

            monitor.discover()


        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif choice == "0":

            monitor.stop()

            break


        else:

            print(
                f"{Fore.YELLOW}"
                "Unknown option."
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\nStopped."
        )
