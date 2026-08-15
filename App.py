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
# LAN DOMAIN MONITOR
# Authorized lab / network administration use only.
#
# Collects network METADATA:
#   - Source IP
#   - Destination IP
#   - Port
#   - DNS name
#   - TLS SNI
#   - Protocol
#
# Does NOT decrypt HTTPS or collect passwords/cookies/content.
# ============================================================


# ============================================================
# DEPENDENCIES
# ============================================================

REQUIRED_PACKAGES = [
    "psutil",
    "colorama",
]


def install_missing_packages():

    missing = []

    for package in REQUIRED_PACKAGES:

        try:
            __import__(package)

        except ImportError:
            missing.append(package)


    if missing:

        print(
            "[*] Installing missing packages:",
            ", ".join(missing)
        )

        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                *missing
            ]
        )


install_missing_packages()


import psutil

from colorama import Fore
from colorama import Style
from colorama import init


init(autoreset=True)


# ============================================================
# DATA OBJECT
# ============================================================

class Activity:

    def __init__(
        self,
        timestamp,
        source_ip,
        destination_ip,
        domain,
        protocol,
        port,
        source_type
    ):

        self.timestamp = timestamp

        self.source_ip = source_ip

        self.destination_ip = destination_ip

        self.domain = domain or "-"

        self.protocol = protocol or "-"

        self.port = port or "-"

        self.source_type = source_type


# ============================================================
# MONITOR
# ============================================================

class NetworkMonitor:

    def __init__(self):

        self.local_ipv4 = "127.0.0.1"

        self.interface_name = None

        self.tshark_path = None

        self.nmap_path = shutil.which("nmap")

        self.capture_interface = None

        self.capture_process = None

        self.capture_thread = None

        self.running = False

        self.lock = threading.Lock()

        # Recent network activity.
        self.activities = deque(
            maxlen=2000
        )

        # Discovered LAN devices.
        #
        # IP -> information
        self.devices = {}

        # Source IP statistics.
        #
        # IP -> {
        #   domains: set(),
        #   connections: int,
        #   last_seen: str
        # }
        self.statistics = defaultdict(
            lambda: {
                "domains": set(),
                "connections": 0,
                "last_seen": "-"
            }
        )

        # DNS cache:
        #
        # destination IP ->
        # (
        #   domain,
        #   timestamp
        # )
        self.dns_cache = {}

        # Optional source IP filter.
        self.source_filter = None


    # ========================================================
    # LOCAL NETWORK
    # ========================================================

    def detect_local_network(self):

        """
        Find the preferred local IPv4 address.

        This does not send application data.
        """

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            sock.connect(
                (
                    "1.1.1.1",
                    53
                )
            )

            self.local_ipv4 = (
                sock.getsockname()[0]
            )

            sock.close()

        except OSError:

            pass


        # Find OS interface corresponding
        # to the local IPv4.
        for interface_name, addresses in (
            psutil.net_if_addrs().items()
        ):

            for address in addresses:

                if address.family == socket.AF_INET:

                    if address.address == self.local_ipv4:

                        self.interface_name = (
                            interface_name
                        )

                        return


    # ========================================================
    # FIND TSHARK
    # ========================================================

    def find_tshark(self):

        self.tshark_path = shutil.which(
            "tshark"
        )


        if self.tshark_path:

            return True


        # Windows common locations.
        candidates = [

            r"C:\Program Files\Wireshark\tshark.exe",

            r"C:\Program Files (x86)\Wireshark\tshark.exe",

        ]


        for path in candidates:

            if os.path.isfile(path):

                self.tshark_path = path

                return True


        return False


    # ========================================================
    # TSHARK INTERFACES
    # ========================================================

    def list_tshark_interfaces(self):

        if not self.tshark_path:

            return []


        try:

            result = subprocess.run(

                [
                    self.tshark_path,
                    "-D"
                ],

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                text=True,

                encoding="utf-8",

                errors="replace",

                timeout=15

            )


        except Exception as exc:

            print(
                f"{Fore.RED}"
                f"[-] Không chạy được tshark -D: {exc}"
            )

            return []


        interfaces = []


        for line in result.stdout.splitlines():

            line = line.strip()


            if not line:

                continue


            # Typical:
            #
            # 1. \Device\NPF_{...} (Wi-Fi 3)
            #
            match = re.match(
                r"^(\d+)\.\s+(.*)$",
                line
            )


            if match:

                number = match.group(1)

                description = match.group(2)

                interfaces.append(
                    (
                        number,
                        description
                    )
                )


        return interfaces


    def choose_capture_interface(self):

        interfaces = (
            self.list_tshark_interfaces()
        )


        if not interfaces:

            print(
                f"{Fore.RED}"
                "[-] TShark không trả về interface nào."
            )

            print(
                "    Hãy kiểm tra Npcap/Wireshark."
            )

            return False


        print()

        print(
            f"{Fore.CYAN}"
            "================ CAPTURE INTERFACES ================"
        )


        for number, description in interfaces:

            marker = ""

            if (
                self.interface_name
                and self.interface_name.lower()
                in description.lower()
            ):

                marker = "  <-- detected by OS"


            print(
                f"  [{number}] "
                f"{description}"
                f"{marker}"
            )


        # Try automatic match first.
        if self.interface_name:

            needle = (
                self.interface_name
                .lower()
                .strip()
            )


            for number, description in interfaces:

                if needle in description.lower():

                    answer = input(
                        f"\nDùng [{number}] "
                        f"{description}? [Y/n]: "
                    ).strip().lower()


                    if answer in (
                        "",
                        "y",
                        "yes"
                    ):

                        self.capture_interface = number

                        print(
                            f"{Fore.GREEN}"
                            f"[+] Selected interface "
                            f"[{number}]"
                        )

                        return True


        print()

        choice = input(
            "Nhập số interface muốn capture "
            "(ví dụ 1): "
        ).strip()


        if not choice:

            print(
                f"{Fore.YELLOW}"
                "[!] Không chọn interface."
            )

            return False


        for number, description in interfaces:

            if number == choice:

                self.capture_interface = number

                print(
                    f"{Fore.GREEN}"
                    f"[+] Selected [{number}] "
                    f"{description}"
                )

                return True


        print(
            f"{Fore.RED}"
            "[-] Interface không hợp lệ."
        )

        return False


    # ========================================================
    # NMAP NETWORK
    # ========================================================

    def get_ipv4_subnet(self):

        parts = self.local_ipv4.split(".")


        if len(parts) != 4:

            return None


        return (
            f"{parts[0]}."
            f"{parts[1]}."
            f"{parts[2]}."
            f"0/24"
        )


    def discover_devices(self):

        if not self.nmap_path:

            print(
                f"{Fore.YELLOW}"
                "[!] Không tìm thấy Nmap trong PATH."
            )

            return


        subnet = (
            self.get_ipv4_subnet()
        )


        if not subnet:

            print(
                f"{Fore.YELLOW}"
                "[!] Không xác định được IPv4 subnet."
            )

            return


        print()

        print(
            f"{Fore.CYAN}"
            f"[*] Nmap discovery: {subnet}"
        )


        try:

            result = subprocess.run(

                [
                    self.nmap_path,

                    "-sn",

                    subnet
                ],

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                text=True,

                encoding="utf-8",

                errors="replace",

                timeout=60
            )


        except subprocess.TimeoutExpired:

            print(
                f"{Fore.YELLOW}"
                "[!] Nmap timeout."
            )

            return


        except Exception as exc:

            print(
                f"{Fore.RED}"
                f"[-] Nmap error: {exc}"
            )

            return


        output = result.stdout


        current_ip = None

        current_hostname = "Unknown"


        found = 0


        for line in output.splitlines():

            line = line.strip()


            # ----------------------------------------------
            # Nmap scan report
            # ----------------------------------------------

            match = re.match(
                r"Nmap scan report for (.+)",
                line
            )


            if match:

                value = (
                    match.group(1)
                    .strip()
                )


                # Example:
                #
                # hostname (192.168.1.10)
                #
                hostname_match = re.match(
                    r"(.+?)\s+\((\d+\.\d+\.\d+\.\d+)\)$",
                    value
                )


                if hostname_match:

                    current_hostname = (
                        hostname_match.group(1)
                    )

                    current_ip = (
                        hostname_match.group(2)
                    )


                else:

                    # Example:
                    #
                    # 192.168.1.10
                    #
                    ip_match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)",
                        value
                    )


                    if ip_match:

                        current_ip = (
                            ip_match.group(1)
                        )

                        current_hostname = (
                            value
                        )

                    else:

                        current_ip = None

                        current_hostname = (
                            value
                        )


                # IMPORTANT:
                # Save device immediately.
                #
                # We do NOT wait for MAC Address.
                if current_ip:

                    self.devices[
                        current_ip
                    ] = {

                        "hostname":
                            current_hostname,

                        "mac":
                            "",

                        "vendor":
                            "",

                        "last_seen":
                            datetime.now().strftime(
                                "%H:%M:%S"
                            )
                    }

                    found += 1


                continue


            # ----------------------------------------------
            # MAC Address
            # ----------------------------------------------

            match = re.search(
                r"MAC Address:\s+"
                r"([0-9A-Fa-f:-]+)"
                r"(?:\s+\((.*?)\))?",
                line
            )


            if (
                match
                and current_ip
                and current_ip in self.devices
            ):

                self.devices[
                    current_ip
                ]["mac"] = (
                    match.group(1)
                )


                self.devices[
                    current_ip
                ]["vendor"] = (
                    match.group(2)
                    or ""
                )


        print()

        print(
            f"{Fore.GREEN}"
            f"[+] Nmap found "
            f"{len(self.devices)} device(s)."
        )


        if result.stderr.strip():

            # Only display short useful errors.
            stderr_text = (
                result.stderr.strip()
            )

            if stderr_text:

                print(
                    f"{Fore.YELLOW}"
                    f"[Nmap] {stderr_text[:500]}"
                )


    # ========================================================
    # DOMAIN CLEANING
    # ========================================================

    @staticmethod
    def clean_domain(value):

        if value is None:

            return None


        value = str(value)

        value = (
            value
            .strip()
            .lower()
            .rstrip(".")
        )


        if not value:

            return None


        if value in (
            "-",
            "unknown",
            "none"
        ):

            return None


        return value


    # ========================================================
    # DNS CACHE
    # ========================================================

    def add_dns_mapping(
        self,
        domain,
        ip_addresses
    ):

        domain = (
            self.clean_domain(domain)
        )


        if not domain:

            return


        now = time.time()


        for ip in ip_addresses:

            ip = ip.strip()


            if not ip:

                continue


            self.dns_cache[
                ip
            ] = (
                domain,
                now
            )


    def lookup_cached_domain(
        self,
        destination_ip
    ):

        item = self.dns_cache.get(
            destination_ip
        )


        if not item:

            return None


        domain, timestamp = item


        # DNS mapping expires after 5 minutes.
        if (
            time.time() - timestamp
            > 300
        ):

            self.dns_cache.pop(
                destination_ip,
                None
            )

            return None


        return domain


    # ========================================================
    # RECORD ACTIVITY
    # ========================================================

    def record_activity(
        self,
        source_ip,
        destination_ip,
        domain,
        protocol,
        port,
        source_type
    ):

        if not source_ip:

            return


        if not destination_ip:

            return


        # Optional filter.
        if (
            self.source_filter
            and source_ip
            != self.source_filter
        ):

            return


        # Ignore IPv4 broadcast/multicast.
        if destination_ip.startswith(
            (
                "224.",
                "239.",
                "255."
            )
        ):

            return


        timestamp = (
            datetime.now()
            .strftime("%H:%M:%S")
        )


        activity = Activity(

            timestamp,

            source_ip,

            destination_ip,

            domain,

            protocol,

            port,

            source_type
        )


        with self.lock:

            self.activities.appendleft(
                activity
            )


            statistics = (
                self.statistics[
                    source_ip
                ]
            )


            statistics[
                "connections"
            ] += 1


            statistics[
                "last_seen"
            ] = timestamp


            if domain:

                statistics[
                    "domains"
                ].add(
                    domain
                )


    # ========================================================
    # TSHARK CAPTURE
    # ========================================================

    def capture_worker(self):

        """
        Capture metadata from the selected interface.

        Filters:
            DNS
            TLS ClientHello / SNI
            QUIC
            TCP SYN
            UDP/443

        Both IPv4 and IPv6 are supported.
        """


        display_filter = (
            "dns or "
            "tls.handshake.type == 1 or "
            "quic or "
            "tcp.flags.syn == 1 or "
            "udp.dstport == 443"
        )


        fields = [

            "frame.time_epoch",

            # IPv4
            "ip.src",
            "ip.dst",

            # IPv6
            "ipv6.src",
            "ipv6.dst",

            # Ports
            "tcp.dstport",
            "udp.dstport",

            # DNS
            "dns.flags.response",
            "dns.qry.name",
            "dns.a",
            "dns.aaaa",

            # TLS SNI
            "tls.handshake.extensions_server_name",

            # Protocol
            "_ws.col.Protocol",
        ]


        command = [

            self.tshark_path,

            "-i",
            self.capture_interface,

            "-l",

            "-n",

            "-Y",
            display_filter,

            "-T",
            "fields",

            "-E",
            "separator=\t",

            "-E",
            "quote=n",

            "-E",
            "occurrence=a"
        ]


        for field in fields:

            command.extend(
                [
                    "-e",
                    field
                ]
            )


        print()

        print(
            f"{Fore.CYAN}"
            "[*] Starting TShark..."
        )


        print(
            f"{Fore.CYAN}"
            f"[*] Command interface: "
            f"{self.capture_interface}"
        )


        try:

            self.capture_process = (
                subprocess.Popen(

                    command,

                    stdout=subprocess.PIPE,

                    stderr=subprocess.PIPE,

                    text=True,

                    encoding="utf-8",

                    errors="replace",

                    bufsize=1
                )
            )


        except Exception as exc:

            print(
                f"{Fore.RED}"
                f"[-] Không thể start TShark:"
                f" {exc}"
            )

            self.running = False

            return


        print(
            f"{Fore.GREEN}"
            "[+] TShark capture running."
        )


        # ----------------------------------------------------
        # Read stderr in background.
        # ----------------------------------------------------

        def read_errors():

            try:

                for error_line in (
                    self.capture_process.stderr
                ):

                    error_line = (
                        error_line.strip()
                    )


                    if error_line:

                        print(
                            f"{Fore.YELLOW}"
                            f"[TShark] "
                            f"{error_line}"
                        )

            except Exception:

                pass


        threading.Thread(
            target=read_errors,
            daemon=True
        ).start()


        # ----------------------------------------------------
        # Main packet processing loop.
        # ----------------------------------------------------

        while self.running:

            line = (
                self.capture_process
                .stdout
                .readline()
            )


            if not line:

                if (
                    self.capture_process
                    .poll()
                    is not None
                ):

                    print(
                        f"{Fore.YELLOW}"
                        "[!] TShark stopped."
                    )

                    break


                time.sleep(0.01)

                continue


            parts = (
                line
                .rstrip("\r\n")
                .split("\t")
            )


            # We expect 13 fields.
            if len(parts) < 13:

                parts.extend(
                    [""] *
                    (
                        13 - len(parts)
                    )
                )


            (
                frame_time,

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
            # Select IPv4 OR IPv6.
            # ------------------------------------------------

            source_ip = (
                ipv4_src
                or ipv6_src
            )


            destination_ip = (
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

                addresses = []


                if dns_a:

                    addresses.extend(
                        dns_a.split(",")
                    )


                if dns_aaaa:

                    addresses.extend(
                        dns_aaaa.split(",")
                    )


                self.add_dns_mapping(
                    dns_name,
                    addresses
                )


                self.record_activity(

                    source_ip,

                    destination_ip,

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

                self.record_activity(

                    source_ip,

                    destination_ip,

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

            sni_domain = (
                self.clean_domain(
                    tls_sni
                )
            )


            if sni_domain:

                self.record_activity(

                    source_ip,

                    destination_ip,

                    sni_domain,

                    protocol or "TLS",

                    port,

                    "TLS-SNI"
                )


                continue


            # ------------------------------------------------
            # IP + DNS CACHE
            # ------------------------------------------------

            if destination_ip:

                cached_domain = (
                    self.lookup_cached_domain(
                        destination_ip
                    )
                )


                if cached_domain:

                    self.record_activity(

                        source_ip,

                        destination_ip,

                        cached_domain,

                        protocol or "TCP/UDP",

                        port,

                        "DNS-CACHE"
                    )


        # ----------------------------------------------------
        # Cleanup.
        # ----------------------------------------------------

        try:

            self.capture_process.terminate()

        except Exception:

            pass


        self.capture_process = None


        print(
            f"{Fore.YELLOW}"
            "[*] Capture worker exited."
        )


    # ========================================================
    # START CAPTURE
    # ========================================================

    def start_capture(self):

        if self.running:

            print(
                f"{Fore.YELLOW}"
                "[!] Capture đã chạy."
            )

            return


        if not self.capture_interface:

            if not self.choose_capture_interface():

                return


        self.running = True


        self.capture_thread = threading.Thread(

            target=self.capture_worker,

            daemon=True
        )


        self.capture_thread.start()


    # ========================================================
    # STOP CAPTURE
    # ========================================================

    def stop_capture(self):

        if not self.running:

            print(
                f"{Fore.YELLOW}"
                "[!] Capture không chạy."
            )

            return


        self.running = False


        if self.capture_process:

            try:

                self.capture_process.terminate()

            except Exception:

                pass


        print(
            f"{Fore.YELLOW}"
            "[*] Capture stopped."
        )


    # ========================================================
    # RECENT ACTIVITY
    # ========================================================

    def show_recent_activity(
        self,
        limit=50
    ):

        with self.lock:

            activities = list(
                self.activities
            )[:limit]


        print()

        print(
            f"{Fore.CYAN}"
            "================ RECENT ACTIVITY ================"
        )


        if not activities:

            print(
                "Chưa có activity."
            )

            return


        print(
            f"{'TIME':8} "
            f"{'SOURCE':18} "
            f"{'DESTINATION':42} "
            f"{'DOMAIN':42} "
            f"{'TYPE':10}"
        )


        print(
            "-" * 135
        )


        for activity in activities:

            destination = (
                activity.destination_ip
            )


            if activity.port != "-":

                destination += (
                    ":"
                    + activity.port
                )


            print(

                f"{activity.timestamp:8} "

                f"{activity.source_ip:18} "

                f"{destination:42.42} "

                f"{activity.domain:42.42} "

                f"{activity.source_type:10}"
            )


    # ========================================================
    # DOMAIN SUMMARY
    # ========================================================

    def show_domain_summary(self):

        with self.lock:

            entries = sorted(

                self.statistics.items(),

                key=lambda item:
                    item[1]["connections"],

                reverse=True
            )


        print()

        print(
            f"{Fore.CYAN}"
            "================ DOMAINS BY PC ================"
        )


        if not entries:

            print(
                "Chưa quan sát được domain."
            )

            return


        for source_ip, stats in entries:

            print()

            print(
                f"{Fore.GREEN}"
                f"{source_ip}"
            )


            print(
                f"  Connections: "
                f"{stats['connections']}"
            )


            print(
                f"  Last seen: "
                f"{stats['last_seen']}"
            )


            domains = sorted(
                stats["domains"]
            )


            if not domains:

                print(
                    "  Domains: -"
                )

                continue


            print(
                "  Domains:"
            )


            for domain in domains:

                print(
                    f"    - {domain}"
                )


    # ========================================================
    # DEVICES
    # ========================================================

    def show_devices(self):

        print()

        print(
            f"{Fore.CYAN}"
            "================ LAN DEVICES ================"
        )


        if not self.devices:

            print(
                "Chưa có device."
            )

            return


        print(
            f"{'IP':16} "
            f"{'HOSTNAME':30} "
            f"{'MAC':20} "
            f"{'VENDOR':25} "
            f"{'SEEN':10}"
        )


        print(
            "-" * 110
        )


        for ip, info in sorted(
            self.devices.items()
        ):

            print(

                f"{ip:16} "

                f"{info['hostname'][:30]:30} "

                f"{info['mac'] or '-':20} "

                f"{info['vendor'][:25]:25} "

                f"{info['last_seen']:10}"
            )


    # ========================================================
    # FILTER
    # ========================================================

    def set_source_filter(self):

        value = input(
            "\nSource IP "
            "(Enter = all): "
        ).strip()


        if value:

            self.source_filter = value

            print(
                f"{Fore.GREEN}"
                f"[+] Filter = {value}"
            )

        else:

            self.source_filter = None

            print(
                f"{Fore.GREEN}"
                "[+] Filter disabled."
            )


    # ========================================================
    # CLEAR
    # ========================================================

    def clear_activity(self):

        with self.lock:

            self.activities.clear()

            self.statistics.clear()

            self.dns_cache.clear()


        print(
            f"{Fore.GREEN}"
            "[+] Activity cleared."
        )


# ============================================================
# UI
# ============================================================

def clear_screen():

    os.system(
        "cls"
        if os.name == "nt"
        else "clear"
    )


def print_header(
    monitor
):

    print(
        f"{Fore.CYAN}"
        "=============================================================="
    )


    print(
        f"{Fore.CYAN}"
        "                 LAN DOMAIN MONITOR"
    )


    print(
        f"{Fore.CYAN}"
        "=============================================================="
    )


    print(
        f"Local IPv4 : "
        f"{monitor.local_ipv4}"
    )


    print(
        f"OS Interface : "
        f"{monitor.interface_name or 'Unknown'}"
    )


    print(
        f"TShark : "
        f"{monitor.tshark_path or 'Not found'}"
    )


    print(
        f"Nmap : "
        f"{monitor.nmap_path or 'Not found'}"
    )


    print()


    print(
        f"{Fore.YELLOW}"
        "Metadata only:"
    )


    print(
        "  DNS / TLS SNI / IP / port / protocol"
    )


    print(
        "  HTTPS payload is NOT decrypted."
    )


    print()


# ============================================================
# MAIN
# ============================================================

def main():

    monitor = NetworkMonitor()


    # --------------------------------------------------------
    # Detect local network.
    # --------------------------------------------------------

    monitor.detect_local_network()


    clear_screen()


    print_header(
        monitor
    )


    # --------------------------------------------------------
    # TShark.
    # --------------------------------------------------------

    if not monitor.find_tshark():

        print(
            f"{Fore.RED}"
            "[-] Không tìm thấy TShark."
        )


        print(
            "Cài Wireshark + Npcap trước."
        )


        input(
            "\nEnter để thoát..."
        )


        return


    print(
        f"{Fore.GREEN}"
        f"[+] TShark: "
        f"{monitor.tshark_path}"
    )


    # --------------------------------------------------------
    # Nmap discovery.
    # --------------------------------------------------------

    monitor.discover_devices()


    # --------------------------------------------------------
    # Interface.
    # --------------------------------------------------------

    if not monitor.choose_capture_interface():

        print()

        print(
            f"{Fore.RED}"
            "[-] Không chọn được capture interface."
        )


        input(
            "\nEnter để thoát..."
        )


        return


    # ========================================================
    # MENU
    # ========================================================

    while True:

        print()

        print(
            f"{Fore.CYAN}"
            "==================== MENU ===================="
        )


        print(
            "[1] Start live monitoring"
        )


        print(
            "[2] Stop monitoring"
        )


        print(
            "[3] Recent network activity"
        )


        print(
            "[4] Domains by PC/IP"
        )


        print(
            "[5] LAN devices"
        )


        print(
            "[6] Filter source IP"
        )


        print(
            "[7] Clear activity"
        )


        print(
            "[8] Refresh Nmap"
        )


        print(
            "[9] Re-select capture interface"
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

            monitor.start_capture()


        # ----------------------------------------------------
        # STOP
        # ----------------------------------------------------

        elif choice == "2":

            monitor.stop_capture()


        # ----------------------------------------------------
        # ACTIVITY
        # ----------------------------------------------------

        elif choice == "3":

            clear_screen()

            monitor.show_recent_activity()

            input(
                "\nEnter..."
            )


        # ----------------------------------------------------
        # DOMAINS
        # ----------------------------------------------------

        elif choice == "4":

            clear_screen()

            monitor.show_domain_summary()

            input(
                "\nEnter..."
            )


        # ----------------------------------------------------
        # DEVICES
        # ----------------------------------------------------

        elif choice == "5":

            clear_screen()

            monitor.show_devices()

            input(
                "\nEnter..."
            )


        # ----------------------------------------------------
        # FILTER
        # ----------------------------------------------------

        elif choice == "6":

            monitor.set_source_filter()


        # ----------------------------------------------------
        # CLEAR
        # ----------------------------------------------------

        elif choice == "7":

            monitor.clear_activity()


        # ----------------------------------------------------
        # NMAP REFRESH
        # ----------------------------------------------------

        elif choice == "8":

            monitor.discover_devices()


        # ----------------------------------------------------
        # RESELECT INTERFACE
        # ----------------------------------------------------

        elif choice == "9":

            if monitor.running:

                print(
                    f"{Fore.YELLOW}"
                    "[!] Hãy stop monitoring trước."
                )

            else:

                monitor.capture_interface = None

                monitor.choose_capture_interface()


        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif choice == "0":

            monitor.stop_capture()

            break


        else:

            print(
                f"{Fore.YELLOW}"
                "[!] Lựa chọn không hợp lệ."
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()

        print(
            f"{Fore.YELLOW}"
            "[*] Stopped by user."
        )

    except Exception as exc:

        print()

        print(
            f"{Fore.RED}"
            "================================================"
        )

        print(
            f"{Fore.RED}"
            "FATAL ERROR"
        )

        print(
            f"{Fore.RED}"
            f"{exc}"
        )

        print(
            f"{Fore.RED}"
            "================================================"
        )

        input(
            "\nEnter để thoát..."
        )
