#!/usr/bin/env python3
"""
PRTG Hybrid Audit Tool
======================
Bridges the gap between known assets (PRTG) and unknown assets (Active Scan).
identifies "Unmonitored Assets" (Upsell Opportunities).

Usage:
    python prtg_hybrid_audit.py
"""

__version__ = "1.3.1"

import argparse
import csv
import ipaddress
import logging
import socket
import sys
import yaml
import concurrent.futures
import requests
import subprocess
import shutil
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup, BaseMacLookup

# Update lookup location to avoid permission issues if possible, or handle caching
BaseMacLookup.cache_path = "mac-vendors.txt"

# Optional imports with safe handling to avoid immediate crashes if missing
try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from impacket.dcerpc.v5 import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
except ImportError:
    wmi = None

try:
    from pysnmp.hlapi import (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
    )
except ImportError:
    pass


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


class PRTGClient:
    """Handles interaction with the PRTG Core API."""

    def __init__(self, url, apitoken):
        self.url = url.rstrip("/")
        self.apitoken = apitoken
        self.verify_ssl = False  # Usually internal PRTGs use self-signed certs

    def fetch_devices(self):
        """
        Fetches all devices from PRTG.
        Returns a dictionary keyed by IP address.
        """
        logger.info(f"Fetching devices from PRTG Core at {self.url}...")

        # PRTG API to get devices
        # content=devices
        # columns=objid,host,device,active,totalsens,totalsens_raw,sensor

        endpoint = f"{self.url}/api/table.json"
        params = {
            "content": "devices",
            "output": "json",
            "columns": "objid,host,device,active,totalsens,totalsens_raw,sensor",
            "apitoken": self.apitoken,
        }

        try:
            response = requests.get(
                endpoint, params=params, verify=self.verify_ssl, timeout=10
            )
            response.raise_for_status()
            data = response.json()

            devices = {}
            for item in data.get("devices", []):
                host = item.get("host")
                # Try to normalize host to IP if possible, or keep hostname
                # For this exercise, we focus on IP matching
                try:
                    # Simple check if it looks like an IP
                    ipaddress.ip_address(host)
                    devices[host] = item
                except ValueError:
                    # Could be a DNS name, we might want to resolve it or just store it
                    # For hybrid audit, we compare IPs usually.
                    # Let's try to resolve it? Or just store as is.
                    # Storing as is for now to avoid DNS timeout delays during import
                    devices[host] = item

            logger.info(f"Imported {len(devices)} devices (active & paused) from PRTG.")
            return devices

        except Exception as e:
            logger.error(f"Failed to fetch PRTG devices: {e}")
            return {}


class NetworkScanner:
    """Handles active network scanning and deep identification."""

    def __init__(self, config):
        self.config = config
        self.cidrs = config.get("scan", {}).get("cidr_ranges", [])
        self.ports = config.get("scan", {}).get("scan_ports", [22, 135, 161, 443])
        self.timeout = config.get("scan", {}).get("timeout", 1.0)
        self.creds = config.get("credentials", {})
        self.mac_lookup = MacLookup()
        try:
            self.mac_lookup.update_vendors()  # Downloads OUI list
        except Exception:
            pass  # Maybe offline, use existing cache if available or fail gracefully

    def scan_network(self):
        """
        Iterates through CIDRs and scans for live hosts.
        Returns a list of dicts with discovery data.
        """
        discovered_hosts = []

        # Pre-load ARP table (especially for WSL)
        arp_table = self._get_arp_table()
        logger.info(f"Loaded {len(arp_table)} devices from ARP table.")

        for cidr in self.cidrs:
            logger.info(f"Scanning Network: {cidr}")

            try:
                network = ipaddress.ip_network(cidr, strict=False)
                hosts = list(network.hosts())  # This can be large, careful

                # Check for live hosts first via simple socket connect to common ports
                # Threaded scan
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    future_to_ip = {
                        executor.submit(
                            self._check_host, str(ip), arp_table.get(str(ip))
                        ): str(ip)
                        for ip in hosts
                    }

                    for future in concurrent.futures.as_completed(future_to_ip):
                        result = future.result()
                        if result:
                            discovered_hosts.append(result)

            except Exception as e:
                logger.error(f"Error scanning CIDR {cidr}: {e}")

        return discovered_hosts

    def _check_host(self, ip, known_mac=None):
        """Checks if a host is alive on any of the target ports OR if it was in ARP."""
        open_ports = []
        is_alive = False

        # If in ARP, it's alive (Layer 2)
        if known_mac:
            is_alive = True

        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    is_alive = True
                sock.close()
            except Exception:
                pass

        if is_alive:
            # Host is alive, try deep ID
            info = self._deep_identify(ip, open_ports, known_mac)
            return info
        return None

    def _deep_identify(self, ip, open_ports, known_mac=None):
        """Attempts to identify OS/Hardware via SNMP, SSH, WMI."""
        info = {
            "ip": ip,
            "open_ports": open_ports,
            "os": "Unknown",
            "vendor": "Unknown",
            "model": "Unknown",
            "mac": known_mac or self._get_mac(ip),
            "mac_vendor": "Unknown",
        }

        if info["mac"]:
            info["mac_vendor"] = self._lookup_vendor(info["mac"])
            # If generic vendor is unknown, use MAC vendor as hint
            if info["vendor"] == "Unknown" and info["mac_vendor"] != "Unknown":
                info["vendor"] = info["mac_vendor"]

        # Priority 1: SNMP (Fast, good for network gear)
        if 161 in open_ports:
            self._probe_snmp(ip, info)

        # Priority 2: SSH (Linux/Unix)
        if 22 in open_ports and info["os"] == "Unknown":
            self._probe_ssh(ip, info)

        # Priority 3: WMI (Windows)
        if 135 in open_ports and info["os"] == "Unknown":
            self._probe_wmi(ip, info)

        # Reverse DNS Lookup
        info["hostname"] = self._get_hostname(ip)

        logger.info(f"Found {ip} -> Hostname: {info['hostname']}, OS: {info['os']}, Vendor: {info['vendor']}")
        return info

    def _get_hostname(self, ip):
        """Resolves IP to hostname via Reverse DNS."""
        # socket.gethostbyaddr() uses the global default timeout and can block
        # for a long time on some systems. Temporarily set a reasonable timeout
        # (matching other network operations) and then restore the original.
        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception as e:
            logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
            return ""
        finally:
            socket.setdefaulttimeout(prev_timeout)

    def _probe_snmp(self, ip, info):
        """Query SNMP sysDescr."""
        community = self.creds.get("snmp_community", "public")
        try:
            # Try SNMP v2c first
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=self.timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.2.0")),  # sysObjectID
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if not errorIndication and not errorStatus:
                sys_descr = str(varBinds[0][1])
                try:
                    _ = str(varBinds[1][1])
                except Exception:
                    pass

                info["os"] = f"SNMP Detected: {sys_descr[:50]}..."

                # Use data-driven vendor detection
                self._identify_vendor_from_snmp(sys_descr, info)

                logger.info(
                    f"SNMP Identification for {ip}: {info['vendor']} - {info['os']}"
                )

        except Exception:
            # logger.debug(f"SNMP probe failed for {ip}: {e}")
            pass

    def _identify_vendor_from_snmp(self, sys_descr, info):
        """
        Identify vendor/model/os from SNMP sysDescr using pattern matching.
        Uses a data-driven approach to reduce complexity.
        """
        lower_descr = sys_descr.lower()

        # Pattern definitions: (keywords, vendor, model, os_override)
        # keywords can be a string or tuple of strings (any match)
        # model and os_override can be None to skip setting
        vendor_patterns = [
            # Network Equipment
            (("cisco",), "Cisco", "Network Device", None),
            (("fortinet", "fortigate", "fortiswitch"), "Fortinet",
             "Network/Security Device", None),
            (("mikrotik", "routeros"), "MikroTik", "Network Device", None),
            (("ubiquiti", "unifi", "edgeos"), "Ubiquiti", "Network Device", None),
            (("aruba",), "HPE Aruba", "Network Device", None),
            (("juniper",), "Juniper", "Network Device", None),
            (("palo alto",), "Palo Alto Networks", "Firewall", None),
            (("moxa",), "Moxa", "Industrial Network Device", None),
            (("insys", "icom"), "Insys icom", "Industrial Router", None),
            (("scalance",), "Siemens SCALANCE", "Industrial Network Device", None),
            (("hirschmann",), "Hirschmann", "Industrial Switch", None),
            # Storage Systems
            (("netapp", "ontap", "data ontap"), "NetApp", "Storage System", "ONTAP"),
            (("synology",), "Synology", "NAS", "DSM"),
            (("qnap",), "QNAP", "NAS", None),
            (("emc", "isilon"), "Dell EMC", "Storage System", None),
            # Servers/OS
            (("windows",), "Microsoft", None, "Windows"),
            (("linux",), "Linux Generic", None, "Linux"),
            (("vmware", "esxi"), "VMware", None, "ESXi"),
            (("dell", "poweredge", "idrac"), "Dell", "Server", None),
            (("lenovo", "thinkserver", "thinksystem"), "Lenovo", "Server", None),
            (("hpe", "proliant", "ilo"), "HPE", "Server", None),
            (("supermicro",), "Supermicro", "Server", None),
            # Environmental/IoT Sensors
            (("kentix",), "Kentix", "Environmental Sensor", None),
            (("rittal",), "Rittal", "Environmental/PDU", None),
            (("apc", "schneider"), "APC/Schneider Electric", "UPS/PDU", None),
            (("eaton",), "Eaton", "UPS/PDU", None),
            (("gude",), "Gude", "PDU/Sensor", None),
            (("raritan",), "Raritan", "PDU/KVM", None),
            (("vertiv", "liebert"), "Vertiv", "Cooling/UPS", None),
            # Cameras/Security
            (("axis",), "AXIS", "IP Camera", None),
            (("hikvision",), "Hikvision", "IP Camera", None),
            (("dahua",), "Dahua", "IP Camera", None),
            (("hanwha", "wisenet"), "Hanwha/Wisenet", "IP Camera", None),
            # Industrial/Automation
            (("siemens", "simatic"), "Siemens", "Industrial Controller", None),
            (("phoenix", "plcnext"), "Phoenix Contact", "Industrial Controller", None),
            (("beckhoff",), "Beckhoff", "Industrial Controller", None),
            (("rockwell", "allen-bradley"), "Rockwell/Allen-Bradley",
             "Industrial Controller", None),
            (("bender",), "Bender", "Power Monitoring", None),
            (("wago",), "WAGO", "Industrial Controller", None),
            # Printers
            (("xerox",), "Xerox", "Printer", None),
            (("epson",), "Epson", "Printer", None),
            (("brother",), "Brother", "Printer", None),
            (("kyocera",), "Kyocera", "Printer", None),
            (("ricoh",), "Ricoh", "Printer", None),
            (("lexmark",), "Lexmark", "Printer", None),
            # Consumer/SMB Network Equipment
            (("tp-link", "tplink"), "TP-Link", "Network Device", None),
            (("d-link", "dlink"), "D-Link", "Network Device", None),
            (("netgear",), "NETGEAR", "Network Device", None),
            (("zyxel",), "Zyxel", "Network Device", None),
            (("linksys",), "Linksys", "Network Device", None),
            # Enterprise Network Equipment
            (("extreme",), "Extreme Networks", "Network Device", None),
            (("alcatel", "nokia"), "Alcatel-Lucent/Nokia", "Network Device", None),
            (("brocade",), "Brocade", "Network/Storage Switch", None),
            (("ruckus",), "Ruckus", "Wireless AP", None),
            (("aerohive",), "Aerohive", "Wireless AP", None),
            (("meraki",), "Cisco Meraki", "Network Device", None),
            (("sonicwall",), "SonicWall", "Firewall", None),
            (("watchguard",), "WatchGuard", "Firewall", None),
            (("sophos",), "Sophos", "Firewall/Security", None),
            (("barracuda",), "Barracuda", "Security Appliance", None),
            (("f5", "big-ip"), "F5", "Load Balancer", None),
            (("a10",), "A10 Networks", "Load Balancer", None),
            # VoIP/Telecom
            (("avaya",), "Avaya", "VoIP/Phone System", None),
            (("mitel",), "Mitel", "VoIP/Phone System", None),
            (("polycom", "poly"), "Polycom/Poly", "VoIP Phone/Conference", None),
            (("yealink",), "Yealink", "VoIP Phone", None),
            (("grandstream",), "Grandstream", "VoIP Phone", None),
            (("snom",), "Snom", "VoIP Phone", None),
            (("audiocodes",), "AudioCodes", "VoIP Gateway", None),
            (("asterisk", "freepbx"), "Asterisk/FreePBX", "PBX Server", None),
            # More Storage
            (("nimble",), "HPE Nimble", "Storage", None),
            (("3par",), "HPE 3PAR", "Storage", None),
            (("hitachi",), "Hitachi", "Storage System", None),
            (("buffalo",), "Buffalo", "NAS", None),
            (("drobo",), "Drobo", "NAS", None),
            (("asustor",), "Asustor", "NAS", None),
            (("terramaster",), "TerraMaster", "NAS", None),
            # More Cameras
            (("vivotek",), "Vivotek", "IP Camera", None),
            (("mobotix",), "Mobotix", "IP Camera", None),
            (("pelco",), "Pelco", "IP Camera", None),
            (("uniview",), "Uniview", "IP Camera", None),
            (("geovision",), "GeoVision", "IP Camera", None),
            (("foscam",), "Foscam", "IP Camera", None),
            (("reolink",), "Reolink", "IP Camera", None),
            (("amcrest",), "Amcrest", "IP Camera", None),
            # More Environmental/Power
            (("geist",), "Geist", "PDU/Environmental", None),
            (("servertech", "server technology"), "Server Technology", "PDU", None),
            (("cyberpower",), "CyberPower", "UPS/PDU", None),
            (("tripp", "tripplite"), "Tripp Lite", "UPS/PDU", None),
            (("paessler", "prtg"), "Paessler", "PRTG Probe", None),
            (("digi",), "Digi International", "Serial/IoT Gateway", None),
            (("advantech",), "Advantech", "Industrial IoT", None),
            # Virtualization/Hypervisors
            (("proxmox",), "Proxmox", None, "Proxmox VE"),
            (("nutanix",), "Nutanix", "HCI", None),
            (("hyper-v",), "Microsoft", None, "Hyper-V"),
            # More Industrial/Automation
            (("abb",), "ABB", "Industrial Controller", None),
            (("omron",), "Omron", "Industrial Controller", None),
            (("emerson",), "Emerson", "Industrial Controller", None),
            (("honeywell",), "Honeywell", "Industrial/Building", None),
            (("keyence",), "Keyence", "Industrial Sensor/Controller", None),
            (("ifm",), "IFM", "Industrial Sensor", None),
            (("pepperl", "fuchs"), "Pepperl+Fuchs", "Industrial Sensor", None),
            (("balluff",), "Balluff", "Industrial Sensor", None),
            (("turck",), "Turck", "Industrial Sensor", None),
        ]

        # Patterns requiring additional context checks
        special_patterns = [
            # Bosch camera needs camera/dinion context
            (("bosch",), ("camera", "dinion"), "Bosch", "IP Camera", None),
            # HP printer needs printer context
            (("hp",), ("printer", "laserjet", "officejet"), "HP", "Printer", None),
            # Canon printer needs print context
            (("canon",), ("print",), "Canon", "Printer", None),
            # ASUS network needs router/switch context
            (("asus",), ("router", "switch"), "ASUS", "Network Device", None),
            # Citrix ADC needs netscaler/adc context
            (("citrix",), ("netscaler", "adc"), "Citrix", "Load Balancer", None),
            # XenServer needs server context
            (("xen",), ("server",), "Citrix", None, "XenServer"),
            # KVM needs qemu/libvirt context
            (("kvm",), ("qemu", "libvirt"), "Linux", None, "KVM"),
            # Pure Storage needs storage context
            (("pure",), ("storage",), "Pure Storage", "Flash Array", None),
            # IBM storage needs storage context
            (("ibm",), ("storage", "storwize", "flashsystem"), "IBM",
             "Storage System", None),
            # Schneider PLC needs modicon/plc context
            (("schneider",), ("modicon", "plc"), "Schneider Electric",
             "Industrial Controller", None),
            # Mitsubishi PLC needs plc/melsec context
            (("mitsubishi",), ("plc", "melsec"), "Mitsubishi",
             "Industrial Controller", None),
            # SICK sensor needs sensor/scanner context
            (("sick",), ("sensor", "scanner"), "SICK", "Industrial Sensor", None),
            # Banner sensor needs engineering context
            (("banner",), ("engineering",), "Banner Engineering",
             "Industrial Sensor", None),
            # Konica Minolta
            (("konica", "minolta"), (), "Konica Minolta", "Printer", None),
            # Cisco phone needs phone/cp- context
            (("cisco",), ("phone", "cp-"), "Cisco", "VoIP Phone", None),
        ]

        # Check simple patterns first
        for keywords, vendor, model, os_override in vendor_patterns:
            if any(kw in lower_descr for kw in keywords):
                info["vendor"] = vendor
                if model:
                    info["model"] = model
                if os_override:
                    info["os"] = os_override
                return

        # Check patterns requiring additional context
        for primary_kw, context_kw, vendor, model, os_override in special_patterns:
            if any(pk in lower_descr for pk in primary_kw):
                # Empty context means just primary match is enough
                if not context_kw or any(ck in lower_descr for ck in context_kw):
                    info["vendor"] = vendor
                    if model:
                        info["model"] = model
                    if os_override:
                        info["os"] = os_override
                    return

    def _probe_ssh(self, ip, info):
        """Query via SSH."""
        if not paramiko:
            return

        ssh_creds = self.creds.get("ssh", {})
        user = ssh_creds.get("username")
        password = ssh_creds.get("password")

        if not user or not password:
            return

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Fast timeout for identification
            client.connect(
                ip,
                username=user,
                password=password,
                timeout=3,
                banner_timeout=3,
                allow_agent=False,
                look_for_keys=False,
            )

            # Try getting OS release
            stdin, stdout, stderr = client.exec_command(
                "cat /etc/os-release; uname -r", timeout=3
            )
            out = stdout.read().decode().strip()

            if "PRETTY_NAME" in out:
                for line in out.split("\n"):
                    if "PRETTY_NAME" in line:
                        info["os"] = line.split("=")[1].strip('"')
                        break
            else:
                # Fallback to uname
                info["os"] = f"Linux ({out.split()[-1] if out else 'Unknown'})"

            info["vendor"] = "Linux/Unix"

            # Try to get hardware info (needs root usually, but try)
            # stdin, stdout, stderr = client.exec_command("cat /sys/devices/virtual/dmi/id/sys_vendor")
            # vendor = stdout.read().decode().strip()
            # if vendor:
            #    info['vendor'] = vendor

            logger.info(f"SSH Identification for {ip}: {info['os']}")
            client.close()
        except Exception:
            # logger.debug(f"SSH probe failed for {ip}: {e}")
            pass

    def _probe_wmi(self, ip, info):
        """Query via WMI."""
        if not wmi:
            return

        wmi_creds = self.creds.get("wmi", {})
        user = wmi_creds.get("username")
        password = wmi_creds.get("password")
        domain = wmi_creds.get("domain", "")

        if not user or not password:
            return

        try:
            # Impacket WMI connection
            dcomConnection = DCOMConnection(
                ip,
                user,
                password,
                domain,
                object=wmi.CLSID_WbemLevel1Login,
                oxidResolver=True,
            )
            iInterface = dcomConnection.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Query Win32_OperatingSystem
            # Note: ExecQuery is complex with raw DCOM.
            # We would need to implement the full IEnumWbemClassObject traversal.
            # Simplified: If we connected, it's Windows.
            info["vendor"] = "Microsoft"
            info["os"] = "Windows (Verified via WMI)"

            logger.info(f"WMI Connection successful for {ip}")

            dcomConnection.disconnect()
        except Exception:
            # logger.debug(f"WMI probe failed for {ip}: {e}")
            pass

    def _get_arp_table(self):
        """
        Retrieves ARP table using available system tools.
        Returns dict: {ip: mac}
        """
        table = {}

        # 1. Try Windows arp.exe (WSL support)
        if shutil.which("arp.exe"):
            try:
                cmd = ["arp.exe", "-a"]
                output = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL
                ).decode()
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        # Check if it looks like an IP
                        try:
                            ipaddress.ip_address(ip)
                            mac = parts[1].replace("-", ":").lower()
                            # Standardize MAC format
                            if len(mac.split(":")) == 6:
                                table[ip] = mac
                        except Exception:
                            pass
            except Exception:
                pass

        # 2. Try Linux /proc/net/arp
        if not table:
            try:
                with open("/proc/net/arp", "r") as f:
                    # Skip header
                    next(f)
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = parts[3]
                            if mac != "00:00:00:00:00:00":
                                table[ip] = mac
            except Exception:
                pass

        return table

    def _get_mac(self, ip):
        """Attempts to retrieve MAC address."""
        mac = None
        try:
            mac = get_mac_address(ip=ip)
        except Exception:
            pass

        if not mac:
            # Try WSL fallback
            mac = self._get_mac_wsl(ip)

        return mac

    def _get_mac_wsl(self, ip):
        """Attempts to get MAC via Windows arp.exe (for WSL)."""
        if not shutil.which("arp.exe"):
            return None

        try:
            # Run arp.exe -a and grep for IP
            # We can't easily grep specific IP in arp.exe without parsing,
            # so just get all and find line.
            cmd = ["arp.exe", "-a"]
            # Specific ip argument for arp.exe works on windows?
            # "arp -a 192.168.1.1" -> "No ARP Entries Found" if not specific.
            # standard arp.exe -a output lists all.

            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()

            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    # Found it: 192.168.0.1 2a-70...
                    mac = parts[1]
                    return mac.replace("-", ":").lower()
        except Exception:
            pass
        return None

    def _lookup_vendor(self, mac):
        """Looks up manufacturer by MAC OUI."""
        try:
            return self.mac_lookup.lookup(mac)
        except Exception:
            return "Unknown"


class ReconciliationEngine:
    """Compares PRTG data with Scan data."""

    def reconcile(self, prtg_devices, scan_results):
        """
        Matches IPs and generates leads.
        Resolves FQDN hostnames to IPs for proper matching.
        """
        report_data = []
        dns_cache = {}

        # Build lookup structures
        prtg_ips = set()  # IPs registered directly in PRTG
        prtg_ip_to_device = {}  # Map of IP -> PRTG device data

        # Collect FQDNs to resolve in parallel
        fqdns_to_resolve = []
        for host_key, device_data in prtg_devices.items():
            try:
                ipaddress.ip_address(host_key)
                prtg_ips.add(host_key)
                prtg_ip_to_device[host_key] = device_data
            except ValueError:
                fqdns_to_resolve.append(host_key)

        # Batch Parallel DNS Resolution
        failed_resolutions = []
        if fqdns_to_resolve:
            logger.info(
                f"Resolving {len(fqdns_to_resolve)} PRTG hostnames in parallel..."
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                # Map FQDN to future
                future_to_fqdn = {
                    executor.submit(self._resolve_hostname, fqdn): fqdn
                    for fqdn in fqdns_to_resolve
                }

                for future in concurrent.futures.as_completed(future_to_fqdn):
                    fqdn = future_to_fqdn[future]
                    try:
                        resolved_ip = future.result()
                        if resolved_ip:
                            dns_cache[fqdn] = resolved_ip
                            prtg_ips.add(resolved_ip)
                            # Link to device data
                            prtg_ip_to_device[resolved_ip] = prtg_devices[fqdn]
                        else:
                            # DNS resolution failed for this hostname
                            failed_resolutions.append(fqdn)
                            logger.warning(f"DNS resolution failed for PRTG device: {fqdn}")
                    except Exception as e:
                        failed_resolutions.append(fqdn)
                        logger.warning(f"DNS resolution error for {fqdn}: {e}")

        # Log summary of resolution results
        if failed_resolutions:
            logger.warning(
                f"Failed to resolve {len(failed_resolutions)} PRTG hostnames - "
                f"these devices may appear as 'Unmonitored' even if they exist in PRTG!"
            )
        logger.info(
            f"PRTG devices: {len(prtg_devices)} total, {len(prtg_ips)} resolved to IPs, "
            f"{len(failed_resolutions)} failed DNS resolution"
        )

        for host in scan_results:
            ip = host["ip"]

            row = {
                "IP Address": ip,
                "Hostname": host.get("hostname", ""),
                "Hardware Vendor": host.get("vendor", "Unknown"),
                "Hardware Model": host.get("model", "Unknown"),
                "OS Version": host.get("os", "Unknown"),
                "Sensor Count": "0",
                "Source": "Active Scan",
                "Recommendation": "Investigate",
                "MAC Address": host.get("mac", ""),
            }

            if ip in prtg_ips:
                # Managed - device found in PRTG (either by IP or resolved FQDN)
                row["Monitoring Status"] = "Managed"
                row["Source"] = "PRTG & Scan"
                # Enrich with PRTG data from our resolved lookup
                prtg_data = prtg_ip_to_device.get(ip, {})
                row["Hostname"] = prtg_data.get("device", row["Hostname"])

                # Parse sensor totals - PRTG API returns values in multiple formats:
                # - 'sensor': text summary like "5 Sensors (OK: 5)"
                # - 'totalsens': formatted string or numeric
                # - 'totalsens_raw': raw numeric value
                # Check all possible keys to ensure we get the sensor count
                sensor_count = (
                    prtg_data.get("sensor")
                    or prtg_data.get("totalsens")
                    or prtg_data.get("totalsens_raw")
                    or "0"
                )
                row["Sensor Count"] = str(sensor_count)

                row["Recommendation"] = "Verify Sensors (Up/Down)"

            else:
                # Unmonitored Opportunity
                row["Monitoring Status"] = "Unmonitored"
                row["Recommendation"] = "ADD TO PRTG - Potential Revenue"

            report_data.append(row)

        return report_data

    def _resolve_hostname(self, hostname):
        """
        Resolves a hostname/FQDN to an IP address.
        Returns None if resolution fails.
        """
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            return None
        except Exception:
            return None


class Reporter:
    """Generates the CSV report."""

    def generate_csv(self, data, filename="Hybrid_Assessment_Report.csv"):
        if not data:
            logger.warning("No data to report.")
            return

        keys = [
            "IP Address",
            "Hostname",
            "Source",
            "MAC Address",
            "Hardware Vendor",
            "Hardware Model",
            "OS Version",
            "Monitoring Status",
            "Sensor Count",
            "Recommendation",
        ]

        try:
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for row in data:
                    # Ensure only relevant keys are written
                    filtered_row = {k: row.get(k, "") for k in keys}
                    writer.writerow(filtered_row)
            logger.info(f"Report generated: {filename}")
        except Exception as e:
            logger.error(f"Failed to write report: {e}")


def main():
    parser = argparse.ArgumentParser(description="PRTG Hybrid Audit Tool")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    args = parser.parse_args()

    # Load Config
    try:
        with open(args.config, "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Could not load config: {e}")
        sys.exit(1)

    # 1. PRTG Import
    prtg = PRTGClient(config["prtg"]["url"], config["prtg"]["apitoken"])
    prtg_devices = prtg.fetch_devices()

    # 2. Active Discovery
    scanner = NetworkScanner(config)
    scan_results = scanner.scan_network()

    # 3. Reconciliation
    engine = ReconciliationEngine()
    final_data = engine.reconcile(prtg_devices, scan_results)

    # 4. Report
    reporter = Reporter()
    # Construct filename based on customer or timestamp?
    # For now just default
    reporter.generate_csv(final_data)


if __name__ == "__main__":
    main()
