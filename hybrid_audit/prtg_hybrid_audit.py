#!/usr/bin/env python3
"""
PRTG Hybrid Audit Tool
======================
Bridges the gap between known assets (PRTG) and unknown assets (Active Scan).
identifies "Unmonitored Assets" (Upsell Opportunities).

Usage:
    python prtg_hybrid_audit.py
"""

__version__ = "1.3.0"

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
        # columns=objid,host,device,active,totalsens,sensor

        endpoint = f"{self.url}/api/table.json"
        params = {
            "content": "devices",
            "output": "json",
            "columns": "objid,host,device,active,totalsens,sensor",
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
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return ""

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

                # Heuristics - expanded vendor detection
                lower_descr = sys_descr.lower()
                
                # Network Equipment
                if "cisco" in lower_descr:
                    info["vendor"] = "Cisco"
                    info["model"] = "Network Device"
                elif "fortinet" in lower_descr or "fortigate" in lower_descr or "fortiswitch" in lower_descr:
                    info["vendor"] = "Fortinet"
                    info["model"] = "Network/Security Device"
                elif "mikrotik" in lower_descr or "routeros" in lower_descr:
                    info["vendor"] = "MikroTik"
                    info["model"] = "Network Device"
                elif "ubiquiti" in lower_descr or "unifi" in lower_descr or "edgeos" in lower_descr:
                    info["vendor"] = "Ubiquiti"
                    info["model"] = "Network Device"
                elif "aruba" in lower_descr:
                    info["vendor"] = "HPE Aruba"
                    info["model"] = "Network Device"
                elif "juniper" in lower_descr:
                    info["vendor"] = "Juniper"
                    info["model"] = "Network Device"
                elif "palo alto" in lower_descr:
                    info["vendor"] = "Palo Alto Networks"
                    info["model"] = "Firewall"
                elif "moxa" in lower_descr:
                    info["vendor"] = "Moxa"
                    info["model"] = "Industrial Network Device"
                elif "insys" in lower_descr or "icom" in lower_descr:
                    info["vendor"] = "Insys icom"
                    info["model"] = "Industrial Router"
                elif "scalance" in lower_descr:
                    info["vendor"] = "Siemens SCALANCE"
                    info["model"] = "Industrial Network Device"
                elif "hirschmann" in lower_descr:
                    info["vendor"] = "Hirschmann"
                    info["model"] = "Industrial Switch"
                
                # Storage Systems
                elif "netapp" in lower_descr or "ontap" in lower_descr or "data ontap" in lower_descr:
                    info["vendor"] = "NetApp"
                    info["model"] = "Storage System"
                    info["os"] = "ONTAP"
                elif "synology" in lower_descr:
                    info["vendor"] = "Synology"
                    info["model"] = "NAS"
                    info["os"] = "DSM"
                elif "qnap" in lower_descr:
                    info["vendor"] = "QNAP"
                    info["model"] = "NAS"
                elif "emc" in lower_descr or "isilon" in lower_descr:
                    info["vendor"] = "Dell EMC"
                    info["model"] = "Storage System"
                
                # Servers
                elif "windows" in lower_descr:
                    info["vendor"] = "Microsoft"
                    info["os"] = "Windows"
                elif "linux" in lower_descr:
                    info["vendor"] = "Linux Generic"
                    info["os"] = "Linux"
                elif "vmware" in lower_descr or "esxi" in lower_descr:
                    info["vendor"] = "VMware"
                    info["os"] = "ESXi"
                elif "dell" in lower_descr or "poweredge" in lower_descr or "idrac" in lower_descr:
                    info["vendor"] = "Dell"
                    info["model"] = "Server"
                elif "lenovo" in lower_descr or "thinkserver" in lower_descr or "thinksystem" in lower_descr:
                    info["vendor"] = "Lenovo"
                    info["model"] = "Server"
                elif "hpe" in lower_descr or "proliant" in lower_descr or "ilo" in lower_descr:
                    info["vendor"] = "HPE"
                    info["model"] = "Server"
                elif "supermicro" in lower_descr:
                    info["vendor"] = "Supermicro"
                    info["model"] = "Server"
                
                # Environmental/IoT Sensors
                elif "kentix" in lower_descr:
                    info["vendor"] = "Kentix"
                    info["model"] = "Environmental Sensor"
                elif "rittal" in lower_descr:
                    info["vendor"] = "Rittal"
                    info["model"] = "Environmental/PDU"
                elif "apc" in lower_descr or "schneider" in lower_descr:
                    info["vendor"] = "APC/Schneider Electric"
                    info["model"] = "UPS/PDU"
                elif "eaton" in lower_descr:
                    info["vendor"] = "Eaton"
                    info["model"] = "UPS/PDU"
                elif "gude" in lower_descr:
                    info["vendor"] = "Gude"
                    info["model"] = "PDU/Sensor"
                elif "raritan" in lower_descr:
                    info["vendor"] = "Raritan"
                    info["model"] = "PDU/KVM"
                elif "vertiv" in lower_descr or "liebert" in lower_descr:
                    info["vendor"] = "Vertiv"
                    info["model"] = "Cooling/UPS"
                
                # Cameras/Security
                elif "axis" in lower_descr:
                    info["vendor"] = "AXIS"
                    info["model"] = "IP Camera"
                elif "bosch" in lower_descr and ("camera" in lower_descr or "dinion" in lower_descr):
                    info["vendor"] = "Bosch"
                    info["model"] = "IP Camera"
                elif "hikvision" in lower_descr:
                    info["vendor"] = "Hikvision"
                    info["model"] = "IP Camera"
                elif "dahua" in lower_descr:
                    info["vendor"] = "Dahua"
                    info["model"] = "IP Camera"
                elif "hanwha" in lower_descr or "wisenet" in lower_descr:
                    info["vendor"] = "Hanwha/Wisenet"
                    info["model"] = "IP Camera"
                
                # Industrial/Automation
                elif "siemens" in lower_descr or "simatic" in lower_descr:
                    info["vendor"] = "Siemens"
                    info["model"] = "Industrial Controller"
                elif "phoenix" in lower_descr or "plcnext" in lower_descr:
                    info["vendor"] = "Phoenix Contact"
                    info["model"] = "Industrial Controller"
                elif "beckhoff" in lower_descr:
                    info["vendor"] = "Beckhoff"
                    info["model"] = "Industrial Controller"
                elif "rockwell" in lower_descr or "allen-bradley" in lower_descr:
                    info["vendor"] = "Rockwell/Allen-Bradley"
                    info["model"] = "Industrial Controller"
                elif "bender" in lower_descr:
                    info["vendor"] = "Bender"
                    info["model"] = "Power Monitoring"
                elif "wago" in lower_descr:
                    info["vendor"] = "WAGO"
                    info["model"] = "Industrial Controller"
                elif "kvm" in lower_descr:
                    info["vendor"] = "KVM"
                    info["model"] = "KVM Switch"
                
                # Printers
                elif "hp" in lower_descr and ("printer" in lower_descr or "laserjet" in lower_descr or "officejet" in lower_descr):
                    info["vendor"] = "HP"
                    info["model"] = "Printer"
                elif "xerox" in lower_descr:
                    info["vendor"] = "Xerox"
                    info["model"] = "Printer"
                elif "canon" in lower_descr and "print" in lower_descr:
                    info["vendor"] = "Canon"
                    info["model"] = "Printer"
                elif "epson" in lower_descr:
                    info["vendor"] = "Epson"
                    info["model"] = "Printer"
                elif "brother" in lower_descr:
                    info["vendor"] = "Brother"
                    info["model"] = "Printer"
                elif "kyocera" in lower_descr:
                    info["vendor"] = "Kyocera"
                    info["model"] = "Printer"
                elif "ricoh" in lower_descr:
                    info["vendor"] = "Ricoh"
                    info["model"] = "Printer"
                elif "konica" in lower_descr or "minolta" in lower_descr:
                    info["vendor"] = "Konica Minolta"
                    info["model"] = "Printer"
                elif "lexmark" in lower_descr:
                    info["vendor"] = "Lexmark"
                    info["model"] = "Printer"
                
                # Consumer/SMB Network Equipment
                elif "tp-link" in lower_descr or "tplink" in lower_descr:
                    info["vendor"] = "TP-Link"
                    info["model"] = "Network Device"
                elif "d-link" in lower_descr or "dlink" in lower_descr:
                    info["vendor"] = "D-Link"
                    info["model"] = "Network Device"
                elif "netgear" in lower_descr:
                    info["vendor"] = "NETGEAR"
                    info["model"] = "Network Device"
                elif "zyxel" in lower_descr:
                    info["vendor"] = "Zyxel"
                    info["model"] = "Network Device"
                elif "linksys" in lower_descr:
                    info["vendor"] = "Linksys"
                    info["model"] = "Network Device"
                elif "asus" in lower_descr and ("router" in lower_descr or "switch" in lower_descr):
                    info["vendor"] = "ASUS"
                    info["model"] = "Network Device"
                
                # Enterprise Network Equipment
                elif "extreme" in lower_descr:
                    info["vendor"] = "Extreme Networks"
                    info["model"] = "Network Device"
                elif "alcatel" in lower_descr or "nokia" in lower_descr:
                    info["vendor"] = "Alcatel-Lucent/Nokia"
                    info["model"] = "Network Device"
                elif "brocade" in lower_descr:
                    info["vendor"] = "Brocade"
                    info["model"] = "Network/Storage Switch"
                elif "ruckus" in lower_descr:
                    info["vendor"] = "Ruckus"
                    info["model"] = "Wireless AP"
                elif "aerohive" in lower_descr:
                    info["vendor"] = "Aerohive"
                    info["model"] = "Wireless AP"
                elif "meraki" in lower_descr:
                    info["vendor"] = "Cisco Meraki"
                    info["model"] = "Network Device"
                elif "sonicwall" in lower_descr:
                    info["vendor"] = "SonicWall"
                    info["model"] = "Firewall"
                elif "watchguard" in lower_descr:
                    info["vendor"] = "WatchGuard"
                    info["model"] = "Firewall"
                elif "sophos" in lower_descr:
                    info["vendor"] = "Sophos"
                    info["model"] = "Firewall/Security"
                elif "barracuda" in lower_descr:
                    info["vendor"] = "Barracuda"
                    info["model"] = "Security Appliance"
                elif "f5" in lower_descr or "big-ip" in lower_descr:
                    info["vendor"] = "F5"
                    info["model"] = "Load Balancer"
                elif "citrix" in lower_descr and ("netscaler" in lower_descr or "adc" in lower_descr):
                    info["vendor"] = "Citrix"
                    info["model"] = "Load Balancer"
                elif "a10" in lower_descr:
                    info["vendor"] = "A10 Networks"
                    info["model"] = "Load Balancer"
                
                # VoIP/Telecom
                elif "avaya" in lower_descr:
                    info["vendor"] = "Avaya"
                    info["model"] = "VoIP/Phone System"
                elif "mitel" in lower_descr:
                    info["vendor"] = "Mitel"
                    info["model"] = "VoIP/Phone System"
                elif "polycom" in lower_descr or "poly" in lower_descr:
                    info["vendor"] = "Polycom/Poly"
                    info["model"] = "VoIP Phone/Conference"
                elif "yealink" in lower_descr:
                    info["vendor"] = "Yealink"
                    info["model"] = "VoIP Phone"
                elif "grandstream" in lower_descr:
                    info["vendor"] = "Grandstream"
                    info["model"] = "VoIP Phone"
                elif "snom" in lower_descr:
                    info["vendor"] = "Snom"
                    info["model"] = "VoIP Phone"
                elif "cisco" in lower_descr and ("phone" in lower_descr or "cp-" in lower_descr):
                    info["vendor"] = "Cisco"
                    info["model"] = "VoIP Phone"
                elif "audiocodes" in lower_descr:
                    info["vendor"] = "AudioCodes"
                    info["model"] = "VoIP Gateway"
                elif "asterisk" in lower_descr or "freepbx" in lower_descr:
                    info["vendor"] = "Asterisk/FreePBX"
                    info["model"] = "PBX Server"
                
                # More Storage
                elif "pure" in lower_descr and "storage" in lower_descr:
                    info["vendor"] = "Pure Storage"
                    info["model"] = "Flash Array"
                elif "nimble" in lower_descr:
                    info["vendor"] = "HPE Nimble"
                    info["model"] = "Storage"
                elif "3par" in lower_descr:
                    info["vendor"] = "HPE 3PAR"
                    info["model"] = "Storage"
                elif "ibm" in lower_descr and ("storage" in lower_descr or "storwize" in lower_descr or "flashsystem" in lower_descr):
                    info["vendor"] = "IBM"
                    info["model"] = "Storage System"
                elif "hitachi" in lower_descr:
                    info["vendor"] = "Hitachi"
                    info["model"] = "Storage System"
                elif "buffalo" in lower_descr:
                    info["vendor"] = "Buffalo"
                    info["model"] = "NAS"
                elif "drobo" in lower_descr:
                    info["vendor"] = "Drobo"
                    info["model"] = "NAS"
                elif "asustor" in lower_descr:
                    info["vendor"] = "Asustor"
                    info["model"] = "NAS"
                elif "terramaster" in lower_descr:
                    info["vendor"] = "TerraMaster"
                    info["model"] = "NAS"
                
                # More Cameras
                elif "vivotek" in lower_descr:
                    info["vendor"] = "Vivotek"
                    info["model"] = "IP Camera"
                elif "mobotix" in lower_descr:
                    info["vendor"] = "Mobotix"
                    info["model"] = "IP Camera"
                elif "pelco" in lower_descr:
                    info["vendor"] = "Pelco"
                    info["model"] = "IP Camera"
                elif "uniview" in lower_descr:
                    info["vendor"] = "Uniview"
                    info["model"] = "IP Camera"
                elif "geovision" in lower_descr:
                    info["vendor"] = "GeoVision"
                    info["model"] = "IP Camera"
                elif "foscam" in lower_descr:
                    info["vendor"] = "Foscam"
                    info["model"] = "IP Camera"
                elif "reolink" in lower_descr:
                    info["vendor"] = "Reolink"
                    info["model"] = "IP Camera"
                elif "amcrest" in lower_descr:
                    info["vendor"] = "Amcrest"
                    info["model"] = "IP Camera"
                
                # More Environmental/Power
                elif "geist" in lower_descr:
                    info["vendor"] = "Geist"
                    info["model"] = "PDU/Environmental"
                elif "servertech" in lower_descr or "server technology" in lower_descr:
                    info["vendor"] = "Server Technology"
                    info["model"] = "PDU"
                elif "cyberpower" in lower_descr:
                    info["vendor"] = "CyberPower"
                    info["model"] = "UPS/PDU"
                elif "tripp" in lower_descr or "tripplite" in lower_descr:
                    info["vendor"] = "Tripp Lite"
                    info["model"] = "UPS/PDU"
                elif "paessler" in lower_descr or "prtg" in lower_descr:
                    info["vendor"] = "Paessler"
                    info["model"] = "PRTG Probe"
                elif "digi" in lower_descr:
                    info["vendor"] = "Digi International"
                    info["model"] = "Serial/IoT Gateway"
                elif "advantech" in lower_descr:
                    info["vendor"] = "Advantech"
                    info["model"] = "Industrial IoT"
                
                # Virtualization/Hypervisors
                elif "proxmox" in lower_descr:
                    info["vendor"] = "Proxmox"
                    info["os"] = "Proxmox VE"
                elif "xen" in lower_descr and "server" in lower_descr:
                    info["vendor"] = "Citrix"
                    info["os"] = "XenServer"
                elif "nutanix" in lower_descr:
                    info["vendor"] = "Nutanix"
                    info["model"] = "HCI"
                elif "hyper-v" in lower_descr:
                    info["vendor"] = "Microsoft"
                    info["os"] = "Hyper-V"
                elif "kvm" in lower_descr and ("qemu" in lower_descr or "libvirt" in lower_descr):
                    info["vendor"] = "Linux"
                    info["os"] = "KVM"
                
                # More Industrial/Automation
                elif "abb" in lower_descr:
                    info["vendor"] = "ABB"
                    info["model"] = "Industrial Controller"
                elif "omron" in lower_descr:
                    info["vendor"] = "Omron"
                    info["model"] = "Industrial Controller"
                elif "emerson" in lower_descr:
                    info["vendor"] = "Emerson"
                    info["model"] = "Industrial Controller"
                elif "honeywell" in lower_descr:
                    info["vendor"] = "Honeywell"
                    info["model"] = "Industrial/Building"
                elif "schneider" in lower_descr and ("modicon" in lower_descr or "plc" in lower_descr):
                    info["vendor"] = "Schneider Electric"
                    info["model"] = "Industrial Controller"
                elif "mitsubishi" in lower_descr and ("plc" in lower_descr or "melsec" in lower_descr):
                    info["vendor"] = "Mitsubishi"
                    info["model"] = "Industrial Controller"
                elif "keyence" in lower_descr:
                    info["vendor"] = "Keyence"
                    info["model"] = "Industrial Sensor/Controller"
                elif "ifm" in lower_descr:
                    info["vendor"] = "IFM"
                    info["model"] = "Industrial Sensor"
                elif "pepperl" in lower_descr or "fuchs" in lower_descr:
                    info["vendor"] = "Pepperl+Fuchs"
                    info["model"] = "Industrial Sensor"
                elif "sick" in lower_descr and ("sensor" in lower_descr or "scanner" in lower_descr):
                    info["vendor"] = "SICK"
                    info["model"] = "Industrial Sensor"
                elif "balluff" in lower_descr:
                    info["vendor"] = "Balluff"
                    info["model"] = "Industrial Sensor"
                elif "turck" in lower_descr:
                    info["vendor"] = "Turck"
                    info["model"] = "Industrial Sensor"
                elif "banner" in lower_descr and "engineering" in lower_descr:
                    info["vendor"] = "Banner Engineering"
                    info["model"] = "Industrial Sensor"

                logger.info(
                    f"SNMP Identification for {ip}: {info['vendor']} - {info['os']}"
                )

        except Exception:
            # logger.debug(f"SNMP probe failed for {ip}: {e}")
            pass

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

                # Parse sensor totals usually in format like "{'upsens': 5, 'downsens': 0, ...}"
                # Use 'sensor' for a nice status summary, or fallback to 'totalsens'
                row["Sensor Count"] = str(
                    prtg_data.get("sensor", prtg_data.get("totalsens", "0"))
                )

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
