#!/usr/bin/env python3
"""
Net-SNMP Vulnerability Scanner
==============================
Scans subnets for devices running vulnerable versions of Net-SNMP (< 5.9.5)
related to CVE-2025-68615 (CVSS 9.8) affecting snmptrapd daemon.

CVE Reference:
    https://nvd.nist.gov/vuln/detail/CVE-2025-68615

Installation:
    1. Ensure Python 3.7+ is installed:
       $ python --version

    2. Install required dependencies:
       $ pip install pysnmp

    3. (Optional) Create a virtual environment first:
       $ python -m venv venv
       $ source venv/bin/activate  # Linux/macOS
       $ venv\\Scripts\\activate     # Windows
       $ pip install pysnmp

Usage:
    python scan_netsnmp.py 192.168.1.0/24
    python scan_netsnmp.py 192.168.1.0/24 10.0.0.0/24 --community mySecretString
    python scan_netsnmp.py 192.168.1.0/24 --timeout 2 --workers 50

Options:
    -c, --community   SNMP community string (default: public)
    -t, --timeout     Timeout in seconds per device (default: 1.0)
    -r, --retries     Number of retries per device (default: 1)
    -w, --workers     Number of parallel workers (default: 50)
    -v, --verbose     Show all responding devices, not just vulnerable ones
    --no-color        Disable colored output

Author: Security Team
Date: December 2025
License: Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
"""

__version__ = "1.0.0"

import argparse
import ipaddress
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple, List

try:
    from pysnmp.hlapi import (
        getCmd,
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
    )
except ImportError as e:
    print(f"Error: pysnmp library is required. Details: {e}")
    print("Install it with: pip install pysnmp")
    sys.exit(1)


# OID for sysDescr - contains system description including Net-SNMP version
SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"

# Minimum safe version
SAFE_VERSION = (5, 9, 5)


# ANSI color codes for terminal output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """
    Parse a version string into a tuple of integers for comparison.

    Args:
        version_str: Version string like "5.9.4" or "5.8"

    Returns:
        Tuple of version integers or None if parsing fails
    """
    try:
        parts = version_str.strip().split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return None


def extract_netsnmp_version(sys_descr: str) -> Optional[str]:
    """
    Extract Net-SNMP version from sysDescr string.

    Args:
        sys_descr: The sysDescr OID response string

    Returns:
        Version string if Net-SNMP is detected, None otherwise
    """
    # Common patterns for Net-SNMP version in sysDescr
    patterns = [
        r"Net-SNMP\s+version[:\s]+(\d+\.\d+(?:\.\d+)?)",
        r"net-snmp[:\s]+(\d+\.\d+(?:\.\d+)?)",
        r"NET-SNMP[:\s]+(\d+\.\d+(?:\.\d+)?)",
        r"snmpd[:\s]+(\d+\.\d+(?:\.\d+)?)",
    ]

    for pattern in patterns:
        match = re.search(pattern, sys_descr, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def is_vulnerable(version_str: str) -> bool:
    """
    Check if a Net-SNMP version is vulnerable (< 5.9.5).

    Args:
        version_str: Version string to check

    Returns:
        True if vulnerable, False if safe or unknown
    """
    version = parse_version(version_str)
    if version is None:
        return False

    # Pad version tuple for comparison
    while len(version) < 3:
        version = version + (0,)

    return version < SAFE_VERSION


def query_snmp(
    ip: str, community: str, timeout: float, retries: int
) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Query a device's sysDescr OID via SNMP.

    Args:
        ip: IP address to query
        community: SNMP community string
        timeout: Timeout in seconds
        retries: Number of retries

    Returns:
        Tuple of (ip, sys_descr, error_message)
    """
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # SNMPv2c
            UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(SYS_DESCR_OID)),
        )

        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            return (ip, None, str(error_indication))
        elif error_status:
            return (ip, None, f"{error_status.prettyPrint()} at {error_index}")
        else:
            for var_bind in var_binds:
                return (ip, str(var_bind[1]), None)

        return (ip, None, "No response")

    except Exception as e:
        return (ip, None, str(e))


def scan_subnet(
    subnet: str,
    community: str,
    timeout: float,
    retries: int,
    workers: int,
    verbose: bool,
) -> List[dict]:
    """
    Scan a subnet for vulnerable Net-SNMP versions.

    Args:
        subnet: CIDR notation subnet (e.g., "192.168.1.0/24")
        community: SNMP community string
        timeout: Timeout in seconds per device
        retries: Number of retries per device
        workers: Number of parallel workers
        verbose: Print all responses, not just vulnerable ones

    Returns:
        List of dictionaries containing scan results
    """
    results = []

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        print(f"{Colors.RED}Error: Invalid subnet '{subnet}': {e}{Colors.END}")
        return results

    hosts = list(network.hosts())
    total_hosts = len(hosts)

    print(f"\n{Colors.CYAN}Scanning {subnet} ({total_hosts} hosts)...{Colors.END}")

    vulnerable_count = 0
    responding_count = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(query_snmp, str(ip), community, timeout, retries): ip
            for ip in hosts
        }

        for i, future in enumerate(as_completed(futures), 1):
            ip, sys_descr, error = future.result()

            # Progress indicator
            if i % 10 == 0 or i == total_hosts:
                print(
                    f"\r  Progress: {i}/{total_hosts} hosts scanned", end="", flush=True
                )

            if sys_descr:
                responding_count += 1
                version = extract_netsnmp_version(sys_descr)

                result = {
                    "ip": ip,
                    "sys_descr": sys_descr,
                    "version": version,
                    "vulnerable": False,
                    "is_netsnmp": version is not None,
                }

                if version:
                    if is_vulnerable(version):
                        result["vulnerable"] = True
                        vulnerable_count += 1
                        results.append(result)
                    elif verbose:
                        results.append(result)
                elif verbose:
                    results.append(result)

    print(f"\r  Progress: {total_hosts}/{total_hosts} hosts scanned")
    print(
        f"  {Colors.BLUE}Responding: {responding_count} | Vulnerable: {vulnerable_count}{Colors.END}"
    )

    return results


def print_results(results: List[dict], verbose: bool):
    """
    Print scan results in a formatted table.

    Args:
        results: List of scan result dictionaries
        verbose: Show all results vs only vulnerable
    """
    vulnerable = [r for r in results if r["vulnerable"]]
    safe_netsnmp = [r for r in results if r["is_netsnmp"] and not r["vulnerable"]]
    other = [r for r in results if not r["is_netsnmp"]]

    if vulnerable:
        print(
            f"\n{Colors.RED}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════╗"
        )
        print("║  VULNERABLE DEVICES FOUND - CVE-2025-68615                       ║")
        print(
            f"╚══════════════════════════════════════════════════════════════════╝{Colors.END}"
        )
        print(
            f"\n{Colors.RED}The following devices are running Net-SNMP < 5.9.5 and should be"
        )
        print(
            f"patched immediately to address the snmptrapd vulnerability:{Colors.END}\n"
        )

        print(f"{'IP Address':<18} {'Version':<12} {'System Description'}")
        print("-" * 80)

        for r in sorted(vulnerable, key=lambda x: ipaddress.ip_address(x["ip"])):
            version_display = r["version"] or "Unknown"
            sys_descr_short = (
                r["sys_descr"][:45] + "..."
                if len(r["sys_descr"]) > 48
                else r["sys_descr"]
            )
            print(
                f"{Colors.RED}{r['ip']:<18} {version_display:<12} {sys_descr_short}{Colors.END}"
            )

        print()

    if verbose and safe_netsnmp:
        print(
            f"\n{Colors.GREEN}{Colors.BOLD}Safe Net-SNMP Devices (>= 5.9.5):{Colors.END}"
        )
        print(f"{'IP Address':<18} {'Version':<12} {'System Description'}")
        print("-" * 80)

        for r in sorted(safe_netsnmp, key=lambda x: ipaddress.ip_address(x["ip"])):
            version_display = r["version"] or "Unknown"
            sys_descr_short = (
                r["sys_descr"][:45] + "..."
                if len(r["sys_descr"]) > 48
                else r["sys_descr"]
            )
            print(
                f"{Colors.GREEN}{r['ip']:<18} {version_display:<12} {sys_descr_short}{Colors.END}"
            )

    if verbose and other:
        print(
            f"\n{Colors.YELLOW}{Colors.BOLD}Other SNMP-Enabled Devices (Non Net-SNMP):{Colors.END}"
        )
        print(f"{'IP Address':<18} {'System Description'}")
        print("-" * 80)

        for r in sorted(other, key=lambda x: ipaddress.ip_address(x["ip"])):
            sys_descr_short = (
                r["sys_descr"][:60] + "..."
                if len(r["sys_descr"]) > 63
                else r["sys_descr"]
            )
            print(f"{Colors.YELLOW}{r['ip']:<18} {sys_descr_short}{Colors.END}")


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════╗
║                  Net-SNMP Vulnerability Scanner                       ║
║                      CVE-2025-68615 (CVSS 9.8)                        ║
║                                                                       ║
║  Scans for snmptrapd daemon vulnerability in Net-SNMP < 5.9.5         ║
╚═══════════════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scan subnets for vulnerable Net-SNMP versions (< 5.9.5) - CVE-2025-68615",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s 192.168.1.0/24 10.0.0.0/24 --community mySecretString
  %(prog)s 192.168.1.0/24 --timeout 2 --workers 100 --verbose

The script queries OID 1.3.6.1.2.1.1.1.0 (sysDescr) to identify
Net-SNMP versions and flags any device running a version older
than 5.9.5 as vulnerable to CVE-2025-68615.
        """,
    )

    parser.add_argument(
        "subnets",
        nargs="+",
        help="Subnet(s) to scan in CIDR notation (e.g., 192.168.1.0/24)",
    )

    parser.add_argument(
        "-c",
        "--community",
        default="public",
        help="SNMP community string (default: public)",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds per device (default: 1.0)",
    )

    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=1,
        help="Number of retries per device (default: 1)",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Number of parallel workers (default: 50)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all responding devices, not just vulnerable ones",
    )

    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.CYAN = ""
        Colors.BOLD = ""
        Colors.END = ""

    print_banner()

    print(f"{Colors.BLUE}Configuration:{Colors.END}")
    print(f"  Subnets:    {', '.join(args.subnets)}")
    print(f"  Community:  {args.community}")
    print(f"  Timeout:    {args.timeout}s")
    print(f"  Retries:    {args.retries}")
    print(f"  Workers:    {args.workers}")

    all_results = []

    for subnet in args.subnets:
        results = scan_subnet(
            subnet,
            args.community,
            args.timeout,
            args.retries,
            args.workers,
            args.verbose,
        )
        all_results.extend(results)

    print_results(all_results, args.verbose)

    # Summary
    vulnerable_count = sum(1 for r in all_results if r["vulnerable"])

    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
    print(f"{Colors.BOLD}SCAN COMPLETE{Colors.END}")
    print(f"{'=' * 70}")

    if vulnerable_count > 0:
        print(
            f"\n{Colors.RED}{Colors.BOLD}⚠  {vulnerable_count} VULNERABLE DEVICE(S) FOUND!{Colors.END}"
        )
        print(f"\n{Colors.YELLOW}Recommended Actions:{Colors.END}")
        print("  1. Patch affected devices to Net-SNMP 5.9.5 or later")
        print("  2. If patching is not possible, disable snmptrapd service")
        print("  3. Block UDP port 162 from untrusted networks")
        print("  4. Monitor affected devices for suspicious activity")
        print(
            f"\n{Colors.CYAN}Reference: CVE-2025-68615 - snmptrapd Remote Code Execution{Colors.END}"
        )
        sys.exit(1)
    else:
        print(
            f"\n{Colors.GREEN}{Colors.BOLD}✓  No vulnerable Net-SNMP devices detected.{Colors.END}"
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
