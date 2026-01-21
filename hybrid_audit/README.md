# PRTG Hybrid Audit Tool (`hybrid_audit/prtg_hybrid_audit.py`)

A "Hybrid Audit Tool" that combines data from an existing PRTG installation with a fresh network scan to identify unmanaged assets and upsell opportunities.

## Features

- **PRTG Integration**: Imports current device list from PRTG Core API.
- **Active Discovery**: Scans CIDR ranges for live hosts using threaded socket checks.
- **Deep Identification**: Fingerprints devices via SNMP, SSH, and WMI to identify Vendor, Model, and OS.
- **Gap Analysis**: Reconciles PRTG data with scan results to find "Unmonitored" devices.
- **Reporting**: Generates a CSV report with sales recommendations.

## Installation

1. **Install required dependencies:**
   ```bash
   pip install -r ../requirements.txt
   ```
   *Dependencies include: `requests`, `paramiko`, `impacket`, `pysnmp-lextudio`, `pyyaml`*

## Usage

1. **Configure**: Edit `config.yaml` with your PRTG details and Scan settings.
   
   Example `config.yaml`:
   ```yaml
   prtg:
     url: "https://your-prtg-server.com"
     api_hash: "YOUR_PASSHASH"
   scan:
     cidr_ranges: ["192.168.1.0/24"]
   credentials:
     # ... see config_example.yaml
   ```

2. **Run**:
   ```bash
   python prtg_hybrid_audit.py
   ```

3. **Report**: Check `Hybrid_Assessment_Report.csv` for results.

## Troubleshooting

-   **Missing MAC Addresses**: MAC address detection requires **Layer 2 connectivity**. The script must be run on the same physical subnet as the target devices. If you run this from WSL, Docker, or across a router, MAC addresses (and Vendor lookups) will effectively be empty.

