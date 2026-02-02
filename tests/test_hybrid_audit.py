import pytest
import ipaddress
from unittest.mock import MagicMock, patch
from hybrid_audit.prtg_hybrid_audit import PRTGClient, ReconciliationEngine

# --- PRTGClient Tests ---

@patch('requests.get')
def test_prtg_fetch_devices_success(mock_get):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "devices": [
            {"host": "192.168.1.1", "device": "Device 1", "totalsens": 5, "sensor": "5 Sensors (OK: 5)"},
            {"host": "test.local", "device": "Device 2", "totalsens": 2, "sensor": "2 Sensors (OK: 2)"}
        ]
    }
    mock_get.return_value = mock_response

    client = PRTGClient("http://prtg.example.com", "fake-token")
    devices = client.fetch_devices()

    assert len(devices) == 2
    assert "192.168.1.1" in devices
    assert "test.local" in devices
    assert devices["192.168.1.1"]["device"] == "Device 1"

@patch('requests.get')
def test_prtg_fetch_devices_failure(mock_get):
    mock_get.side_effect = Exception("Connection error")
    
    client = PRTGClient("http://prtg.example.com", "fake-token")
    devices = client.fetch_devices()
    
    assert devices == {}

# --- ReconciliationEngine Tests ---

def test_reconcile_managed_and_unmonitored():
    engine = ReconciliationEngine()
    
    # Mock PRTG data
    prtg_devices = {
        "192.168.1.1": {"device": "PRTG-Device-1", "totalsens": 10, "sensor": "10 Sensors (OK)"},
        "192.168.1.50": {"device": "PRTG-Device-2", "totalsens": 5, "sensor": "5 Sensors (OK)"}
    }
    
    # Mock Scan results
    scan_results = [
        {"ip": "192.168.1.1", "vendor": "Cisco", "os": "IOS"},
        {"ip": "192.168.1.100", "vendor": "Unknown", "os": "Unknown"}
    ]
    
    report = engine.reconcile(prtg_devices, scan_results)
    
    assert len(report) == 2
    
    # Check managed device
    managed = next(r for r in report if r["IP Address"] == "192.168.1.1")
    assert managed["Monitoring Status"] == "Managed"
    assert "PRTG-Device-1" in managed["Hostname"]
    assert "10 Sensors" in managed["Sensor Count"]
    
    # Check unmonitored device
    unmonitored = next(r for r in report if r["IP Address"] == "192.168.1.100")
    assert unmonitored["Monitoring Status"] == "Unmonitored"
    assert "ADD TO PRTG" in unmonitored["Recommendation"]

@patch.object(ReconciliationEngine, '_resolve_hostname')
def test_reconcile_with_dns_resolution(mock_resolve):
    engine = ReconciliationEngine()
    
    # Mock resolution: test.local -> 192.168.1.5
    mock_resolve.return_value = "192.168.1.5"
    
    prtg_devices = {
        "test.local": {"device": "DNS-Device", "totalsens": 3, "sensor": "3 Sensors"}
    }
    
    scan_results = [
        {"ip": "192.168.1.5", "vendor": "Dell", "os": "Linux"}
    ]
    
    report = engine.reconcile(prtg_devices, scan_results)
    
    assert len(report) == 1
    assert report[0]["IP Address"] == "192.168.1.5"
    assert report[0]["Monitoring Status"] == "Managed"
    assert report[0]["Hostname"] == "DNS-Device"
