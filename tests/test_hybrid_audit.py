from unittest.mock import MagicMock, patch
from hybrid_audit.prtg_hybrid_audit import PRTGClient, ReconciliationEngine

# --- PRTGClient Tests ---


@patch("requests.get")
def test_prtg_fetch_devices_success(mock_get):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "devices": [
            {
                "host": "192.168.1.1",
                "device": "Device 1",
                "totalsens": 5,
                "sensor": "5 Sensors (OK: 5)",
            },
            {
                "host": "test.local",
                "device": "Device 2",
                "totalsens": 2,
                "sensor": "2 Sensors (OK: 2)",
            },
        ]
    }
    mock_get.return_value = mock_response

    client = PRTGClient("http://prtg.example.com", "fake-token")
    devices = client.fetch_devices()

    assert len(devices) == 2
    assert "192.168.1.1" in devices
    assert "test.local" in devices
    assert devices["192.168.1.1"]["device"] == "Device 1"


@patch("requests.get")
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
        "192.168.1.1": {
            "device": "PRTG-Device-1",
            "totalsens": 10,
            "sensor": "10 Sensors (OK)",
        },
        "192.168.1.50": {
            "device": "PRTG-Device-2",
            "totalsens": 5,
            "sensor": "5 Sensors (OK)",
        },
    }

    # Mock Scan results
    scan_results = [
        {"ip": "192.168.1.1", "vendor": "Cisco", "os": "IOS", "hostname": "router1.local"},
        {"ip": "192.168.1.100", "vendor": "Unknown", "os": "Unknown", "hostname": ""},
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


@patch.object(ReconciliationEngine, "_resolve_hostname")
def test_reconcile_with_dns_resolution(mock_resolve):
    engine = ReconciliationEngine()

    # Mock resolution: test.local -> 192.168.1.5
    mock_resolve.return_value = "192.168.1.5"

    prtg_devices = {
        "test.local": {"device": "DNS-Device", "totalsens": 3, "sensor": "3 Sensors"}
    }

    scan_results = [{"ip": "192.168.1.5", "vendor": "Dell", "os": "Linux", "hostname": "server.local"}]

    report = engine.reconcile(prtg_devices, scan_results)

    assert len(report) == 1
    assert report[0]["IP Address"] == "192.168.1.5"
    assert report[0]["Monitoring Status"] == "Managed"
    assert report[0]["Hostname"] == "DNS-Device"


def test_reconcile_sensor_count_with_sensor_field():
    """Test that sensor count is correctly extracted when 'sensor' field is present and non-empty."""
    engine = ReconciliationEngine()

    prtg_devices = {
        "192.168.1.1": {
            "device": "Device-With-Sensor",
            "sensor": "10 Sensors (OK: 8, Warning: 2)",
            "totalsens": "5",  # Should be ignored when sensor is present
            "totalsens_raw": 3,  # Should be ignored when sensor is present
        }
    }

    scan_results = [
        {"ip": "192.168.1.1", "vendor": "Cisco", "os": "IOS", "hostname": "router1"}
    ]

    report = engine.reconcile(prtg_devices, scan_results)

    assert len(report) == 1
    managed = report[0]
    assert managed["IP Address"] == "192.168.1.1"
    assert managed["Monitoring Status"] == "Managed"
    assert managed["Sensor Count"] == "10 Sensors (OK: 8, Warning: 2)"


def test_reconcile_sensor_count_fallback_to_totalsens():
    """Test that sensor count falls back to 'totalsens' when 'sensor' field is empty or missing."""
    engine = ReconciliationEngine()

    prtg_devices = {
        "192.168.1.1": {
            "device": "Device-Without-Sensor",
            "sensor": "",  # Empty sensor field
            "totalsens": "7",
            "totalsens_raw": 5,  # Should be ignored when totalsens is present
        },
        "192.168.1.2": {
            "device": "Device-Missing-Sensor",
            # No sensor field at all
            "totalsens": "12",
            "totalsens_raw": 10,  # Should be ignored when totalsens is present
        },
    }

    scan_results = [
        {"ip": "192.168.1.1", "vendor": "HP", "os": "Linux", "hostname": "server1"},
        {"ip": "192.168.1.2", "vendor": "Dell", "os": "Windows", "hostname": "server2"},
    ]

    report = engine.reconcile(prtg_devices, scan_results)

    assert len(report) == 2

    device1 = next(r for r in report if r["IP Address"] == "192.168.1.1")
    assert device1["Sensor Count"] == "7"

    device2 = next(r for r in report if r["IP Address"] == "192.168.1.2")
    assert device2["Sensor Count"] == "12"


def test_reconcile_sensor_count_fallback_to_totalsens_raw():
    """Test that sensor count falls back to 'totalsens_raw' when only that field is present."""
    engine = ReconciliationEngine()

    prtg_devices = {
        "192.168.1.1": {
            "device": "Device-Only-Raw",
            # No sensor field
            # No totalsens field
            "totalsens_raw": 15,
        },
        "192.168.1.2": {
            "device": "Device-Empty-Fields",
            "sensor": "",  # Empty
            "totalsens": "",  # Empty
            "totalsens_raw": 20,
        },
    }

    scan_results = [
        {"ip": "192.168.1.1", "vendor": "Juniper", "os": "JunOS", "hostname": "switch1"},
        {"ip": "192.168.1.2", "vendor": "Arista", "os": "EOS", "hostname": "switch2"},
    ]

    report = engine.reconcile(prtg_devices, scan_results)

    assert len(report) == 2

    device1 = next(r for r in report if r["IP Address"] == "192.168.1.1")
    assert device1["Sensor Count"] == "15"

    device2 = next(r for r in report if r["IP Address"] == "192.168.1.2")
    assert device2["Sensor Count"] == "20"
