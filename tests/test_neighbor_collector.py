import pytest
from unittest.mock import MagicMock, patch
from network_monitor.snmp.neighbor_collector import (
    NeighborCollector,
    _format_ip_address,
    FDP_CACHE_IF_INDEX,
    FDP_CACHE_DEVICE_ID,
    FDP_CACHE_DEVICE_PORT,
    FDP_CACHE_ADDRESS,
    FDP_CACHE_PLATFORM,
    LLDP_REM_SYS_NAME,
    LLDP_REM_PORT_ID,
    LLDP_REM_PORT_DESC,
)


def test_format_ip_address():
    assert _format_ip_address("192.168.1.1") == "192.168.1.1"
    assert _format_ip_address("0xc0a80101") == "192.168.1.1"
    assert _format_ip_address(bytes([10, 0, 0, 1])) == "10.0.0.1"
    assert _format_ip_address(None) == ""


def test_poll_fdp_neighbors_parsing():
    collector = NeighborCollector()
    sw = MagicMock()
    sw.management_ip = "192.69.1.101"
    sw.snmp_version = "2c"
    sw.community = "public"
    snmp_settings = MagicMock(version="2c", timeout_seconds=1.0, retries=1, community="public")

    # Mock walks for FDP table with 2 neighbors on port 1/1/1 (ifIndex 1) and 1/1/2 (ifIndex 2)
    fake_if = [("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.1.1.1", 1), ("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.1.2.1", 2)]
    fake_dev_id = [("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.3.1.1", "Brocade-Core"), ("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.3.2.1", "Ruckus-Edge")]
    fake_port = [("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.7.1.1", "1/1/48"), ("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.7.2.1", "1/1/24")]
    fake_addr = [("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.5.1.1", "192.69.1.254"), ("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.5.2.1", "192.69.1.105")]
    fake_plat = [("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.8.1.1", "ICX7150-48"), ("1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.8.2.1", "ICX7150-24")]

    with patch.object(collector, "_execute_walks", return_value=[fake_if, fake_dev_id, fake_port, fake_addr, fake_plat]):
        results = collector.poll_fdp_neighbors(sw, snmp_settings)

    assert len(results) == 2
    assert results[0]["protocol"] == "FDP"
    assert results[0]["local_port"] == 1
    assert results[0]["remote_device_name"] == "Brocade-Core"
    assert results[0]["remote_port_id"] == "1/1/48"
    assert results[0]["remote_mgmt_ip"] == "192.69.1.254"
    assert results[0]["remote_platform"] == "ICX7150-48"

    assert results[1]["protocol"] == "FDP"
    assert results[1]["local_port"] == 2
    assert results[1]["remote_device_name"] == "Ruckus-Edge"


def test_poll_lldp_neighbors_parsing():
    collector = NeighborCollector()
    sw = MagicMock()
    sw.management_ip = "192.69.1.102"
    snmp_settings = MagicMock()

    # LLDP OID: .1.0.8802.1.1.2.1.4.1.1.9.{timeMark}.{localPortNum}.{remIndex}
    fake_sys = [("1.0.8802.1.1.2.1.4.1.1.9.12345.55.1", "Aruba-Core")]
    fake_port = [("1.0.8802.1.1.2.1.4.1.1.7.12345.55.1", "A1")]
    fake_desc = [("1.0.8802.1.1.2.1.4.1.1.8.12345.55.1", "10GbE Port A1")]

    with patch.object(collector, "_execute_walks", return_value=[fake_sys, fake_port, fake_desc]):
        results = collector.poll_lldp_neighbors(sw, snmp_settings)

    assert len(results) == 1
    assert results[0]["protocol"] == "LLDP"
    assert results[0]["local_port"] == 55
    assert results[0]["remote_device_name"] == "Aruba-Core"
    assert results[0]["remote_port_id"] == "A1"


def test_poll_all_neighbors_merges_lldp_and_fdp():
    collector = NeighborCollector()
    sw = MagicMock(management_ip="192.69.1.101")
    snmp_settings = MagicMock()

    lldp_mock = [
        {"protocol": "LLDP", "local_port": 1, "local_if_index": 1, "remote_device_name": "Core-SW", "remote_port_id": "1/1/48", "remote_mgmt_ip": "", "remote_platform": ""}
    ]
    fdp_mock = [
        {"protocol": "FDP", "local_port": 1, "local_if_index": 1, "remote_device_name": "Core-SW", "remote_port_id": "1/1/48", "remote_mgmt_ip": "192.69.1.254", "remote_platform": "ICX7150-48"},
        {"protocol": "FDP", "local_port": 2, "local_if_index": 2, "remote_device_name": "Access-SW", "remote_port_id": "1/1/1", "remote_mgmt_ip": "192.69.1.103", "remote_platform": "ICX7150-24"}
    ]

    with patch.object(collector, "poll_lldp_neighbors", return_value=lldp_mock), \
         patch.object(collector, "poll_fdp_neighbors", return_value=fdp_mock):
        merged = collector.poll_all_neighbors(sw, snmp_settings)

    assert len(merged) == 2
    port1 = next(item for item in merged if item["local_port"] == 1)
    assert port1["protocol"] == "LLDP+FDP"
    assert port1["remote_mgmt_ip"] == "192.69.1.254"
    assert port1["remote_platform"] == "ICX7150-48"

    port2 = next(item for item in merged if item["local_port"] == 2)
    assert port2["protocol"] == "FDP"
    assert port2["remote_device_name"] == "Access-SW"
