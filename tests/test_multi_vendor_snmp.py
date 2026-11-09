import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from services.snmp_poller import SnmpPollerService
from snmp.fdb_collector import FdbCollector, _mac_from_oid_suffix
from network_monitor.snmp.neighbor_collector import NeighborCollector
from network_monitor.models import FdbEntry
from database.connection import connect_database


@pytest.fixture
def mock_db(tmp_path):
    db_file = tmp_path / "multi_vendor.db"
    return str(db_file)


def test_mac_from_oid_suffix():
    # Standard decimal OID suffix for MAC: 0.24.254.1.2.3 -> 00:18:FE:01:02:03
    oid_suffix = "0.24.254.1.2.3"
    mac = _mac_from_oid_suffix(oid_suffix)
    assert mac == "00:18:FE:01:02:03"


def test_multi_vendor_switches_loading(mock_db):
    """Verify that switches.yaml is correctly loaded with all vendors (Ruckus, Cisco, Aruba, Dlink, Fortinet)."""
    service = SnmpPollerService(database_path=mock_db)
    switches = service.get_configured_switches()

    assert len(switches) >= 10
    vendors = {s["vendor"].lower() for s in switches}
    assert "ruckus" in vendors
    assert "cisco" in vendors
    assert "aruba" in vendors
    assert "dlink" in vendors
    assert "brocade" in vendors

    # Check that communities are preserved
    cisco_sw = next(s for s in switches if s["vendor"].lower() == "cisco")
    assert cisco_sw["community"] == "SnmpPublic@TPC"
    assert "10101" in cisco_sw["uplink_ports"] or "35" in cisco_sw["uplink_ports"]


def test_multi_vendor_polling_and_uplink_marking(mock_db):
    """Simulate polling a Cisco switch, an Aruba switch, and a D-Link switch."""
    service = SnmpPollerService(database_path=mock_db)

    # Mock 3 multi-vendor switches
    mock_switches = [
        {
            "ip": "192.69.1.110",
            "name": "Cisco-Core",
            "vendor": "Cisco",
            "model": "C3560E",
            "community": "SnmpPublic@TPC",
            "uplink_ports": ["10101", "35"]
        },
        {
            "ip": "192.69.1.102",
            "name": "Aruba-3810M",
            "vendor": "Aruba",
            "model": "JL072A",
            "community": "SnmpPublic@TPC",
            "uplink_ports": ["49", "55"]
        },
        {
            "ip": "192.69.1.97",
            "name": "Dlink-97",
            "vendor": "Dlink",
            "model": "DGS1100-24",
            "community": "SnmpPublic@TPC",
            "uplink_ports": ["18"]
        }
    ]
    service.get_configured_switches = MagicMock(return_value=mock_switches)

    # Cisco FDB on access port (ifIndex 10)
    cisco_fdb = [FdbEntry(switch_id=0, mac="00:11:22:AA:BB:CC", bridge_port=10, if_index=10, vlan_id=1)]
    # Aruba FDB on access port (ifIndex 5)
    aruba_fdb = [FdbEntry(switch_id=0, mac="00:33:44:55:66:77", bridge_port=5, if_index=5, vlan_id=10)]
    # D-Link FDB on access port (ifIndex 2)
    dlink_fdb = [FdbEntry(switch_id=0, mac="00:88:99:AA:BB:CC", bridge_port=2, if_index=2, vlan_id=1)]

    # Mock neighbors
    cisco_nb = [{"local_if_index": 10101, "protocol": "LLDP", "remote_device_name": "Aruba-Core", "remote_port_id": "55"}]
    aruba_nb = [{"local_if_index": 55, "protocol": "LLDP", "remote_device_name": "Cisco-Core", "remote_port_id": "10101"}]
    dlink_nb = []

    async def mock_poll_switch(sw):
        ip = sw["ip"]
        if ip == "192.69.1.110":
            fdb, nb = cisco_fdb, cisco_nb
        elif ip == "192.69.1.102":
            fdb, nb = aruba_fdb, aruba_nb
        else:
            fdb, nb = dlink_fdb, dlink_nb

        return {
            "switch_id": ip,
            "ip": ip,
            "name": sw["name"],
            "vendor": sw["vendor"],
            "model": sw["model"],
            "uplink_ports": sw["uplink_ports"],
            "status": "reachable",
            "neighbors": nb,
            "fdb_entries": fdb,
            "error": None,
            "polled_at": "2026-11-08T14:00:00Z"
        }

    with patch.object(service, "poll_switch", side_effect=mock_poll_switch):
        count = asyncio.run(service.run_once())
        assert count > 0

    # Verify Database state
    conn = connect_database(mock_db)

    # 1. Verify all 3 switches recorded
    sw_rows = conn.execute("SELECT switch_id, vendor, model, poll_status FROM switches").fetchall()
    assert len(sw_rows) == 3
    sw_dict = {r["switch_id"]: r for r in sw_rows}
    assert sw_dict["192.69.1.110"]["vendor"] == "Cisco"
    assert sw_dict["192.69.1.102"]["vendor"] == "Aruba"
    assert sw_dict["192.69.1.97"]["vendor"] == "Dlink"

    # 2. Verify Uplink ports configured properly
    cisco_uplinks = conn.execute("SELECT if_index, is_uplink FROM switch_interfaces WHERE switch_id='192.69.1.110'").fetchall()
    cisco_up_indices = {r["if_index"] for r in cisco_uplinks if r["is_uplink"] == 1}
    assert 10101 in cisco_up_indices
    assert 35 in cisco_up_indices

    aruba_uplinks = conn.execute("SELECT if_index, is_uplink FROM switch_interfaces WHERE switch_id='192.69.1.102'").fetchall()
    aruba_up_indices = {r["if_index"] for r in aruba_uplinks if r["is_uplink"] == 1}
    assert 55 in aruba_up_indices

    # 3. Verify FDB entries
    fdb_rows = conn.execute("SELECT * FROM switch_fdb_current").fetchall()
    assert len(fdb_rows) == 3

    # 4. Verify Neighbors
    nb_rows = conn.execute("SELECT * FROM switch_neighbors").fetchall()
    assert len(nb_rows) == 2

    conn.close()
