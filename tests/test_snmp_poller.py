import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.models import DhcpEvent
from services.snmp_poller import SnmpPollerService
from network_monitor.models import FdbEntry


@pytest.fixture
def mock_db(tmp_path):
    db_file = tmp_path / "test_poller.db"
    return str(db_file)


def test_snmp_poller_service_basic(mock_db):
    service = SnmpPollerService(database_path=mock_db)
    
    # Mock single switch
    mock_switches = [{
        "ip": "10.0.0.1",
        "name": "Test-Switch-01",
        "community": "public",
        "model": "ICX 7450"
    }]
    service.get_configured_switches = MagicMock(return_value=mock_switches)

    # Mock neighbors dict
    mock_nb = {
        "local_if_index": 1,
        "local_port": 1,
        "remote_device_name": "Neighbor-Core",
        "remote_port_id": "1/1/1",
        "remote_mgmt_ip": "10.0.0.2",
        "remote_platform": "Brocade",
        "protocol": "LLDP+FDP"
    }
    mock_fdb = FdbEntry(
        switch_id=0,
        mac="00:11:22:33:44:55",
        bridge_port=1,
        if_index=1,
        vlan_id=10
    )

    with patch.object(service.neighbor_collector, "poll_all_neighbors") as mock_nb_col, \
         patch.object(service.fdb_collector, "collect_fdb", new_callable=AsyncMock) as mock_fdb_col:
        
        mock_nb_col.return_value = [mock_nb]
        mock_fdb_col.return_value = [mock_fdb]

        import asyncio
        count = asyncio.run(service.run_once())
        assert count == 2  # 1 neighbor + 1 FDB

    # Verify database contents
    from database.connection import connect_database
    conn = connect_database(mock_db)
    sw = conn.execute("SELECT * FROM switches WHERE switch_id='10.0.0.1'").fetchone()
    assert sw is not None
    assert sw["management_ip"] == "10.0.0.1"
    assert sw["sys_name"] == "Test-Switch-01"

    nb_row = conn.execute("SELECT * FROM switch_neighbors WHERE switch_id='10.0.0.1'").fetchone()
    assert nb_row is not None
    assert nb_row["remote_sys_name"] == "Neighbor-Core"
    assert nb_row["protocol"] == "LLDP+FDP"

    fdb_row = conn.execute("SELECT * FROM switch_fdb_current WHERE switch_id='10.0.0.1'").fetchone()
    assert fdb_row is not None
    assert fdb_row["mac_address"] == "00:11:22:33:44:55"
    assert fdb_row["vlan_id"] == 10

    conn.close()
