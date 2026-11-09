import pytest
from unittest.mock import AsyncMock, patch

from services.snmp_poller import SnmpPollerService
from services.diagnostics import NetworkDiagnosticsEngine
from database.connection import connect_database
from database.migrations import migrate
from core.models import utc_now


@pytest.fixture
def mock_db(tmp_path):
    db_file = tmp_path / "diag_test.db"
    conn = connect_database(str(db_file))
    migrate(conn)
    conn.close()
    return str(db_file)


def test_ping_probe_and_community_misconfigured_state(mock_db):
    """Test that when Ping succeeds but SNMP fails, status becomes COMMUNITY_MISCONFIGURED."""
    service = SnmpPollerService(database_path=mock_db)

    # 1. Switch responds to Ping, but SNMP throws exception
    with patch.object(service, "ping_host", new_callable=AsyncMock) as mock_ping, \
         patch.object(service.neighbor_collector, "poll_all_neighbors", side_effect=Exception("SNMP timeout")), \
         patch.object(service.fdb_collector, "collect_fdb", side_effect=Exception("SNMP timeout")):

        mock_ping.return_value = True  # Host is alive via ICMP

        import asyncio
        sw_result = asyncio.run(service.poll_switch({
            "ip": "192.69.1.50",
            "name": "Switch-Pending-Config",
            "vendor": "Cisco",
            "community": "WrongCommunity"
        }))

        assert sw_result["status"] == "COMMUNITY_MISCONFIGURED"
        assert sw_result["is_ping_ok"] is True

        # Commit to DB
        service.commit_polling_results([sw_result])

    # 2. Run Diagnostics Engine to verify COMMUNITY_MISCONFIGURED alert
    diag_engine = NetworkDiagnosticsEngine(database_path=mock_db)
    alerts = diag_engine.diagnose_switch_community_health()

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "SNMP_COMMUNITY_MISCONFIGURED"
    assert alerts[0]["ip"] == "192.69.1.50"
    assert "WrongCommunity" in alerts[0]["description"] or "misconfigured" in alerts[0]["description"]


def test_diagnostics_rogue_and_conflict(mock_db):
    """Test Rogue DHCP detection and IP Conflict detection in Diagnostics Engine."""
    conn = connect_database(mock_db)
    now = utc_now()

    # Insert analysis_job and switch first for FK constraint
    conn.execute(
        """INSERT INTO analysis_jobs(job_id, source_type, source_name, status, created_at)
        VALUES ('job-1', 'live', 'live_monitor', 'running', ?)""",
        (now,)
    )
    conn.execute(
        """INSERT INTO switches(switch_id, management_ip, sys_name)
        VALUES ('192.69.1.110', '192.69.1.110', 'Core-3560')"""
    )

    # 1. Insert Rogue DHCP OFFER
    conn.execute(
        """INSERT INTO dhcp_events(job_id, event_uid, event_time, created_at, source_type, message_type, client_mac, server_ip, server_mac, assigned_ip)
        VALUES ('job-1', 'uid-1', ?, ?, 'scapy', 'OFFER', '00:11:22:33:44:55', '192.168.1.1', 'AA:BB:CC:DD:EE:FF', '192.168.1.100')""",
        (now, now)
    )

    # Insert Rogue FDB location (Switch.110 Port 12)
    conn.execute(
        """INSERT INTO switch_fdb_current(switch_id, mac_address, bridge_port, if_index, last_updated)
        VALUES ('192.69.1.110', 'AA:BB:CC:DD:EE:FF', 12, 12, ?)""",
        (now,)
    )

    # 2. Insert IP Conflict (two MACs claiming same IP 192.69.1.88)
    conn.execute(
        """INSERT INTO dhcp_events(job_id, event_uid, event_time, created_at, source_type, message_type, client_mac, assigned_ip)
        VALUES ('job-1', 'uid-2', ?, ?, 'scapy', 'ACK', '11:11:11:11:11:11', '192.69.1.88')""",
        (now, now)
    )
    conn.execute(
        """INSERT INTO dhcp_events(job_id, event_uid, event_time, created_at, source_type, message_type, client_mac, assigned_ip)
        VALUES ('job-1', 'uid-3', ?, ?, 'scapy', 'ACK', '22:22:22:22:22:22', '192.69.1.88')""",
        (now, now)
    )
    conn.commit()
    conn.close()

    # Run Diagnostics
    diag_engine = NetworkDiagnosticsEngine(database_path=mock_db)

    # Authorized server is 192.69.1.9, so 192.168.1.1 must trigger ROGUE_DHCP
    rogue_alerts = diag_engine.detect_rogue_dhcp(authorized_servers=["192.69.1.9"])
    assert len(rogue_alerts) == 1
    assert rogue_alerts[0]["alert_type"] == "ROGUE_DHCP"
    assert rogue_alerts[0]["ip"] == "192.168.1.1"
    assert rogue_alerts[0]["switch_id"] == "192.69.1.110"
    assert rogue_alerts[0]["port"] == "12"

    # Verify IP Conflict
    conflict_alerts = diag_engine.detect_ip_conflicts()
    assert len(conflict_alerts) == 1
    assert conflict_alerts[0]["alert_type"] == "IP_CONFLICT"
    assert conflict_alerts[0]["ip"] == "192.69.1.88"
    assert "11:11:11:11:11:11" in conflict_alerts[0]["mac"]
    assert "22:22:22:22:22:22" in conflict_alerts[0]["mac"]
