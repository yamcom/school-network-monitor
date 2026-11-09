import sqlite3
import pytest
from core.models import DhcpEvent, WriteBatch
from core.vlan_resolver import VlanResolver
from database.migrations import migrate
from db_writer import DBWriter


def test_vlan_resolver_priorities():
    resolver = VlanResolver(
        default_vlan_id=1,
        relay_vlan_mapping={
            "192.168.10.1": 10,
            "192.168.20.1": 20,
        },
    )

    # Priority 1: giaddr hits relay_vlan_mapping
    vlan, source = resolver.resolve("192.168.10.1")
    assert vlan == 10
    assert source == "relay_mapping"

    vlan, source = resolver.resolve("192.168.20.1")
    assert vlan == 20
    assert source == "relay_mapping"

    # Priority 2: unmapped giaddr falls back to default VLAN
    vlan, source = resolver.resolve("192.168.99.1")
    assert vlan == 1
    assert source == "configured_default"

    # Priority 2: None giaddr falls back to default VLAN
    vlan, source = resolver.resolve(None)
    assert vlan == 1
    assert source == "configured_default"

    # Priority 3: default_vlan_id disabled and unmapped
    strict_resolver = VlanResolver(default_vlan_id=None, relay_vlan_mapping={"192.168.10.1": 10})
    vlan, source = strict_resolver.resolve("192.168.99.1")
    assert vlan is None
    assert source == "unknown"


def test_composite_device_identity_key():
    key1 = VlanResolver.make_device_identity_key("00:11:22:33:44:55", 1)
    assert key1 == "00:11:22:33:44:55|VLAN:1"

    key10 = VlanResolver.make_device_identity_key("00-11-22-33-44-55", 10)
    assert key10 == "00-11-22-33-44-55|VLAN:10"

    key_unknown = VlanResolver.make_device_identity_key("AA:BB:CC:DD:EE:FF", None)
    assert key_unknown == "AA:BB:CC:DD:EE:FF|VLAN:UNKNOWN"


def test_same_mac_different_vlans_in_database(tmp_path):
    db_path = tmp_path / "test_vlan.db"
    conn = sqlite3.connect(str(db_path))
    migrate(conn)

    writer = DBWriter(str(db_path))

    # Event 1: MAC on VLAN 10 (via Relay 192.168.10.1)
    ev1 = DhcpEvent(
        job_id="job-vlan",
        event_time="2026-11-08T08:00:00Z",
        message_type="ACK",
        client_mac="AA:BB:CC:11:22:33",
        assigned_ip="192.168.10.50",
        hostname="PC-VLAN10",
        relay_ip="192.168.10.1",
        vlan_id=10,
        vlan_source="relay_mapping",
        device_identity_key="AA:BB:CC:11:22:33|VLAN:10",
    )

    # Event 2: SAME MAC on VLAN 20 (via Relay 192.168.20.1)
    ev2 = DhcpEvent(
        job_id="job-vlan",
        event_time="2026-11-08T09:00:00Z",
        message_type="ACK",
        client_mac="AA:BB:CC:11:22:33",
        assigned_ip="192.168.20.50",
        hostname="PC-VLAN20",
        relay_ip="192.168.20.1",
        vlan_id=20,
        vlan_source="relay_mapping",
        device_identity_key="AA:BB:CC:11:22:33|VLAN:20",
    )

    batch = WriteBatch(job_id="job-vlan", events=(ev1, ev2))
    success = writer.apply_batch(batch)
    assert success is True

    # Verify that devices table contains TWO independent records for the SAME MAC!
    cur = conn.cursor()
    cur.execute("SELECT device_identity_key, mac, vlan_id, last_ip, hostname FROM devices ORDER BY vlan_id ASC")
    rows = cur.fetchall()

    assert len(rows) == 2

    assert rows[0][0] == "AA:BB:CC:11:22:33|VLAN:10"
    assert rows[0][1] == "AA:BB:CC:11:22:33"
    assert rows[0][2] == 10
    assert rows[0][3] == "192.168.10.50"
    assert rows[0][4] == "PC-VLAN10"

    assert rows[1][0] == "AA:BB:CC:11:22:33|VLAN:20"
    assert rows[1][1] == "AA:BB:CC:11:22:33"
    assert rows[1][2] == 20
    assert rows[1][3] == "192.168.20.50"
    assert rows[1][4] == "PC-VLAN20"

    conn.close()
