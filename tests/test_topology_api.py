import pytest
from fastapi.testclient import TestClient
from api_v2 import create_query_app
from database.connection import connect_database
from database.migrations import migrate
from core.models import utc_now


@pytest.fixture
def client_with_db(tmp_path):
    db_file = tmp_path / "test_topology_api.db"
    conn = connect_database(str(db_file))
    migrate(conn)

    now = utc_now()
    # Insert 2 switches
    conn.execute(
        """INSERT INTO switches(switch_id, management_ip, sys_name, vendor, model, poll_status, last_poll_time)
        VALUES ('192.69.1.110', '192.69.1.110', 'Cisco-Core', 'Cisco', 'C3560E', 'ONLINE_SNMP_OK', ?)""",
        (now,)
    )
    conn.execute(
        """INSERT INTO switches(switch_id, management_ip, sys_name, vendor, model, poll_status, last_poll_time)
        VALUES ('192.69.1.102', '192.69.1.102', 'Aruba-Edge', 'Aruba', '3810M', 'COMMUNITY_MISCONFIGURED', ?)""",
        (now,)
    )

    # Insert LLDP Neighbor link between 110 and 102
    conn.execute(
        """INSERT INTO switch_neighbors(switch_id, local_if_index, protocol, remote_sys_name, remote_port_id, remote_mgmt_ip, observed_at)
        VALUES ('192.69.1.110', 35, 'LLDP', 'Aruba-Edge', '55', '192.69.1.102', ?)""",
        (now,)
    )

    # Insert FDB on Cisco 110 port 12
    conn.execute(
        """INSERT INTO switch_fdb_current(switch_id, mac_address, bridge_port, if_index, last_updated)
        VALUES ('192.69.1.110', '00:11:22:33:44:55', 12, 12, ?)""",
        (now,)
    )

    # Insert device
    conn.execute(
        """INSERT INTO devices(device_identity_key, mac, vlan_id, hostname, last_ip, device_name, first_seen, last_seen, created_at, updated_at)
        VALUES ('00:11:22:33:44:55|VLAN:1', '00:11:22:33:44:55', 1, 'PC-Lab-01', '192.69.1.88', '化學實驗室電腦', ?, ?, ?, ?)""",
        (now, now, now, now)
    )

    conn.commit()
    conn.close()

    app = create_query_app(database_path=str(db_file), route_prefix="/api/v2")
    return TestClient(app)


def test_topology_graph_endpoint(client_with_db):
    resp = client_with_db.get("/api/v2/topology/graph")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"

    nodes = body["data"]["nodes"]
    edges = body["data"]["edges"]

    # Verify switch nodes and core nodes exist
    switch_nodes = [n for n in nodes if n["id"] not in {"__FIREWALL__", "__GATEWAY__"}]
    assert len(switch_nodes) == 2
    # Verify node colors match 4-state health model
    cisco_node = next(n for n in switch_nodes if n["id"] == "192.69.1.110")
    aruba_node = next(n for n in switch_nodes if n["id"] == "192.69.1.102")

    assert cisco_node["poll_status"] == "ONLINE_SNMP_OK"
    assert cisco_node["color"]["background"] == "#10B981"  # Emerald green

    assert aruba_node["poll_status"] == "COMMUNITY_MISCONFIGURED"
    assert aruba_node["color"]["background"] == "#F59E0B"  # Amber warning

    # Verify switch edge between them exists
    sw_edge = next(e for e in edges if e["from"] == "192.69.1.110" and e["to"] == "192.69.1.102")
    assert "LLDP" in sw_edge["label"]


def test_diagnostics_summary_endpoint(client_with_db):
    resp = client_with_db.get("/api/v2/diagnostics/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"

    counts = body["data"]["switch_counts"]
    assert counts["total"] == 2
    assert counts["online_ok"] == 1
    assert counts["community_misconfigured"] == 1
    assert counts["offline"] == 0

    assert 0 <= body["data"]["health_score"] <= 100


def test_topology_locate_endpoint(client_with_db):
    # Locate by IP
    resp_ip = client_with_db.get("/api/v2/topology/locate?q=192.69.1.88")
    assert resp_ip.status_code == 200
    body_ip = resp_ip.json()
    assert body_ip["status"] == "success"
    assert body_ip["found"] is True
    assert body_ip["data"]["switch_id"] == "192.69.1.110"
    assert body_ip["data"]["if_index"] == 12

    # Locate by MAC
    resp_mac = client_with_db.get("/api/v2/topology/locate?q=00:11:22:33:44:55")
    assert resp_mac.status_code == 200
    body_mac = resp_mac.json()
    assert body_mac["status"] == "success"
    assert body_mac["found"] is True
    assert body_mac["data"]["switch_id"] == "192.69.1.110"

    # Locate non-existent
    resp_none = client_with_db.get("/api/v2/topology/locate?q=10.99.99.99")
    assert resp_none.status_code == 200
    assert resp_none.json()["found"] is False


def test_core_nodes_api(client_with_db):
    # Test GET core-nodes
    resp = client_with_db.get("/api/v2/topology/core-nodes")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert "gateway_ip" in body["data"]

    # Test POST update core-nodes
    update_resp = client_with_db.post("/api/v2/topology/core-nodes", json={
        "gateway_ip": "192.69.1.254",
        "gateway_name": "校園核心閘道 (Gateway)",
        "firewall_ip": "192.69.1.253",
        "firewall_name": "核心防火牆 (FortiGate)",
        "core_switch_ip": "192.69.1.117"
    })
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "success"
