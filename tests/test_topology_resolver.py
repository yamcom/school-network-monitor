from datetime import datetime
from network_monitor.models import (
    FDBEntry,
    ResolutionStatus,
    SwitchInfo,
    SwitchInterface,
)
from network_monitor.topology.resolver import TopologyResolver


def test_single_switch_access_port(in_memory_repo):
    repo = in_memory_repo
    sw_id = repo.upsert_switch(SwitchInfo(None, "192.168.10.1", "SW-ACCESS", "Ruckus", "ICX", "", datetime.now()))
    repo.save_interfaces([
        SwitchInterface(switch_id=sw_id, if_index=1, bridge_port=1, if_name="1/1/1", is_uplink=False)
    ])
    repo.replace_fdb_snapshot(sw_id, [
        FDBEntry(switch_id=sw_id, mac_address="00:11:22:33:44:55", bridge_port=1, if_index=1)
    ])

    resolver = TopologyResolver(repo)
    loc = resolver.resolve_mac("00:11:22:33:44:55")
    assert loc.resolution_status == ResolutionStatus.CONFIRMED
    assert loc.switch_id == sw_id
    assert loc.if_index == 1
    assert loc.confidence == 1.0


def test_mac_on_uplink_port_not_arbitrarily_confirmed(in_memory_repo):
    repo = in_memory_repo
    sw_id = repo.upsert_switch(SwitchInfo(None, "192.168.10.1", "CORE-SW", "Aruba", "CX", "", datetime.now()))
    repo.save_interfaces([
        SwitchInterface(switch_id=sw_id, if_index=48, bridge_port=48, if_name="1/1/48", is_uplink=True)
    ])
    repo.replace_fdb_snapshot(sw_id, [
        FDBEntry(switch_id=sw_id, mac_address="00:11:22:33:44:55", bridge_port=48, if_index=48)
    ])

    resolver = TopologyResolver(repo)
    loc = resolver.resolve_mac("00:11:22:33:44:55")
    assert loc.resolution_status != ResolutionStatus.CONFIRMED
    assert loc.confidence < 0.5
    assert "uplink" in loc.reason.lower()


def test_multiple_switches_same_mac_candidate_preserved(in_memory_repo):
    repo = in_memory_repo
    sw1 = repo.upsert_switch(SwitchInfo(None, "192.168.10.1", "SW-1", "HPE", "1920", "", datetime.now()))
    sw2 = repo.upsert_switch(SwitchInfo(None, "192.168.10.2", "SW-2", "HPE", "1920", "", datetime.now()))

    repo.save_interfaces([
        SwitchInterface(switch_id=sw1, if_index=5, bridge_port=5, if_name="1/0/5", is_uplink=False),
        SwitchInterface(switch_id=sw2, if_index=6, bridge_port=6, if_name="1/0/6", is_uplink=False),
    ])

    repo.replace_fdb_snapshot(sw1, [FDBEntry(sw1, "00:11:22:33:44:55", 5, 5)])
    repo.replace_fdb_snapshot(sw2, [FDBEntry(sw2, "00:11:22:33:44:55", 6, 6)])

    resolver = TopologyResolver(repo)
    loc = resolver.resolve_mac("00:11:22:33:44:55")
    assert loc.resolution_status == ResolutionStatus.CANDIDATE
    assert "multiple access port candidates" in loc.reason.lower()
