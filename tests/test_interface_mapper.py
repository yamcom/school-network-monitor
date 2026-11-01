from network_monitor.models import FDBEntry, SwitchInterface
from network_monitor.topology.interface_mapper import InterfaceMapper


def test_bridge_port_to_ifindex_mapping():
    interfaces = [
        SwitchInterface(switch_id=1, if_index=101, bridge_port=1, if_name="GigabitEthernet1/0/1"),
        SwitchInterface(switch_id=1, if_index=102, bridge_port=2, if_name="GigabitEthernet1/0/2"),
    ]
    mapper = InterfaceMapper(interfaces)

    assert mapper.resolve_ifindex(1) == 101
    assert mapper.resolve_ifindex(2) == 102
    assert mapper.resolve_ifindex(999) is None

    fdb = [FDBEntry(switch_id=1, mac_address="00:11:22:33:44:55", bridge_port=1)]
    mapped = mapper.map_fdb_entries(fdb)
    assert mapped[0].if_index == 101
