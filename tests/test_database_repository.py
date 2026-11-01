from datetime import datetime
from network_monitor.models import (
    DHCPEvent,
    DHCPMessageType,
    SwitchInfo,
    SwitchInterface,
)


def test_dhcp_events_and_device_separation(in_memory_repo):
    repo = in_memory_repo

    ev1 = DHCPEvent(
        event_time=datetime(2026, 1, 1, 8, 0, 0),
        client_mac="00:11:22:33:44:55",
        message_type=DHCPMessageType.DISCOVER,
        hostname="PC-LAB-01",
    )
    repo.record_dhcp_event(ev1)
    dev = repo.get_device_by_mac("00:11:22:33:44:55")
    assert dev is not None
    assert dev.current_ip is None
    assert dev.hostname == "PC-LAB-01"

    ev2 = DHCPEvent(
        event_time=datetime(2026, 1, 1, 8, 0, 1),
        client_mac="00:11:22:33:44:55",
        message_type=DHCPMessageType.REQUEST,
        requested_ip="192.168.1.50",
    )
    repo.record_dhcp_event(ev2)
    dev = repo.get_device_by_mac("00:11:22:33:44:55")
    assert dev.current_ip is None

    ev3 = DHCPEvent(
        event_time=datetime(2026, 1, 1, 8, 0, 2),
        client_mac="00:11:22:33:44:55",
        message_type=DHCPMessageType.ACK,
        assigned_ip="192.168.1.50",
        dhcp_server_id="192.168.1.254",
    )
    repo.record_dhcp_event(ev3)
    dev = repo.get_device_by_mac("00:11:22:33:44:55")
    assert dev.current_ip == "192.168.1.50"
    assert dev.last_ack_time == datetime(2026, 1, 1, 8, 0, 2)


def test_switch_interface_persistence(in_memory_repo):
    repo = in_memory_repo
    sw_id = repo.upsert_switch(
        SwitchInfo(
            switch_id=None,
            management_ip="192.168.10.1",
            sys_name="SW-01",
            vendor="Aruba",
            model="CX8100",
            sys_descr="ArubaOS-CX",
            last_poll_time=datetime.now(),
        )
    )

    intf1 = SwitchInterface(
        switch_id=sw_id,
        if_index=101,
        bridge_port=1,
        if_name="1/1/1",
        if_alias="Room 101 PC",
        is_uplink=False,
    )
    repo.save_interfaces([intf1])

    interfaces = repo.get_interfaces(sw_id)
    assert 101 in interfaces
    assert interfaces[101].if_name == "1/1/1"
    assert interfaces[101].if_alias == "Room 101 PC"
