from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from network_monitor.dhcp.parser import DHCPParser
from network_monitor.models import DHCPMessageType, normalize_mac


def build_dhcp_packet(msg_type: int, chaddr: bytes, yiaddr="0.0.0.0", req_ip=None, hostname=None, srv_id=None):
    opts = [("message-type", msg_type)]
    if req_ip:
        opts.append(("requested_addr", req_ip))
    if hostname:
        opts.append(("hostname", hostname.encode()))
    if srv_id:
        opts.append(("server_id", srv_id))
    opts.append("end")

    return (
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=chaddr, hlen=6, yiaddr=yiaddr, xid=0x12345678)
        / DHCP(options=opts)
    )


def test_mac_normalization():
    assert normalize_mac("001122aabbcc") == "00:11:22:AA:BB:CC"
    assert normalize_mac("00-11-22-aa-bb-cc") == "00:11:22:AA:BB:CC"
    assert normalize_mac("00:11:22:AA:BB:CC") == "00:11:22:AA:BB:CC"
    assert normalize_mac("invalid_mac") is None
    assert normalize_mac("") is None


def test_parse_dhcp_discover():
    pkt = build_dhcp_packet(msg_type=1, chaddr=b"\x00\xaa\xbb\xcc\xdd\xee", hostname="DESKTOP-ABC")
    event = DHCPParser.parse(pkt, capture_iface="eth0")
    assert event is not None
    assert event.message_type == DHCPMessageType.DISCOVER
    assert event.client_mac == "00:AA:BB:CC:DD:EE"
    assert event.hostname == "DESKTOP-ABC"
    assert event.assigned_ip is None


def test_parse_dhcp_request_requested_ip():
    pkt = build_dhcp_packet(msg_type=3, chaddr=b"\x00\xaa\xbb\xcc\xdd\xee", req_ip="192.168.1.100")
    event = DHCPParser.parse(pkt)
    assert event.message_type == DHCPMessageType.REQUEST
    assert event.requested_ip == "192.168.1.100"
    assert event.assigned_ip is None


def test_parse_dhcp_ack_confirmed_ip():
    pkt = build_dhcp_packet(msg_type=5, chaddr=b"\x00\xaa\xbb\xcc\xdd\xee", yiaddr="192.168.1.100", srv_id="192.168.1.1")
    event = DHCPParser.parse(pkt)
    assert event.message_type == DHCPMessageType.ACK
    assert event.assigned_ip == "192.168.1.100"
    assert event.dhcp_server_id == "192.168.1.1"


def test_parse_dhcp_nak():
    pkt = build_dhcp_packet(msg_type=6, chaddr=b"\x00\xaa\xbb\xcc\xdd\xee", srv_id="192.168.1.1")
    event = DHCPParser.parse(pkt)
    assert event.message_type == DHCPMessageType.NAK
    assert event.dhcp_server_id == "192.168.1.1"
    assert event.assigned_ip is None


def test_parse_missing_hostname_graceful():
    pkt = build_dhcp_packet(msg_type=1, chaddr=b"\x00\xaa\xbb\xcc\xdd\xee")
    event = DHCPParser.parse(pkt)
    assert event is not None
    assert event.hostname is None
