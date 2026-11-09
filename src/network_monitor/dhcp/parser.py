"""DHCP packet parser using Scapy."""

from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from network_monitor.models import DHCPEvent, DHCPMessageType, normalize_mac

DHCP_MSG_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM"
}


class DHCPParser:
    @staticmethod
    def parse(packet: Any, capture_iface: Optional[str] = None) -> Optional[DHCPEvent]:
        """相容 Scapy DHCP 封包與已解析物件的強固解析器"""
        if isinstance(packet, DHCPEvent):
            if capture_iface and not packet.capture_interface:
                packet.capture_interface = capture_iface
            return packet

        if not packet or not hasattr(packet, "haslayer") or not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
            return None

        bootp = packet[BOOTP]
        dhcp = packet[DHCP]

        # 擷取 DHCP 選項
        dhcp_opts: dict[Any, Any] = {}
        if hasattr(dhcp, "options") and dhcp.options:
            for opt in dhcp.options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    dhcp_opts[opt[0]] = opt[1]

        msg_type_code = dhcp_opts.get("message-type") or dhcp_opts.get(53) or 0
        msg_type_str = DHCP_MSG_TYPES.get(int(msg_type_code), f"UNKNOWN({msg_type_code})")

        try:
            msg_type = DHCPMessageType(msg_type_str) if msg_type_str in DHCPMessageType.__members__ else DHCPMessageType.DISCOVER
        except Exception:
            msg_type = DHCPMessageType.DISCOVER

        # 用戶端 MAC
        client_mac = ""
        if bootp.chaddr:
            raw_chaddr = bootp.chaddr[:bootp.hlen] if hasattr(bootp, "hlen") and bootp.hlen else bootp.chaddr[:6]
            client_mac = ":".join(f"{b:02X}" for b in raw_chaddr if isinstance(b, int))
        
        norm_client_mac = normalize_mac(client_mac)
        if not norm_client_mac and packet.haslayer(Ether):
            norm_client_mac = normalize_mac(packet[Ether].src)

        if not norm_client_mac:
            return None

        yiaddr = bootp.yiaddr if (bootp.yiaddr and bootp.yiaddr != "0.0.0.0") else None
        ciaddr = bootp.ciaddr if (bootp.ciaddr and bootp.ciaddr != "0.0.0.0") else None
        requested_ip = dhcp_opts.get("requested_addr") or dhcp_opts.get(50)
        assigned_ip = yiaddr if msg_type_str in ("OFFER", "ACK") else None

        hostname = dhcp_opts.get("hostname") or dhcp_opts.get(12)
        if isinstance(hostname, bytes):
            hostname = hostname.decode("utf-8", errors="ignore").rstrip("\x00")

        fqdn = dhcp_opts.get("client_FQDN") or dhcp_opts.get(81)
        if isinstance(fqdn, bytes):
            fqdn = fqdn.decode("utf-8", errors="ignore").rstrip("\x00")
        elif isinstance(fqdn, tuple) and len(fqdn) > 1 and isinstance(fqdn[1], (bytes, str)):
            fqdn = str(fqdn[1]).rstrip("\x00")

        # Lease Time (Option 51)
        lease_time = dhcp_opts.get("lease_time") or dhcp_opts.get(51)
        if lease_time is not None:
            try:
                lease_time = int(lease_time)
            except (ValueError, TypeError):
                lease_time = None

        # T1/T2 (Option 58, 59)
        renewal_time = dhcp_opts.get("renewal_time") or dhcp_opts.get(58)
        rebinding_time = dhcp_opts.get("rebinding_time") or dhcp_opts.get(59)

        # Client Identifier (Option 61)
        client_id = dhcp_opts.get("client_id") or dhcp_opts.get(61)
        if isinstance(client_id, bytes):
            client_id = client_id.hex()

        server_id = dhcp_opts.get("server_id") or dhcp_opts.get("server_identifier") or dhcp_opts.get(54)
        if not server_id and packet.haslayer(IP):
            server_id = packet[IP].src
        server_id = str(server_id) if server_id else "0.0.0.0"

        xid = hex(bootp.xid) if hasattr(bootp, "xid") else None
        src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
        src_mac = normalize_mac(packet[Ether].src) if packet.haslayer(Ether) else ""

        return DHCPEvent(
            timestamp=datetime.now(),
            mac=norm_client_mac,
            message_type=msg_type,
            ip=assigned_ip,
            requested_ip=requested_ip,
            hostname=hostname,
            fqdn=fqdn,
            dhcp_server_id=server_id,
            transaction_id=xid,
            source_ip=src_ip,
            source_mac=src_mac,
            capture_interface=capture_iface,
            lease_time=lease_time,
            renewal_time=renewal_time,
            rebinding_time=rebinding_time,
            client_id=client_id,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
        )