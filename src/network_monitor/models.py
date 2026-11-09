"""Domain models and data structures."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Any


class ResolutionStatus(str, Enum):
    CONFIRMED = "confirmed"
    CANDIDATE = "candidate"
    UNRESOLVED = "unresolved"
    VERIFIED = "verified"


class DHCPMessageType(str, Enum):
    DISCOVER = "DISCOVER"
    OFFER = "OFFER"
    REQUEST = "REQUEST"
    DECLINE = "DECLINE"
    ACK = "ACK"
    NAK = "NAK"
    RELEASE = "RELEASE"
    INFORM = "INFORM"


def normalize_mac(mac: str) -> Optional[str]:
    """Normalize MAC address to standard format."""
    if not mac:
        return None
    clean = "".join(c for c in mac if c.isalnum()).upper()
    if len(clean) == 12 and all(c in "0123456789ABCDEF" for c in clean):
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    return None


@dataclass
class SwitchConfig:
    management_ip: str
    name: str
    vendor: str = "Generic"
    model: str = "Standard-MIB"
    adapter: str = "standard_mib"
    enabled: bool = True
    snmp_version: Optional[str] = None
    community: Optional[str] = None
    v3_user: Optional[str] = None
    v3_auth_key: Optional[str] = None
    v3_priv_key: Optional[str] = None
    uplink_ports: List[str] = field(default_factory=list)


@dataclass
class SwitchInfo:
    switch_id: Optional[int] = None
    management_ip: str = ""
    sys_name: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    vendor: str = ""
    model: str = ""
    adapter_name: str = "standard_mib"
    snmp_version: Optional[str] = None
    community: Optional[str] = None
    poll_status: str = "offline"
    last_poll_time: Optional[datetime] = None
    uplink_ports: List[str] = field(default_factory=list)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        valid_fields = [
            "switch_id", "management_ip", "sys_name", "sys_descr",
            "sys_object_id", "vendor", "model", "adapter_name",
            "snmp_version", "community", "poll_status",
            "last_poll_time", "uplink_ports"
        ]
        for i, val in enumerate(args):
            if i < len(valid_fields):
                setattr(self, valid_fields[i], val)

        for k, v in kwargs.items():
            if k in valid_fields:
                setattr(self, k, v)
            elif k == "name" and not hasattr(self, "sys_name"):
                self.sys_name = v
            elif k == "adapter" and not hasattr(self, "adapter_name"):
                self.adapter_name = v

        for field_name in valid_fields:
            if not hasattr(self, field_name):
                if field_name == "uplink_ports":
                    setattr(self, field_name, [])
                elif field_name == "poll_status":
                    setattr(self, field_name, "offline")
                elif field_name == "adapter_name":
                    setattr(self, field_name, "standard_mib")
                elif field_name in ("switch_id", "snmp_version", "community", "last_poll_time"):
                    setattr(self, field_name, None)
                else:
                    setattr(self, field_name, "")


@dataclass
class SwitchInterface:
    switch_id: int
    if_index: int
    if_name: str = ""
    if_descr: Optional[str] = None
    if_alias: Optional[str] = None
    bridge_port: Optional[int] = None
    is_uplink: bool = False


@dataclass
class FdbEntry:
    switch_id: int = 0
    mac: str = ""
    bridge_port: int = 0
    vlan_id: Optional[int] = None
    last_seen: Optional[datetime] = None
    if_index: Optional[int] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        fields = ["switch_id", "mac", "bridge_port", "vlan_id", "last_seen", "if_index"]
        for i, val in enumerate(args):
            if i < len(fields):
                setattr(self, fields[i], val)

        if "mac_address" in kwargs and "mac" not in kwargs:
            kwargs["mac"] = kwargs.pop("mac_address")

        for k, v in kwargs.items():
            if k in fields:
                setattr(self, k, v)

        for field_name in fields:
            if not hasattr(self, field_name):
                if field_name in ("vlan_id", "last_seen", "if_index"):
                    setattr(self, field_name, None)
                elif field_name == "mac":
                    setattr(self, field_name, "")
                else:
                    setattr(self, field_name, 0)


# 建立大寫別名以相容 repository.py 的匯入需求
FDBEntry = FdbEntry


@dataclass
class DeviceCurrent:
    mac: str
    current_ip: Optional[str] = None
    hostname: Optional[str] = None
    last_seen: Optional[datetime] = None
    last_ack_time: Optional[datetime] = None


@dataclass
class DHCPEvent:
    id: Optional[int] = None
    mac: str = ""
    ip: Optional[str] = None
    hostname: Optional[str] = None
    timestamp: Optional[datetime] = None
    message_type: Optional[Any] = None
    requested_ip: Optional[str] = None
    fqdn: Optional[str] = None
    dhcp_server_id: Optional[str] = None
    transaction_id: Optional[str] = None
    source_ip: Optional[str] = None
    source_mac: Optional[str] = None
    capture_interface: Optional[str] = None
    is_rogue: bool = False
    alert_status: str = "NORMAL"

    @property
    def client_mac(self) -> str:
        """相容 repository.py 所需的 client_mac 屬性"""
        return self.mac

    @client_mac.setter
    def client_mac(self, val: str) -> None:
        self.mac = val

    @property
    def assigned_ip(self) -> Optional[str]:
        return self.ip

    @assigned_ip.setter
    def assigned_ip(self, val: Optional[str]) -> None:
        self.ip = val

    @property
    def event_time(self) -> Optional[datetime]:
        return self.timestamp

    @event_time.setter
    def event_time(self, val: Optional[datetime]) -> None:
        self.timestamp = val

    def __init__(self, **kwargs: Any) -> None:
        valid_fields = {
            "id", "mac", "ip", "hostname", "timestamp", "message_type",
            "requested_ip", "fqdn", "dhcp_server_id", "transaction_id",
            "source_ip", "source_mac", "capture_interface", "is_rogue", 
            "alert_status"
        }
        
        # 兼容各種別名傳遞（防止不同模組命名不一致導致錯誤）
        if "client_mac" in kwargs and "mac" not in kwargs:
            kwargs["mac"] = kwargs.pop("client_mac")
        if "assigned_ip" in kwargs and "ip" not in kwargs:
            kwargs["ip"] = kwargs.pop("assigned_ip")
        if "event_time" in kwargs and "timestamp" not in kwargs:
            kwargs["timestamp"] = kwargs.pop("event_time")
        if "server_identifier" in kwargs and "dhcp_server_id" not in kwargs:
            kwargs["dhcp_server_id"] = kwargs.pop("server_identifier")
        if "interface_name" in kwargs and "capture_interface" not in kwargs:
            kwargs["capture_interface"] = kwargs.pop("interface_name")

        for k, v in kwargs.items():
            if k in valid_fields:
                setattr(self, k, v)

        for field_name in valid_fields:
            if not hasattr(self, field_name):
                if field_name in ("id", "ip", "hostname", "timestamp", "message_type",
                                  "requested_ip", "fqdn", "dhcp_server_id", "transaction_id",
                                  "source_ip", "source_mac", "capture_interface"):
                    setattr(self, field_name, None)
                elif field_name == "mac":
                    setattr(self, field_name, "")


@dataclass
class DeviceLocation:
    mac: str
    switch_id: Optional[int] = None
    if_index: Optional[int] = None
    confidence: float = 0.0
    resolution_status: ResolutionStatus = ResolutionStatus.UNRESOLVED
    reason: str = ""
    candidates_count: int = 0


@dataclass
class DeviceVerification:
    id: Optional[int] = None
    mac: str = ""
    expected_switch_id: Optional[int] = None
    expected_if_index: Optional[int] = None
    actual_switch_id: Optional[int] = None
    actual_if_index: Optional[int] = None
    verified_at: Optional[datetime] = None
    is_match: bool = False
    note: str = ""
    
    # 追加至 src/network_monitor/models.py

class DeviceType(str, Enum):
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    PRINTER = "printer"
    SERVER = "server"
    NETWORK = "network"
    UNKNOWN = "unknown"


class IpAssignmentType(str, Enum):
    DHCP = "DHCP"
    STATIC = "STATIC"
    RESERVATION = "RESERVATION"
    UNKNOWN = "UNKNOWN"


class ManagementStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    IDENTIFIED = "IDENTIFIED"
    MANAGED = "MANAGED"
    UNMANAGED = "UNMANAGED"
    RETIRED = "RETIRED"


class RecordSource(str, Enum):
    DHCP = "DHCP"
    FDB = "FDB"
    MANUAL = "MANUAL"
    IMPORT = "IMPORT"


@dataclass
class DeviceInventoryItem:
    device_id: Optional[int] = None
    mac_address: str = ""
    device_name: Optional[str] = None
    hostname: Optional[str] = None
    device_type: str = "UNKNOWN"
    ip_assignment_type: str = "UNKNOWN"
    management_status: str = "UNMANAGED"
    record_source: str = "DISCOVERED"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    notes: Optional[str] = None
    current_ip: Optional[str] = None
    lease_status: Optional[str] = None
    lease_expiry: Optional[datetime] = None


@dataclass
class DeviceIpAssignment:
    id: Optional[int] = None
    device_id: int = 0
    ip_address: str = ""
    assignment_type: str = "UNKNOWN"
    vlan_id: Optional[int] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    is_current: bool = True
    source: str = "DHCP"
    verification_status: str = "UNVERIFIED"


from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any

class PortRole(str, Enum):
    UPLINK = "UPLINK"
    DOWNLINK = "DOWNLINK"
    ACCESS = "ACCESS"
    INTERCONNECT = "INTERCONNECT"
    UNKNOWN = "UNKNOWN"

class LinkConfidence(str, Enum):
    VERIFIED = "VERIFIED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"

@dataclass
class TopologyLink:
    link_id: Optional[int] = None
    local_switch_id: int = 0
    local_if_index: int = 0
    remote_switch_id: Optional[int] = None
    remote_switch_name: Optional[str] = None
    remote_mgmt_ip: Optional[str] = None
    remote_if_name: Optional[str] = None
    discovery_protocol: str = "LLDP"
    confidence_level: LinkConfidence = LinkConfidence.MEDIUM
    is_bidirectional: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: str = "ACTIVE"
    notes: Optional[str] = None

@dataclass
class TopologyObservation:
    obs_id: Optional[int] = None
    switch_id: int = 0
    if_index: int = 0
    protocol: str = "LLDP"
    remote_device_name: Optional[str] = None
    remote_mgmt_ip: Optional[str] = None
    remote_port_id: Optional[str] = None
    remote_port_desc: Optional[str] = None
    observed_at: Optional[datetime] = None