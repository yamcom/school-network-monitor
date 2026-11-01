"""Bridge Port to ifIndex and interface name mapping."""

from __future__ import annotations
from typing import Dict, List, Optional
from network_monitor.models import FDBEntry, SwitchInterface


class InterfaceMapper:
    def __init__(self, interfaces: List[SwitchInterface]):
        self.interfaces_by_index: Dict[int, SwitchInterface] = {i.if_index: i for i in interfaces}
        self.bridge_to_ifindex: Dict[int, int] = {}

        for intf in interfaces:
            if intf.bridge_port is not None:
                self.bridge_to_ifindex[intf.bridge_port] = intf.if_index

    def resolve_ifindex(self, bridge_port: int) -> Optional[int]:
        if bridge_port in self.bridge_to_ifindex:
            return self.bridge_to_ifindex[bridge_port]
        if bridge_port in self.interfaces_by_index:
            return bridge_port
        return None

    def map_fdb_entries(self, fdb_entries: List[FDBEntry]) -> List[FDBEntry]:
        for entry in fdb_entries:
            if entry.if_index is None:
                entry.if_index = self.resolve_ifindex(entry.bridge_port)
        return fdb_entries

    def get_interface(self, if_index: int) -> Optional[SwitchInterface]:
        return self.interfaces_by_index.get(if_index)
