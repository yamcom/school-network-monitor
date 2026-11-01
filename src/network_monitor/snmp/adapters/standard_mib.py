"""Standard MIB-II, BRIDGE-MIB and IF-MIB Switch Adapter."""

from __future__ import annotations
import logging
from typing import Dict, List, Tuple
from network_monitor.models import FDBEntry, SwitchInterface, normalize_mac
from network_monitor.snmp.adapters.base import BaseSwitchAdapter

logger = logging.getLogger("network_monitor.snmp.adapters.standard")

OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJ_ID = "1.3.6.1.2.1.1.2.0"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
OID_DOT1D_TP_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"


class StandardMIBAdapter(BaseSwitchAdapter):
    def fetch_system_info(self) -> Tuple[str, str, str]:
        name = self.client.sync_get(OID_SYS_NAME) or ""
        descr = self.client.sync_get(OID_SYS_DESCR) or ""
        obj_id = self.client.sync_get(OID_SYS_OBJ_ID) or ""
        return name, descr, obj_id

    def fetch_interfaces(self) -> List[SwitchInterface]:
        ifname_data = self.client.sync_walk(OID_IF_NAME)
        ifnames: Dict[int, str] = {}
        for oid, val in ifname_data:
            idx = int(oid.split(".")[-1])
            ifnames[idx] = str(val)

        ifdescr_data = self.client.sync_walk(OID_IF_DESCR)
        ifdescrs: Dict[int, str] = {}
        for oid, val in ifdescr_data:
            idx = int(oid.split(".")[-1])
            ifdescrs[idx] = str(val)

        ifalias_data = self.client.sync_walk(OID_IF_ALIAS)
        ifaliases: Dict[int, str] = {}
        for oid, val in ifalias_data:
            idx = int(oid.split(".")[-1])
            ifaliases[idx] = str(val)

        bridge_to_if: Dict[int, int] = {}
        base_port_data = self.client.sync_walk(OID_DOT1D_BASE_PORT_IF_INDEX)
        for oid, val in base_port_data:
            b_port = int(oid.split(".")[-1])
            try:
                bridge_to_if[b_port] = int(val)
            except ValueError:
                continue

        if_to_bridge = {v: k for k, v in bridge_to_if.items()}
        all_indices = set(ifnames.keys()) | set(ifdescrs.keys()) | set(bridge_to_if.values())
        results: List[SwitchInterface] = []

        for if_idx in sorted(all_indices):
            name = ifnames.get(if_idx) or ifdescrs.get(if_idx) or f"port-{if_idx}"
            b_port = if_to_bridge.get(if_idx)
            alias = ifaliases.get(if_idx)

            results.append(
                SwitchInterface(
                    switch_id=self.switch_info.switch_id or 0,
                    if_index=if_idx,
                    bridge_port=b_port,
                    if_name=name,
                    if_descr=ifdescrs.get(if_idx),
                    if_alias=alias,
                    is_uplink=False,
                )
            )
        return results

    def fetch_fdb(self) -> List[FDBEntry]:
        fdb_data = self.client.sync_walk(OID_DOT1D_TP_FDB_PORT)
        entries: List[FDBEntry] = []
        status_data = dict(self.client.sync_walk(OID_DOT1D_TP_FDB_STATUS))

        for oid, val in fdb_data:
            try:
                bridge_port = int(val)
            except ValueError:
                continue

            if bridge_port <= 0:
                continue

            parts = oid.split(".")
            if len(parts) < 6:
                continue

            mac_octets = parts[-6:]
            try:
                mac_bytes = [int(o) for o in mac_octets]
                mac_str = ":".join(f"{b:02X}" for b in mac_bytes)
            except ValueError:
                continue

            norm_mac = normalize_mac(mac_str)
            if not norm_mac:
                continue

            status_oid = f"{OID_DOT1D_TP_FDB_STATUS}.{'.'.join(mac_octets)}"
            status_val = status_data.get(status_oid)
            if status_val is not None:
                try:
                    s_code = int(status_val)
                    if s_code not in (3, 4):
                        continue
                except ValueError:
                    pass

            entries.append(
                FDBEntry(
                    switch_id=self.switch_info.switch_id or 0,
                    mac_address=norm_mac,
                    bridge_port=bridge_port,
                    if_index=None,
                )
            )

        return entries
