"""SNMP FDB (Forwarding Database / MAC Address Table) collector."""

from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from network_monitor.snmp.client import SNMPClient
from network_monitor.models import FdbEntry, normalize_mac

logger = logging.getLogger("network_monitor.snmp.fdb_collector")

# Standard Bridge MIB & Q-BRIDGE-MIB OIDs
DOT1D_TP_FDB_PORT  = "1.3.6.1.2.1.17.4.3.1.2"  # dot1dTpFdbPort (index: mac as 6 decimal octets)
DOT1Q_TP_FDB_PORT  = "1.3.6.1.2.1.17.7.1.2.2.1.2" # dot1qTpFdbPort (index: vlan_id.mac)
DOT1D_BASE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex (bridge_port -> if_index)


def _mac_from_oid_suffix(octets_str: str) -> Optional[str]:
    """Parse 6 decimal octets e.g. '0.24.254.1.2.3' into '00:18:FE:01:02:03'."""
    try:
        parts = [int(p) for p in octets_str.split(".") if p.isdigit()]
        if len(parts) >= 6:
            mac_octets = parts[-6:]
            return ":".join(f"{b:02X}" for b in mac_octets)
    except Exception:
        pass
    return None


class FdbCollector:
    """Collects MAC addresses learned on switch ports via SNMP."""

    def __init__(self, repo=None) -> None:
        self.repo = repo

    async def collect_bridge_port_mapping(self, client: SNMPClient) -> Dict[int, int]:
        """Fetch dot1dBasePortIfIndex to map bridge_port -> if_index."""
        mapping: Dict[int, int] = {}
        try:
            results = await client.walk(DOT1D_BASE_PORT_IF)
            for oid, val in results:
                # oid: .1.3.6.1.2.1.17.1.4.1.2.<bridge_port>
                parts = str(oid).strip(".").split(".")
                if parts:
                    b_port = int(parts[-1])
                    if_idx = int(val)
                    mapping[b_port] = if_idx
        except Exception as exc:
            logger.debug(f"Failed to collect dot1dBasePortIfIndex on {client.ip}: {exc}")
        return mapping

    async def collect_fdb(self, client: SNMPClient, switch_id: int = 0) -> List[FdbEntry]:
        """Collect FDB MAC table from a switch using Q-BRIDGE or standard Bridge-MIB."""
        entries: List[FdbEntry] = []
        now = datetime.now(timezone.utc)
        bp_to_if = await self.collect_bridge_port_mapping(client)

        # 1. Try dot1qTpFdbPort first
        try:
            q_results = await client.walk(DOT1Q_TP_FDB_PORT)
            for oid, val in q_results:
                clean_oid = str(oid).strip(".")
                norm_root = DOT1Q_TP_FDB_PORT.strip(".")
                suffix = clean_oid[len(norm_root):].strip(".")
                parts = suffix.split(".")
                if len(parts) >= 7:
                    vlan_id = int(parts[0])
                    mac = _mac_from_oid_suffix(".".join(parts[1:]))
                    bridge_port = int(val)
                    if mac and bridge_port > 0:
                        if_idx = bp_to_if.get(bridge_port, bridge_port)
                        entries.append(FdbEntry(
                            switch_id=switch_id,
                            mac=mac,
                            bridge_port=bridge_port,
                            vlan_id=vlan_id,
                            if_index=if_idx,
                            last_seen=now
                        ))
        except Exception as exc:
            logger.debug(f"Q-Bridge walk failed on {client.ip}: {exc}")

        # 2. If no entries found, fallback to standard dot1dTpFdbPort
        if not entries:
            try:
                d_results = await client.walk(DOT1D_TP_FDB_PORT)
                for oid, val in d_results:
                    clean_oid = str(oid).strip(".")
                    norm_root = DOT1D_TP_FDB_PORT.strip(".")
                    suffix = clean_oid[len(norm_root):].strip(".")
                    mac = _mac_from_oid_suffix(suffix)
                    bridge_port = int(val)
                    if mac and bridge_port > 0:
                        if_idx = bp_to_if.get(bridge_port, bridge_port)
                        entries.append(FdbEntry(
                            switch_id=switch_id,
                            mac=mac,
                            bridge_port=bridge_port,
                            vlan_id=1,
                            if_index=if_idx,
                            last_seen=now
                        ))
            except Exception as exc:
                logger.debug(f"Standard Bridge walk failed on {client.ip}: {exc}")

        return entries
