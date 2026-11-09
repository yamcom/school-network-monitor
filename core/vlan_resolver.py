"""VLAN Resolver implementing Relay Only strategy and Device Identity composite key.

Spec V2.3 Chapter 8:
- Priority 1: giaddr hits relay_vlan_mapping -> (vlan_id, "relay_mapping")
- Priority 2: default_vlan_id configured -> (default_vlan_id, "configured_default")
- Priority 3: no mapping and default disabled -> (None, "unknown")

Device Identity Key:
  Normalized MAC + VLAN ID (e.g. AA:BB:CC:11:22:33|VLAN:10)
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple


class VlanResolver:
    def __init__(
        self,
        default_vlan_id: Optional[int] = 1,
        mode: str = "relay",
        relay_vlan_mapping: Optional[Dict[str, int]] = None,
    ) -> None:
        self.default_vlan_id = default_vlan_id
        self.mode = mode
        # Normalize mapping keys (strip whitespace)
        self.relay_vlan_mapping: Dict[str, int] = {
            str(k).strip(): int(v) for k, v in (relay_vlan_mapping or {}).items()
        }

    def resolve(self, relay_ip: Optional[str]) -> Tuple[Optional[int], str]:
        """Resolve VLAN ID and source based on Relay Only strategy."""
        clean_relay = str(relay_ip).strip() if relay_ip else ""
        if clean_relay and clean_relay in self.relay_vlan_mapping:
            return self.relay_vlan_mapping[clean_relay], "relay_mapping"

        if self.default_vlan_id is not None:
            return self.default_vlan_id, "configured_default"

        return None, "unknown"

    @staticmethod
    def make_device_identity_key(mac: str, vlan_id: Optional[int]) -> str:
        """Create composite key = Normalized MAC + VLAN ID."""
        clean_mac = str(mac).strip().upper()
        vlan_suffix = f"VLAN:{vlan_id}" if vlan_id is not None else "VLAN:UNKNOWN"
        return f"{clean_mac}|{vlan_suffix}"
