"""Vendor-specific extension hooks."""

from __future__ import annotations
from network_monitor.snmp.adapters.standard_mib import StandardMIBAdapter


class CiscoCatalystAdapter(StandardMIBAdapter):
    pass


class ArubaAOSCXAdapter(StandardMIBAdapter):
    pass


ADAPTER_REGISTRY = {
    "standard_mib": StandardMIBAdapter,
    "cisco_catalyst": CiscoCatalystAdapter,
    "aruba_aoscx": ArubaAOSCXAdapter,
}


def get_adapter(adapter_name: str) -> type[StandardMIBAdapter]:
    return ADAPTER_REGISTRY.get(adapter_name.lower(), StandardMIBAdapter)
