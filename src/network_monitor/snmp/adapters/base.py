"""Base Switch MIB Adapter interface."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple
from network_monitor.models import FDBEntry, SwitchInfo, SwitchInterface
from network_monitor.snmp.client import SNMPClient


class BaseSwitchAdapter(ABC):
    def __init__(self, client: SNMPClient, switch_info: SwitchInfo):
        self.client = client
        self.switch_info = switch_info

    @abstractmethod
    def fetch_system_info(self) -> Tuple[str, str, str]:
        pass

    @abstractmethod
    def fetch_interfaces(self) -> List[SwitchInterface]:
        pass

    @abstractmethod
    def fetch_fdb(self) -> List[FDBEntry]:
        pass
