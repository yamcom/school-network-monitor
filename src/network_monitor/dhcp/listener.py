"""Passive DHCP packet listener using Scapy sniff."""

from __future__ import annotations
import logging
import threading
from typing import Callable, Optional
from scapy.all import sniff
from scapy.packet import Packet
from network_monitor.dhcp.parser import DHCPParser
from network_monitor.models import DHCPEvent

logger = logging.getLogger("network_monitor.dhcp.listener")


class DHCPListener:
    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "udp and (port 67 or port 68)",
        callback: Optional[Callable[[DHCPEvent], None]] = None,
    ) -> None:
        """初始化 DHCP 監聽器。若 interface 為 None 或空字串，將自動交由 Scapy 預設網卡監聽。"""
        self.interface = interface if interface else None
        self.bpf_filter = bpf_filter
        self.callback = callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _packet_handler(self, pkt: Packet) -> None:
        try:
            event = DHCPParser.parse(pkt, capture_iface=self.interface)
            if event and self.callback:
                self.callback(event)
        except Exception as e:
            logger.error(f"Unexpected error handling captured packet: {e}", exc_info=True)

    def _sniff_loop(self) -> None:
        target_iface_str = self.interface if self.interface else "Default Interface"
        logger.info(f"Starting Scapy sniff on interface='{target_iface_str}', filter='{self.bpf_filter}'")
        try:
            sniff_kwargs = {
                "filter": self.bpf_filter,
                "prn": self._packet_handler,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "store": False,
            }
            # 若有傳入明確網卡介面則指定；若為 None 則不傳 iface 讓 Scapy 自動依路由決定
            if self.interface:
                sniff_kwargs["iface"] = self.interface

            sniff(**sniff_kwargs)
        except Exception as e:
            logger.critical(f"Sniffer crashed on interface '{target_iface_str}': {e}", exc_info=True)
        finally:
            logger.info("Sniffer loop terminated.")

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name="DHCPListenerThread")
        self._thread.start()

    def stop(self) -> None:
        logger.info("Stopping DHCPListener...")
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("DHCPListener stopped.")