from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from datetime import datetime, timezone
from typing import Callable

from scapy.utils import PcapReader

from core.anomaly_engine import DhcpAnomalyEngine
from core.dhcp_parser import parse_scapy_packet
from core.models import WriteBatch
from core.vlan_resolver import VlanResolver


class PcapAnalysisWorker:
    """Streaming PCAP/PCAPNG worker; one packet is held at a time."""

    def __init__(self, batch_size: int = 1000, authorized_servers: set[str] | None = None, vlan_resolver: VlanResolver | None = None):
        self.batch_size = batch_size
        self.engine = DhcpAnomalyEngine(authorized_servers=authorized_servers or set())
        self.vlan_resolver = vlan_resolver or VlanResolver()

    def run(self, path: str | Path, job_id: str, emit: Callable[[WriteBatch], bool | None]) -> dict[str, int]:
        events = []
        counters: dict[str, int] = {}
        processed = 0
        parse_errors = 0
        sequence = 0
        with PcapReader(str(path)) as reader:
            for packet in reader:
                processed += 1
                try:
                    packet_time = getattr(packet, "time", None)
                    if packet_time is not None:
                        event_time = datetime.fromtimestamp(float(packet_time), timezone.utc).isoformat().replace("+00:00", "Z")
                    else:
                        event_time = "unknown"
                    event = parse_scapy_packet(packet, job_id, source_type="pcap", source_packet_no=processed, event_time=event_time)
                    if event is None:
                        continue
                    vlan_id, vlan_source = self.vlan_resolver.resolve(event.relay_ip)
                    dev_key = self.vlan_resolver.make_device_identity_key(event.client_mac, vlan_id)
                    event = replace(event, vlan_id=vlan_id, vlan_source=vlan_source, device_identity_key=dev_key)
                    event = self.engine.classify(event)
                    events.append(event)
                    counters[event.message_type] = counters.get(event.message_type, 0) + 1
                    if event.anomaly_type != "NONE":
                        counters[event.anomaly_type] = counters.get(event.anomaly_type, 0) + 1
                    if len(events) >= self.batch_size:
                        sequence += 1
                        emit(WriteBatch(job_id=job_id, events=tuple(events), stats=dict(counters), processed_packets=processed, batch_sequence=sequence))
                        events.clear()
                except Exception:
                    parse_errors += 1
        if events:
            sequence += 1
            emit(WriteBatch(job_id=job_id, events=tuple(events), stats=dict(counters), processed_packets=processed, batch_sequence=sequence))
        return {"processed_packets": processed, "parse_errors": parse_errors, **counters}

