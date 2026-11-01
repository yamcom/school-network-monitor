"""Main service entrypoint: orchestrates DHCP Listener and SNMP Polling."""

from __future__ import annotations
import os
import sys

# 強制在 Windows 繁體中文環境下以 UTF-8 讀取檔案，防止 pysnmp 載入 MIB 時發生 cp950 解碼錯誤
if sys.platform == "win32":
    os.environ["PYTHONUTF8"] = "1"
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")

import signal
import time
from network_monitor.cli.commands import cli
from network_monitor.config import load_settings
from network_monitor.dhcp.listener import DHCPListener
from network_monitor.logging_setup import setup_logging
from network_monitor.models import DHCPEvent
from network_monitor.snmp.collector import SNMPCollector
from network_monitor.storage.database import Database
from network_monitor.storage.migrations import apply_migrations
from network_monitor.storage.repository import NetworkRepository
from network_monitor.topology.resolver import TopologyResolver


def run_monitor_service(config_path: str = "config/settings.yaml", switches_path: str = "config/switches.example.yaml") -> None:
    settings = load_settings(config_path, switches_path)
    logger = setup_logging(settings.app.log_level)
    logger.info("Initializing School Network Monitor (Phase 1 Prototype)...")

    db = Database(settings.database.path)
    apply_migrations(db)
    repo = NetworkRepository(db)
    resolver = TopologyResolver(repo)

    def on_dhcp_event(event: DHCPEvent) -> None:
        logger.info(
            f"DHCP Event: [{event.message_type.value}] MAC: {event.client_mac} "
            f"AssignedIP: {event.assigned_ip} Hostname: '{event.hostname}'"
        )
        repo.record_dhcp_event(event)
        loc = resolver.resolve_mac(event.client_mac)
        repo.record_location(loc)

    listener = None
    if settings.capture.enabled:
        listener = DHCPListener(
            interface=settings.capture.interface,
            bpf_filter=settings.capture.filter,
            callback=on_dhcp_event,
        )
        listener.start()
    else:
        logger.warning("Packet capture is DISABLED in settings.yaml ('capture.enabled: false').")

    collector = SNMPCollector(repo)
    stop_requested = False

    def handle_sigint(signum, frame):
        nonlocal stop_requested
        logger.info("Shutdown signal received. Cleaning up...")
        stop_requested = True

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    last_poll = 0.0
    poll_interval = settings.snmp.poll_interval_seconds

    logger.info("Service loop started. Press Ctrl+C to terminate.")
    try:
        while not stop_requested:
            now = time.time()
            if now - last_poll >= poll_interval:
                logger.info("Starting scheduled SNMP polling cycle...")
                collector.poll_all(settings.switches, settings.snmp)
                last_poll = now

                purged = repo.purge_old_dhcp_events(settings.retention.dhcp_events_days)
                if purged > 0:
                    logger.info(f"Purged {purged} expired DHCP event records.")

            time.sleep(1.0)
    finally:
        if listener:
            listener.stop()
        logger.info("School Network Monitor stopped cleanly.")


def cli_entrypoint() -> None:
    if len(sys.argv) == 1:
        cli(["--help"])
    else:
        cli()


if __name__ == "__main__":
    cli_entrypoint()
