"""Background SNMP Poller Service.

Periodically polls configured switches via SNMP for:
1. LLDP & FDP neighbors (Brocade/Ruckus FastIron & Standard)
2. FDB MAC Address Table (dot1qTpFdbPort & dot1dTpFdbPort)
3. Computes endpoint switch/port via TopologyResolver (uplink pruning)
4. Submits updates to db_writer via NORMAL priority queue.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.config import load_config
from core.models import WriteBatch, utc_now
from db_writer import WriterClient
from network_monitor.models import SwitchConfig, FdbEntry
from network_monitor.snmp.client import SNMPClient
from network_monitor.snmp.neighbor_collector import NeighborCollector
from snmp.fdb_collector import FdbCollector

logger = logging.getLogger("school_network_monitor.snmp_poller")


class SnmpPollerService:
    def __init__(self, database_path: str = "data/dhcp_analyzer.db", config_path: Optional[str] = None):
        self.database_path = database_path
        self.config_path = config_path
        self.cfg = load_config(config_path)
        self.writer = WriterClient(database_path)
        self.neighbor_collector = NeighborCollector()
        self.fdb_collector = FdbCollector()
        self.is_running = False

    def get_configured_switches(self) -> List[Dict[str, Any]]:
        # 優先讀取 config/switches.yaml
        from pathlib import Path
        import yaml
        switches_file = Path("config/switches.yaml")
        if switches_file.is_file():
            try:
                with open(switches_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                raw_list = data.get("switches", [])
                result = []
                for s in raw_list:
                    if s:
                        raw_uplinks = s.get("uplink_ports") or []
                        result.append({
                            "ip": s.get("management_ip"),
                            "name": s.get("name"),
                            "vendor": s.get("vendor", "Generic"),
                            "model": s.get("model", ""),
                            "community": s.get("community", "SnmpPublic@TPC"),
                            "snmp_version": s.get("snmp_version", "2c"),
                            "enabled": bool(s.get("enabled", True)),
                            "uplink_ports": [str(p) for p in raw_uplinks if p is not None],
                        })
                if result:
                    return result
            except Exception as e:
                logger.warning(f"Failed to load config/switches.yaml: {e}")

        # Fallback to config.yaml
        snmp_cfg = self.cfg.get("snmp_poller", {})
        return snmp_cfg.get("switches", [])

    @staticmethod
    async def ping_host(ip: str, timeout_ms: int = 1000) -> bool:
        """Asynchronously ping host reliably via Windows threadpool executor."""
        import subprocess
        try:
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["ping", "-n", "1", "-w", str(timeout_ms), ip],
                    capture_output=True
                )
            )
            return res.returncode == 0 and b"TTL=" in res.stdout.upper()
        except Exception as e:
            logger.debug(f"Ping exception for {ip}: {e}")
            return False

    async def poll_switch(self, sw: Dict[str, Any]) -> Dict[str, Any]:
        """Poll a single switch for neighbors and FDB with Ping probe first.
        If enabled == False, only perform Ping probe and mark as SNMP_UNCONFIGURED if online."""
        ip = sw.get("ip")
        community = sw.get("community", "public")
        name = sw.get("name", ip)
        sw_id = str(ip)
        is_enabled = sw.get("enabled", True)

        # 1. Ping Probe First: Check physical reachability
        is_ping_ok = await self.ping_host(ip)

        # If switch is disabled in switches.yaml, do NOT perform SNMP queries
        if not is_enabled:
            return {
                "switch_id": sw_id,
                "ip": ip,
                "name": name,
                "vendor": sw.get("vendor", "Generic"),
                "model": sw.get("model", ""),
                "uplink_ports": sw.get("uplink_ports", []),
                "status": "SNMP_UNCONFIGURED" if is_ping_ok else "HOST_OFFLINE",
                "is_ping_ok": is_ping_ok,
                "neighbors": [],
                "fdb_entries": [],
                "error": None if is_ping_ok else "Device is physically unreachable (ICMP Ping timeout)",
                "polled_at": utc_now(),
            }

        client = SNMPClient(
            ip=ip,
            version=sw.get("snmp_version", "2c"),
            community=community,
            timeout=float(self.cfg.get("snmp_poller", {}).get("timeout_seconds", 3)),
            retries=int(self.cfg.get("snmp_poller", {}).get("retries", 1)),
        )

        neighbors = []
        fdb_entries = []
        snmp_error = None

        try:
            # 2. Collect Neighbors (LLDP + FDP)
            sw_dummy = type("DummySwitch", (), {"management_ip": ip})()
            snmp_settings = type("DummySettings", (), {
                "version": "2c",
                "community": community,
                "timeout_seconds": float(self.cfg.get("snmp_poller", {}).get("timeout_seconds", 3)),
                "retries": int(self.cfg.get("snmp_poller", {}).get("retries", 1)),
            })()
            neighbors = self.neighbor_collector.poll_all_neighbors(sw_dummy, snmp_settings)
        except Exception as exc:
            snmp_error = exc

        try:
            # 3. Collect FDB MACs
            fdb_entries = await self.fdb_collector.collect_fdb(client, switch_id=0)
        except Exception as exc:
            snmp_error = exc or snmp_error

        # 4. Evaluate 4-State Health Model
        error_msg = None
        if is_ping_ok:
            if neighbors or fdb_entries:
                status = "ONLINE_SNMP_OK"
            else:
                # Ping is OK, but SNMP returned nothing or timed out -> Community 未設定或不符
                status = "COMMUNITY_MISCONFIGURED"
                error_msg = f"Ping OK, but SNMP query failed/timed out (Community: {community})"
        else:
            status = "HOST_OFFLINE"
            error_msg = "Device is physically unreachable (ICMP Ping timeout)"

        return {
            "switch_id": sw_id,
            "ip": ip,
            "name": name,
            "vendor": sw.get("vendor", "Generic"),
            "model": sw.get("model", ""),
            "uplink_ports": sw.get("uplink_ports", []),
            "status": status,
            "is_ping_ok": is_ping_ok,
            "neighbors": neighbors,
            "fdb_entries": fdb_entries,
            "error": error_msg or (str(snmp_error) if snmp_error else None),
            "polled_at": utc_now(),
        }

    async def poll_all_switches(self) -> List[Dict[str, Any]]:
        switches = self.get_configured_switches()
        if not switches:
            logger.info("No switches configured for SNMP polling.")
            return []

        tasks = [self.poll_switch(sw) for sw in switches]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return results

    def commit_polling_results(self, results: List[Dict[str, Any]]) -> int:
        """Persist SNMP neighbors, FDB, and switch statuses to SQLite via direct SQL connection."""
        from database.connection import connect_database
        from database.migrations import migrate
        
        conn = connect_database(self.database_path)
        migrate(conn)
        total_records = 0
        now = utc_now()

        with conn:
            for res in results:
                sw_id = res["switch_id"]
                ip = res["ip"]
                name = res["name"]
                
                # Upsert switch
                conn.execute(
                    """INSERT INTO switches(switch_id, management_ip, sys_name, vendor, model, poll_status, last_poll_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(switch_id) DO UPDATE SET
                        management_ip=excluded.management_ip,
                        sys_name=excluded.sys_name,
                        vendor=excluded.vendor,
                        model=excluded.model,
                        poll_status=excluded.poll_status,
                        last_poll_time=excluded.last_poll_time""",
                    (sw_id, ip, name, res.get("vendor", "Generic"), res.get("model", ""), res["status"], now),
                )

                # Update configured uplink ports for this switch
                uplinks = res.get("uplink_ports", [])
                for u_port in uplinks:
                    try:
                        u_idx = int(u_port)
                        conn.execute(
                            """INSERT INTO switch_interfaces(switch_id, if_index, is_uplink)
                            VALUES (?, ?, 1)
                            ON CONFLICT(switch_id, if_index) DO UPDATE SET is_uplink=1""",
                            (sw_id, u_idx),
                        )
                    except ValueError:
                        pass

                # Insert neighbors
                for nb in res.get("neighbors", []):
                    conn.execute(
                        """INSERT INTO switch_neighbors(
                            switch_id, local_if_index, protocol, remote_sys_name,
                            remote_port_id, remote_mgmt_ip, remote_platform, observed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            sw_id,
                            nb.get("local_if_index") or nb.get("local_port"),
                            nb.get("protocol", "LLDP"),
                            nb.get("remote_device_name"),
                            nb.get("remote_port_id"),
                            nb.get("remote_mgmt_ip"),
                            nb.get("remote_platform"),
                            now,
                        ),
                    )
                    total_records += 1

                # Upsert FDB entries
                for fdb in res.get("fdb_entries", []):
                    conn.execute(
                        """INSERT INTO switch_fdb_current(
                            switch_id, mac_address, bridge_port, if_index, vlan_id, last_updated
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(switch_id, mac_address, bridge_port) DO UPDATE SET
                            if_index=excluded.if_index,
                            vlan_id=excluded.vlan_id,
                            last_updated=excluded.last_updated""",
                        (
                            sw_id,
                            fdb.mac,
                            fdb.bridge_port,
                            fdb.if_index,
                            fdb.vlan_id or 1,
                            now,
                        ),
                    )
                    total_records += 1

        conn.close()
        return total_records

    async def run_once(self) -> int:
        results = await self.poll_all_switches()
        count = self.commit_polling_results(results)
        logger.info(f"SNMP poll completed: {len(results)} switches polled, {count} records committed.")
        return count

    async def run_forever(self):
        self.is_running = True
        interval = int(self.cfg.get("snmp_poller", {}).get("interval_seconds", 300))
        logger.info(f"Starting SNMP Poller daemon (interval={interval}s)...")
        while self.is_running:
            try:
                await self.run_once()
            except Exception as exc:
                logger.error(f"Error during SNMP polling loop: {exc}")
            await asyncio.sleep(interval)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SNMP Poller Service for School Network Monitor")
    parser.add_argument("--once", action="store_true", help="Run polling once and exit")
    args = parser.parse_args()

    service = SnmpPollerService()
    if args.once:
        asyncio.run(service.run_once())
    else:
        try:
            asyncio.run(service.run_forever())
        except KeyboardInterrupt:
            print("\nSNMP Poller stopped by user.")
