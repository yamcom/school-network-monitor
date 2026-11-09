"""Network Health Diagnostics Engine.

Implements automated diagnostics for common campus network faults:
1. Rogue DHCP Server Detection (correlated with switch access ports)
2. IP Conflict Detection (multiple MACs declaring same IP)
3. DHCP Pool Exhaustion / Starvation Attack (burst of random MACs / NAK spikes)
4. Broadcast Storm & Loop Warning (PPS surges & MAC flapping)
5. Switch Health & SNMP Misconfiguration (Ping alive but Community invalid)
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.models import utc_now
from database.connection import connect_database

logger = logging.getLogger("school_network_monitor.diagnostics")


class NetworkDiagnosticsEngine:
    def __init__(self, database_path: str = "data/dhcp_analyzer.db"):
        self.database_path = database_path

    def diagnose_switch_community_health(self, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
        """Identify switches that respond to Ping but failed SNMP due to invalid/missing Community."""
        close_conn = False
        if conn is None:
            conn = connect_database(self.database_path)
            close_conn = True

        alerts = []
        rows = conn.execute(
            """SELECT switch_id, management_ip, sys_name, vendor, model, poll_status, last_poll_time
            FROM switches
            WHERE poll_status = 'COMMUNITY_MISCONFIGURED'"""
        ).fetchall()

        for r in rows:
            alerts.append({
                "alert_type": "SNMP_COMMUNITY_MISCONFIGURED",
                "severity": "WARNING",
                "switch_id": r["switch_id"],
                "ip": r["management_ip"],
                "mac": None,
                "port": None,
                "description": f"Switch {r['sys_name']} ({r['management_ip']}) is alive (Ping OK) but SNMP Community is misconfigured or not set.",
                "timestamp": utc_now()
            })

        if close_conn:
            conn.close()
        return alerts

    def detect_rogue_dhcp(self, authorized_servers: Optional[List[str]] = None, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
        """Detect rogue DHCP servers offering/acknowledging leases not in authorized whitelist."""
        close_conn = False
        if conn is None:
            conn = connect_database(self.database_path)
            close_conn = True

        from core.config import load_config
        if authorized_servers is None:
            cfg = load_config()
            authorized_servers = cfg.get("anomaly", {}).get("rogue_dhcp", {}).get("authorized_servers", [])

        alerts = []
        # Query distinct server_ips from dhcp_events
        rows = conn.execute(
            """SELECT server_ip, server_mac, COUNT(*) as cnt, MAX(event_time) as last_seen
            FROM dhcp_events
            WHERE server_ip IS NOT NULL AND server_ip != '0.0.0.0' AND message_type IN ('OFFER', 'ACK')
            GROUP BY server_ip"""
        ).fetchall()

        for r in rows:
            s_ip = r["server_ip"]
            s_mac = r["server_mac"]
            if authorized_servers and s_ip not in authorized_servers:
                # Query physical location from FDB
                loc = conn.execute(
                    """SELECT switch_id, bridge_port, if_index FROM switch_fdb_current
                    WHERE mac_address = ? ORDER BY last_updated DESC LIMIT 1""",
                    (s_mac.upper() if s_mac else "",)
                ).fetchone()

                sw_id = loc["switch_id"] if loc else "Unknown"
                port = str(loc["if_index"] or loc["bridge_port"]) if loc else "Unknown"

                alerts.append({
                    "alert_type": "ROGUE_DHCP",
                    "severity": "CRITICAL",
                    "ip": s_ip,
                    "mac": s_mac,
                    "switch_id": sw_id,
                    "port": port,
                    "description": f"Unauthorized DHCP server {s_ip} detected ({r['cnt']} packets) at Switch {sw_id} Port {port}.",
                    "timestamp": r["last_seen"] or utc_now()
                })

        if close_conn:
            conn.close()
        return alerts

    def detect_ip_conflicts(self, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
        """Detect distinct MAC addresses claiming or assigned the same IP address."""
        close_conn = False
        if conn is None:
            conn = connect_database(self.database_path)
            close_conn = True

        alerts = []
        # Group by IP having multiple MACs
        rows = conn.execute(
            """SELECT assigned_ip as ip, COUNT(DISTINCT client_mac) as mac_count,
                      GROUP_CONCAT(DISTINCT client_mac) as mac_list, MAX(event_time) as last_seen
            FROM dhcp_events
            WHERE assigned_ip IS NOT NULL AND assigned_ip != '' AND assigned_ip != '0.0.0.0'
            GROUP BY assigned_ip
            HAVING mac_count > 1"""
        ).fetchall()

        for r in rows:
            alerts.append({
                "alert_type": "IP_CONFLICT",
                "severity": "CRITICAL",
                "ip": r["ip"],
                "mac": r["mac_list"],
                "switch_id": None,
                "port": None,
                "description": f"IP Conflict: {r['ip']} is claimed by {r['mac_count']} distinct MACs: [{r['mac_list']}].",
                "timestamp": r["last_seen"] or utc_now()
            })

        if close_conn:
            conn.close()
        return alerts

    def detect_pool_exhaustion(self, conn: Optional[sqlite3.Connection] = None, nak_threshold: int = 10) -> List[Dict[str, Any]]:
        """Detect high volume of DHCP NAKs indicating subnet/pool exhaustion."""
        close_conn = False
        if conn is None:
            conn = connect_database(self.database_path)
            close_conn = True

        alerts = []
        rows = conn.execute(
            """SELECT vlan_id, COUNT(*) as nak_count, MAX(event_time) as last_seen
            FROM dhcp_events
            WHERE message_type = 'NAK'
            GROUP BY vlan_id
            HAVING nak_count >= ?""",
            (nak_threshold,)
        ).fetchall()

        for r in rows:
            v_id = r["vlan_id"] or 1
            alerts.append({
                "alert_type": "POOL_EXHAUSTION",
                "severity": "WARNING",
                "ip": None,
                "mac": None,
                "switch_id": None,
                "port": None,
                "description": f"DHCP Pool exhaustion warning: VLAN {v_id} received {r['nak_count']} NAK responses.",
                "timestamp": r["last_seen"] or utc_now()
            })

        if close_conn:
            conn.close()
        return alerts

    def run_all_diagnostics(self) -> List[Dict[str, Any]]:
        """Execute all diagnostics and persist new alerts to database."""
        conn = connect_database(self.database_path)
        all_alerts: List[Dict[str, Any]] = []

        try:
            all_alerts.extend(self.diagnose_switch_community_health(conn))
            all_alerts.extend(self.detect_rogue_dhcp(conn=conn))
            all_alerts.extend(self.detect_ip_conflicts(conn=conn))
            all_alerts.extend(self.detect_pool_exhaustion(conn=conn))

            with conn:
                for a in all_alerts:
                    conn.execute(
                        """INSERT INTO alerts(alert_type, severity, status, mac, ip, switch_id, port, description, first_seen, last_seen)
                        VALUES (?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            a["alert_type"],
                            a["severity"],
                            a.get("mac"),
                            a.get("ip"),
                            a.get("switch_id"),
                            a.get("port"),
                            a.get("description"),
                            a["timestamp"],
                            a["timestamp"],
                        ),
                    )
        finally:
            conn.close()

        logger.info(f"Diagnostics complete: {len(all_alerts)} anomalies diagnosed.")
        return all_alerts
