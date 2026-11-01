"""SQLite database connection and schema management."""

from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from typing import Generator


class Database:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a transactional scope around a series of operations with WAL enabled."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a read-friendly connection scope for querying without explicit auto-commit."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            yield conn
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Initialize database schema with all required tables including inventory, MVP-06 topology, and MVP-07 alerts."""
        schema_sql = """
        CREATE TABLE IF NOT EXISTS switches (
            switch_id INTEGER PRIMARY KEY AUTOINCREMENT,
            management_ip TEXT UNIQUE NOT NULL,
            sys_name TEXT,
            sys_descr TEXT,
            sys_object_id TEXT,
            vendor TEXT,
            model TEXT,
            adapter_name TEXT,
            poll_status TEXT,
            last_poll_time DATETIME
        );

        CREATE TABLE IF NOT EXISTS interfaces (
            switch_id INTEGER,
            if_index INTEGER,
            if_name TEXT,
            if_descr TEXT,
            if_alias TEXT,
            bridge_port INTEGER,
            is_uplink INTEGER,
            PRIMARY KEY (switch_id, if_index),
            FOREIGN KEY (switch_id) REFERENCES switches(switch_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS fdb_entries (
            switch_id INTEGER,
            mac TEXT,
            bridge_port INTEGER,
            vlan_id INTEGER,
            last_seen DATETIME,
            if_index INTEGER
        );

        CREATE TABLE IF NOT EXISTS devices_current (
            mac TEXT PRIMARY KEY,
            current_ip TEXT,
            hostname TEXT,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            last_dhcp_event DATETIME,
            lease_time INTEGER,
            lease_expiry DATETIME,
            lease_status TEXT DEFAULT 'observed',
            server_id TEXT,
            status TEXT DEFAULT 'observed'
        );
        
        CREATE TABLE IF NOT EXISTS dhcp_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            alert_type TEXT,
            server_ip TEXT,
            client_mac TEXT,
            assigned_ip TEXT,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS dhcp_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            ip TEXT,
            hostname TEXT,
            timestamp DATETIME NOT NULL,
            message_type TEXT NOT NULL,
            requested_ip TEXT,
            server_identifier TEXT,
            lease_time INTEGER,
            renewal_time INTEGER,
            rebinding_time INTEGER,
            client_id TEXT,
            ciaddr TEXT,
            yiaddr TEXT,
            chaddr TEXT,
            vlan_id INTEGER,
            interface_name TEXT
        );

        CREATE TABLE IF NOT EXISTS device_locations (
            mac TEXT PRIMARY KEY,
            switch_id INTEGER,
            if_index INTEGER,
            confidence REAL,
            resolution_status TEXT,
            reason TEXT,
            updated_at DATETIME
        );

        CREATE TABLE IF NOT EXISTS device_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            expected_switch_id INTEGER,
            expected_if_index INTEGER,
            actual_switch_id INTEGER,
            actual_if_index INTEGER,
            verified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_match INTEGER,
            note TEXT
        );

        -- 統一設備主檔與 IP 配置歷史 (MVP-05)
        CREATE TABLE IF NOT EXISTS devices (
            device_id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            device_name TEXT,
            hostname TEXT,
            device_type TEXT DEFAULT 'UNKNOWN',
            ip_assignment_type TEXT DEFAULT 'UNKNOWN',
            management_status TEXT DEFAULT 'UNMANAGED',
            record_source TEXT DEFAULT 'DISCOVERED',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS device_ip_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            assignment_type TEXT DEFAULT 'UNKNOWN',
            vlan_id INTEGER,
            valid_from DATETIME NOT NULL,
            valid_until DATETIME,
            is_current INTEGER DEFAULT 1,
            source TEXT DEFAULT 'DHCP',
            verification_status TEXT DEFAULT 'UNVERIFIED',
            FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
        );

        -- 網路拓樸與設備位置關聯管理 (MVP-06)
        CREATE TABLE IF NOT EXISTS topology_links (
            link_id INTEGER PRIMARY KEY AUTOINCREMENT,
            local_switch_id INTEGER NOT NULL,
            local_if_index INTEGER NOT NULL,
            remote_switch_id INTEGER,
            remote_switch_name TEXT,
            remote_mgmt_ip TEXT,
            remote_if_name TEXT,
            discovery_protocol TEXT NOT NULL,
            confidence_level TEXT DEFAULT 'MEDIUM',
            is_bidirectional INTEGER DEFAULT 0,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            notes TEXT,
            FOREIGN KEY (local_switch_id) REFERENCES switches(switch_id) ON DELETE CASCADE,
            UNIQUE(local_switch_id, local_if_index)
        );

        CREATE TABLE IF NOT EXISTS topology_observations (
            obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
            switch_id INTEGER NOT NULL,
            if_index INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            remote_device_name TEXT,
            remote_mgmt_ip TEXT,
            remote_port_id TEXT,
            remote_port_desc TEXT,
            observed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (switch_id) REFERENCES switches(switch_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS switch_port_roles (
            switch_id INTEGER NOT NULL,
            if_index INTEGER NOT NULL,
            role TEXT DEFAULT 'ACCESS',
            role_source TEXT DEFAULT 'AUTO',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (switch_id, if_index),
            FOREIGN KEY (switch_id) REFERENCES switches(switch_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS topology_verifications (
            verification_id INTEGER PRIMARY KEY AUTOINCREMENT,
            link_id INTEGER,
            local_switch_ip TEXT NOT NULL,
            local_port TEXT NOT NULL,
            expected_remote_switch_ip TEXT NOT NULL,
            expected_remote_port TEXT NOT NULL,
            is_match INTEGER NOT NULL,
            verified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            verified_by TEXT,
            notes TEXT
        );

        -- ========================================================
        -- MVP-07: 網路異常偵測與事件管理資料表
        -- ========================================================
        CREATE TABLE IF NOT EXISTS alert_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT UNIQUE NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'MEDIUM',
            status TEXT DEFAULT 'OPEN',
            title TEXT NOT NULL,
            description TEXT,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            occurrence_count INTEGER DEFAULT 1,
            confidence REAL DEFAULT 1.0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            acknowledged_at DATETIME,
            resolved_at DATETIME,
            resolution_note TEXT
        );

        CREATE TABLE IF NOT EXISTS alert_evidence (
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            evidence_type TEXT,
            source_ip TEXT,
            client_mac TEXT,
            assigned_ip TEXT,
            raw_details TEXT,
            recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES alert_events(event_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alert_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT,
            operator TEXT DEFAULT 'SYSTEM',
            note TEXT,
            changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES alert_events(event_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS monitoring_health (
            module_name TEXT PRIMARY KEY,
            status TEXT DEFAULT 'RUNNING',
            last_success_time DATETIME,
            error_message TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_fdb_mac ON fdb_entries(mac);
        CREATE INDEX IF NOT EXISTS idx_dhcp_mac ON dhcp_events(mac);
        CREATE INDEX IF NOT EXISTS idx_dhcp_time ON dhcp_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dev_ip ON devices_current(current_ip);
        CREATE INDEX IF NOT EXISTS idx_dev_mac ON devices_current(mac);
        CREATE INDEX IF NOT EXISTS idx_alerts_time ON dhcp_alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
        CREATE INDEX IF NOT EXISTS idx_ip_assign_dev ON device_ip_assignments(device_id);
        CREATE INDEX IF NOT EXISTS idx_ip_assign_ip ON device_ip_assignments(ip_address);
        CREATE INDEX IF NOT EXISTS idx_topo_local ON topology_links(local_switch_id, local_if_index);
        CREATE INDEX IF NOT EXISTS idx_topo_remote ON topology_links(remote_switch_id);
        CREATE INDEX IF NOT EXISTS idx_topo_obs_sw ON topology_observations(switch_id, if_index);
        CREATE INDEX IF NOT EXISTS idx_alerts_key ON alert_events(event_key);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alert_events(status);
        """
        with self.transaction() as conn:
            conn.executescript(schema_sql)