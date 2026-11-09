from __future__ import annotations

import sqlite3


MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS analysis_jobs (
            job_id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            source_name TEXT NOT NULL,
            source_path TEXT,
            status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','interrupted','cancelled')),
            progress INTEGER NOT NULL DEFAULT 0 CHECK(progress BETWEEN 0 AND 100),
            processed_packets INTEGER NOT NULL DEFAULT 0,
            total_events INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            last_progress_at TEXT,
            completed_at TEXT,
            error_message TEXT,
            worker_id TEXT
        );

        CREATE TABLE IF NOT EXISTS analysis_sources (
            source_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL REFERENCES analysis_jobs(job_id) ON DELETE CASCADE,
            original_filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            file_size INTEGER NOT NULL DEFAULT 0 CHECK(file_size >= 0),
            file_hash TEXT,
            source_type TEXT NOT NULL,
            upload_status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dhcp_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_uid TEXT NOT NULL UNIQUE,
            job_id TEXT NOT NULL REFERENCES analysis_jobs(job_id) ON DELETE CASCADE,
            event_time TEXT NOT NULL,
            created_at TEXT NOT NULL,
            source_type TEXT NOT NULL,
            message_type TEXT NOT NULL,
            client_mac TEXT NOT NULL,
            source_ip TEXT,
            source_mac TEXT,
            server_ip TEXT,
            server_mac TEXT,
            requested_ip TEXT,
            assigned_ip TEXT,
            hostname TEXT,
            lease_time INTEGER,
            is_rogue INTEGER NOT NULL DEFAULT 0 CHECK(is_rogue IN (0,1)),
            anomaly_type TEXT NOT NULL DEFAULT 'NONE',
            severity TEXT NOT NULL DEFAULT 'INFO'
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL UNIQUE,
            hostname TEXT,
            last_ip TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_source_type TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS analysis_stats (
            job_id TEXT PRIMARY KEY REFERENCES analysis_jobs(job_id) ON DELETE CASCADE,
            snapshot_sequence INTEGER NOT NULL DEFAULT 0,
            total_packets INTEGER NOT NULL DEFAULT 0,
            total_events INTEGER NOT NULL DEFAULT 0,
            silent_count INTEGER NOT NULL DEFAULT 0,
            write_failed_count INTEGER NOT NULL DEFAULT 0,
            counters_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS system_status (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS write_batches (
            batch_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            batch_sequence INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('committed','failed')),
            committed_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_job_time ON dhcp_events(job_id, event_time DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_events_job_type_time ON dhcp_events(job_id, message_type, event_time DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_events_anomaly ON dhcp_events(anomaly_type, event_time DESC);
        CREATE INDEX IF NOT EXISTS idx_events_mac ON dhcp_events(client_mac);
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_jobs_created ON analysis_jobs(created_at DESC);
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS job_device_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL REFERENCES analysis_jobs(job_id) ON DELETE CASCADE,
            mac TEXT NOT NULL,
            hostname TEXT,
            ip TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(job_id, mac)
        );
        CREATE INDEX IF NOT EXISTS idx_job_device_mappings_job_mac
            ON job_device_mappings(job_id, mac);
        CREATE INDEX IF NOT EXISTS idx_devices_last_seen
            ON devices(last_seen DESC);
        """,
    ),
    (
        3,
        """
        INSERT OR IGNORE INTO job_device_mappings(job_id, mac, hostname, ip, first_seen, last_seen)
        SELECT
            e.job_id,
            e.client_mac,
            (SELECT e2.hostname FROM dhcp_events e2
             WHERE e2.job_id=e.job_id AND e2.client_mac=e.client_mac AND e2.hostname IS NOT NULL
             ORDER BY e2.id DESC LIMIT 1),
            (SELECT COALESCE(e2.assigned_ip, e2.requested_ip) FROM dhcp_events e2
             WHERE e2.job_id=e.job_id AND e2.client_mac=e.client_mac
               AND COALESCE(e2.assigned_ip, e2.requested_ip) IS NOT NULL
             ORDER BY e2.id DESC LIMIT 1),
            MIN(e.event_time),
            MAX(e.event_time)
        FROM dhcp_events e
        WHERE e.client_mac IS NOT NULL AND e.client_mac <> ''
        GROUP BY e.job_id, e.client_mac;
        """,
    ),
    (
        4,
        """
        ALTER TABLE dhcp_events ADD COLUMN transaction_id INTEGER;
        ALTER TABLE dhcp_events ADD COLUMN relay_ip TEXT;
        ALTER TABLE dhcp_events ADD COLUMN anomaly_details TEXT;
        ALTER TABLE dhcp_events ADD COLUMN anomaly_score INTEGER;
        ALTER TABLE dhcp_events ADD COLUMN detected_at TEXT;
        ALTER TABLE dhcp_events ADD COLUMN matched_watch INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE dhcp_events ADD COLUMN vlan_id INTEGER;
        ALTER TABLE dhcp_events ADD COLUMN source_packet_no INTEGER;

        CREATE TABLE IF NOT EXISTS switches (
            switch_id TEXT PRIMARY KEY,
            management_ip TEXT NOT NULL UNIQUE,
            sys_name TEXT,
            vendor TEXT,
            model TEXT,
            sys_descr TEXT,
            last_poll_time TEXT,
            poll_status TEXT
        );

        CREATE TABLE IF NOT EXISTS switch_interfaces (
            switch_id TEXT NOT NULL REFERENCES switches(switch_id) ON DELETE CASCADE,
            if_index INTEGER NOT NULL,
            bridge_port INTEGER,
            if_name TEXT,
            if_descr TEXT,
            if_alias TEXT,
            is_uplink INTEGER NOT NULL DEFAULT 0 CHECK(is_uplink IN (0,1)),
            location_label TEXT,
            PRIMARY KEY(switch_id, if_index)
        );

        CREATE TABLE IF NOT EXISTS device_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER REFERENCES devices(device_id) ON DELETE SET NULL,
            mac_address TEXT NOT NULL,
            switch_id TEXT REFERENCES switches(switch_id) ON DELETE SET NULL,
            if_index INTEGER,
            bridge_port INTEGER,
            vlan_id INTEGER,
            observed_at TEXT NOT NULL,
            query_time TEXT NOT NULL,
            location_source TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'candidate',
            resolution_status TEXT NOT NULL DEFAULT 'unresolved',
            reason TEXT,
            source_poll_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_device_locations_mac_time
            ON device_locations(mac_address, observed_at DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_device_locations_switch_port
            ON device_locations(switch_id, if_index, observed_at DESC);

        UPDATE dhcp_events
        SET anomaly_type='DECLINE_DETECTED', severity='WARNING', detected_at=COALESCE(detected_at, created_at)
        WHERE message_type='DECLINE' AND anomaly_type='NONE';
        UPDATE dhcp_events
        SET anomaly_type='ABNORMAL_LEASE', severity='WARNING',
            anomaly_details='lease_time=' || lease_time,
            detected_at=COALESCE(detected_at, created_at)
        WHERE lease_time IS NOT NULL
          AND (lease_time < 300 OR lease_time > 2592000)
          AND anomaly_type='NONE';
        """,
    ),
    (
        5,
        """
        ALTER TABLE analysis_jobs ADD COLUMN monitor_instance_id TEXT;
        CREATE INDEX IF NOT EXISTS idx_jobs_monitor_instance
            ON analysis_jobs(monitor_instance_id);
        """,
    ),
    (
        6,
        """
        CREATE INDEX IF NOT EXISTS idx_events_event_time
            ON dhcp_events(event_time DESC, id DESC);
        """,
    ),
    (
        7,
        """
        ALTER TABLE devices ADD COLUMN device_name TEXT;
        ALTER TABLE devices ADD COLUMN location TEXT;
        ALTER TABLE devices ADD COLUMN verification_status TEXT DEFAULT 'unverified';
        """,
    ),
    (
        8,
        """
        CREATE TABLE IF NOT EXISTS switch_fdb_current (
            switch_id TEXT NOT NULL REFERENCES switches(switch_id) ON DELETE CASCADE,
            mac_address TEXT NOT NULL,
            bridge_port INTEGER NOT NULL,
            if_index INTEGER,
            vlan_id INTEGER,
            last_updated TEXT NOT NULL,
            PRIMARY KEY(switch_id, mac_address, bridge_port)
        );
        CREATE INDEX IF NOT EXISTS idx_fdb_mac ON switch_fdb_current(mac_address);

        CREATE TABLE IF NOT EXISTS switch_neighbors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            switch_id TEXT NOT NULL REFERENCES switches(switch_id) ON DELETE CASCADE,
            local_if_index INTEGER,
            protocol TEXT NOT NULL DEFAULT 'LLDP',
            remote_sys_name TEXT,
            remote_port_id TEXT,
            remote_mgmt_ip TEXT,
            remote_platform TEXT,
            observed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_switch_neighbors_sw_if ON switch_neighbors(switch_id, local_if_index);

        CREATE TABLE IF NOT EXISTS alerts (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            mac TEXT,
            ip TEXT,
            switch_id TEXT,
            port TEXT,
            description TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolution_note TEXT,
            resolved_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity);
        """,
    ),
    (
        9,
        """
        -- Spec Chapter 8: Relay-to-VLAN & Device Identity MAC + VLAN composite key
        CREATE TABLE IF NOT EXISTS devices_new (
            device_id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_identity_key TEXT NOT NULL UNIQUE,
            mac TEXT NOT NULL,
            vlan_id INTEGER DEFAULT 1,
            hostname TEXT,
            last_ip TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_source_type TEXT,
            device_name TEXT,
            location TEXT,
            verification_status TEXT DEFAULT 'unverified',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        INSERT OR IGNORE INTO devices_new (
            device_id, device_identity_key, mac, vlan_id, hostname, last_ip,
            first_seen, last_seen, last_source_type, device_name, location,
            verification_status, created_at, updated_at
        )
        SELECT
            device_id,
            UPPER(mac) || '|VLAN:1',
            UPPER(mac),
            1,
            hostname,
            last_ip,
            first_seen,
            last_seen,
            last_source_type,
            device_name,
            location,
            verification_status,
            created_at,
            updated_at
        FROM devices;

        DROP TABLE devices;
        ALTER TABLE devices_new RENAME TO devices;
        CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
        CREATE INDEX IF NOT EXISTS idx_devices_identity ON devices(device_identity_key);
        CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);

        ALTER TABLE dhcp_events ADD COLUMN vlan_source TEXT DEFAULT 'configured_default';
        ALTER TABLE dhcp_events ADD COLUMN device_identity_key TEXT;
        UPDATE dhcp_events SET device_identity_key = UPPER(client_mac) || '|VLAN:' || COALESCE(vlan_id, 1) WHERE device_identity_key IS NULL;
        CREATE INDEX IF NOT EXISTS idx_events_identity ON dhcp_events(device_identity_key, event_time DESC);

        ALTER TABLE job_device_mappings ADD COLUMN vlan_id INTEGER DEFAULT 1;
        ALTER TABLE job_device_mappings ADD COLUMN device_identity_key TEXT;
        UPDATE job_device_mappings SET device_identity_key = UPPER(mac) || '|VLAN:' || COALESCE(vlan_id, 1) WHERE device_identity_key IS NULL;
        CREATE INDEX IF NOT EXISTS idx_job_device_mappings_identity ON job_device_mappings(job_id, device_identity_key);
        """,
    ),
)


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    applied = {
        row[0]
        for row in connection.execute("SELECT version FROM schema_migrations")
    }
    for version, script in MIGRATIONS:
        if version in applied:
            continue
        with connection:
            connection.executescript(script)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                (version,),
            )

