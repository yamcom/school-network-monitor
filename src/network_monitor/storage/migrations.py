"""Database migrations to handle schema updates smoothly."""

from __future__ import annotations
import logging
from .database import Database

logger = logging.getLogger("network_monitor.storage.migrations")


def apply_migrations(db: Database) -> None:
    """Apply any necessary schema migrations, ensure all tables exist, and backfill data."""
    logger.info("Verifying and applying database migrations...")
    db.init_schema()
    
    # 針對既有資料庫安全檢查並動態補上可能缺少的欄位（防禦性程式碼）
    with db.transaction() as conn:
        cur = conn.cursor()
        
        cur.execute("PRAGMA table_info(devices_current)")
        dev_cols = {row["name"] for row in cur.fetchall()}
        if dev_cols:
            if "lease_status" not in dev_cols:
                cur.execute("ALTER TABLE devices_current ADD COLUMN lease_status TEXT DEFAULT 'observed'")
            if "lease_time" not in dev_cols:
                cur.execute("ALTER TABLE devices_current ADD COLUMN lease_time INTEGER")
            if "lease_expiry" not in dev_cols:
                cur.execute("ALTER TABLE devices_current ADD COLUMN lease_expiry DATETIME")
            if "server_id" not in dev_cols:
                cur.execute("ALTER TABLE devices_current ADD COLUMN server_id TEXT")
            if "last_dhcp_event" not in dev_cols:
                cur.execute("ALTER TABLE devices_current ADD COLUMN last_dhcp_event DATETIME")

        cur.execute("PRAGMA table_info(dhcp_events)")
        dhcp_cols = {row["name"] for row in cur.fetchall()}
        if dhcp_cols:
            if "lease_time" not in dhcp_cols:
                cur.execute("ALTER TABLE dhcp_events ADD COLUMN lease_time INTEGER")
            if "renewal_time" not in dhcp_cols:
                cur.execute("ALTER TABLE dhcp_events ADD COLUMN renewal_time INTEGER")
            if "rebinding_time" not in dhcp_cols:
                cur.execute("ALTER TABLE dhcp_events ADD COLUMN rebinding_time INTEGER")
            if "client_id" not in dhcp_cols:
                cur.execute("ALTER TABLE dhcp_events ADD COLUMN client_id TEXT")
            if "ciaddr" not in dhcp_cols:
                cur.execute("ALTER TABLE dhcp_events ADD COLUMN ciaddr TEXT")
            if "yiaddr" not in dhcp_cols:
                cur.execute("ALTER TABLE dhcp_events ADD COLUMN yiaddr TEXT")
            if "chaddr" not in dhcp_cols:
                cur.execute("ALTER TABLE dhcp_events ADD COLUMN chaddr TEXT")

    logger.info("Database schema and MVP-06 topology structures are up to date.")