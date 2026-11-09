"""Database repository providing access to network topology, switch info, and verification data."""

from __future__ import annotations
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from network_monitor.models import (
    DeviceCurrent,
    DeviceLocation,
    DeviceVerification,
    DHCPEvent,
    DHCPMessageType,
    FdbEntry,
    ResolutionStatus,
    SwitchInfo,
    SwitchInterface,
    normalize_mac,
)
from network_monitor.storage.database import Database


class NetworkRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---------------------------------------------------------
    # Switch & Interface Methods
    # ---------------------------------------------------------

    def upsert_switch(self, sw: SwitchInfo) -> int:
        """新增或更新交換器基本資料與狀態，並回傳 switch_id。"""
        select_query = "SELECT * FROM switches WHERE management_ip = ?"
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(select_query, (sw.management_ip,))
            raw_row = cur.fetchone()
            row = dict(raw_row) if raw_row else None

            if row:
                col_name = "switch_id" if "switch_id" in row else "id"
                switch_id = row[col_name]
                update_query = f"""
                    UPDATE switches
                    SET sys_name = ?, sys_descr = ?, sys_object_id = ?,
                        vendor = ?, model = ?, adapter_name = ?,
                        poll_status = ?, last_poll_time = ?
                    WHERE {col_name} = ?
                """
                cur.execute(
                    update_query,
                    (
                        sw.sys_name,
                        sw.sys_descr,
                        sw.sys_object_id,
                        sw.vendor,
                        sw.model,
                        sw.adapter_name,
                        sw.poll_status,
                        sw.last_poll_time or datetime.now(),
                        switch_id,
                    ),
                )
                return switch_id
            else:
                insert_query = """
                    INSERT INTO switches (
                        management_ip, sys_name, sys_descr, sys_object_id,
                        vendor, model, adapter_name, poll_status, last_poll_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cur.execute(
                    insert_query,
                    (
                        sw.management_ip,
                        sw.sys_name,
                        sw.sys_descr,
                        sw.sys_object_id,
                        sw.vendor,
                        sw.model,
                        sw.adapter_name,
                        sw.poll_status,
                        sw.last_poll_time or datetime.now(),
                    ),
                )
                return cur.lastrowid

    def get_switch_by_ip(self, ip: str) -> Optional[SwitchInfo]:
        """依管理 IP 取得交換器基本資料。"""
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM switches WHERE management_ip = ?", (ip.strip(),))
            raw = cur.fetchone()
            if not raw:
                return None
            row = dict(raw)
            s_id = row.get("switch_id") or row.get("id")
            return SwitchInfo(
                switch_id=s_id,
                management_ip=row.get("management_ip", ""),
                sys_name=row.get("sys_name", ""),
                sys_descr=row.get("sys_descr"),
                sys_object_id=row.get("sys_object_id", ""),
                vendor=row.get("vendor", ""),
                model=row.get("model", ""),
                adapter_name=row.get("adapter_name", "standard_mib"),
                poll_status=row.get("poll_status", "offline"),
                last_poll_time=row.get("last_poll_time"),
            )

    def list_switches(self) -> List[SwitchInfo]:
        """列出資料庫中已記錄的所有交換器。"""
        query = "SELECT * FROM switches"
        results: List[SwitchInfo] = []
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query)
                for raw_row in cur.fetchall():
                    row = dict(raw_row)
                    s_id = row.get("switch_id") or row.get("id")
                    results.append(
                        SwitchInfo(
                            switch_id=s_id,
                            management_ip=row.get("management_ip", ""),
                            sys_name=row.get("sys_name", ""),
                            sys_descr=row.get("sys_descr", ""),
                            sys_object_id=row.get("sys_object_id", ""),
                            vendor=row.get("vendor", ""),
                            model=row.get("model", ""),
                            adapter_name=row.get("adapter_name", "standard_mib"),
                            poll_status=row.get("poll_status", "offline"),
                            last_poll_time=row.get("last_poll_time"),
                        )
                    )
        except Exception:
            pass
        return results

    def save_interfaces(self, *args: Any, **kwargs: Any) -> None:
        """批次更新或新增交換器的介面資訊。"""
        switch_id = kwargs.get("switch_id")
        interfaces = kwargs.get("interfaces")

        if not interfaces and args:
            if len(args) == 1:
                interfaces = args[0]
            elif len(args) >= 2:
                switch_id = args[0]
                interfaces = args[1]

        if not interfaces:
            return

        if isinstance(interfaces, dict):
            interfaces = list(interfaces.values())

        query = """
            INSERT INTO interfaces (
                switch_id, if_index, if_name, if_descr, if_alias, bridge_port, is_uplink
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(switch_id, if_index) DO UPDATE SET
                if_name = excluded.if_name,
                if_descr = excluded.if_descr,
                if_alias = excluded.if_alias,
                bridge_port = excluded.bridge_port,
                is_uplink = excluded.is_uplink
        """
        with self.db.transaction() as conn:
            cur = conn.cursor()
            for intf in interfaces:
                s_id = switch_id if switch_id is not None else getattr(intf, "switch_id", None)
                if s_id is None:
                    continue
                cur.execute(
                    query,
                    (
                        s_id,
                        getattr(intf, "if_index", 0),
                        getattr(intf, "if_name", ""),
                        getattr(intf, "if_descr", ""),
                        getattr(intf, "if_alias", ""),
                        getattr(intf, "bridge_port", None),
                        1 if getattr(intf, "is_uplink", False) else 0,
                    ),
                )

    def get_interfaces(self, switch_id: int) -> Dict[int, SwitchInterface]:
        """取得指定交換器的所有介面對應表 (鍵為 if_index)。"""
        query = """
            SELECT switch_id, if_index, if_name, if_descr, if_alias,
                   bridge_port, is_uplink
            FROM interfaces
            WHERE switch_id = ?
        """
        interfaces: Dict[int, SwitchInterface] = {}
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query, (switch_id,))
                for raw_row in cur.fetchall():
                    row = dict(raw_row)
                    intf = SwitchInterface(
                        switch_id=row["switch_id"],
                        if_index=row["if_index"],
                        if_name=row.get("if_name") or "",
                        if_descr=row.get("if_descr") or "",
                        if_alias=row.get("if_alias") or "",
                        bridge_port=row.get("bridge_port"),
                        is_uplink=bool(row.get("is_uplink")),
                    )
                    interfaces[intf.if_index] = intf
        except Exception:
            pass
        return interfaces

    def get_port_role(self, switch_id: int, if_index: int) -> str:
        """查詢或推導指定交換器連接埠的角色 (例如 UPLINK, ACCESS 等)。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT is_uplink, if_alias, if_name FROM interfaces
                    WHERE switch_id = ? AND if_index = ?
                """, (switch_id, if_index))
                row = cur.fetchone()
                if row:
                    row_dict = dict(row)
                    if row_dict.get("is_uplink") == 1:
                        return "UPLINK"
                    alias = (row_dict.get("if_alias") or "").upper()
                    if "UPLINK" in alias or "TRUNK" in alias:
                        return "UPLINK"
                return "ACCESS"
        except Exception:
            return "ACCESS"

    # ---------------------------------------------------------
    # FDB & Device Methods
    # ---------------------------------------------------------

    def save_fdb_entries(self, *args: Any, **kwargs: Any) -> None:
        """更新交換器的 FDB 轉發表資料。"""
        switch_id = kwargs.get("switch_id")
        entries = kwargs.get("entries")

        if entries is None and args:
            if len(args) == 1:
                entries = args[0]
            elif len(args) >= 2:
                switch_id = args[0]
                entries = args[1]

        if entries is None:
            return

        with self.db.transaction() as conn:
            cur = conn.cursor()
            processed_switch_ids = set()
            if switch_id is not None:
                processed_switch_ids.add(switch_id)
            for entry in entries:
                s_id = switch_id if switch_id is not None else getattr(entry, "switch_id", None)
                if s_id is not None:
                    processed_switch_ids.add(s_id)

            for s_id in processed_switch_ids:
                cur.execute("DELETE FROM fdb_entries WHERE switch_id = ?", (s_id,))

            insert_query = """
                INSERT INTO fdb_entries (
                    switch_id, mac, bridge_port, vlan_id, last_seen, if_index
                ) VALUES (?, ?, ?, ?, ?, ?)
            """
            for entry in entries:
                s_id = switch_id if switch_id is not None else getattr(entry, "switch_id", 0)
                mac_val = getattr(entry, "mac", getattr(entry, "mac_address", ""))
                clean_mac = normalize_mac(mac_val)
                cur.execute(
                    insert_query,
                    (
                        s_id,
                        clean_mac,
                        getattr(entry, "bridge_port", 0),
                        getattr(entry, "vlan_id", None),
                        getattr(entry, "last_seen", None) or datetime.now(),
                        getattr(entry, "if_index", None),
                    ),
                )

    def replace_fdb_snapshot(self, *args: Any, **kwargs: Any) -> None:
        """替換交換器的 FDB 快照。"""
        return self.save_fdb_entries(*args, **kwargs)

    def get_fdb_for_mac(self, mac: str) -> List[FdbEntry]:
        """取得特定 MAC 在各交換器上的所有 FDB 轉發表記錄。"""
        clean_mac = normalize_mac(mac)
        query = """
            SELECT switch_id, mac, bridge_port, vlan_id, last_seen, if_index
            FROM fdb_entries
            WHERE UPPER(REPLACE(REPLACE(mac, '-', ''), ':', '')) = UPPER(REPLACE(REPLACE(?, '-', ''), ':', ''))
        """
        entries: List[FdbEntry] = []
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query, (clean_mac,))
                for raw_row in cur.fetchall():
                    row = dict(raw_row)
                    entries.append(
                        FdbEntry(
                            switch_id=row["switch_id"],
                            mac=row["mac"],
                            bridge_port=row["bridge_port"],
                            vlan_id=row.get("vlan_id"),
                            last_seen=row.get("last_seen"),
                            if_index=row.get("if_index"),
                        )
                    )
        except Exception:
            pass
        return entries

    def get_device_by_mac(self, mac: str) -> Optional[DeviceCurrent]:
        """取得特定 MAC 目前已記錄的 IP、主機名稱與租約狀態。"""
        clean_mac = normalize_mac(mac)
        query = """
            SELECT mac, current_ip, hostname, last_seen, last_ack_time, lease_status, lease_time, lease_expiry
            FROM devices_current
            WHERE UPPER(REPLACE(REPLACE(mac, '-', ''), ':', '')) = UPPER(REPLACE(REPLACE(?, '-', ''), ':', ''))
        """
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query, (clean_mac,))
                raw_row = cur.fetchone()
                if not raw_row:
                    return None
                row = dict(raw_row)
                ack_t = row.get("last_ack_time")
                if isinstance(ack_t, str):
                    try:
                        ack_t = datetime.fromisoformat(ack_t)
                    except ValueError:
                        pass
                seen_t = row.get("last_seen")
                if isinstance(seen_t, str):
                    try:
                        seen_t = datetime.fromisoformat(seen_t)
                    except ValueError:
                        pass
                dev = DeviceCurrent(
                    mac=row["mac"],
                    current_ip=row.get("current_ip"),
                    hostname=row.get("hostname"),
                    last_seen=seen_t,
                    last_ack_time=ack_t,
                )
                setattr(dev, "lease_status", row.get("lease_status") or "observed")
                setattr(dev, "lease_time", row.get("lease_time"))
                setattr(dev, "lease_expiry", row.get("lease_expiry"))
                return dev
        except Exception:
            return None

    def get_device_by_ip(self, ip: str) -> Optional[DeviceCurrent]:
        """根據 IP 查詢目前對應的設備與租約資訊。"""
        query = """
            SELECT mac, current_ip, hostname, last_seen, lease_status, lease_time, lease_expiry
            FROM devices_current
            WHERE current_ip = ?
            ORDER BY last_seen DESC
            LIMIT 1
        """
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query, (ip,))
                raw_row = cur.fetchone()
                if not raw_row:
                    return None
                row = dict(raw_row)
                dev = DeviceCurrent(
                    mac=row["mac"],
                    current_ip=row.get("current_ip"),
                    hostname=row.get("hostname"),
                    last_seen=row.get("last_seen"),
                    last_ack_time=row.get("last_ack_time"),
                )
                setattr(dev, "lease_status", row.get("lease_status") or "observed")
                setattr(dev, "lease_time", row.get("lease_time"))
                setattr(dev, "lease_expiry", row.get("lease_expiry"))
                return dev
        except Exception:
            return None

    def list_all_devices_for_export(self) -> List[Dict[str, Any]]:
        """取得所有裝置的完整綜合資訊以供 CSV 匯出。"""
        query = """
            SELECT d.mac, d.current_ip, d.hostname, d.lease_status, d.lease_expiry,
                   d.last_seen, l.switch_id, l.if_index, l.confidence, l.resolution_status, l.reason
            FROM devices_current d
            LEFT JOIN device_locations l ON d.mac = l.mac
        """
        results = []
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query)
                for raw_row in cur.fetchall():
                    results.append(dict(raw_row))
        except Exception:
            pass
        return results

    # ---------------------------------------------------------
    # DHCP Event & Lease Methods
    # ---------------------------------------------------------

    def record_dhcp_event(self, event: DHCPEvent) -> int:
        """記錄 DHCP 封包事件，智慧更新租約期限與狀態，並保護主機名稱不被空白覆寫。"""
        clean_mac = normalize_mac(event.mac)
        event_time = event.timestamp or datetime.now()
        msg_type = event.message_type
        msg_type_str = msg_type.value if hasattr(msg_type, "value") else str(msg_type)

        insert_event_query = """
            INSERT INTO dhcp_events (
                mac, ip, hostname, timestamp, message_type,
                requested_ip, server_identifier, interface_name,
                lease_time, renewal_time, rebinding_time, client_id, ciaddr, yiaddr, chaddr
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                insert_event_query,
                (
                    clean_mac,
                    event.ip or event.requested_ip,
                    event.hostname,
                    event_time,
                    msg_type_str,
                    event.requested_ip,
                    event.dhcp_server_id,
                    event.capture_interface,
                    getattr(event, "lease_time", None),
                    getattr(event, "renewal_time", None),
                    getattr(event, "rebinding_time", None),
                    getattr(event, "client_id", None),
                    getattr(event, "ciaddr", None),
                    getattr(event, "yiaddr", None),
                    getattr(event, "chaddr", None),
                ),
            )
            event_id = cur.lastrowid

            cur.execute("SELECT * FROM devices_current WHERE mac = ?", (clean_mac,))
            raw_row = cur.fetchone()
            existing_dev = dict(raw_row) if raw_row else None

            target_ip = event.ip or event.requested_ip
            existing_hostname = existing_dev.get("hostname") if existing_dev else None
            final_hostname = event.hostname if event.hostname else existing_hostname

            current_ip = existing_dev.get("current_ip") if existing_dev else None
            lease_status = existing_dev.get("lease_status", "observed") if existing_dev else "observed"
            lease_time_val = getattr(event, "lease_time", None)
            lease_expiry = None

            last_ack_time = existing_dev.get("last_ack_time") if existing_dev else None

            if msg_type_str == "ACK":
                if target_ip and target_ip != "0.0.0.0":
                    current_ip = target_ip
                last_ack_time = event_time
                if lease_time_val and lease_time_val > 0:
                    lease_status = "bound"
                    lease_expiry = event_time + timedelta(seconds=int(lease_time_val))
                else:
                    lease_status = "bound_no_lease"
            elif msg_type_str == "OFFER":
                if lease_status != "bound":
                    lease_status = "offered"
            elif msg_type_str in ["DISCOVER", "REQUEST"]:
                if lease_status != "bound":
                    lease_status = "requesting"
            elif msg_type_str in ["RELEASE", "DECLINE"]:
                lease_status = "released"

            if existing_dev:
                cur.execute("""
                    UPDATE devices_current
                    SET current_ip = ?,
                        hostname = COALESCE(?, hostname),
                        last_seen = ?,
                        last_ack_time = COALESCE(?, last_ack_time),
                        lease_status = ?,
                        lease_time = COALESCE(?, lease_time),
                        lease_expiry = COALESCE(?, lease_expiry),
                        server_id = COALESCE(?, server_id)
                    WHERE mac = ?
                """, (
                    current_ip,
                    final_hostname,
                    event_time,
                    last_ack_time,
                    lease_status,
                    lease_time_val,
                    lease_expiry,
                    event.dhcp_server_id,
                    clean_mac
                ))
            else:
                cur.execute("""
                    INSERT INTO devices_current (
                        mac, current_ip, hostname, first_seen, last_seen, last_ack_time,
                        lease_status, lease_time, lease_expiry, server_id, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'observed')
                """, (
                    clean_mac,
                    current_ip,
                    final_hostname,
                    event_time,
                    event_time,
                    last_ack_time,
                    lease_status,
                    lease_time_val,
                    lease_expiry,
                    event.dhcp_server_id
                ))

        self.upsert_device_master(
            mac=clean_mac,
            ip=current_ip,
            hostname=final_hostname,
            assignment_type="DHCP",
            record_source="DHCP",
            seen_time=event_time
        )
        return event_id

    def upsert_device_master(
        self,
        mac: str,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        assignment_type: str = "DHCP",
        record_source: str = "DHCP",
        seen_time: Optional[datetime] = None,
    ) -> Any:
        """維護全校統一設備主檔與 IP 配發歷程 (安全相容 sqlite3.Row)。"""
        clean_mac = normalize_mac(mac)
        now = seen_time or datetime.now()

        with self.db.transaction() as conn:
            cur = conn.cursor()

            cur.execute("SELECT * FROM devices_current WHERE mac = ?", (clean_mac,))
            raw_row = cur.fetchone()
            row = dict(raw_row) if raw_row else None

            device_pk: Any = clean_mac

            if row:
                if "device_id" in row:
                    device_pk = row["device_id"]
                elif "id" in row:
                    device_pk = row["id"]
                else:
                    device_pk = row["mac"]

                final_hostname = hostname if hostname else row.get("hostname")
                final_ip = ip if (ip and ip != "0.0.0.0") else row.get("current_ip")

                cur.execute("""
                    UPDATE devices_current
                    SET current_ip = COALESCE(?, current_ip),
                        hostname = COALESCE(?, hostname),
                        last_seen = ?,
                        status = 'observed'
                    WHERE mac = ?
                """, (final_ip, final_hostname, now, clean_mac))
            else:
                cur.execute("""
                    INSERT INTO devices_current (
                        mac, current_ip, hostname, first_seen, last_seen, status
                    ) VALUES (?, ?, ?, ?, ?, 'observed')
                """, (clean_mac, ip, hostname, now, now))
                device_pk = cur.lastrowid or clean_mac

            if ip and ip != "0.0.0.0":
                try:
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_history'")
                    if cur.fetchone():
                        cur.execute("""
                            UPDATE ip_history
                            SET is_current = 0, valid_until = ?
                            WHERE device_id = ? AND is_current = 1 AND ip_address != ?
                        """, (now, device_pk, ip))

                        cur.execute("""
                            INSERT INTO ip_history (device_id, ip_address, assignment_type, valid_from, is_current)
                            VALUES (?, ?, ?, ?, 1)
                        """, (device_pk, ip, assignment_type, now))
                except Exception:
                    pass

            return device_pk

    def purge_old_dhcp_events(self, days: int) -> int:
        """清除保留天數以外的歷史 DHCP 事件。"""
        query = """
            DELETE FROM dhcp_events
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        """
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(query, (days,))
            return cur.rowcount

    # ---------------------------------------------------------
    # Location Resolution Methods
    # ---------------------------------------------------------

    def record_location(self, loc: DeviceLocation) -> None:
        """寫入或更新設備定位結果至資料庫。"""
        query = """
            INSERT INTO device_locations (
                mac, switch_id, if_index, confidence, resolution_status, reason, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(mac) DO UPDATE SET
                switch_id = excluded.switch_id,
                if_index = excluded.if_index,
                confidence = excluded.confidence,
                resolution_status = excluded.resolution_status,
                reason = excluded.reason,
                updated_at = excluded.updated_at
        """
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                query,
                (
                    loc.mac,
                    loc.switch_id,
                    loc.if_index,
                    loc.confidence,
                    loc.resolution_status.value,
                    loc.reason,
                ),
            )

    def get_latest_location(self, mac: str) -> Optional[DeviceLocation]:
        """取得特定 MAC 最近推導的實體位置記錄。"""
        clean_mac = normalize_mac(mac)
        query = """
            SELECT mac, switch_id, if_index, confidence, resolution_status, reason
            FROM device_locations
            WHERE UPPER(REPLACE(REPLACE(mac, '-', ''), ':', '')) = UPPER(REPLACE(REPLACE(?, '-', ''), ':', ''))
        """
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query, (clean_mac,))
                raw_row = cur.fetchone()
                if not raw_row:
                    return None
                row = dict(raw_row)
                return DeviceLocation(
                    mac=row["mac"],
                    switch_id=row.get("switch_id"),
                    if_index=row.get("if_index"),
                    confidence=row.get("confidence", 0.0),
                    resolution_status=ResolutionStatus(row.get("resolution_status", "unknown")),
                    reason=row.get("reason", ""),
                )
        except Exception:
            return None

    # ---------------------------------------------------------
    # Physical Verification Methods (串接 N08)
    # ---------------------------------------------------------

    def get_latest_verification(self, mac: str) -> Optional[DeviceVerification]:
        """查詢指定 MAC 最近一筆管理員實機插線驗證記錄。"""
        clean_mac = normalize_mac(mac)
        query = """
            SELECT id, mac, expected_switch_id, expected_if_index,
                   actual_switch_id, actual_if_index, verified_at, is_match, note
            FROM device_verifications
            WHERE UPPER(REPLACE(REPLACE(mac, '-', ''), ':', '')) = UPPER(REPLACE(REPLACE(?, '-', ''), ':', ''))
            ORDER BY verified_at DESC, id DESC
            LIMIT 1
        """
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query, (clean_mac,))
                raw_row = cur.fetchone()
                if not raw_row:
                    return None
                row = dict(raw_row)
                return DeviceVerification(
                    id=row["id"],
                    mac=row["mac"],
                    expected_switch_id=row.get("expected_switch_id"),
                    expected_if_index=row.get("expected_if_index"),
                    actual_switch_id=row.get("actual_switch_id"),
                    actual_if_index=row.get("actual_if_index"),
                    verified_at=row.get("verified_at"),
                    is_match=bool(row.get("is_match")),
                    note=row.get("note") or "",
                )
        except Exception:
            return None

    def add_verification(
        self,
        mac: str,
        expected_switch_id: Optional[int],
        expected_if_index: Optional[int],
        actual_switch_id: Optional[int],
        actual_if_index: Optional[int],
        is_match: bool,
        note: str = "",
    ) -> int:
        """新增一筆管理員實機驗證記錄。"""
        clean_mac = normalize_mac(mac)
        query = """
            INSERT INTO device_verifications (
                mac, expected_switch_id, expected_if_index,
                actual_switch_id, actual_if_index, is_match, note
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                query,
                (
                    clean_mac,
                    expected_switch_id,
                    expected_if_index,
                    actual_switch_id,
                    actual_if_index,
                    1 if is_match else 0,
                    note,
                ),
            )
            return cur.lastrowid

    def record_alert(self, alert_type: str, server_ip: str, client_mac: str, assigned_ip: str, details: str = "") -> None:
        """記錄 DHCP 安全異常事件至資料庫"""
        with self.db.transaction() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dhcp_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    alert_type TEXT,
                    server_ip TEXT,
                    client_mac TEXT,
                    assigned_ip TEXT,
                    details TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO dhcp_alerts (timestamp, alert_type, server_ip, client_mac, assigned_ip, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (datetime.now(), alert_type, server_ip, client_mac, assigned_ip, details)
            )

    def list_all_alerts(self) -> list[dict[str, Any]]:
        """列出所有已記錄的資安警報事件"""
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='dhcp_alerts'")
            if not cur.fetchone():
                return []
            cur.execute(
                "SELECT id, timestamp, alert_type, server_ip, client_mac, assigned_ip, details FROM dhcp_alerts ORDER BY timestamp DESC"
            )
            return [dict(row) for row in cur.fetchall()]

    def verify_and_evaluate_location(
        self,
        mac: str,
        switch_ip: str,
        port: str,
        note: str = "",
    ) -> tuple[bool, str, bool]:
        """記錄人工實機驗證，比對當前 FDB，若不符自動觸發 N08 告警。"""
        clean_mac = normalize_mac(mac)
        
        switches = self.list_switches()
        target_sw = next((s for s in switches if s.management_ip == switch_ip or s.sys_name == switch_ip), None)
        if not target_sw or target_sw.switch_id is None:
            return False, f"找不到指定的交換器: {switch_ip}", False

        intfs = self.get_interfaces(target_sw.switch_id)
        target_intf = None
        for idx, i_obj in intfs.items():
            if str(idx) == port or i_obj.if_name == port:
                target_intf = i_obj
                break

        if not target_intf:
            return False, f"在交換器 {target_sw.sys_name} 上找不到連接埠: {port}", False

        fdb_entries = self.get_fdb_for_mac(clean_mac)
        actual_switch_id = target_sw.switch_id
        actual_if_index = target_intf.if_index

        is_match = False
        for entry in fdb_entries:
            if entry.switch_id == actual_switch_id and entry.if_index == actual_if_index:
                is_match = True
                break

        resolution_status = ResolutionStatus.VERIFIED if (is_match or not fdb_entries) else ResolutionStatus.CONFLICT
        reason = "管理員實機驗證相符" if is_match else "注意：實機驗證位置與最新 FDB 觀測不符（可能已移動）"

        if not is_match:
            try:
                from network_monitor.anomaly.engine import AnomalyEngine
                ae = AnomalyEngine(self)
                ae.check_n08_verification_mismatch(
                    mac=clean_mac,
                    expected_switch_id=fdb_entries[0].switch_id if fdb_entries else actual_switch_id,
                    expected_if_index=fdb_entries[0].if_index if fdb_entries else actual_if_index,
                    actual_switch_id=actual_switch_id,
                    actual_if_index=actual_if_index,
                    note=note
                )
            except Exception as e:
                import logging
                logging.getLogger("network_monitor").error(f"觸發 N08 告警失敗: {e}")

        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO device_verifications (
                    mac, expected_switch_id, expected_if_index,
                    actual_switch_id, actual_if_index, is_match, note, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """, (
                clean_mac,
                fdb_entries[0].switch_id if fdb_entries else actual_switch_id,
                fdb_entries[0].if_index if fdb_entries else actual_if_index,
                actual_switch_id,
                actual_if_index,
                1 if is_match else 0,
                note
            ))

            cur.execute("""
                INSERT INTO device_locations (
                    mac, switch_id, if_index, confidence, resolution_status, reason, updated_at
                ) VALUES (?, ?, ?, 1.0, ?, ?, datetime('now'))
                ON CONFLICT(mac) DO UPDATE SET
                    switch_id = excluded.switch_id,
                    if_index = excluded.if_index,
                    confidence = 1.0,
                    resolution_status = excluded.resolution_status,
                    reason = excluded.reason,
                    updated_at = excluded.updated_at
            """, (
                clean_mac,
                actual_switch_id,
                actual_if_index,
                resolution_status.value,
                reason
            ))

        match_str = "相符 (VERIFIED)" if is_match else "衝突 (CONFLICT)"
        return True, f"成功完成 MAC {clean_mac} 驗證，狀態: {match_str}", is_match

    # ---------------------------------------------------------
    # Monitoring Health Methods (自適應 Schema 補齊欄位)
    # ---------------------------------------------------------

    def record_monitoring_health(self, module_name: str, status: str, error_message: Optional[str] = None) -> None:
        """記錄或更新各監控模組 (SNMP, Anomaly, DHCP) 的即時健康狀態與心跳。"""
        now = datetime.now()
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_health (
                    module_name TEXT PRIMARY KEY,
                    status TEXT,
                    last_success_time DATETIME,
                    last_update_time DATETIME,
                    error_message TEXT
                )
            """)

            cur.execute("PRAGMA table_info(monitoring_health)")
            existing_cols = {row["name"] for row in cur.fetchall()}

            for col in ["last_success_time", "last_update_time", "error_message"]:
                if col not in existing_cols:
                    try:
                        cur.execute(f"ALTER TABLE monitoring_health ADD COLUMN {col} DATETIME")
                    except Exception:
                        pass

            if status == "RUNNING":
                cur.execute("""
                    INSERT INTO monitoring_health (module_name, status, last_success_time, last_update_time, error_message)
                    VALUES (?, ?, ?, ?, NULL)
                    ON CONFLICT(module_name) DO UPDATE SET
                        status = excluded.status,
                        last_success_time = excluded.last_success_time,
                        last_update_time = excluded.last_update_time,
                        error_message = NULL
                """, (module_name, status, now, now))
            else:
                cur.execute("""
                    INSERT INTO monitoring_health (module_name, status, last_update_time, error_message)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(module_name) DO UPDATE SET
                        status = excluded.status,
                        last_update_time = excluded.last_update_time,
                        error_message = excluded.error_message
                """, (module_name, status, now, error_message))

    def get_all_monitoring_health(self) -> List[Dict[str, Any]]:
        """取得所有監控模組的即時運作狀態清單。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='monitoring_health'")
                if not cur.fetchone():
                    return []
                cur.execute("SELECT * FROM monitoring_health ORDER BY module_name ASC")
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    # ---------------------------------------------------------
    # 設備清冊管理 (Inventory Methods)
    # ---------------------------------------------------------

    def list_inventory_devices(
        self,
        device_type: Optional[str] = None,
        management_status: Optional[str] = None,
        assignment_type: Optional[str] = None,
        location_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """查詢設備清冊並支援條件篩選。"""
        query = """
            SELECT d.device_id, d.mac_address, d.current_ip, d.hostname, d.device_name,
                   d.device_type, d.ip_assignment_type, d.management_status,
                   l.switch_id, l.if_index, l.resolution_status, s.sys_name as switch_name,
                   i.if_name as interface_name
            FROM devices_master d
            LEFT JOIN device_locations l ON d.mac_address = l.mac
            LEFT JOIN switches s ON l.switch_id = s.switch_id
            LEFT JOIN interfaces i ON l.switch_id = i.switch_id AND l.if_index = i.if_index
            WHERE 1=1
        """
        params: List[Any] = []
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices_master'")
                if not cur.fetchone():
                    cur.execute("""
                        SELECT 1 as device_id, d.mac as mac_address, d.current_ip, d.hostname,
                               d.hostname as device_name, 'unknown' as device_type, 'DHCP' as ip_assignment_type,
                               'OBSERVED' as management_status, l.switch_id, l.if_index, l.resolution_status,
                               s.sys_name as switch_name, i.if_name as interface_name
                        FROM devices_current d
                        LEFT JOIN device_locations l ON d.mac = l.mac
                        LEFT JOIN switches s ON l.switch_id = s.switch_id
                        LEFT JOIN interfaces i ON l.switch_id = i.switch_id AND l.if_index = i.if_index
                    """)
                    return [dict(r) for r in cur.fetchall()]

                if device_type:
                    query += " AND d.device_type = ?"
                    params.append(device_type)
                if management_status:
                    query += " AND d.management_status = ?"
                    params.append(management_status)
                if assignment_type:
                    query += " AND d.ip_assignment_type = ?"
                    params.append(assignment_type)
                if location_status:
                    query += " AND l.resolution_status = ?"
                    params.append(location_status)

                cur.execute(query, params)
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    def find_inventory_device(self, identifier: str) -> Optional[Dict[str, Any]]:
        """依 MAC、IP 或 ID 查詢單一設備紀錄。"""
        clean_mac = normalize_mac(identifier)
        query = """
            SELECT d.device_id, d.mac_address, d.current_ip, d.hostname, d.device_name,
                   d.device_type, d.ip_assignment_type, d.management_status, d.record_source,
                   d.first_seen, d.last_seen,
                   c.lease_status, c.lease_expiry,
                   l.switch_id, l.if_index, l.resolution_status, l.confidence, l.reason,
                   s.sys_name as switch_name, s.management_ip as switch_ip,
                   i.if_name as interface_name
            FROM devices_master d
            LEFT JOIN devices_current c ON d.mac_address = c.mac
            LEFT JOIN device_locations l ON d.mac_address = l.mac
            LEFT JOIN switches s ON l.switch_id = s.switch_id
            LEFT JOIN interfaces i ON l.switch_id = i.switch_id AND l.if_index = i.if_index
            WHERE d.mac_address = ? OR d.current_ip = ? OR CAST(d.device_id AS TEXT) = ?
            LIMIT 1
        """
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices_master'")
                if not cur.fetchone():
                    cur.execute("""
                        SELECT 1 as device_id, c.mac as mac_address, c.current_ip, c.hostname,
                               c.hostname as device_name, 'unknown' as device_type, 'DHCP' as ip_assignment_type,
                               'OBSERVED' as management_status, 'DHCP' as record_source,
                               c.first_seen, c.last_seen, c.lease_status, c.lease_expiry,
                               l.switch_id, l.if_index, l.resolution_status, l.confidence, l.reason,
                               s.sys_name as switch_name, s.management_ip as switch_ip,
                               i.if_name as interface_name
                        FROM devices_current c
                        LEFT JOIN device_locations l ON c.mac = l.mac
                        LEFT JOIN switches s ON l.switch_id = s.switch_id
                        LEFT JOIN interfaces i ON l.switch_id = i.switch_id AND l.if_index = i.if_index
                        WHERE c.mac = ? OR c.current_ip = ?
                        LIMIT 1
                    """, (clean_mac, identifier))
                    row = cur.fetchone()
                    return dict(row) if row else None

                cur.execute(query, (clean_mac, identifier, identifier))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception:
            return None

    def add_static_device(
        self,
        mac: str,
        ip: Optional[str] = None,
        device_name: Optional[str] = None,
        device_type: str = "unknown",
        assignment_type: str = "STATIC",
        management_status: str = "MANAGED",
        vlan_id: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> tuple[bool, str]:
        """手動註冊或登錄靜態設備至清冊。"""
        clean_mac = normalize_mac(mac)
        now = datetime.now()
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS devices_master (
                    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_address TEXT UNIQUE,
                    current_ip TEXT,
                    hostname TEXT,
                    device_name TEXT,
                    device_type TEXT,
                    ip_assignment_type TEXT,
                    management_status TEXT,
                    record_source TEXT,
                    notes TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME
                )
            """)
            cur.execute("""
                INSERT INTO devices_master (
                    mac_address, current_ip, device_name, device_type,
                    ip_assignment_type, management_status, record_source, notes,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, 'MANUAL', ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    current_ip = COALESCE(excluded.current_ip, devices_master.current_ip),
                    device_name = COALESCE(excluded.device_name, devices_master.device_name),
                    device_type = excluded.device_type,
                    ip_assignment_type = excluded.ip_assignment_type,
                    management_status = excluded.management_status,
                    notes = COALESCE(excluded.notes, devices_master.notes),
                    last_seen = excluded.last_seen
            """, (clean_mac, ip, device_name, device_type, assignment_type, management_status, notes, now, now))
        return True, f"已成功新增/更新設備 {clean_mac} 至清冊。"

    def update_device_by_identifier(
        self,
        identifier: str,
        device_name: Optional[str] = None,
        ip: Optional[str] = None,
        device_type: Optional[str] = None,
        assignment_type: Optional[str] = None,
        management_status: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> tuple[bool, str]:
        """修改設備清冊屬性。"""
        clean_mac = normalize_mac(identifier)
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE devices_master
                SET device_name = COALESCE(?, device_name),
                    current_ip = COALESCE(?, current_ip),
                    device_type = COALESCE(?, device_type),
                    ip_assignment_type = COALESCE(?, ip_assignment_type),
                    management_status = COALESCE(?, management_status),
                    notes = COALESCE(?, notes),
                    last_seen = datetime('now')
                WHERE mac_address = ? OR current_ip = ? OR CAST(device_id AS TEXT) = ?
            """, (device_name, ip, device_type, assignment_type, management_status, notes, clean_mac, identifier, identifier))
            if cur.rowcount > 0:
                return True, f"成功更新設備: {identifier}"
        return False, f"找不到設備或無變更: {identifier}"

    def get_ip_history_for_device(self, device_id: Any) -> List[Dict[str, Any]]:
        """取得特定設備的 IP 配發歷程。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_history'")
                if not cur.fetchone():
                    return []
                cur.execute("""
                    SELECT ip_address, assignment_type, valid_from, valid_until, is_current
                    FROM ip_history
                    WHERE device_id = ?
                    ORDER BY valid_from DESC
                """, (device_id,))
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    def get_unmanaged_devices_report(self) -> List[Dict[str, Any]]:
        """產出未登錄至清冊之設備清單。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT c.mac, c.current_ip, c.hostname, c.last_seen, 'DHCP/FDB' as detection_source
                    FROM devices_current c
                    LEFT JOIN devices_master m ON c.mac = m.mac_address
                    WHERE m.management_status IS NULL OR m.management_status = 'UNMANAGED'
                    ORDER BY c.last_seen DESC
                """)
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    def get_ip_conflict_report(self) -> List[Dict[str, Any]]:
        """產出 IP 衝突清單 (多個 MAC 爭用同一個 IP)。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT current_ip as ip, COUNT(DISTINCT mac) as mac_count,
                           GROUP_CONCAT(mac, ', ') as conflicting_macs,
                           MAX(last_seen) as last_conflict_time
                    FROM devices_current
                    WHERE current_ip IS NOT NULL AND current_ip != '' AND current_ip != '0.0.0.0'
                    GROUP BY current_ip
                    HAVING COUNT(DISTINCT mac) > 1
                """)
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    def get_comprehensive_export_rows(self) -> List[Dict[str, Any]]:
        """產出全校設備、定位、驗證與安全資訊的綜合導出數據。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT c.mac, c.current_ip, c.hostname,
                           COALESCE(m.device_name, c.hostname) as device_name,
                           COALESCE(m.device_type, 'unknown') as device_type,
                           COALESCE(m.ip_assignment_type, 'DHCP') as ip_assignment_type,
                           c.lease_status, c.lease_expiry, c.last_seen,
                           s.sys_name as switch_name, s.management_ip as switch_ip,
                           i.if_name as interface_name,
                           l.confidence, l.resolution_status, l.reason,
                           v.is_match as last_verification_match, v.verified_at as last_verified_at
                    FROM devices_current c
                    LEFT JOIN devices_master m ON c.mac = m.mac_address
                    LEFT JOIN device_locations l ON c.mac = l.mac
                    LEFT JOIN switches s ON l.switch_id = s.switch_id
                    LEFT JOIN interfaces i ON l.switch_id = i.switch_id AND l.if_index = i.if_index
                    LEFT JOIN (
                        SELECT mac, is_match, verified_at FROM device_verifications
                        GROUP BY mac HAVING MAX(verified_at)
                    ) v ON c.mac = v.mac
                """)
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return self.list_all_devices_for_export()

    # ---------------------------------------------------------
    # 拓樸與鄰居管理 (Topology Methods)
    # ---------------------------------------------------------

    def save_topology_observations(self, local_switch_id: int, neighbors: List[Any]) -> None:
        """儲存交換器 LLDP/FDP 鄰居觀測資料。支援 Dict 與 Object 雙介面。"""
        with self.db.transaction() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS topology_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    local_switch_id INTEGER,
                    local_if_index INTEGER,
                    protocol TEXT DEFAULT 'LLDP',
                    remote_chassis_id TEXT,
                    remote_port_id TEXT,
                    remote_sys_name TEXT,
                    remote_mgmt_ip TEXT,
                    observed_at DATETIME
                )
            """)
            # 檢查是否有 protocol 欄位，若舊表沒有則自動補齊
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(topology_observations)")
            cols = [col[1] for col in cur.fetchall()]
            if "protocol" not in cols:
                try:
                    cur.execute("ALTER TABLE topology_observations ADD COLUMN protocol TEXT DEFAULT 'LLDP'")
                except Exception:
                    pass

            now = datetime.now()
            for n in neighbors:
                if isinstance(n, dict):
                    loc_if = n.get("local_if_index") or n.get("local_port")
                    proto = n.get("protocol", "LLDP")
                    chassis = n.get("remote_chassis_id", "")
                    port_id = n.get("remote_port_id", "")
                    sys_name = n.get("remote_device_name") or n.get("remote_sys_name", "")
                    mgmt_ip = n.get("remote_mgmt_ip", "")
                else:
                    loc_if = getattr(n, "local_if_index", None) or getattr(n, "local_port", None)
                    proto = getattr(n, "protocol", "LLDP")
                    chassis = getattr(n, "remote_chassis_id", "")
                    port_id = getattr(n, "remote_port_id", "")
                    sys_name = getattr(n, "remote_device_name", None) or getattr(n, "remote_sys_name", "")
                    mgmt_ip = getattr(n, "remote_mgmt_ip", "")

                cur.execute("""
                    INSERT INTO topology_observations (
                        local_switch_id, local_if_index, protocol, remote_chassis_id,
                        remote_port_id, remote_sys_name, remote_mgmt_ip, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    local_switch_id,
                    loc_if,
                    proto,
                    chassis,
                    port_id,
                    sys_name,
                    mgmt_ip,
                    now
                ))

    def list_all_topology_observations(self) -> List[Dict[str, Any]]:
        """取得資料庫中記錄的所有交換器 LLDP/CDP 鄰居觀測原始資料。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='topology_observations'")
                if not cur.fetchone():
                    return []
                cur.execute("""
                    SELECT local_switch_id, local_if_index, remote_chassis_id,
                           remote_port_id, remote_sys_name, remote_mgmt_ip, observed_at
                    FROM topology_observations
                """)
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    def list_topology_links(self) -> List[Dict[str, Any]]:
        """取得已推算確認的交換器骨幹互聯拓樸鏈路。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='topology_links'")
                if not cur.fetchone():
                    return []
                cur.execute("""
                    SELECT tl.*,
                           s1.sys_name as local_switch_name, s1.management_ip as local_switch_ip,
                           s2.sys_name as remote_switch_name, s2.management_ip as resolved_remote_ip,
                           i1.if_name as local_interface_name, i2.if_name as remote_if_name
                    FROM topology_links tl
                    LEFT JOIN switches s1 ON tl.local_switch_id = s1.switch_id
                    LEFT JOIN switches s2 ON tl.remote_switch_id = s2.switch_id
                    LEFT JOIN interfaces i1 ON tl.local_switch_id = i1.switch_id AND tl.local_if_index = i1.if_index
                    LEFT JOIN interfaces i2 ON tl.remote_switch_id = i2.switch_id AND tl.remote_if_index = i2.if_index
                """)
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    # ---------------------------------------------------------
    # 告警事件中心 (Alert Management Methods)
    # ---------------------------------------------------------

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """列出系統安全與維運告警事件。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
                if not cur.fetchone():
                    return []
                query = "SELECT * FROM alerts WHERE 1=1"
                params: List[Any] = []
                if status:
                    query += " AND status = ?"
                    params.append(status)
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                if event_type:
                    query += " AND event_type = ?"
                    params.append(event_type)
                query += " ORDER BY last_seen DESC LIMIT ?"
                params.append(limit)
                cur.execute(query, params)
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    def get_alert_detail(self, event_id: int) -> Optional[Dict[str, Any]]:
        """取得告警事件詳情與相關證據/歷程。"""
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM alerts WHERE event_id = ?", (event_id,))
                raw = cur.fetchone()
                if not raw:
                    return None
                alert = dict(raw)
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alert_evidences'")
                if cur.fetchone():
                    cur.execute("SELECT * FROM alert_evidences WHERE event_id = ? ORDER BY recorded_at DESC", (event_id,))
                    alert["evidence"] = [dict(r) for r in cur.fetchall()]
                else:
                    alert["evidence"] = []

                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alert_history'")
                if cur.fetchone():
                    cur.execute("SELECT * FROM alert_history WHERE event_id = ? ORDER BY changed_at DESC", (event_id,))
                    alert["history"] = [dict(r) for r in cur.fetchall()]
                else:
                    alert["history"] = []
                return alert
        except Exception:
            return None

    def update_alert_status(self, event_id: int, new_status: str, note: str = "", operator: str = "ADMIN") -> tuple[bool, str]:
        """更新告警事件狀態 (ACKNOWLEDGED, RESOLVED, SUPPRESSED)。"""
        now = datetime.now()
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT status FROM alerts WHERE event_id = ?", (event_id,))
                row = cur.fetchone()
                if not row:
                    return False, f"找不到 ID 為 #{event_id} 的告警事件。"
                old_status = dict(row)["status"]

                cur.execute("""
                    UPDATE alerts
                    SET status = ?, resolution_note = ?, resolved_at = ?
                    WHERE event_id = ?
                """, (new_status, note, now if new_status == "RESOLVED" else None, event_id))

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS alert_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id INTEGER,
                        old_status TEXT,
                        new_status TEXT,
                        operator TEXT,
                        note TEXT,
                        changed_at DATETIME
                    )
                """)
                cur.execute("""
                    INSERT INTO alert_history (event_id, old_status, new_status, operator, note, changed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (event_id, old_status, new_status, operator, note, now))
                return True, f"告警 #{event_id} 狀態已變更為 [{new_status}]。"
        except Exception as e:
            return False, f"更新失敗: {e}"

    def get_alert_statistics_report(self) -> Dict[str, Any]:
        """產出全網告警摘要統計報表。"""
        stats: Dict[str, Any] = {
            "total_alerts": 0,
            "open_alerts": 0,
            "resolved_alerts": 0,
            "by_severity": {},
            "by_type": {},
            "recent_alerts": [],
        }
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
                if not cur.fetchone():
                    return stats

                cur.execute("SELECT COUNT(*) as cnt FROM alerts")
                stats["total_alerts"] = cur.fetchone()["cnt"]

                cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status IN ('OPEN', 'REOPENED', 'ACKNOWLEDGED')")
                stats["open_alerts"] = cur.fetchone()["cnt"]

                cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status = 'RESOLVED'")
                stats["resolved_alerts"] = cur.fetchone()["cnt"]

                cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
                stats["by_severity"] = {r["severity"]: r["cnt"] for r in cur.fetchall()}

                cur.execute("SELECT event_type, COUNT(*) as cnt FROM alerts GROUP BY event_type ORDER BY cnt DESC")
                stats["by_type"] = {r["event_type"]: r["cnt"] for r in cur.fetchall()}

                cur.execute("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT 10")
                stats["recent_alerts"] = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass
        return stats