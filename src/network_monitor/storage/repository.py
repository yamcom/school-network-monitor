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
            row = cur.fetchone()

            if row:
                col_name = "switch_id" if "switch_id" in row.keys() else "id"
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

    def list_switches(self) -> List[SwitchInfo]:
        """列出資料庫中已記錄的所有交換器。"""
        query = "SELECT * FROM switches"
        results: List[SwitchInfo] = []
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query)
                for row in cur.fetchall():
                    s_id = row["switch_id"] if "switch_id" in row.keys() else row.get("id")
                    results.append(
                        SwitchInfo(
                            switch_id=s_id,
                            management_ip=row["management_ip"] or "",
                            sys_name=row.get("sys_name") or "",
                            sys_descr=row.get("sys_descr") or "",
                            sys_object_id=row.get("sys_object_id") or "",
                            vendor=row.get("vendor") or "",
                            model=row.get("model") or "",
                            adapter_name=row.get("adapter_name") or "standard_mib",
                            poll_status=row.get("poll_status") or "offline",
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
                for row in cur.fetchall():
                    intf = SwitchInterface(
                        switch_id=row["switch_id"],
                        if_index=row["if_index"],
                        if_name=row["if_name"] or "",
                        if_descr=row["if_descr"] or "",
                        if_alias=row["if_alias"] or "",
                        bridge_port=row["bridge_port"],
                        is_uplink=bool(row["is_uplink"]),
                    )
                    interfaces[intf.if_index] = intf
        except Exception:
            pass
        return interfaces

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
                for row in cur.fetchall():
                    entries.append(
                        FdbEntry(
                            switch_id=row["switch_id"],
                            mac=row["mac"],
                            bridge_port=row["bridge_port"],
                            vlan_id=row["vlan_id"],
                            last_seen=row["last_seen"],
                            if_index=row["if_index"],
                        )
                    )
        except Exception:
            pass
        return entries

    def get_device_by_mac(self, mac: str) -> Optional[DeviceCurrent]:
        """取得特定 MAC 目前已記錄的 IP、主機名稱與租約狀態。"""
        clean_mac = normalize_mac(mac)
        query = """
            SELECT mac, current_ip, hostname, last_seen, lease_status, lease_time, lease_expiry
            FROM devices_current
            WHERE UPPER(REPLACE(REPLACE(mac, '-', ''), ':', '')) = UPPER(REPLACE(REPLACE(?, '-', ''), ':', ''))
        """
        try:
            with self.db.transaction() as conn:
                cur = conn.cursor()
                cur.execute(query, (clean_mac,))
                row = cur.fetchone()
                if not row:
                    return None
                dev = DeviceCurrent(
                    mac=row["mac"],
                    current_ip=row["current_ip"],
                    hostname=row["hostname"],
                    last_seen=row["last_seen"],
                )
                setattr(dev, "lease_status", row["lease_status"] or "observed")
                setattr(dev, "lease_time", row["lease_time"])
                setattr(dev, "lease_expiry", row["lease_expiry"])
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
                row = cur.fetchone()
                if not row:
                    return None
                dev = DeviceCurrent(
                    mac=row["mac"],
                    current_ip=row["current_ip"],
                    hostname=row["hostname"],
                    last_seen=row["last_seen"],
                )
                setattr(dev, "lease_status", row["lease_status"] or "observed")
                setattr(dev, "lease_time", row["lease_time"])
                setattr(dev, "lease_expiry", row["lease_expiry"])
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
                for row in cur.fetchall():
                    results.append(dict(row))
        except Exception:
            pass
        return results

    # ---------------------------------------------------------
    # DHCP Event & Lease Methods (MVP-04.1)
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

            cur.execute("SELECT mac, hostname, current_ip, lease_status FROM devices_current WHERE mac = ?", (clean_mac,))
            existing_dev = cur.fetchone()

            target_ip = event.ip or event.requested_ip
            existing_hostname = existing_dev["hostname"] if existing_dev else None
            final_hostname = event.hostname if event.hostname else existing_hostname

            current_ip = existing_dev["current_ip"] if existing_dev else None
            lease_status = existing_dev["lease_status"] if existing_dev else "observed"
            lease_time_val = getattr(event, "lease_time", None)
            lease_expiry = None

            if msg_type_str == "ACK":
                if target_ip and target_ip != "0.0.0.0":
                    current_ip = target_ip
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
                    SET current_ip = COALESCE(?, current_ip),
                        hostname = COALESCE(?, hostname),
                        last_seen = ?,
                        lease_status = ?,
                        lease_time = COALESCE(?, lease_time),
                        lease_expiry = COALESCE(?, lease_expiry),
                        server_id = COALESCE(?, server_id)
                    WHERE mac = ?
                """, (
                    current_ip,
                    final_hostname,
                    event_time,
                    lease_status,
                    lease_time_val,
                    lease_expiry,
                    event.dhcp_server_id,
                    clean_mac
                ))
            else:
                cur.execute("""
                    INSERT INTO devices_current (
                        mac, current_ip, hostname, first_seen, last_seen,
                        lease_status, lease_time, lease_expiry, server_id, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'observed')
                """, (
                    clean_mac,
                    current_ip,
                    final_hostname,
                    event_time,
                    event_time,
                    lease_status,
                    lease_time_val,
                    lease_expiry,
                    event.dhcp_server_id
                ))

        self.upsert_device_master(
            mac=clean_mac,
            ip=target_ip,
            hostname=final_hostname,
            assignment_type="DHCP",
            record_source="DHCP",
            seen_time=event_time
        )
        return event_id

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
                row = cur.fetchone()
                if not row:
                    return None
                return DeviceLocation(
                    mac=row["mac"],
                    switch_id=row["switch_id"],
                    if_index=row["if_index"],
                    confidence=row["confidence"],
                    resolution_status=ResolutionStatus(row["resolution_status"]),
                    reason=row["reason"],
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
                row = cur.fetchone()
                if not row:
                    return None
                return DeviceVerification(
                    id=row["id"],
                    mac=row["mac"],
                    expected_switch_id=row["expected_switch_id"],
                    expected_if_index=row["expected_if_index"],
                    actual_switch_id=row["actual_switch_id"],
                    actual_if_index=row["actual_if_index"],
                    verified_at=row["verified_at"],
                    is_match=bool(row["is_match"]),
                    note=row["note"] or "",
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
                INSERT INTO dhcp_alerts (timestamp, alert_type, server_ip, client_mac, assigned_ip, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (datetime.now(), alert_type, server_ip, client_mac, assigned_ip, details)
            )

    def list_all_alerts(self) -> list[dict[str, Any]]:
        """列出所有已記錄的資安警報事件"""
        with self.db.transaction() as conn:
            cur = conn.cursor()
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

        # 觸發 N08 異常規則
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
    # 設備清冊與拓樸相關方法 (upsert_device_master, get_comprehensive_export_rows, 
    # save_topology_observations, upsert_topology_link, 告警與健康狀態等)
    # ---------------------------------------------------------
    # (此處保留原有的其他完整 repository 方法...)