"""Anomaly detection rules engine for ================================================================================
 系統異常偵測規則定義總表 (Alert Rules)
================================================================================
規則代碼       規則名稱                 嚴重度        模組狀態               觸發條件與說明
----------------------------------------------------------------------------------------------------------
.N01        未授權 DHCP Server      HIGH       啟用 (MVP-07.1)      DHCP OFFER/ACK 來源不在授權 DHCP Server 清單
.N02        DHCP Scope 不符        MEDIUM     啟用 (MVP-07.1)      配發 IP 不符合群組設定之伺服器或網段規則
.N03        SNMP 設備失聯            HIGH       啟用 (MVP-07.1)      交換器連續 3 次 SNMP 輪詢逾時/失敗
.N04        未登錄設備                LOW        啟用 (MVP-07.1)      非 Uplink 接入埠學習到清冊中不存在的 MAC
N05        MAC 位址漂移             MEDIUM     啟用 (MVP-07.4)     同一 MAC 短時間出現在不同接入埠 (排除骨幹轉發)
N06        Uplink 連線異常          HIGH       啟用 (MVP-07.4)     已確認之主幹 Uplink 埠狀態轉為 Down
N07        IP 位址衝突              HIGH       啟用 (MVP-07.4)     同一 IP 位址短時間被不同 MAC 同步使用
N08        人工驗證位置不符             MEDIUM     啟用 (MVP-07.4)     目前 FDB 位置與網管人員實機驗證位置產生衝突
N09        拓樸異動                 LOW        啟用 (MVP-07.4)     交換器 LLDP/CDP 鄰居主幹連接關係發生變動
N10        DHCP Listener 異常     CRITICAL   啟用 (MVP-07.3)      封包監聽程序停止、介面失效或持續報錯
=========================================================================================================="""

from __future__ import annotations
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from network_monitor.storage.repository import NetworkRepository

logger = logging.getLogger("network_monitor.anomaly.engine")


class AnomalyEngine:
    def __init__(self, repo: NetworkRepository) -> None:
        self.repo = repo

    def _trigger_or_update_event(
        self,
        event_key: str,
        event_type: str,
        severity: str,
        title: str,
        description: str,
        evidence_data: Dict[str, Any]
    ) -> None:
        """核心去重與事件觸發機制：持續發生時更新 last_seen 與 occurrence_count，不重複建立。"""
        now = datetime.now()
        with self.repo.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("SELECT event_id, status, occurrence_count FROM alert_events WHERE event_key = ?", (event_key,))
            row = cur.fetchone()

            if row:
                event_id = row["event_id"]
                current_status = row["status"]
                new_status = "REOPENED" if current_status == "RESOLVED" else current_status

                cur.execute("""
                    UPDATE alert_events
                    SET last_seen = ?,
                        occurrence_count = occurrence_count + 1,
                        status = CASE WHEN status = 'RESOLVED' THEN 'REOPENED' ELSE status END
                    WHERE event_id = ?
                """, (now, event_id))
            else:
                cur.execute("""
                    INSERT INTO alert_events (
                        event_key, event_type, severity, status, title, description,
                        first_seen, last_seen, occurrence_count, confidence
                    ) VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?, 1, 1.0)
                """, (event_key, event_type, severity, title, description, now, now))
                event_id = cur.lastrowid

            # 記錄證據
            cur.execute("""
                INSERT INTO alert_evidence (
                    event_id, evidence_type, source_ip, client_mac, assigned_ip, raw_details, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                evidence_data.get("evidence_type", "GENERAL"),
                evidence_data.get("source_ip"),
                evidence_data.get("client_mac"),
                evidence_data.get("assigned_ip"),
                evidence_data.get("raw_details"),
                now
            ))

    def check_n01_unauthorized_dhcp(self, event: Any, authorized_servers: List[str]) -> bool:
        """N01: 未授權 DHCP Server 檢測 (OFFER/ACK 來源不在授權清單)"""
        msg_type = str(getattr(event, "message_type", ""))
        server_ip = getattr(event, "dhcp_server_id", "0.0.0.0")
        
        if msg_type in ["OFFER", "ACK", "NAK"] and server_ip and server_ip != "0.0.0.0":
            if server_ip not in authorized_servers:
                event_key = f"DHCP_UNAUTHORIZED:{server_ip}"
                self._trigger_or_update_event(
                    event_key=event_key,
                    event_type="DHCP_UNAUTHORIZED",
                    severity="HIGH",
                    title=f"偵測到未授權 DHCP 伺服器: {server_ip}",
                    description=f"IP 為 {server_ip} 的 DHCP 伺服器發送了 {msg_type} 封包，但未列於校園授權清單中。",
                    evidence_data={
                        "evidence_type": "DHCP_PACKET",
                        "source_ip": server_ip,
                        "client_mac": getattr(event, "mac", ""),
                        "assigned_ip": getattr(event, "ip", ""),
                        "raw_details": f"Message: {msg_type}, Server: {server_ip}"
                    }
                )
                return True
        return False

    def check_n02_scope_mismatch(self, event: Any, scope_rules: List[Dict[str, Any]]) -> bool:
        """N02: DHCP Scope 不符檢測"""
        client_mac = getattr(event, "mac", "")
        server_ip = getattr(event, "dhcp_server_id", "0.0.0.0")
        assigned_ip = getattr(event, "ip", "")
        msg_type = str(getattr(event, "message_type", ""))

        if msg_type in ["ACK"] and client_mac:
            for rule in scope_rules:
                allowed_macs = {m.upper() for m in rule.get("macs", [])}
                allowed_servers = rule.get("allowed_servers", [])
                if client_mac.upper() in allowed_macs and server_ip not in allowed_servers:
                    event_key = f"DHCP_SCOPE_MISMATCH:{client_mac}"
                    self._trigger_or_update_event(
                        event_key=event_key,
                        event_type="DHCP_SCOPE_MISMATCH",
                        severity="MEDIUM",
                        title=f"DHCP Scope/Server 配發不符: {client_mac}",
                        description=f"裝置 {client_mac} 從非預期伺服器 {server_ip} 取得 IP (違反分組原則)。",
                        evidence_data={
                            "evidence_type": "DHCP_PACKET",
                            "source_ip": server_ip,
                            "client_mac": client_mac,
                            "assigned_ip": assigned_ip,
                            "raw_details": f"Group: {rule.get('group_name')}, Server: {server_ip}"
                        }
                    )
                    return True
        return False

    def check_n03_snmp_down(self, switch_ip: str, consecutive_failures: int, threshold: int = 3) -> bool:
        """N03: SNMP 設備失聯檢測 (連續失敗次數達門檻時觸發)"""
        event_key = f"SNMP_DOWN:{switch_ip}"
        if consecutive_failures >= threshold:
            self._trigger_or_update_event(
                event_key=event_key,
                event_type="SNMP_DOWN",
                severity="HIGH",
                title=f"交換器 SNMP 輪詢連續失敗: {switch_ip}",
                description=f"交換器 {switch_ip} 已連續失敗 {consecutive_failures} 次 SNMP 輪詢，判定為失聯。",
                evidence_data={
                    "evidence_type": "SNMP_POLL",
                    "source_ip": switch_ip,
                    "raw_details": f"Consecutive Failures: {consecutive_failures}"
                }
            )
            return True
        else:
            self.resolve_event_by_key(event_key, note="SNMP 輪詢已恢復正常")
        return False

    def check_n04_unregistered_device(self, mac: str, switch_id: int, if_index: int, is_uplink: bool) -> bool:
        """N04: 未登錄設備檢測 (非 Uplink 埠發現不在清冊中的 MAC)"""
        if is_uplink:
            return False
            
        clean_mac = mac.upper()
        if clean_mac.startswith("FF:FF") or clean_mac.startswith("01:00:5E") or clean_mac.startswith("33:33"):
            return False

        device = self.repo.find_inventory_device(clean_mac)
        if not device:
            event_key = f"UNREGISTERED_DEVICE:{clean_mac}"
            self._trigger_or_update_event(
                event_key=event_key,
                event_type="UNREGISTERED_DEVICE",
                severity="LOW",
                title=f"在接入埠發現未登錄設備: {clean_mac}",
                description=f"交換器 Switch-{switch_id} Port-{if_index} 學習到未列於設備清冊中的 MAC: {clean_mac}",
                evidence_data={
                    "evidence_type": "FDB_ENTRY",
                    "client_mac": clean_mac,
                    "raw_details": f"Switch ID: {switch_id}, Port Index: {if_index}"
                }
            )
            return True
        return False

    def check_n05_mac_drift(self, mac: str, current_switch_id: int, current_if_index: int) -> bool:
        """N05: MAC 位址漂移檢測 (結合拓樸排除骨幹)"""
        clean_mac = mac.upper()
        role = self.repo.get_port_role(current_switch_id, current_if_index)
        intfs = self.repo.get_interfaces(current_switch_id)
        i_obj = intfs.get(current_if_index)
        if role in ["UPLINK", "INTERCONNECT"] or (i_obj and i_obj.is_uplink):
            return False

        fdb_entries = self.repo.get_fdb_for_mac(clean_mac)
        access_locations = []
        for entry in fdb_entries:
            sw_id = entry.switch_id
            if_idx = entry.if_index
            r = self.repo.get_port_role(sw_id, if_idx)
            itfs = self.repo.get_interfaces(sw_id)
            io = itfs.get(if_idx)
            if r not in ["UPLINK", "INTERCONNECT"] and not (io and io.is_uplink):
                access_locations.append((sw_id, if_idx))

        unique_locations = list(set(access_locations))
        if len(unique_locations) > 1:
            event_key = f"MAC_DRIFT:{clean_mac}"
            loc_str = ", ".join([f"[SW:{s}, Port:{i}]" for s, i in unique_locations])
            self._trigger_or_update_event(
                event_key=event_key,
                event_type="MAC_DRIFT",
                severity="MEDIUM",
                title=f"偵測到 MAC 位址漂移: {clean_mac}",
                description=f"裝置 MAC {clean_mac} 在多個非骨幹接入埠被同時觀測到: {loc_str}。",
                evidence_data={
                    "evidence_type": "FDB_DRIFT",
                    "client_mac": clean_mac,
                    "raw_details": f"Locations: {loc_str}"
                }
            )
            return True
        return False

    def check_n07_ip_conflict(self) -> int:
        """N07: IP 位址衝突檢測"""
        conflicts = self.repo.get_ip_conflict_report()
        triggered_count = 0
        for c in conflicts:
            ip = c["ip"]
            conflicting_macs = c["conflicting_macs"]
            event_key = f"IP_CONFLICT:{ip}"
            
            self._trigger_or_update_event(
                event_key=event_key,
                event_type="IP_CONFLICT",
                severity="HIGH",
                title=f"偵測到 IP 位址衝突: {ip}",
                description=f"IP 位址 {ip} 被多個不同的 MAC 位址 ({conflicting_macs}) 同時共用或輪流使用。",
                evidence_data={
                    "evidence_type": "DHCP_CONFLICT",
                    "assigned_ip": ip,
                    "raw_details": f"Conflicting MACs: {conflicting_macs}"
                }
            )
            triggered_count += 1
        return triggered_count

    def check_n08_verification_mismatch(
        self,
        mac: str,
        expected_switch_id: int,
        expected_if_index: int,
        actual_switch_id: int,
        actual_if_index: int,
        note: str = ""
    ) -> bool:
        """N08: 人工驗證位置不符檢測 (網管實機驗證位置與系統觀測不一致時觸發)"""
        clean_mac = mac.upper()
        event_key = f"VERIFICATION_CONFLICT:{clean_mac}"
        
        self._trigger_or_update_event(
            event_key=event_key,
            event_type="VERIFICATION_CONFLICT",
            severity="MEDIUM",
            title=f"人工驗證位置不符 (衝突): {clean_mac}",
            description=f"網管實機驗證之實際位置 [SW:{actual_switch_id}, Port:{actual_if_index}] 與系統觀測位置 [SW:{expected_switch_id}, Port:{expected_if_index}] 不一致。",
            evidence_data={
                "evidence_type": "VERIFICATION_MISMATCH",
                "client_mac": clean_mac,
                "raw_details": f"Expected [SW:{expected_switch_id}, Port:{expected_if_index}] vs Actual [SW:{actual_switch_id}, Port:{actual_if_index}]. Note: {note}"
            }
        )
        return True

    def check_n09_topology_change(self, local_sw_id: int, local_if_index: int, change_type: str, details: str) -> bool:
        """N09: 拓樸異動檢測 (交換器鄰居關係新增、消失或變更)"""
        event_key = f"TOPOLOGY_CHANGE:{local_sw_id}:{local_if_index}"
        self._trigger_or_update_event(
            event_key=event_key,
            event_type="TOPOLOGY_CHANGE",
            severity="LOW",
            title=f"交換器拓樸異動: SW-{local_sw_id} Port-{local_if_index}",
            description=f"交換器主幹互聯關係發生變動 ({change_type}): {details}",
            evidence_data={
                "evidence_type": "TOPOLOGY_EVENT",
                "raw_details": f"Switch: {local_sw_id}, Port: {local_if_index}, Change: {change_type}, Details: {details}"
            }
        )
        return True

    def resolve_event_by_key(self, event_key: str, note: str = "狀況已自動排除") -> None:
        """將指定事件自動標記為 RESOLVED"""
        now = datetime.now()
        with self.repo.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE alert_events
                SET status = 'RESOLVED', resolved_at = ?, resolution_note = ?
                WHERE event_key = ? AND status != 'RESOLVED'
            """, (now, note, event_key))


