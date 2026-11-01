"""Continuous monitoring background loop and health tracking service (MVP-07.3)."""

from __future__ import annotations
import logging
import signal
import time
from datetime import datetime
from typing import Any, List, Dict

from network_monitor.config import Settings
from network_monitor.storage.repository import NetworkRepository
from network_monitor.snmp.collector import SNMPCollector
from network_monitor.snmp.neighbor_collector import NeighborCollector
from network_monitor.topology.engine import TopologyEngine
from network_monitor.anomaly.engine import AnomalyEngine
from network_monitor.dhcp.listener import DHCPListener

logger = logging.getLogger("network_monitor.monitor.service")


class MonitorService:
    def __init__(self, settings: Settings, repo: NetworkRepository) -> None:
        self.settings = settings
        self.repo = repo
        self.collector = SNMPCollector(repo)
        self.neighbor_collector = NeighborCollector(repo)
        self.topo_engine = TopologyEngine(repo)
        self.anomaly_engine = AnomalyEngine(repo)

        self._stop_requested = False
        self.listener: Any = None
        self.snmp_fail_counts: Dict[str, int] = {}

    def _setup_signal_handlers(self) -> None:
        def _handle_stop(signum, frame):
            logger.info("收到終止訊號，準備安全停止持續監控服務...")
            self._stop_requested = True

        signal.signal(signal.SIGINT, _handle_stop)
        signal.signal(signal.SIGTERM, _handle_stop)

    def _on_dhcp_packet(self, event: Any) -> None:
        """處理即時 DHCP 封包事件並即時觸發 N01 / N02 異常規則檢測"""
        try:
            self.repo.record_dhcp_event(event)
            authorized = getattr(self.settings.dhcp, "authorized_servers", ["192.69.1.9", "192.69.1.254", "192.69.6.41", "192.69.6.101"])
            scope_rules = getattr(self.settings.dhcp, "scope_rules", [])

            # N01: 未授權 DHCP Server
            self.anomaly_engine.check_n01_unauthorized_dhcp(event, authorized)
            # N02: DHCP Scope 不符
            self.anomaly_engine.check_n02_scope_mismatch(event, scope_rules)

            self.repo.record_monitoring_health("DHCP_LISTENER", "RUNNING")
        except Exception as e:
            logger.error(f"DHCP 封包處理或異常檢測例外: {e}")
            self.repo.record_monitoring_health("DHCP_LISTENER", "ERROR", str(e))

    def _run_snmp_cycle(self) -> None:
        """執行 SNMP 交換器輪詢與 N03 設備失聯檢測"""
        logger.info("開始執行週期性 SNMP 交換器輪詢與狀態檢查...")
        enabled_switches = [sw for sw in self.settings.switches if sw.enabled]

        for sw in enabled_switches:
            success = False
            try:
                success = self.collector.poll_switch(sw, self.settings.snmp)
            except Exception as e:
                logger.error(f"交換器 {sw.name} ({sw.management_ip}) 輪詢發生例外: {e}")

            if success:
                self.snmp_fail_counts[sw.management_ip] = 0
                # 若之前有失聯告警，自動解除
                self.anomaly_engine.check_n03_snmp_down(sw.management_ip, 0)
            else:
                self.snmp_fail_counts[sw.management_ip] = self.snmp_fail_counts.get(sw.management_ip, 0) + 1
                self.anomaly_engine.check_n03_snmp_down(
                    switch_ip=sw.management_ip,
                    consecutive_failures=self.snmp_fail_counts[sw.management_ip],
                    threshold=3
                )

        self.repo.record_monitoring_health("SNMP_COLLECTOR", "RUNNING")

    def _run_fdb_device_scan(self) -> None:
        """掃描 FDB 轉發表並執行 N04 未登錄設備、N05 MAC 漂移與 N07 IP 衝突檢查"""
        try:
            switches = self.repo.list_switches()
            for sw in switches:
                if not sw.switch_id:
                    continue
                intfs = self.repo.get_interfaces(sw.switch_id)
                for if_idx, intf_obj in intfs.items():
                    role = self.repo.get_port_role(sw.switch_id, if_idx)
                    is_uplink = intf_obj.is_uplink or (role in ["UPLINK", "INTERCONNECT"])
                    
                    with self.repo.db.conn() as conn:
                        cur = conn.cursor()
                        cur.execute("SELECT mac FROM fdb_entries WHERE switch_id = ? AND if_index = ?", (sw.switch_id, if_idx))
                        for row in cur.fetchall():
                            mac = row["mac"]
                            # N04: 未登錄設備檢查 (排除 Uplink 埠)
                            if not is_uplink:
                                self.anomaly_engine.check_n04_unregistered_device(
                                    mac=mac,
                                    switch_id=sw.switch_id,
                                    if_index=if_idx,
                                    is_uplink=False
                                )
                            # N05: MAC 位址漂移檢查 (結合拓樸判定)
                            self.anomaly_engine.check_n05_mac_drift(mac, sw.switch_id, if_idx)

            # N07: IP 衝突檢測
            self.anomaly_engine.check_n07_ip_conflict()

            self.repo.record_monitoring_health("ANOMALY_ENGINE", "RUNNING")
        except Exception as e:
            logger.error(f"FDB 掃描與進階異常檢測例外: {e}")
            self.repo.record_monitoring_health("ANOMALY_ENGINE", "ERROR", str(e))

    def start(self) -> None:
        """啟動常駐監控循環"""
        self._setup_signal_handlers()

        # 啟動 DHCP 監聽器
        if getattr(self.settings.capture, "enabled", False):
            try:
                self.listener = DHCPListener(
                    interface=getattr(self.settings.capture, "interface", None),
                    bpf_filter=getattr(self.settings.capture, "filter", "udp and (port 67 or 68)"),
                    callback=self._on_dhcp_packet,
                )
                self.listener.start()
                self.repo.record_monitoring_health("DHCP_LISTENER", "RUNNING")
                logger.info("DHCP 被動監聽器已順利啟動。")
            except Exception as e:
                logger.error(f"啟動 DHCP 監聽器失敗: {e}")
                self.repo.record_monitoring_health("DHCP_LISTENER", "ERROR", str(e))

        poll_interval = getattr(self.settings.snmp, "poll_interval_seconds", 300)
        last_poll = 0.0

        logger.info(f"🚀 校園網路持續監控服務已啟動（輪詢週期: {poll_interval} 秒），按 Ctrl+C 可安全停止。")

        try:
            while not self._stop_requested:
                now = time.time()
                if now - last_poll >= poll_interval:
                    self._run_snmp_cycle()
                    self._run_fdb_device_scan()
                    last_poll = now

                time.sleep(1.0)
        finally:
            if self.listener:
                self.listener.stop()
                self.repo.record_monitoring_health("DHCP_LISTENER", "STOPPED")
            self.repo.record_monitoring_health("SNMP_COLLECTOR", "STOPPED")
            self.repo.record_monitoring_health("ANOMALY_ENGINE", "STOPPED")
            logger.info("持續監控服務已完全停止。")

