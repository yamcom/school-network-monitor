"""Switch SNMP Polling Collector."""

from __future__ import annotations
import logging
import time
from datetime import datetime
from typing import List
from network_monitor.config import SwitchItemConfig
from network_monitor.models import SwitchInfo
from network_monitor.snmp.adapters.vendor_specific import get_adapter
from network_monitor.snmp.client import SNMPClient
from network_monitor.storage.repository import NetworkRepository
from network_monitor.topology.interface_mapper import InterfaceMapper

logger = logging.getLogger("network_monitor.snmp.collector")


class SNMPCollector:
    def __init__(self, repo: NetworkRepository, client_factory=SNMPClient):
        self.repo = repo
        self.client_factory = client_factory

    def poll_switch(self, sw_cfg: SwitchItemConfig, global_snmp_cfg) -> bool:
        if not sw_cfg.enabled:
            logger.info(f"Skipping disabled switch {sw_cfg.name} ({sw_cfg.management_ip})")
            return False

        logger.info(f"Polling switch {sw_cfg.name} [{sw_cfg.management_ip}]...")

        version = sw_cfg.snmp_version or global_snmp_cfg.version
        client = self.client_factory(
            ip=sw_cfg.management_ip,
            version=version,
            timeout=global_snmp_cfg.timeout_seconds,
            retries=global_snmp_cfg.retries,
            community=sw_cfg.community or global_snmp_cfg.v2_community,
            v3_user=sw_cfg.v3_user or global_snmp_cfg.v3_user,
            v3_auth_key=sw_cfg.v3_auth_key or global_snmp_cfg.v3_auth_key,
            v3_auth_proto=global_snmp_cfg.v3_auth_proto,
            v3_priv_key=sw_cfg.v3_priv_key or global_snmp_cfg.v3_priv_key,
            v3_priv_proto=global_snmp_cfg.v3_priv_proto,
        )

        dummy_info = SwitchInfo(
            switch_id=None,
            management_ip=sw_cfg.management_ip,
            sys_name=sw_cfg.name,
            vendor=sw_cfg.vendor,
            model=sw_cfg.model,
            sys_descr=None,
            last_poll_time=None,
        )

        adapter_cls = get_adapter(sw_cfg.adapter)
        adapter = adapter_cls(client, dummy_info)

        try:
            sys_name, sys_descr, sys_obj_id = adapter.fetch_system_info()
            if not sys_name and not sys_descr:
                raise ConnectionError(f"No response from switch {sw_cfg.management_ip}")

            switch_rec = SwitchInfo(
                switch_id=None,
                management_ip=sw_cfg.management_ip,
                sys_name=sys_name or sw_cfg.name,
                vendor=sw_cfg.vendor,
                model=sw_cfg.model,
                sys_descr=sys_descr,
                last_poll_time=datetime.now(),
                poll_status="online",
            )
            switch_id = self.repo.upsert_switch(switch_rec)
            adapter.switch_info.switch_id = switch_id

            interfaces = adapter.fetch_interfaces()
            for intf in interfaces:
                intf.switch_id = switch_id
                if intf.if_name in sw_cfg.uplink_ports or str(intf.if_index) in sw_cfg.uplink_ports:
                    intf.is_uplink = True

            self.repo.save_interfaces(interfaces)

            fdb_entries = adapter.fetch_fdb()
            for f in fdb_entries:
                f.switch_id = switch_id

            mapper = InterfaceMapper(interfaces)
            mapped_fdb = mapper.map_fdb_entries(fdb_entries)

            self.repo.replace_fdb_snapshot(switch_id, mapped_fdb)
            logger.info(
                f"Successfully polled {sw_cfg.name}: {len(interfaces)} interfaces, {len(mapped_fdb)} FDB entries."
            )
            return True

        except Exception as e:
            logger.error(f"Failed to poll switch {sw_cfg.name} ({sw_cfg.management_ip}): {e}")
            fail_info = SwitchInfo(
                switch_id=None,
                management_ip=sw_cfg.management_ip,
                sys_name=sw_cfg.name,
                vendor=sw_cfg.vendor,
                model=sw_cfg.model,
                sys_descr=None,
                last_poll_time=datetime.now(),
                poll_status="error",
            )
            self.repo.upsert_switch(fail_info)
            return False

    def poll_all(self, switches_cfg: List[SwitchItemConfig], global_snmp_cfg) -> int:
        success = 0
        for sw in switches_cfg:
            if self.poll_switch(sw, global_snmp_cfg):
                success += 1
                time.sleep(0.1)  # 讓 Windows 底層 Winsock 完整回收已關閉的 Socket
        return success