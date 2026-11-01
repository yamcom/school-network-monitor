"""LLDP neighbor discovery collector using asynchronous SNMPClient with list-compatible parsing."""

from __future__ import annotations
import logging
import asyncio
from typing import List, Dict, Any
from network_monitor.snmp.client import SNMPClient

logger = logging.getLogger("network_monitor.snmp.neighbor_collector")

LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_PORT_ID  = "1.0.8802.1.1.2.1.4.1.1.7"


class NeighborCollector:
    def __init__(self, repo) -> None:
        self.repo = repo

    def poll_lldp_neighbors(self, sw: Any, snmp_settings: Any) -> List[Dict[str, Any]]:
        """利用專案標準的非同步 SNMPClient 讀取 LLDP 鄰居資訊"""
        neighbors = []
        try:
            version = getattr(sw, "snmp_version", None) or getattr(snmp_settings, "version", 2)
            community = getattr(sw, "community", None) or getattr(snmp_settings, "v2_community", "public")
            
            client = SNMPClient(
                ip=sw.management_ip,
                version=version,
                timeout=getattr(snmp_settings, "timeout_seconds", 3),
                retries=getattr(snmp_settings, "retries", 1),
                community=community,
            )

            async def _async_fetch():
                sys_names = await client.walk(LLDP_REM_SYS_NAME)
                port_ids = await client.walk(LLDP_REM_PORT_ID)
                return sys_names, port_ids

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    sys_names, port_ids = pool.submit(asyncio.run, _async_fetch()).result()
            else:
                sys_names, port_ids = asyncio.run(_async_fetch())

            # 確保回傳為 list 結構，並建立以 OID 為 key 的字典對應
            sys_dict = {}
            if isinstance(sys_names, list):
                for item in sys_names:
                    if isinstance(item, tuple) and len(item) >= 2:
                        sys_dict[str(item[0])] = str(item[1])
            elif isinstance(sys_names, dict):
                sys_dict = {str(k): str(v) for k, v in sys_names.items()}

            port_dict = {}
            if isinstance(port_ids, list):
                for item in port_ids:
                    if isinstance(item, tuple) and len(item) >= 2:
                        port_dict[str(item[0])] = str(item[1])
            elif isinstance(port_ids, dict):
                port_dict = {str(k): str(v) for k, v in port_ids.items()}

            for oid, rem_name in sys_dict.items():
                parts = oid.split(".")
                local_port_num = int(parts[-2]) if len(parts) >= 2 else 0
                rem_port = port_dict.get(oid, "")

                existing = next((n for n in neighbors if n["local_port"] == local_port_num), None)
                if not existing:
                    existing = {
                        "protocol": "LLDP",
                        "local_port": local_port_num,
                        "remote_device_name": rem_name.strip(),
                        "remote_port_id": rem_port.strip()
                    }
                    neighbors.append(existing)

        except Exception as e:
            logger.warning(f"交換器 {sw.management_ip} 抓取 LLDP 發生例外: {e}")
            
        return neighbors