"""Neighbor discovery collector using asynchronous/synchronous SNMPClient supporting both LLDP and FDP."""

from __future__ import annotations
import logging
import asyncio
from typing import List, Dict, Any, Optional
from network_monitor.snmp.client import SNMPClient

logger = logging.getLogger("network_monitor.snmp.neighbor_collector")

# Standard LLDP-MIB OIDs
LLDP_REM_SYS_NAME    = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_PORT_ID     = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC   = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_DESC    = "1.0.8802.1.1.2.1.4.1.1.10"
LLDP_REM_CHASSIS_ID  = "1.0.8802.1.1.2.1.4.1.1.5"

# Foundry/Brocade/Ruckus FDP MIB (FOUNDRY-SN-SWITCH-GROUP-MIB) OIDs
FDP_CACHE_IF_INDEX    = "1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.1"
FDP_CACHE_DEVICE_ID   = "1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.3"
FDP_CACHE_ADDRESS     = "1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.5"
FDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.7"
FDP_CACHE_PLATFORM    = "1.3.6.1.4.1.1991.1.1.3.20.1.2.1.1.8"


def _format_ip_address(val: Any) -> str:
    """Format raw SNMP IP address value (IpAddress, octets or string) to standard dotted IPv4."""
    if not val:
        return ""
    val_str = str(val).strip()
    if "." in val_str and all(part.isdigit() and 0 <= int(part) <= 255 for part in val_str.split(".")):
        return val_str
    
    # Handle hex representation e.g. 0xc0a80101 or raw bytes
    if isinstance(val, (bytes, bytearray)) and len(val) == 4:
        return ".".join(str(b) for b in val)
    if val_str.startswith("0x") and len(val_str) == 10:
        try:
            raw = bytes.fromhex(val_str[2:])
            if len(raw) == 4:
                return ".".join(str(b) for b in raw)
        except ValueError:
            pass
    return val_str


class NeighborCollector:
    def __init__(self, repo=None) -> None:
        self.repo = repo

    def _create_client(self, sw: Any, snmp_settings: Any) -> SNMPClient:
        version = getattr(sw, "snmp_version", None) or getattr(snmp_settings, "version", "2c")
        community = getattr(sw, "community", None) or getattr(snmp_settings, "v2_community", getattr(snmp_settings, "community", "public"))
        timeout = getattr(snmp_settings, "timeout_seconds", 3.0)
        retries = getattr(snmp_settings, "retries", 1)
        return SNMPClient(
            ip=sw.management_ip,
            version=str(version),
            timeout=timeout,
            retries=retries,
            community=community,
        )

    def _execute_walks(self, client: SNMPClient, oids: List[str]) -> List[List[Any]]:
        async def _fetch():
            tasks = [client.walk(oid) for oid in oids]
            return await asyncio.gather(*tasks, return_exceptions=True)

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, _fetch()).result()
        else:
            return asyncio.run(_fetch())

    def poll_lldp_neighbors(self, sw: Any, snmp_settings: Any) -> List[Dict[str, Any]]:
        """利用專案標準的非同步 SNMPClient 讀取 LLDP 鄰居資訊"""
        neighbors = []
        try:
            client = self._create_client(sw, snmp_settings)
            raw_results = self._execute_walks(client, [LLDP_REM_SYS_NAME, LLDP_REM_PORT_ID, LLDP_REM_PORT_DESC])
            sys_names = raw_results[0] if len(raw_results) > 0 and not isinstance(raw_results[0], Exception) else []
            port_ids = raw_results[1] if len(raw_results) > 1 and not isinstance(raw_results[1], Exception) else []
            port_descs = raw_results[2] if len(raw_results) > 2 and not isinstance(raw_results[2], Exception) else []

            def _extract_lldp_suffix(oid: str) -> str:
                # LLDP OID format: 1.0.8802.1.1.2.1.4.1.1.<col>.<suffix>
                # Prefix has 11 components (indices 0..10), suffix starts at index 11
                parts = oid.lstrip(".").split(".")
                return ".".join(parts[11:]) if len(parts) > 11 else oid

            sys_dict: Dict[str, str] = {
                _extract_lldp_suffix(str(item[0])): str(item[1])
                for item in sys_names if isinstance(item, tuple)
            }
            port_dict: Dict[str, str] = {
                _extract_lldp_suffix(str(item[0])): str(item[1])
                for item in port_ids if isinstance(item, tuple)
            }
            desc_dict: Dict[str, str] = {
                _extract_lldp_suffix(str(item[0])): str(item[1])
                for item in port_descs if isinstance(item, tuple)
            }

            for suffix, rem_name in sys_dict.items():
                parts = suffix.split(".")
                # Suffix format: {timeMark}.{localPortNum}.{remIndex}
                local_port_num = int(parts[-2]) if len(parts) >= 2 and parts[-2].isdigit() else 0
                rem_port = port_dict.get(suffix, desc_dict.get(suffix, ""))

                existing = next((n for n in neighbors if n["local_port"] == local_port_num), None)
                if not existing:
                    neighbors.append({
                        "protocol": "LLDP",
                        "local_port": local_port_num,
                        "local_if_index": local_port_num,
                        "remote_device_name": str(rem_name).strip(),
                        "remote_port_id": str(rem_port).strip(),
                        "remote_mgmt_ip": "",
                        "remote_platform": "",
                    })
        except Exception as e:
            logger.warning(f"交換器 {sw.management_ip} 抓取 LLDP 發生例外: {e}")

        return neighbors

    def poll_fdp_neighbors(self, sw: Any, snmp_settings: Any) -> List[Dict[str, Any]]:
        """利用 SNMPClient 讀取 Foundry / Brocade / Ruckus FDP 鄰居快取資訊 (snFdpCacheTable)"""
        neighbors = []
        try:
            client = self._create_client(sw, snmp_settings)
            raw_results = self._execute_walks(
                client,
                [FDP_CACHE_IF_INDEX, FDP_CACHE_DEVICE_ID, FDP_CACHE_DEVICE_PORT, FDP_CACHE_ADDRESS, FDP_CACHE_PLATFORM]
            )

            if_indices = raw_results[0] if len(raw_results) > 0 and not isinstance(raw_results[0], Exception) else []
            device_ids = raw_results[1] if len(raw_results) > 1 and not isinstance(raw_results[1], Exception) else []
            device_ports = raw_results[2] if len(raw_results) > 2 and not isinstance(raw_results[2], Exception) else []
            addresses = raw_results[3] if len(raw_results) > 3 and not isinstance(raw_results[3], Exception) else []
            platforms = raw_results[4] if len(raw_results) > 4 and not isinstance(raw_results[4], Exception) else []

            # 建立以 {ifIndex}.{devIndex} 為 key 的對應表
            def _extract_suffix(oid: str) -> str:
                parts = oid.split(".")
                return f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else oid

            dev_id_dict = { _extract_suffix(str(item[0])): str(item[1]) for item in device_ids if isinstance(item, tuple) }
            port_dict   = { _extract_suffix(str(item[0])): str(item[1]) for item in device_ports if isinstance(item, tuple) }
            addr_dict   = { _extract_suffix(str(item[0])): _format_ip_address(item[1]) for item in addresses if isinstance(item, tuple) }
            plat_dict   = { _extract_suffix(str(item[0])): str(item[1]) for item in platforms if isinstance(item, tuple) }

            for item in if_indices:
                if not isinstance(item, tuple):
                    continue
                oid_str = str(item[0])
                suffix = _extract_suffix(oid_str)
                try:
                    local_if = int(item[1])
                except (ValueError, TypeError):
                    parts = suffix.split(".")
                    local_if = int(parts[0]) if parts[0].isdigit() else 0

                rem_name = dev_id_dict.get(suffix, "").strip()
                rem_port = port_dict.get(suffix, "").strip()
                rem_ip   = addr_dict.get(suffix, "").strip()
                rem_plat = plat_dict.get(suffix, "").strip()

                if rem_name or rem_port or rem_ip:
                    neighbors.append({
                        "protocol": "FDP",
                        "local_port": local_if,
                        "local_if_index": local_if,
                        "remote_device_name": rem_name,
                        "remote_port_id": rem_port,
                        "remote_mgmt_ip": rem_ip,
                        "remote_platform": rem_plat,
                    })

            # 若 if_indices 為空，但 device_ids 有回傳，直接從 device_ids 的 suffix 提取 local_if
            if not neighbors and dev_id_dict:
                for suffix, rem_name in dev_id_dict.items():
                    parts = suffix.split(".")
                    local_if = int(parts[0]) if parts[0].isdigit() else 0
                    neighbors.append({
                        "protocol": "FDP",
                        "local_port": local_if,
                        "local_if_index": local_if,
                        "remote_device_name": rem_name.strip(),
                        "remote_port_id": port_dict.get(suffix, "").strip(),
                        "remote_mgmt_ip": addr_dict.get(suffix, "").strip(),
                        "remote_platform": plat_dict.get(suffix, "").strip(),
                    })

        except Exception as e:
            logger.warning(f"交換器 {sw.management_ip} 抓取 FDP 發生例外: {e}")

        return neighbors

    def poll_all_neighbors(self, sw: Any, snmp_settings: Any) -> List[Dict[str, Any]]:
        """同時輪詢 LLDP 與 FDP 鄰居，並在同一介面上自動去重合併。"""
        lldp_list = self.poll_lldp_neighbors(sw, snmp_settings)
        fdp_list = self.poll_fdp_neighbors(sw, snmp_settings)

        merged: Dict[int, Dict[str, Any]] = {}

        # 優先加入 LLDP 資訊
        for item in lldp_list:
            port = item.get("local_port") or item.get("local_if_index") or 0
            merged[port] = dict(item)

        # 融合 FDP 資訊
        for item in fdp_list:
            port = item.get("local_port") or item.get("local_if_index") or 0
            if port in merged:
                existing = merged[port]
                existing["protocol"] = f"{existing['protocol']}+FDP"
                if not existing.get("remote_mgmt_ip") and item.get("remote_mgmt_ip"):
                    existing["remote_mgmt_ip"] = item["remote_mgmt_ip"]
                if not existing.get("remote_platform") and item.get("remote_platform"):
                    existing["remote_platform"] = item["remote_platform"]
                if not existing.get("remote_device_name") and item.get("remote_device_name"):
                    existing["remote_device_name"] = item["remote_device_name"]
                if not existing.get("remote_port_id") and item.get("remote_port_id"):
                    existing["remote_port_id"] = item["remote_port_id"]
            else:
                merged[port] = dict(item)

        return list(merged.values())
