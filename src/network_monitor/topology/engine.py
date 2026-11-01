"""Topology reconciliation and MAC path trace engine."""

from __future__ import annotations
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models import PortRole, LinkConfidence, normalize_mac
from ..storage.repository import NetworkRepository


class TopologyEngine:
    def __init__(self, repo: NetworkRepository) -> None:
        self.repo = repo

    def reconcile_topology(self) -> Dict[str, int]:
        """
        整合 LLDP/CDP 觀測紀錄，建立交換器互聯拓樸表 (topology_links)，
        並自動更新 switch_port_roles (UPLINK / ACCESS)。
        """
        switches = self.repo.list_switches()
        sw_map_by_ip = {s.management_ip: s for s in switches if s.switch_id}
        sw_map_by_name = {s.sys_name.lower(): s for s in switches if s.switch_id and s.sys_name}

        observations = self.repo.list_all_topology_observations()
        stats = {"created": 0, "verified_links": 0, "conflicts": 0}

        # 暫存各埠由鄰居通告推導出的角色
        port_role_updates = []

        for obs in observations:
            local_sw_id = obs["switch_id"]
            local_if_index = obs["if_index"]
            rem_name = obs["remote_device_name"] or ""
            rem_ip = obs["remote_mgmt_ip"] or ""
            rem_port = obs["remote_port_id"] or obs["remote_port_desc"] or ""

            # 嘗試比對對端是否為本校已列管交換器
            target_remote_sw = None
            if rem_ip in sw_map_by_ip:
                target_remote_sw = sw_map_by_ip[rem_ip]
            elif rem_name.lower() in sw_map_by_name:
                target_remote_sw = sw_map_by_name[rem_name.lower()]

            remote_sw_id = target_remote_sw.switch_id if target_remote_sw else None

            # 檢查是否存在反向觀測（雙端一致性檢查）
            is_bidirectional = False
            confidence = LinkConfidence.HIGH if remote_sw_id else LinkConfidence.MEDIUM

            if remote_sw_id:
                reverse_obs = self.repo.find_topology_observation(
                    switch_id=remote_sw_id,
                    remote_device_name=sw_map_by_ip.get(obs.get("local_sw_ip", "")).sys_name if obs.get("local_sw_ip") in sw_map_by_ip else None
                )
                if reverse_obs:
                    is_bidirectional = True
                    confidence = LinkConfidence.VERIFIED
                    stats["verified_links"] += 1

            self.repo.upsert_topology_link(
                local_sw_id=local_sw_id,
                local_if_index=local_if_index,
                remote_sw_id=remote_sw_id,
                remote_sw_name=rem_name,
                remote_mgmt_ip=rem_ip,
                remote_if_name=rem_port,
                protocol=obs["protocol"],
                confidence=confidence,
                is_bidirectional=is_bidirectional
            )
            stats["created"] += 1

            # 若該埠已確認連接至另一台交換器，自動賦予 UPLINK / INTERCONNECT 角色
            port_role_updates.append((local_sw_id, local_if_index, PortRole.UPLINK.value, "LLDP_CDP"))

        # 批次更新介面角色
        for sw_id, if_idx, role, src in port_role_updates:
            self.repo.set_port_role(sw_id, if_idx, role, src)

        return stats

    def trace_mac_path(self, mac: str) -> Dict[str, Any]:
        """
        核心演算法：沿著拓樸關係分析 MAC 在各交換器間的學習路徑。
        - 排除已確認的 UPLINK / DOWNLINK 互聯埠。
        - 若 MAC 僅在接取交換器的 ACCESS 埠出現，判定為直接終端設備。
        - 若核心交換器與邊緣交換器同時學到，保留路徑並指向末端邊緣埠。
        """
        clean_mac = normalize_mac(mac)
        fdb_entries = self.repo.get_fdb_for_mac(clean_mac)
        switches_map = {s.switch_id: s for s in self.repo.list_switches() if s.switch_id}

        if not fdb_entries:
            return {
                "mac": clean_mac,
                "status": "UNRESOLVED",
                "final_location": None,
                "path_nodes": [],
                "reason": "在所有交換器的 FDB 表格中均未發現此 MAC 位址。"
            }

        path_nodes = []
        candidate_edge_ports = []

        for entry in fdb_entries:
            sw = switches_map.get(entry.switch_id)
            sw_name = sw.sys_name if sw else f"SW-{entry.switch_id}"
            intfs = self.repo.get_interfaces(entry.switch_id) if entry.switch_id else {}
            i_obj = intfs.get(entry.if_index) if entry.if_index else None
            port_name = i_obj.if_name if i_obj else str(entry.if_index)

            # 查詢該埠在拓樸中的角色
            role = self.repo.get_port_role(entry.switch_id, entry.if_index)

            node_info = {
                "switch_id": entry.switch_id,
                "switch_name": sw_name,
                "switch_ip": sw.management_ip if sw else "N/A",
                "port_name": port_name,
                "if_index": entry.if_index,
                "port_role": role,
                "last_seen": entry.last_seen,
                "vlan_id": entry.vlan_id,
            }
            path_nodes.append(node_info)

            # 若非上行/主幹互聯埠，視為潛在末端接取埠（Access Port）
            if role not in [PortRole.UPLINK.value, PortRole.INTERCONNECT.value] and not (i_obj and i_obj.is_uplink):
                candidate_edge_ports.append(node_info)

        # 評估最終定位
        if len(candidate_edge_ports) == 1:
            final_loc = candidate_edge_ports[0]
            status = "CONFIRMED"
            reason = f"已排除上行鏈路，精確定位於接取交換器 {final_loc['switch_name']} 之 Access 埠 {final_loc['port_name']}。"
        elif len(candidate_edge_ports) > 1:
            final_loc = candidate_edge_ports[0]
            status = "CONFLICT"
            reason = f"在多台交換器的非上行連接埠同時觀測到該 MAC（可能存在未記錄的 Dumb Switch 或線路迴圈）。"
        else:
            final_loc = path_nodes[0] if path_nodes else None
            status = "INFERRED_CORE_ONLY"
            reason = "該 MAC 僅出現在交換器之上行或骨幹互聯埠，下游交換器 FDB 可能已老化或未轉發。"

        return {
            "mac": clean_mac,
            "status": status,
            "final_location": final_loc,
            "path_nodes": path_nodes,
            "reason": reason
        }