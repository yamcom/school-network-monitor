"""Topology resolver for MAC address location tracking."""

from __future__ import annotations
from typing import List, Tuple, Optional
from ..models import DeviceLocation, ResolutionStatus
from ..storage.repository import NetworkRepository


class TopologyResolver:
    def __init__(self, repo: NetworkRepository):
        self.repo = repo

    def resolve_mac(self, mac: str) -> DeviceLocation:
        clean_mac = mac.upper()
        
        # 1. 檢查是否有管理員實機驗證記錄（已驗證狀態）
        verification = self.repo.get_latest_verification(clean_mac)
        if verification and verification.is_match:
            switches = {s.switch_id: s for s in self.repo.list_switches() if s.switch_id}
            sw = switches.get(verification.actual_switch_id)
            sw_name = sw.sys_name if sw else str(verification.actual_switch_id)
            return DeviceLocation(
                mac=clean_mac,
                switch_id=verification.actual_switch_id,
                if_index=verification.actual_if_index,
                confidence=1.0,
                resolution_status=ResolutionStatus.VERIFIED,
                reason=f"Manually verified by admin on {verification.verified_at} (Note: {verification.note})",
                candidates_count=1
            )

        # 2. 取得 FDB 候選與交換器介面
        fdb_entries = self.repo.get_fdb_for_mac(clean_mac)
        if not fdb_entries:
            return DeviceLocation(
                mac=clean_mac,
                confidence=0.0,
                resolution_status=ResolutionStatus.UNRESOLVED,
                reason="No FDB entries found for this MAC address."
            )

        access_candidates = []
        all_candidates_count = len(fdb_entries)

        for entry in fdb_entries:
            if not entry.switch_id or not entry.if_index:
                continue
            interfaces = self.repo.get_interfaces(entry.switch_id)
            intf = interfaces.get(entry.if_index)
            
            is_uplink = intf.is_uplink if intf else False
            if not is_uplink:
                access_candidates.append((entry, intf))

        if not access_candidates:
            return DeviceLocation(
                mac=clean_mac,
                confidence=0.2,
                resolution_status=ResolutionStatus.CANDIDATE,
                reason="MAC detected only on uplink/trunk ports. Unable to determine edge access port.",
                candidates_count=all_candidates_count
            )

        if len(access_candidates) == 1:
            entry, intf = access_candidates[0]
            intf_label = intf.if_name if intf and intf.if_name else f"Index-{entry.if_index}"
            return DeviceLocation(
                mac=clean_mac,
                switch_id=entry.switch_id,
                if_index=entry.if_index,
                confidence=0.8,  # MVP-03.1: 程式推導未經驗證前設為 80% (Candidate)
                resolution_status=ResolutionStatus.CANDIDATE,
                reason=f"Single edge access port match on interface {intf_label} (Inferred, pending physical verification)",
                candidates_count=all_candidates_count
            )

        # 多個候選接入埠
        candidate_labels = []
        for entry, intf in access_candidates:
            sw_map = {s.switch_id: s.sys_name for s in self.repo.list_switches() if s.switch_id}
            sw_name = sw_map.get(entry.switch_id, f"SW-{entry.switch_id}")
            i_name = intf.if_name if intf and intf.if_name else f"Index-{entry.if_index}"
            candidate_labels.append(f"[{sw_name} Intf {i_name}]")

        return DeviceLocation(
            mac=clean_mac,
            switch_id=access_candidates[0][0].switch_id,
            if_index=access_candidates[0][0].if_index,
            confidence=0.5,
            resolution_status=ResolutionStatus.CANDIDATE,
            reason=f"Multiple access port candidates detected: {', '.join(candidate_labels)}",
            candidates_count=all_candidates_count
        )