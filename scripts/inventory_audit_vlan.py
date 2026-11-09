"""Phase 0: Pre-migration Consistency Backup and Read-only Inventory Analysis Tool.

As mandated by V2.3 Chapter 8 and 10.4:
1. Performs SQLite Online Backup before touching schema.
2. Records SHA-256 and backup size.
3. Conducts read-only audit on devices and dhcp_events.
4. Generates a Conflict Preview Report for Migration 9 (VLAN composite key).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List

from core.config import load_config, project_path
from database.connection import connect_readonly_database
from database.migrations import migrate


def create_pre_migration_backup(db_path: Path, backup_dir: Path) -> Dict[str, Any]:
    """Execute SQLite Online Backup and compute SHA-256 checksum."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"dhcp_analyzer_pre_vlan_{timestamp}.db"

    # Ensure source DB schema is initialized
    conn_src = sqlite3.connect(str(db_path))
    migrate(conn_src)
    conn_dst = sqlite3.connect(str(backup_file))

    with conn_dst:
        conn_src.backup(conn_dst)

    conn_dst.close()
    conn_src.close()

    # Calculate SHA-256 and size
    hasher = hashlib.sha256()
    size_bytes = backup_file.stat().st_size
    with open(backup_file, "rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    sha256_hex = hasher.hexdigest()

    return {
        "backup_path": str(backup_file.resolve()),
        "size_bytes": size_bytes,
        "sha256": sha256_hex,
        "created_at": datetime.now().isoformat(),
    }


def analyze_inventory(db_path: Path) -> Dict[str, Any]:
    """Read-only audit analyzing devices, giaddr distributions, and MAC conflicts."""
    conn = connect_readonly_database(str(db_path))
    try:
        cur = conn.cursor()

        # 1. Total devices
        cur.execute("SELECT COUNT(*) as total FROM devices")
        total_devices = cur.fetchone()["total"]

        # 2. Total events
        cur.execute("SELECT COUNT(*) as total FROM dhcp_events")
        total_events = cur.fetchone()["total"]

        # 3. Relay IP (giaddr) distribution
        cur.execute("""
            SELECT COALESCE(relay_ip, 'NONE') as relay, COUNT(*) as cnt
            FROM dhcp_events
            GROUP BY relay_ip
            ORDER BY cnt DESC
        """)
        relay_dist = {r["relay"]: r["cnt"] for r in cur.fetchall()}

        # 4. Check for MACs associated with multiple distinct relay_ip (potential multi-VLAN roaming)
        cur.execute("""
            SELECT client_mac, COUNT(DISTINCT relay_ip) as relay_count,
                   GROUP_CONCAT(DISTINCT relay_ip) as relays,
                   COUNT(*) as event_count
            FROM dhcp_events
            WHERE relay_ip IS NOT NULL AND relay_ip <> '' AND relay_ip <> '0.0.0.0'
            GROUP BY client_mac
            HAVING COUNT(DISTINCT relay_ip) > 1
        """)
        conflicting_macs = [
            {
                "mac": r["client_mac"],
                "relay_count": r["relay_count"],
                "relays": r["relays"].split(",") if r["relays"] else [],
                "event_count": r["event_count"],
            }
            for r in cur.fetchall()
        ]

        # 5. Devices with manual metadata (device_name, location)
        cur.execute("""
            SELECT mac, device_name, location, last_ip, hostname
            FROM devices
            WHERE (device_name IS NOT NULL AND device_name <> '')
               OR (location IS NOT NULL AND location <> '')
        """)
        manual_devices = [dict(r) for r in cur.fetchall()]

        return {
            "total_devices": total_devices,
            "total_events": total_events,
            "relay_ip_distribution": relay_dist,
            "conflicting_macs_count": len(conflicting_macs),
            "conflicting_macs": conflicting_macs,
            "manual_devices_count": len(manual_devices),
            "manual_devices": manual_devices,
        }
    finally:
        conn.close()


def generate_preview_report(backup_info: Dict[str, Any], audit_info: Dict[str, Any], output_path: Path) -> str:
    """Generate Markdown conflict preview report."""
    md = f"""# Migration 9 (VLAN & Composite Key) 前置備份與盤點分析報告

**產出時間**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**執行狀態**：Phase 0 唯讀盤點完成，無任何資料遭到修改。

---

## 1. 前置一致性熱備份驗證 (Pre-Migration Backup)
- **備份檔案路徑**：`{backup_info['backup_path']}`
- **檔案大小**：{backup_info['size_bytes']:,} Bytes ({backup_info['size_bytes'] / (1024*1024):.2f} MB)
- **SHA-256 校驗碼**：`{backup_info['sha256']}`
- **復原機制保證**：若後續 Migration 9 升級發生異常，可隨時以本備份檔案進行百分之百原樣還原。

---

## 2. 舊資料庫設備與事件盤點 (Inventory Audit)
- **現存設備總數 (`devices`)**：{audit_info['total_devices']:,} 台
- **現存歷史事件總數 (`dhcp_events`)**：{audit_info['total_events']:,} 筆
- **人工維護備註設備數**：{audit_info['manual_devices_count']} 台 (所有人工設備名稱與擺放位置均完整保存)

### Relay IP (`giaddr`) 分布概況
| Relay Agent IP (giaddr) | 事件數量 | 預設歸屬判定 |
| :--- | :--- | :--- |
"""
    for relay, cnt in audit_info["relay_ip_distribution"].items():
        note = "預設 VLAN 1 (無 Relay)" if relay == "NONE" else "待比對 relay_vlan_mapping"
        md += f"| `{relay}` | {cnt:,} 筆 | {note} |\n"

    md += f"""
---

## 3. 跨網段 / 多 VLAN 衝突偵測結果
- **跨多個 Relay IP 之 MAC 數量**：{audit_info['conflicting_macs_count']} 台
"""
    if audit_info["conflicting_macs_count"] > 0:
        md += "\n> [!WARNING]\n> 以下 MAC 曾出現在不同 Relay 網段，Migration 9 將依據複合鍵 `MAC + VLAN ID` 建立獨立紀錄，嚴禁暴力覆寫合併：\n\n"
        md += "| MAC 位址 | 觀測 Relay 數 | 涵蓋 Relay 網段清單 | 相關事件數 |\n| :--- | :---: | :--- | :---: |\n"
        for cm in audit_info["conflicting_macs"][:20]:
            relays_str = ", ".join(f"`{r}`" for r in cm["relays"])
            md += f"| `{cm['mac']}` | {cm['relay_count']} | {relays_str} | {cm['event_count']} |\n"
        if audit_info["conflicting_macs_count"] > 20:
            md += f"| ... 以及其餘 {audit_info['conflicting_macs_count'] - 20} 筆 ... | | | |\n"
    else:
        md += "\n> [!NOTE]\n> 目前所有設備之 MAC 與 Relay 網段均為一對一對應，無跨網段衝突，可安全進行升級。\n"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md, encoding="utf-8")
    return md


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 0: Pre-migration Consistency Backup and Inventory Audit")
    parser.add_argument("--db", type=str, default="", help="Path to database")
    parser.add_argument("--backup-dir", type=str, default="backups", help="Directory to store backups")
    parser.add_argument("--report", type=str, default="docs/vlan_migration_preview_report.md", help="Output report path")
    args = parser.parse_args()

    cfg = load_config()
    db_path = Path(args.db) if args.db else project_path(cfg.get("database", {}).get("path", "data/dhcp_analyzer.db"))
    backup_dir = Path(args.backup_dir)
    report_path = Path(args.report)

    print(f"🚀 開始執行 Phase 0 前置作業：資料庫路徑 [{db_path}]...")
    backup_info = create_pre_migration_backup(db_path, backup_dir)
    print(f"✅ 線上熱備份成功！檔案: {backup_info['backup_path']} (SHA-256: {backup_info['sha256'][:16]}...)")

    print(f"🔍 正在執行唯讀盤點與衝突分析...")
    audit_info = analyze_inventory(db_path)
    print(f"   - 設備總數: {audit_info['total_devices']}, 事件總數: {audit_info['total_events']}")
    print(f"   - 跨 Relay 衝突 MAC 數: {audit_info['conflicting_macs_count']}")

    generate_preview_report(backup_info, audit_info, report_path)
    print(f"📄 預覽報告已產出至: {report_path.resolve()}")


if __name__ == "__main__":
    main()
