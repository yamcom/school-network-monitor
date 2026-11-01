import csv
import os
from pathlib import Path
import yaml

# 自動取得 CSV_toyaml.py 所在的目錄 (即 config 目錄)
SCRIPT_DIR = Path(__file__).resolve().parent

# 如果 CSV 在專案根目錄，或是直接放在 config 目錄下皆能自動找到
PROJECT_ROOT = SCRIPT_DIR.parent
csv_candidates = [
    PROJECT_ROOT / "sample_switchs.csv",
    SCRIPT_DIR / "sample_switchs.csv",
    Path("sample_switchs.csv"),
]

input_csv = None
for p in csv_candidates:
    if p.exists():
        input_csv = p
        break

if not input_csv:
    raise FileNotFoundError("找不到來源 CSV 檔 sample_switchs.csv，請確認檔案位置！")

# 輸出路徑固定輸出至 config/switches.yaml
output_yaml = SCRIPT_DIR / "switches.yaml"

switches = []
with open(input_csv, mode="r", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    for row in reader:
        name = row["Name"].strip()
        ip = row["IP"].strip()
        vendor = row["Vendor"].strip() if row.get("Vendor") else "Generic"
        model = row["Model"].strip() if row.get("Model") else "Standard"
        community = row["Public Community"].strip() if row.get("Public Community") else "SnmpPublic@TPC"
        loc = row["location"].strip() if row.get("location") else ""

        # 排除防火牆 (PA-1420)
        if "PA1420" in name or "PA-1420" in model:
            continue

        switches.append({
            "management_ip": ip,
            "name": f"{name} ({loc})" if loc else name,
            "vendor": vendor,
            "model": model,
            "adapter": "standard_mib",
            "snmp_version": "2c",
            "community": community,
            "enabled": True,
            "uplink_ports": []
        })

with open(output_yaml, "w", encoding="utf-8") as f:
    yaml.dump({"switches": switches}, f, allow_unicode=True, sort_keys=False)

print(f"✅ 已成功轉換 {len(switches)} 台交換器至: {output_yaml.resolve()}")