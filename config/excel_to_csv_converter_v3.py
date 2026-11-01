import pandas as pd
import subprocess
import platform
import re
import os
import time

def parse_excel_to_csv(excel_path="school_ip_list.xlsx", output_csv="devices_import.csv"):
    if not os.path.exists(excel_path):
        print(f"❌ 找不到指定的 Excel 檔案: {excel_path}")
        return

    print(f"📂 正在讀取 Excel 檔案: {excel_path} ...")
    df = pd.read_excel(excel_path, sheet_name=0)
    print(f"📊 成功讀取，共計 {len(df)} 筆原始 IP 資料。\n" + "="*60)

    processed_rows = []
    system_os = platform.system().lower()
    is_windows = (system_os == "windows")

    for idx, row in df.iterrows():
        ip_raw = row.get("IP位置") or row.get("IP")
        purpose = row.get("用途") or row.get("名稱") or ""
        
        if pd.isna(ip_raw):
            continue
            
        ip_str = str(ip_raw).strip()
        
        # 萃取標準 IP 格式 (避免包含括號或多個IP混雜)
        ip_match = re.search(r'\d{1,3}(?:\.\d{1,3}){3}', ip_str)
        if not ip_match:
            continue
        clean_ip = ip_match.group(0)
        purpose_str = str(purpose).strip()

        print(f"\n[{idx+1}/{len(df)}] 🎯 目標 IP: {clean_ip} | 用途: {purpose_str}")

        # -------------------------------------------------------------
        # 1. 顯示 Ping 過程
        # -------------------------------------------------------------
        ping_param = "-n" if is_windows else "-c"
        ping_cmd = ["ping", ping_param, "1", clean_ip]
        print(f"   ➔ [Ping 執行] {' '.join(ping_cmd)}")
        
        ping_success = False
        try:
            ping_res = subprocess.run(
                ping_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=2
            )
            if ping_res.returncode == 0:
                ping_success = True
                print(f"   ✨ [Ping 結果] 成功！{clean_ip} 線上回應正常。")
            else:
                print(f"   ⚠️ [Ping 結果] 逾時或無回應（設備可能休眠或防火牆阻擋 ICMP）。")
        except subprocess.TimeoutExpired:
            print(f"   ⏱️ [Ping 結果] 連線逾時 (Timeout)。")
        except Exception as e:
            print(f"   ❌ [Ping 錯誤] 無法執行 ping 指令: {e}")

        # -------------------------------------------------------------
        # 2. 顯示 ARP 檢索過程
        # -------------------------------------------------------------
        found_mac = ""
        print(f"   ➔ [ARP 查詢] 正在檢索系統 ARP 快取 (arp -a)...")
        try:
            arp_output = subprocess.check_output(["arp", "-a"], text=True)
            for line in arp_output.splitlines():
                if clean_ip in line:
                    match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                    if match:
                        found_mac = match.group(0).replace("-", ":").upper()
                        break
            
            if found_mac:
                print(f"   ✨ [ARP 結果] 命中！取得 MAC 位址: {found_mac}")
            else:
                print(f"   ⚠️ [ARP 結果] 未在 ARP 快取中找到該 IP 的 MAC（若設備剛開機或不同網段屬正常現象）。")
        except Exception as e:
            print(f"   ❌ [ARP 錯誤] 查詢 ARP 發生異常: {e}")

        # 智慧推斷設備類型
        dev_type = "unknown"
        p_lower = purpose_str.lower()
        if "server" in p_lower or "主機" in p_lower or "ad" in p_lower or "nas" in p_lower or "ems" in p_lower:
            dev_type = "server"
        elif "印表機" in p_lower or "printer" in p_lower or "papercut" in p_lower:
            dev_type = "printer"
        elif "switch" in p_lower or "router" in p_lower or "閘道器" in p_lower or "ap" in p_lower or "防火牆" in p_lower or "網管" in p_lower:
            dev_type = "network"
        elif "電腦" in p_lower or "pc" in p_lower or "老師" in p_lower or "主任" in p_lower:
            dev_type = "desktop"
        elif "監視器" in p_lower or "攝影" in p_lower or "看板" in p_lower or "跑馬燈" in p_lower or "電表" in p_lower or "刷卡機" in p_lower:
            dev_type = "IoT"

        processed_rows.append({
            "MAC": found_mac,
            "IP": clean_ip,
            "設備名稱": purpose_str,
            "類型": dev_type,
            "IP配置": "STATIC",
            "備註": f"原始記錄: {ip_str}" if clean_ip != ip_str else ""
        })
        print("="*60)

    df_out = pd.DataFrame(processed_rows)
    df_out = df_out.drop_duplicates(subset=["IP"])
    df_out.to_csv(output_csv, index=False, encoding="utf-8-sig")
    print(f"\n🎉 轉換與探測作業完畢！已成功輸出檔案至: {output_csv}")

if __name__ == "__main__":
    parse_excel_to_csv()