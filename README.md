# 校園有線網路被動監測系統 (第一階段原型)

專為校園有線網路設計的被動式定位與監測原型系統。透過在 Windows 11 上監聽鏡像埠之 DHCP 封包，並透過唯讀 SNMP 定期收集交換器 MAC 轉送表 (FDB)，實現終端設備的實體交換器埠位推算。

## 特色
- **零干擾**：不主動發送 DHCP 封包，不修改交換器設定，不呼叫 PA-1420 防火牆 API。
- **精準鑑別**：嚴格區分 DHCP Request 與 ACK 狀態；不將上行埠誤判為終端位置。
- **模組化架構**：完整分離監聽、解析、SNMP 收集、拓樸推算與儲存。

## 快速開始

### 1. 安裝環境
- 安裝 Python 3.12 (64-bit)。
- 安裝 Npcap（勾選 WinPcap 相容模式）。

### 2. 安裝套件
```powershell
git clone <repository_url>
cd school-network-monitor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### 3. 配置設定檔
複製並調整設定檔：
```powershell
cp config/switches.example.yaml config/switches.yaml
cp .env.example .env
```
編輯 `config/settings.yaml`，填入 `capture.interface`。

### 4. 執行測試
```powershell
pytest
netmon check-config
```

### 5. 常用指令
- 測試交換器 SNMP 連線：`netmon check-snmp`
- 詳細檢視系統描述與 OID：`netmon check-snmp --verbose`
- 執行 FDB 轉送表與介面採集：`netmon poll-fdb`（或 `poll-switches`）
- 查詢特定交換器的連接埠對照表：`netmon show-interfaces --switch <switch-name-or-ip>`
- 查詢特定 MAC 之實體連接埠位置：`netmon find-mac <mac-address>`（支援無 DHCP 監聽時的純 FDB 快照查詢）
- 查詢特定 IP 設備：`netmon find-ip <ip-address>`
- 匯出報表：`netmon export-csv -o devices_export.csv`
- 備份資料庫：`netmon db-backup`