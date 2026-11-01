# Windows 11 安裝與部署指南

## 1. 前置作業
1. 安裝 **Python 3.12 64-bit**（安裝時勾選 "Add Python to PATH"）。
2. 安裝 **Npcap**（https://npcap.com/）：
   - 勾選 *"Install Npcap in WinPcap API-compatible Mode"*。
   - 勾選 *"Support raw 802.11 traffic"*（選配）。

## 2. 取得鏡像網卡識別碼
以系統管理員權限開啟 PowerShell：
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
netmon list-interfaces
```
畫面會列出 Npcap 網卡，例如：
`\Device\NPF_{2187B13E-122E-49E6-88D3-6D4E398073A6}`。
將此字串貼入 `config/settings.yaml` 的 `capture.interface`，並將 `capture.enabled` 設為 `true`。

## 3. 交換器鏡像埠（SPAN / Monitor Port）前置設定
1. 在 Aruba CX8100 核心交換器上建立 Monitor Session，將對應 VLAN 或接取交換器 Trunk 埠的雙向流量鏡像至監控主機網卡所連接之連接埠。
2. 監控主機的接收網卡**不需設定 IP**（避免作業系統發出雜訊干擾鏡像網段）。
3. 監控主機需有另一張獨立網卡（或無線）連接校園管理網路，負責與交換器進行唯讀 SNMP 溝通。

## 4. 啟動與停止
- 啟動服務：
  ```powershell
  netmon poll-switches
  python src/network_monitor/main.py
  ```
- 停止服務：
  直接在終端機按下 `Ctrl + C`，系統將發送訊號中斷 Sniffer 與輪詢迴圈，釋放資料庫連線後安全退出。
  
  
二、 操作與設定文件更新

1. 交換器清單設定 (config/switches.yaml) 規範啟用狀態控制 (enabled)：
若部分交換器因防火牆 ACL、SNMP 未啟用或暫時無法連線而逾時，請將其設為 enabled: false，避免每次輪詢時因 3 秒等待而拖慢整體掃描效能。上行埠定義 (uplink_ports)：
為避免 VMware 虛擬機器或跨 VLAN 流量被誤判為多重候選（Candidate），建議在各交換器設定中明確定義上行埠或中繼埠（Trunk）：可填入介面名稱字串（例如："ethernet1/3/4"、"GigabitEthernet1/0/1"）。   或直接填入由拓樸圖與 show-interfaces 識別出的介面索引編號（例如："132"、"55"、"49"）。YAML- management_ip: "192.69.1.117"
  name: "Switch.117 (建國樓新機櫃)"
  vendor: "Ruckus"
  model: "ICX-7150"
  adapter: "standard_mib"
  snmp_version: "2c"
  community: "SnmpPublic@TPC"
  enabled: true
  uplink_ports:
    - "132"
三、 錯誤處理與常見問題排除說明（Troubleshooting）本節整理專案在 Windows 11 Python 3.12 環境實作與實機部署時遭遇的關鍵錯誤與解決方案：1. SNMP 逾時與連線拒絕 (No SNMP response received before timeout)原因：多數發生在交換器端啟用了 IP Access Group / Standard ACL 防護，僅允許特定網管來源 IP 進行 SNMP 查詢，導致監控主機的請求被直接丟棄；或社群字串（Community String）設定不符。排除方式：登入該交換器網頁或 CLI 檢查 Security / SNMP Access 設定，將監控主機 IP 加入允許清單。若暫時無法調整交換器設定，請將該設備在 config/switches.yaml 中設定為 enabled: false。2. Windows 核心非同步事件迴圈錯誤 (Event loop is closed / AttributeError: NoneType object has no attribute sendto)原因：Python 3.12 在 Windows 預設採用 ProactorEventLoop，在頻繁發送 UDP 封包（如 SNMP walk/get）時容易因 socket 強制關閉導致 ProactorDatagramTransport 損壞。排除方式：
確保 src/network_monitor/snmp/client.py 頂端已強制切換為 Windows Selector 政策：Pythonif sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
3. Pydantic 驗證錯誤 (Input should be a valid list for uplink_ports)原因：當 switches.yaml 中的 uplink_ports: 欄位完全留空或未定義時，YAML 解析會回傳 None，導致 Pydantic 驗證失敗。   排除方式：
確認 src/network_monitor/config.py 的 SwitchItemConfig 具備前置驗證器（Field Validator）將 None 自動轉換為空列表：Python@field_validator("uplink_ports", mode="before")
@classmethod
def coerce_none_to_list(cls, v):
    if v is None:
        return []
    return v
4. 工作目錄衝突 (FileNotFoundError: Main settings file not found)原因：在終端機內誤將工作目錄切換至 config/ 資料夾內部執行 netmon，導致相對路徑被重複拼湊。排除方式：
務必切換回專案根目錄（school-network-monitor）後再執行任何 CLI 指令：PowerShellcd D:\Users\chengyan\school-network-monitor
netmon poll-fdb
