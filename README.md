# School Network Monitor (校園有線網路被動監測與資安防護系統)

本系統為一套專為校園有線網路設計的自動化監控與資安異常檢測原型系統。系統採用**被動式 DHCP 封包擷取**與**唯讀 SNMP 交換器輪詢**雙軌並行架構，無需更動核心防火牆或交換器設定，即可建立完整的「端點裝置 ⇄ 交換器 ⇄ 實體連接埠」對應與資安防護網。

---

## 一、 系統基本環境需求

在 Windows 11 監控主機上執行本系統前，請確認已完成以下前置環境安裝：

1. **Python 3.12 (64-bit)**：
   * 安裝時請務必勾選 **"Add Python to PATH"**（將 Python 加入環境變數）。
   * 建議確認版本：`python --version`（應顯示 Python 3.12.x）。

2. **Npcap (封包擷取驅動程式)**：
   * 下載並安裝最新版 [Npcap](https://npcap.com/)。
   * **安裝關鍵設定**：安裝精靈中務必勾選以下兩項：
     * ☑ **Support raw 802.11 traffic capture for wireless adapters** (支援無線網路原始流量，選填)
     * ☑ **Install Npcap in WinPcap API-compatible Mode** (**強烈建議勾選**，確保 Scapy 底層能透過 WinPcap 相容介面順利擷取封包)。

---

## 二、 安裝套件步驟

系統依賴 `Scapy` 進行封包解析、`pysnmp` 進行設備輪詢、`Pydantic` 進行強型別設定驗證。

### 1. 建立虛擬環境與安裝相依套件
請開啟命令提示字元 (CMD) 或 PowerShell，進入專案根目錄執行：

```powershell
# 1. 建立虛擬環境
python -m venv .venv

# 2. 啟動虛擬環境 (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# 3. 升級 pip
python -m pip install --upgrade pip

# 4. 安裝專案與開發相依套件
pip install -r requirements.txt
pip install -e .
```

### 2. 專案核心 Python 套件說明 (`requirements.txt` / `pyproject.toml`)
本專案運行所需的關鍵 Python 套件清單如下：
* **`scapy>=2.5.0`**：底層網路封包擷取與 DHCP/BOOTP 封包解碼。
* **`pydantic>=2.0`**：執行 `settings.yaml` 與 `switches.yaml` 的結構與型別驗證。
* **`pysnmp-lextudio`**：提供 SNMP v2c / v3 唯讀輪詢與 MIB 查詢能力。
* **`click>=8.0`**：構建強大且結構化的 `netmon`命令列操作介面。
* **`pyyaml>=6.0`**：讀取與寫入 YAML 格式設定檔。
* **`pandas` / `openpyxl`**：用於解析校園固定 IP 清單與交換器盤點 Excel 檔案。
* **`pytest`**：用於執行單元測試與整合驗證。

---

## 三、 設定檔與資料轉換說明

系統主要依賴 `config/settings.yaml`（全域參數）與 `config/switches.yaml`（設備清單）進行初始化。

### 1. 交換器清單 `config/switches.yaml` 與 Excel 轉換工具
校園內建置的交換器清單（如 Ruckus、Aruba、Cisco、D-Link 等交換器設備）可透過專屬轉換腳本自動生成：
* **`[sample_switchs].csv` 轉 YAML 工具**：
  若您手邊有交換器盤點 CSV，可執行內建腳本自動過濾防火牆並輸出標準格式：
  ```cmd
  python config/CSV_toyaml.py
  ```
  此指令會自動讀取同目錄下的交換器 CSV，並覆寫產生 `config/switches.yaml`。

* **固定 IP 與資安清單 Excel 轉換工具**：
  若需將校園固定 IP 清單（`school_ip_list.xlsx`）匯入系統以進行自動 Ping 探測與 ARP 比對，可執行：
  ```cmd
  python config/excel_to_csv_converter_v3.py
  ```
  此腳本會讀取 Excel，自動執行 Ping 與 `arp -a` 檢索，產出 `devices_import.csv`，後續可透過 `netmon import-devices` 匯入資料庫。

### 2. 全域設定檔 `config/settings.yaml` 細項參數說明
```yaml
app:
  name: "school-network-monitor"
  log_level: "INFO"         # 日誌等級 (DEBUG, INFO, WARNING, ERROR)
  timezone: "Asia/Taipei"   # 系統時區

capture:
  interface: ""             # Npcap 網卡 GUID 或名稱 (執行 --auto-config 會自動填入)
  filter: "udp and (port 67 or port 68)" # BPF 封包過濾條件 (僅攔截 DHCP 流量)
  enabled: false            # 是否隨 background monitor 同時啟動背景監聽

snmp:
  version: "2c"             # 預設 SNMP 版本 ("2c" 或 "3")
  timeout_seconds: 3.0      # SNMP 逾時秒數
  retries: 1                # 逾時重試次數
  poll_interval_seconds: 300 # 交換器輪詢週期 (秒)
  community: "public" # 預設 v2c 社群字串
  v3_user: "mon_user"       # SNMPv3 使用者名稱 (預留)
  v3_auth_proto: "SHA"      # SNMPv3 驗證協定
  v3_priv_proto: "AES"      # SNMPv3 加密協定

database:
  path: "data/network_monitor.db" # SQLite 資料庫檔案路徑

retention:
  dhcp_events_days: 30      # 歷史 DHCP 事件保留天數

dhcp:
  authorized_servers:       # 校園授權之合法 DHCP 伺服器 IP 清單 (防範 N01 Rogue DHCP)
    - "192.168.1.9"
    - "192.168.1.254"
    - "192.168.6.41"
    - "192.168.6.101"

  scope_rules:              # 各電腦教室 Scope 分組與伺服器限制規則 (防範 N02 違規配發)
    - group_name: "電腦教室-二樓"
      allowed_servers: ["192.168.6.41"]
      macs: [...]
```

---

## 四、 網卡介面自動抓取與執行測試操作

為了確保 Scapy / Npcap 能夠順利在 Windows 11 上擷取封包，系統內建了智慧網卡自動偵測與寫入功能：

1. **自動偵測實體網卡並寫入設定檔**：
   執行以下指令，系統會自動掃描所有網卡介面、排除 `0.0.0.0` 與 Loopback，精準鎖定帶有有效實體 IP（例如 `192.168.1.42`）的 Npcap 網卡 GUID（如 `\Device\NPF_{73456D91-2551-4F14-AA3E-F8C558D08E01}`），並自動更新至 `config/settings.yaml` 中：
   ```cmd
   netmon listen-dhcp --auto-config
   ```

2. **手動測試 SNMP 連線**：
   確認網卡與設定無誤後，可先行測試 15 台交換器的 SNMP 回應狀況：
   ```cmd
   netmon check-snmp
   ```

---

## 五、 目前已開發相關指令說明 (CLI Reference)

系統提供完整的 `netmon` 命令列工具，涵蓋網路診斷、持續監控、裝置清冊、拓樸追蹤與資安告警管理：

### 1. 網路與 SNMP 測試
* **`netmon check-snmp`**：測試指定或全體交換器之 SNMP 連線與 MIB 回應。
* **`netmon poll-switches`**（或 `poll-fdb`）：手動執行一次交換器 FDB 與介面表採集。
* **`netmon show-interfaces --switch <IP/Name>`**：檢視特定交換器的連接埠對應與 Uplink 狀態。

### 2. DHCP 監聽指令
* **`netmon listen-dhcp`**：啟動互動式 DHCP 被動監聽（具備彩色日誌：正常 ACK 綠色、未授權 Rogue DHCP 紅色粗體、Scope 不符桃紅色）。
* **`netmon listen-dhcp --auto-config`**：自動偵測帶有有效 IP 的實體網卡並寫入 `settings.yaml`。

### 3. 持續監控服務與模組控制
* **`netmon monitor`**：啟動背景常駐服務（自動排程 SNMP 輪詢、FDB 掃描與 DHCP 背景監聽）。
* **`netmon monitor --module snmp|anomaly|dhcp`**：單獨啟動指定的監控模組。
* **`netmon monitor --stop`**：安全停止所有背景監控服務，並將模組狀態更新為 `STOPPED`。
* **`netmon monitor-health`**：檢視各核心監控模組的目前健康狀態與最後成功時間戳記。

### 4. 設備清冊與定位查詢
* **`netmon list-devices`**：檢視有線網路設備清冊（支援 `--type`、`--status`、`--assignment` 條件篩選）。
* **`netmon find-mac <MAC>`**：依 MAC 查詢交換器實體連接埠與定位可信度詳細診斷報告。
* **`netmon find-ip <IP>`**：依 IP 查詢對應 MAC、租約狀態與交換器連接埠。
* **`netmon find-device <ID/MAC/IP>`**：綜合查詢設備主檔、歷程 IP 與定位結果。
* **`netmon verify-mac <MAC> --switch-ip <IP> --port <Port> --note <備註>`**：記錄網管人員實機插線驗證結果（若不符將自動觸發 N08 告警）。
* **`netmon add-device`** / **`update-device`** / **`import-devices <CSV>`**：手動或批次維護靜態設備清冊。

### 5. 拓樸與路徑追蹤
* **`netmon poll-lldp`**：採集交換器 LLDP 鄰居資訊。
* **`netmon discover-topology`**：分析鄰居數據並建立交換器互聯鏈路拓樸。
* **`netmon show-topology`**：展示交換器主幹互聯架構總表。
* **`netmon trace-mac <MAC>`**：沿著拓樸路徑追蹤 MAC 的交換器傳遞路由並過濾骨幹。

### 6. 告警管理與報表匯出
* **`netmon list-alerts`**：列出未結案告警清單（支援 `--status`、`--severity`、`--type` 篩選）。
* **`netmon show-alert <ID>`**：查看單一告警的詳細資訊、歷次異常證據與狀態變更歷程。
* **`netmon ack-alert <ID>`** / **`resolve-alert <ID>`** / **`suppress-alert <ID>`**：確認、結案或暫時抑制告警。
* **`netmon alert-report`**：產出異常統計摘要並匯出至 CSV。
* **`netmon unmanaged-report`** / **`conflict-report`**：匯出未管理設備報表與 IP 衝突報表。
* **`netmon export-csv`**：匯出完整設備清冊總表與資安告警 CSV。

---

## 六、 下一階段 Web API 與網頁介面開發規劃

為了順利銜接網頁前端（如儀表板、設備清冊、告警中心、拓樸圖），下一階段建議採用 **FastAPI** 進行後端 API 開發：
* **直接資料庫與 Repository 串接**：Web 路由無須透過 CLI 子程序，可直接實例化 `NetworkRepository(Database(settings.database.path))` 讀取 `data/network_monitor.db`。
* **預期提供的 RESTful API 端點**：
  * `GET /api/dashboard/health`：讀取 `get_all_monitoring_health()`。
  * `GET /api/dashboard/stats`：讀取 `get_alert_statistics_report()`。
  * `GET /api/devices`：調用 `list_inventory_devices()`。
  * `GET /api/alerts`：調用 `list_alerts()` 並支援狀態/類型過濾。
  * `POST /api/alerts/{id}/status`：調用 `update_alert_status()` 進行線上 Ack/Resolve。
  * `GET /api/topology/links`：調用 `list_topology_links()` 支援網頁拓樸視覺化。