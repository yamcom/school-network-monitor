# School Network Monitor (校園網路健康診斷與異常監控系統)

> **專案名稱**：校園網路健康診斷與異常監控系統 (School Network Health Monitor)  
> **適用環境**：Windows 11 64-bit / Python 3.10+ 原生環境 / Npcap 1.70+  
> **權威參考架構**：[`docs/DHCP及SNMP網路健康診斷系統架構書.md`](file:///D:/agy-chengyan/school-network-monitor/docs/DHCP及SNMP網路健康診斷系統架構書.md) (V3.2)  
> **系統核心目標**：整合 **被動式 DHCP 即時串流監聽** 與 **多廠牌唯讀 SNMP (LLDP / FDP / FDB MAC) 自動化輪詢**，精確建立「設備 IP/MAC ⇄ 交換機 ⇄ 實體連接埠」動態對照表，達成校園網路故障一鍵精確診斷與即時拓樸視覺化。

---

## 目錄
1. [系統總體架構與核心設計原則](#一系統總體架構與核心設計原則)
2. [系統環境需求與安裝步驟](#二系統環境需求與安裝步驟)
3. [系統日常維運與守護程序啟動 (SOP)](#三系統日常維運與守護程序啟動-sop)
4. [Windows 工作排程器配置 (每日自動維護)](#四windows-工作排程器配置-每日自動維護)
5. [Web 儀表板與拓撲視覺化工作站功能](#五web-儀表板與拓撲視覺化工作站功能)
6. [命令列操作工具清單 (CLI Reference)](#六命令列操作工具清單-cli-reference)
7. [後續待開發與功能演進藍圖 (Roadmap)](#七後續待開發與功能演進藍圖-roadmap)

---

## 一、系統總體架構與核心設計原則

本系統採用「四大獨立解耦運作軌道」與「單一資料庫寫入協調器 (DB Writer)」架構，嚴格遵守以下軟體工程約束：

```text
  [即時封包軌道]                 [SNMP 輪詢軌道]                 [維運清理軌道]
   dhcp_monitor                   snmp_poller                    maintenance
        │                              │                              │
     (HIGH)                         (NORMAL)                        (LOW)
        └──────────────┬───────────────┴──────────────┬───────────────┘
                       ▼                              ▼
                 ┌─────────────────────────────────────────┐
                 │       單一 DB Writer (db_writer.py)     │
                 │   老化機制 (Aging) 杜絕 database is locked │
                 └────────────────────┬────────────────────┘
                                      │ (WAL 模式)
                                      ▼
                           ┌─────────────────────┐
                           │ SQLite3 資料庫核心   │
                           │ network_monitor.db  │
                           └──────────┬──────────┘
                                      │ (唯讀連線 query_only=ON)
                                      ▼
                        ┌───────────────────────────┐
                        │ Web 服務 (FastAPI/Uvicorn) │
                        │ 儀表板 / Vis.js 拓撲工作站 │
                        └───────────────────────────┘
```

1. **單一 SQLite 3 資料庫核心 (WAL Mode)**：唯讀查詢與即時寫入完全分流，API 端點使用唯讀連線，杜絕鎖定衝突。
2. **優先權寫入協調器 (DB Writer)**：即時監控 (HIGH) > 離線分析/SNMP (NORMAL) > 維運清理 (LOW)，保障即時 DHCP 封包零遺漏。
3. **VLAN Relay-Only 策略**：不依賴實體 Trunk/Dot1Q 標籤，透過 DHCP Relay Agent IP (`giaddr`) 映射 VLAN，並以 `MAC + VLAN` 作為複合主鍵。
4. **Web 完全解耦**：網頁端僅提供唯讀查詢與配置管理，絕不直接介入底層背景程序的啟動或停止。
5. **磁碟保護門檻**：內建 5GB (5,120 MB) 預檢防護，剩餘空間不足時主動終止作業保護 SQLite。

---

## 二、系統環境需求與安裝步驟

### 1. 前置軟體環境需求
* **作業系統**：Windows 11 64-bit。
* **Python 環境**：官方原生 Python 3.10+ (推薦 3.11 或 3.12 64-bit，請勾選 *Add Python to PATH*)。
* **封包驅動**：[Npcap 1.70+](https://npcap.com/)。
  * *安裝時請務必勾選*：☑ **Install Npcap in WinPcap API-compatible Mode**。
  * *中文網卡支援*：系統內建自動名稱轉換，自動將「`乙太網路 2`」對應至 `\Device\NPF_{GUID}`。

### 2. 標準安裝與初始化步驟 (原生 Python & pip)
開啟 PowerShell 進入專案根目錄執行：

```powershell
# 1. 建立 Python 官方標準虛擬環境
python -m venv .venv

# 2. 啟動虛擬環境 (PowerShell)
.\.venv\Scripts\Activate.ps1

# 3. 升級 pip 並安裝系統核心套件
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. 安裝 netmon CLI 工具至虛擬環境
pip install -e .
```

---

## 三、系統日常維運與守護程序啟動 (SOP)

系統日常運作依賴三大獨立背景守護行程：

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                        系統管理員日常營運作業循環                      │
 └────────────────────────────────────────────────────────────────────────┘
      │
      ├─► [1. 啟動監控]  .\run_live_monitor.ps1 (或 python dhcp_monitor.py)
      │                  └─ 監聽 UDP 67/68 廣播，自動選擇實體網卡，寫入 WAL。
      │
      ├─► [2. 啟動 Web]  .\run_web.ps1 (或 python app.py)
      │                  └─ 瀏覽 http://127.0.0.1:8000。
      │
      ├─► [3. 拓樸輪詢]  .\scripts\run_snmp_poll.ps1 (或 netmon poll-neighbors)
      │                  └─ 定期掃描交換器 Ping/SNMP，更新 FDB MAC 與鄰居關係。
      │
      └─► [4. 每日維護]  Windows 排程器每日 03:00 自動執行 run_maintenance.bat
                         └─ 5GB 剩餘空間安全檢查、WAL Checkpoint、線上熱備份。
```

### 常用啟動腳本與原生指令對照表：
| 模組名稱 | PowerShell 腳本 (推薦) | Python 原生指令 | 說明 |
| :--- | :--- | :--- | :--- |
| **DHCP 即時監聽** | `.\run_live_monitor.ps1` | `python dhcp_monitor.py` | 實體網卡 UDP 67/68 監聽與即時寫入 |
| **Web 儀表板服務** | `.\run_web.ps1` | `python app.py` | 啟動 FastAPI 服務，監聽 Port 8000 |
| **SNMP 交換器輪巡** | `.\scripts\run_snmp_poll.ps1` | `python -m services.snmp_poller` | 依 `config/switches.yaml` 輪詢鄰居與 MAC |
| **SNMP 單次輪詢測試**| `.\scripts\run_snmp_poll.ps1 -Once` | `python -m services.snmp_poller --once` | 手動執行一次全網設備掃描與拓撲更新 |
| **立即執行系統維護** | `.\run_maintenance.bat` | `python maintenance.py` | 執行空間預檢、WAL 壓縮與線上備份 |

---

## 四、Windows 工作排程器配置 (每日自動維護)

為確保 SQLite 資料庫長期穩定與 WAL 檔案體積受控，系統提供工作排程器自動註冊腳本：

### 1. 註冊自動維護排程 (每日 03:00)
以系統管理員身分開啟 PowerShell 執行：
```powershell
.\register_task_scheduler.ps1
```
* **排程名稱**：`DHCP_Analyzer_Daily_Maintenance`
* **維護內容**：
  1. 磁碟剩餘空間 5GB 安全防護檢查。
  2. 30 天以前之原始封包日誌清理（保留長期資產與主檔）。
  3. WAL `TRUNCATE` 回收 WAL 檔案至 10MB 以下。
  4. 產出線上熱備份至 `backups/` 資料夾。

### 2. 驗證或解除排程
```powershell
# 檢視排程狀態
schtasks /Query /TN "DHCP_Analyzer_Daily_Maintenance" /FO LIST

# 解除註冊排程
.\register_task_scheduler.ps1 -Uninstall
```

---

## 五、Web 儀表板與拓撲視覺化工作站功能

系統啟動 Web 服務後，可透過瀏覽器造訪 `http://127.0.0.1:8000`：

1. **實體拓撲架構工作站 (`/topology`)**：
   - **Gateway 為 Root 階層水平佈局**：出口防火牆 (L0) $\to$ 核心閘道 Gateway (Root / L1) $\to$ 核心交換器 (L2) $\to$ 校園各棟交換器 (L3) 整齊展開。
   - **物理防跳動與解鎖拖曳排列**：關閉持續力導向抖動，提供「🔒 佈局已鎖定 / 🔓 解鎖排列」開關，支援拖曳微調並以 LocalStorage 持久化保存座標。
   - **交換器頻寬線條標準化**：
     - $\ge$ 10 Gbps：**綠色粗線 (`#10B981`)** (寬度 7.5 px / 0.2cm)。
     - 1 Gbps ~ 10 Gbps：**橘色線條 (`#F59E0B`)** (寬度 4.5 px)。
     - $<$ 1 Gbps：**紅色線條 (`#EF4444`)** (寬度 2.0 px)。
   - **5 大嚴格互斥狀態計數 (MECE)**：
     - 🟢 正常 (含拓撲) ｜ ⚪ 在線 (孤立無LLDP) ｜ 🟡 Ping在線 (SNMP障礙) ｜ 🔴 實體離線 ｜ 🟣 待設定 (enabled:false)。
     - 拓撲圖僅呈現已啟用的交換器與核心節點，未啟用設備於清冊明確標記。
2. **網頁直接設定 `config/switches.yaml` 工具**：
   - 導航列點擊「🛠️ 交換器設定管理」，可一鍵 Toggle 開關交換器 `enabled` 狀態，亦可直接於網頁編輯 YAML 原始碼儲存生效。
3. **即時與歷史時間窗電腦設備清冊分析**：
   - 首頁時間窗一鍵分析（15分、30分、1小時、24小時），採用 WAL 唯讀交易與短逾時防護，查詢絕不阻塞背景封包寫入。
4. **一鍵定位與側邊排障抽屜**：
   - 輸入 IP 或 MAC 即時高亮定位交換器與實體 Port，並具備 FDB 與鄰居詳情抽屜。

---

## 六、命令列操作工具清單 (CLI Reference)

透過已安裝至虛擬環境的 `netmon` 指令進行進階除錯：

### 1. 交換器與連線檢測
* `netmon check-config`：檢查 `settings.yaml` 與 `switches.yaml` 格式。
* `netmon check-snmp`：測試全體或特定交換器之 SNMP 連線與回應。
* `netmon poll-neighbors`：採集交換器 FDP 與 LLDP 鄰居資訊。
* `netmon poll-switches`：採集交換器介面表與 FDB MAC 表。

### 2. 設備查詢與實體定位
* `netmon find-mac <MAC>`：查詢指定 MAC 插在哪一台交換器、哪一個 Port。
* `netmon find-ip <IP>`：查詢指定 IP 之實體位置與租約狀態。
* `netmon list-devices`：檢視有線網路設備清冊與連線資訊。

### 3. 五大故障診斷與告警
* `netmon detect-anomalies`：手動觸發一次全網五大故障診斷掃描（Rogue DHCP、IP 衝突、Pool 耗盡、廣播風暴、SNMP 社群字串錯誤）。
* `netmon list-alerts`：檢視當前未結案之故障告警清單。
* `netmon db-backup`：手動執行 SQLite 線上安全熱備份。

---

## 七、後續待開發與功能演進藍圖 (Roadmap)

依據架構書第 12.4 節，後續系統演化與擴充計畫如下：

| 優先級 | 規劃項目 | 效益與目標架構 | 預計工作範圍 |
| :---: | :--- | :--- | :--- |
| **P1** | **SNMPv3 安全加密通訊支援** | 提升校園資安防護，支援 AuthPriv (SHA/AES) 認證與加密，逐步淘汰明文 Community。 | 擴充 `SNMPClient` 與 `switches.yaml` 參數支援 `user`, `auth_key`, `priv_key`。 |
| **P2** | **802.1Q 實體 Tagging 與 Trunk 辨識擴充** | 突破現有 Relay-Only 限制，直接透過 SNMP 採集交換器 `dot1qVlanCurrentTable` 與各 Port 的 Native/Trunk VLAN。 | 於 `services/snmp_poller.py` 增加 VLAN MIB 採集器並存入 `switch_vlan_members`。 |
| **P3** | **多元外部即時告警推播 (Webhook)** | 當偵測到私設 DHCP (Rogue DHCP) 或跨棟環路廣播風暴時，秒級推播通知網管。 | 實作 LINE Notify / Telegram Bot / Teams Webhook 模組，於 `anomaly_engine.py` 觸發。 |
| **P4** | **實體拓撲變更歷史日誌 (Topology Diff)** | 記錄校園骨幹斷線、跳線變更或交換器重啟之時間軸歷史比對。 | 新增 `topology_history` 資料表，週期性快照鄰居關係並提供版本 Diff 視圖。 |
| **P5** | **多子網 DHCP Option 43/ Option 60 設備特徵庫** | 針對教室觸控大屏 (ViewBoard)、IP 攝影機、無線 AP 等自動標註設備型號。 | 解析 Option 60 (Vendor Class Identifier) 並自動補齊 `devices.device_name`。 |
