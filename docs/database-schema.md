# SQLite 資料表規格書

資料庫預設路徑：`data/network_monitor.db`（採用 WAL 模式與 Foreign Key 防護）。

### 1. `switches`（交換器清冊）
- 主鍵：`switch_id` (AUTOINCREMENT)
- 唯一鍵：`management_ip`
- 包含系統名稱、廠牌、型號、SNMP 描述、最後成功輪詢時間與狀態。

### 2. `switch_interfaces`（交換器實體介面）
- 複合主鍵：`(switch_id, if_index)`
- 外鍵：`switch_id -> switches.switch_id ON DELETE CASCADE`
- 包含 bridge_port, if_name, if_descr, if_alias, is_uplink (0/1), location_label。

### 3. `switch_fdb_current`（MAC 轉送表快照）
- 複合主鍵：`(switch_id, mac_address, bridge_port)`
- 索引：`idx_fdb_mac ON (mac_address)`
- 包含標準化 MAC、解析後的 if_index 與最後更新時間。

### 4. `dhcp_events`（被動 DHCP 事件軌跡）
- 索引：`idx_dhcp_mac`, `idx_dhcp_time`
- 記錄 DISCOVER / OFFER / REQUEST / ACK / NAK / INFORM 等事件。
- 嚴格分離 `requested_ip`（Option 50 請求）與 `assigned_ip`（ACK 租約）。

### 5. `devices_current`（設備當前現況表）
- 主鍵：`device_id`；唯一索引：`mac_address`
- 記錄最新確認 IP、Hostname、最後 ACK 時間與活躍時間。

### 6. `device_locations`（實體埠定位判定歷史）
- 外鍵：`device_id -> devices_current.device_id`, `switch_id -> switches.switch_id`
- 記錄 confidence (1.0 = 確定接取埠, 0.5 = 候選埠, 0.2 = 上行埠)、決策狀態與完整判斷理由。
