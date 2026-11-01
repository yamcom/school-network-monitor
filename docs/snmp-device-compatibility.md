# SNMP 交換器相容性驗證手冊

## 1. 核心 MIB 依賴
- `RFC1213-MIB / SNMPv2-MIB`：`sysName` (.1.3.6.1.2.1.1.5.0), `sysDescr` (.1.3.6.1.2.1.1.1.0)
- `IF-MIB` (RFC 2863)：`ifName` (.1.3.6.1.2.1.31.1.1.1.1), `ifAlias` (.1.3.6.1.2.1.31.1.1.1.18)
- `BRIDGE-MIB` (RFC 1493)：`dot1dBasePortIfIndex` (.1.3.6.1.2.1.17.1.4.1.2), `dot1dTpFdbPort` (.1.3.6.1.2.1.17.4.3.1.2)

## 2. 實測相容性評估矩陣
| 廠牌 / 系列 | 預設 Adapter | 支援層級 | 備註說明 |
|---|---|---|---|
| Aruba CX8100 / CX6xxx | `standard_mib` | 完整支援 | 需在 AOS-CX 啟用 `snmp-server` 與 MIB 存取權限。 |
| Ruckus ICX7150 | `standard_mib` | 完整支援 | FastIron 韌體預設支援 BRIDGE-MIB 與 IF-MIB。 |
| HPE 1910 / 1920 | `standard_mib` | 完整支援 | 支援標準 BRIDGE-MIB。建議採用 SNMPv2c 唯讀。 |
| Cisco Catalyst C9200 | `cisco_catalyst` | 需驗證 | 第一階段無 VLAN 採 standard_mib 即可；若多 VLAN 需 community indexing。 |
