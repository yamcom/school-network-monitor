# 驗收測試與已知限制

## 驗收執行步驟
1. 執行 `netmon check-config` 確保設定檔無誤。
2. 執行 `netmon poll-switches` 確認所有被管交換器能順利讀出 sysName 與 MAC 表。
3. 執行測試電腦上網測試：
   - 測試電腦手動執行 `ipconfig /release` 與 `ipconfig /renew`。
   - 觀察日誌是否印出 `DHCP Event: [ACK] ...`。
4. 執行查詢驗收：
   `netmon find-mac <測試電腦MAC>`
   確認輸出之交換器與連接埠介面名稱與實體面板相符。
