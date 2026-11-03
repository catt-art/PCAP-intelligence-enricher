# PCAP-intelligence-enricher

讀取 PCAP / PCAPNG 檔，找出封包中最常出現的Public IP，並向 VirusTotal 查詢這些 IP 是否為惡意或可疑的，以表格顯示結果，也可另存為 JSON。

## 功能

- 以**串流方式**逐封包讀取（scapy `PcapReader`），大檔案也不會一次載入記憶體
- 同時支援 IPv4 與 IPv6
- 自動排除私有位址、迴圈位址、連結本地位址與多播位址，只保留公共單播 IP
- 統計每個 IP 出現的次數（來源與目的各算一次），取前 N 名（預設 4）
- 呼叫 VirusTotal API v3 查詢 IP，擷取各家引擎的判定統計、國家、AS 擁有者
- 單一 IP 查詢失敗不會中斷其他 IP（網路錯誤、404、其他 HTTP 錯誤會記錄在結果中）
- 輸出終端機表格，並可用 `--json-out` 另存成 JSON

## 環境需求

- Python 3.9 以上
- 套件：`scapy`、`requests`
- 一組 VirusTotal API 金鑰（註冊 VirusTotal 帳號後，可在個人頁面取得）

## 安裝

```bash
git clone <你的 repository 網址>
cd <專案資料夾>
pip install scapy requests
```

## 設定 API 金鑰

金鑰透過環境變數 `VT_API_KEY` 提供，**不要寫進程式碼，也不要上傳到版本控制**。

```bash
# macOS / Linux
export VT_API_KEY="你的金鑰"

# Windows PowerShell
$env:VT_API_KEY="你的金鑰"

# Windows cmd（注意：不要加引號）
set VT_API_KEY=你的金鑰
```

環境變數只對**設定它的那個終端機視窗**有效，請在同一個視窗內設定並執行。

## 使用方式

```bash
python main.py capture.pcap
```
**請自行選擇要分析的pcap檔**

| 參數 | 說明 | 預設值 |
|---|---|---|
| `pcap` | PCAP / PCAPNG 檔案路徑（必填） | — |
| `--top N` | 查詢出現次數最多的前 N 個公共 IP | `4` |
| `--json-out 路徑` | 另存結果為 JSON 檔 | 不輸出 |

範例：

```bash
python pcap_vt_lookup.py capture.pcap --top 10 --json-out result.json
python pcap_vt_lookup.py --help
```

## 輸出範例

以下為示意輸出（IP 為範例，數值僅供說明格式）：

```
[*] 讀取 capture.pcap ...
[+] 共發現 3 個不重複的公共 IP，查詢前 3 名：
    8.8.8.8                                  5 個封包
    1.1.1.1                                  3 個封包
    93.184.216.34                            2 個封包

IP                                         Pkts  Mal  Sus  Har  Und CC  AS Owner
--------------------------------------------------------------------------------
8.8.8.8                                       5    1    0   70   20 US  GOOGLE
1.1.1.1                                       3    1    0   70   20 US  GOOGLE
93.184.216.34                                 2  -- not_found: not_found
```

欄位說明：

| 欄位 | 意義 |
|---|---|
| `Pkts` | 該 IP 在 PCAP 中出現的封包數 |
| `Mal` / `Sus` / `Har` / `Und` | VirusTotal 各家引擎判定為 malicious / suspicious / harmless / undetected 的數量 |
| `CC` | 國家代碼 |
| `AS Owner` | 該 IP 所屬自治系統的擁有者 |

`--json-out` 輸出的 JSON 為陣列，每個元素對應一個 IP，欄位比表格多（例如 `reputation`）。

## 運作流程

1. 用 `PcapReader` 逐封包讀取，取出 IPv4 / IPv6 層的來源與目的位址
2. 以 `ipaddress` 模組過濾，只保留公共單播位址，並用 `Counter` 計數
3. 取出現次數最多的前 N 個 IP
4. 對每個 IP 呼叫 `GET /api/v3/ip_addresses/{ip}`，以 `x-apikey` 標頭驗證
5. 從回傳的 JSON 擷取 `last_analysis_stats`、`country`、`as_owner` 等欄位
6. 輸出表格，並依參數另存 JSON

## 專案結構

```
.
├── main.py   # 主程式
├── README.md
└── .gitignore          # 建議忽略 *.pcap、*.pcapng、result.json 等
```

## 注意事項與已知限制

**使用須知**

- 只分析你**有權限**取得的網路流量。PCAP 檔常含有真實 IP、網域與其他敏感資訊，請勿上傳到公開的版本庫。
- 本程式只把**IP 位址**送到 VirusTotal，不會上傳封包內容。但查詢的 IP 清單本身也可能透露你的網路活動，請自行評估。
- VirusTotal 免費金鑰有速率與額度限制（約每分鐘 4 次、每日 500 次請求），且依其條款不得用於商業用途；實際限制請以官方文件為準。

**結果解讀**

- 某個引擎標記 `malicious` **不代表該 IP 一定有害**。VirusTotal 彙整多家引擎，誤報很常見，CDN 與雲端服務的 IP 也常有零星標記，請搭配其他資訊判斷。
- 「最常出現」是依封包數排名，不是流量大小或連線數。
- `not_found` 表示 VirusTotal 沒有該 IP 的資料，不等於安全。

**程式限制**

- 程式沒有查詢間隔，**使用免費金鑰查詢多個 IP 時可能收到 HTTP 429**。遇到 429 或 401（金鑰無效）會直接結束，此時已查完的結果**不會輸出**。
- 只統計最外層的 IP 標頭；隧道封裝（如 IPv6 包在 IPv4 內）的內層位址不會被計入。
- 若 PCAP 檔本身損毀或格式不正確，scapy 會拋出例外，目前沒有額外的友善錯誤訊息。
- 結果在全部查完後才一次輸出。

## 疑難排解

| 訊息 | 原因與處理 |
|---|---|
| `找不到環境變數 VT_API_KEY` | 尚未設定金鑰，或在不同的終端機視窗設定。請在同一視窗設定後再執行。`setx` 設定後需重開終端機才生效。 |
| `找不到檔案：...` | 路徑錯誤。相對路徑是以執行當下的工作目錄為準。 |
| `VirusTotal 回應 401` | API 金鑰無效或複製時多了空白。 |
| `VirusTotal 回應 429` | 超過速率或每日額度，稍後再試，或減少 `--top`。 |
| `封包中沒有找到公共 IP` | PCAP 內的流量都是內網、多播或非 IP 封包。 |

## 授權

MIT License