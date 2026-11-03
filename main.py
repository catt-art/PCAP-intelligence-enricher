import argparse
import ipaddress
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

import requests
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
REQUEST_TIMEOUT = 30  # 秒


# --------------------------------------------------------------------------
# 1. 讀取 PCAP 並統計公共 IP
# --------------------------------------------------------------------------
def is_public(ip_str: str) -> bool:
    """是否為可在公網路由的位址（排除私有、迴圈、連結本地、多播等）。"""
    try:
        addr=ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    
    # is_global 對多播位址仍可能回傳 True，需額外排除
    return addr.is_global and not addr.is_multicast


def count_public_ips(pcap_path: Path) -> Counter:
    """逐封包串流讀取，統計每個公共 IP 出現的封包數（來源與目的各算一次）。"""
    counts: Counter = Counter()

    # PcapReader 是串流式讀取，不會一次把整個檔案載入記憶體；
    # 同時支援 .pcap 與 .pcapng。
    with PcapReader(str(pcap_path)) as reader: #將Path轉string
        for packet in reader:
            if packet.haslayer(IP):
                layer = packet[IP]
            elif packet.haslayer(IPv6):
                layer = packet[IPv6]
            else:
                continue  # ARP 等非 IP 封包

            for addr in (layer.src, layer.dst): #一次讀兩個IP，如果是public，就計數加1
                if is_public(addr): 
                    counts[addr] += 1 
    return counts


# --------------------------------------------------------------------------
# 2. 查詢 VirusTotal
# --------------------------------------------------------------------------
def lookup_ip(ip: str, api_key: str) -> dict:
    """查詢單一 IP，回傳整理後的 dict。

    - 404：VT 資料庫沒有這個 IP，回傳 status="not_found"
    - 401：金鑰錯誤，直接結束程式
    - 429：超過額度，直接結束程式
    - 其他網路錯誤：回傳 status="error"，不影響其他 IP
    """
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(
            f"{VT_IP_URL}/{ip}", headers=headers, timeout=REQUEST_TIMEOUT
        ) #依照官網請求方式，將金鑰放在header
    except requests.RequestException as error: #如果沒回應、timeout
        return {"ip": ip, "status": "error", "detail": str(error)}

    if response.status_code == 404:
        return {"ip": ip, "status": "not_found"}
    if response.status_code == 401:
        raise SystemExit("VirusTotal 回應 401：API 金鑰無效。")
    if response.status_code == 429:
        raise SystemExit(
            "VirusTotal 回應 429：超過速率或每日額度（免費版為每分鐘 4 次、每日 500 次）。"
        )

    try:
        response.raise_for_status() #成功(200)回傳None；出錯4xx（用戶端錯誤）、5xx（伺服器錯誤）丟例外
    except requests.HTTPError as error:
        return {"ip": ip, "status": "error", "detail": str(error)}

    return parse_vt_ip_response(ip, response.json())


def parse_vt_ip_response(ip: str, payload: dict) -> dict:
    """從 VT 回傳的 JSON 取出需要的欄位（用 .get 避免欄位缺漏時當掉）。"""
    # https://docs.virustotal.com/reference/ip-object
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip": ip,
        "status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": attrs.get("country", "-"),
        "as_owner": attrs.get("as_owner", "-"),
        "reputation": attrs.get("reputation", 0),
    }


# --------------------------------------------------------------------------
# 3. 輸出
# --------------------------------------------------------------------------
def print_report(rows: list[dict]) -> None:
    header = (
        f"{'IP':<40} {'Pkts':>6} {'Mal':>4} {'Sus':>4} {'Har':>4} "
        f"{'Und':>4} {'CC':<3} AS Owner"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        if row["status"] == "ok":
            print(
                f"{row['ip']:<40} {row['packets']:>6} {row['malicious']:>4} "
                f"{row['suspicious']:>4} {row['harmless']:>4} "
                f"{row['undetected']:>4} {row['country']:<3} {row['as_owner']}"
            )
        else:
            note = row.get("detail", row["status"])
            print(f"{row['ip']:<40} {row['packets']:>6}  -- {row['status']}: {note}")


# --------------------------------------------------------------------------
# 4. 主程式
# --------------------------------------------------------------------------
#定義執行參數
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="統計 PCAP 中最常見的公共 IP，並查詢 VirusTotal。"
    )
    parser.add_argument("pcap", type=Path, help="PCAP / PCAPNG 檔案路徑")  #在執行時可輸入要解析的PCAP檔
    parser.add_argument("--top", type=int, default=4, help="查詢前 N 個 IP（預設 4）")
    parser.add_argument(
        "--delay",
        type=float,
        default=15.0,
        help="每次查詢間隔秒數；virustotal 免費版每分鐘 4 次，15 秒剛好（預設 15）",
    )
    parser.add_argument("--json-out", type=Path, help="將結果另存為 JSON 檔") #在執行時可輸入要存入的檔案
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.pcap.is_file():
        raise SystemExit(f"找不到檔案：{args.pcap}")

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise SystemExit("找不到環境變數 VT_API_KEY")

    print(f"[*] 讀取 {args.pcap} ...")
    counts = count_public_ips(args.pcap) #計算公共IP出現次數
    if not counts:
        raise SystemExit("封包中沒有找到公共 IP。")

    top = counts.most_common(args.top)
    print(f"[+] 共發現 {len(counts)} 個不重複的公共 IP，查詢前 {len(top)} 名：")
    for ip, n in top:
        print(f"    {ip:<40} {n} 個封包")

    rows = []
    for index, (ip, packets) in enumerate(top): #enumerate(top)賦予編號
        if index > 0:
            time.sleep(args.delay)  # 遵守免費版速率限制
        print(f"[*] 查詢 {ip} ({index + 1}/{len(top)}) ...", file=sys.stderr) #file=sys.stderr顯示進度，但不寫入檔案
        result = lookup_ip(ip, api_key)
        result["packets"] = packets #結果加上出現次數
        rows.append(result) #將每次搜尋整合

    print()
    print_report(rows)

    if args.json_out:
        args.json_out.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8" 
            #把 Python 資料（list 和 dict）轉成 JSON 格式的字串。
        )
        print(f"\n[+] 已輸出 JSON：{args.json_out}")


if __name__ == "__main__":
    main()