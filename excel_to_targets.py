#!/usr/bin/env python3
"""
excel_to_targets.py — 從 Excel 批量提取 IP + Domain，轉換成 bbot/auto_hunt 可用的 targets.txt

用法:
  python3 tools/excel_to_targets.py targets.xlsx
  python3 tools/excel_to_targets.py targets.xlsx --col-ip 0 --col-domain 1
  python3 tools/excel_to_targets.py targets.xlsx --out recon/targets.txt --cidr

安裝依賴:
  pip3 install openpyxl tldextract

輸出格式 (bbot -t targets.txt 直接讀取):
  domain.com
  sub.domain.com
  192.168.1.1
  10.0.0.0/24
"""

import sys
import re
import argparse
import ipaddress
from pathlib import Path

# ── 可選依賴 ──────────────────────────────────────────────────────
try:
    import openpyxl
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False
    print("[!] openpyxl 未安裝，請執行: pip3 install openpyxl", file=sys.stderr)

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

# ── 正規表達式 ────────────────────────────────────────────────────
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
IP_RE = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
)
IPV6_RE = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
)

def is_valid_ip(s: str) -> bool:
    """驗證 IP / CIDR 是否合法"""
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False

def is_valid_domain(s: str) -> bool:
    """過濾明顯不是 domain 的字串（版本號、檔案副檔名等）"""
    if not s or len(s) < 4:
        return False
    # 排除純數字 TLD（版本號如 1.2.3）
    parts = s.split('.')
    if all(p.isdigit() for p in parts):
        return False
    # 排除常見檔案副檔名
    skip_ext = {'.exe', '.dll', '.so', '.zip', '.tar', '.gz', '.py', '.js', '.ts',
                '.json', '.yaml', '.yml', '.xml', '.csv', '.xlsx', '.docx', '.pdf'}
    if any(s.lower().endswith(ext) for ext in skip_ext):
        return False
    # 最後一段必須是合理 TLD（至少 2 字母）
    tld = parts[-1]
    if not re.match(r'^[a-zA-Z]{2,}$', tld):
        return False
    return True

def extract_from_cell(cell_value: str) -> tuple[list[str], list[str]]:
    """從單一格子提取所有 domain 和 IP"""
    if cell_value is None:
        return [], []
    s = str(cell_value).strip()
    ips = []
    domains = []

    # IP / CIDR
    for m in IP_RE.finditer(s):
        candidate = m.group()
        if is_valid_ip(candidate):
            ips.append(candidate)

    # Domain
    for m in DOMAIN_RE.finditer(s):
        candidate = m.group().lower().rstrip('.')
        # 跳過已被辨識為 IP 的 match
        if any(candidate.startswith(ip.split('/')[0]) for ip in ips):
            continue
        if is_valid_domain(candidate):
            domains.append(candidate)

    return ips, domains

def parse_excel(filepath: str, col_ip: int = None, col_domain: int = None,
                sheet: int = 0, skip_header: bool = True) -> tuple[set, set]:
    """解析 Excel，返回 (ips, domains) 兩個 set"""
    if not HAS_OPENPYXL:
        sys.exit(1)

    wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
    ws = list(wb.worksheets)[sheet]

    all_ips = set()
    all_domains = set()

    rows = list(ws.rows)
    if skip_header and rows:
        rows = rows[1:]  # 跳過標題列

    for row in rows:
        cells = [str(c.value or '').strip() for c in row]
        if not any(cells):
            continue

        if col_ip is not None and col_domain is not None:
            # 指定欄位模式
            if col_ip < len(cells):
                ips, _ = extract_from_cell(cells[col_ip])
                all_ips.update(ips)
            if col_domain < len(cells):
                _, domains = extract_from_cell(cells[col_domain])
                all_domains.update(domains)
        else:
            # 自動掃描模式：對每個格子提取
            for cell_val in cells:
                ips, domains = extract_from_cell(cell_val)
                all_ips.update(ips)
                all_domains.update(domains)

    return all_ips, all_domains

def parse_txt(filepath: str) -> tuple[set, set]:
    """解析純文字檔（每行一個 IP 或 domain）"""
    all_ips = set()
    all_domains = set()
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if is_valid_ip(line):
                all_ips.add(line)
            else:
                ips, domains = extract_from_cell(line)
                all_ips.update(ips)
                all_domains.update(domains)
    return all_ips, all_domains

def main():
    p = argparse.ArgumentParser(
        description='從 Excel/TXT 提取 IP + Domain → bbot targets.txt'
    )
    p.add_argument('input', help='輸入檔案 (.xlsx / .xls / .txt / .csv)')
    p.add_argument('--out', default='recon/targets.txt',
                   help='輸出 targets.txt 路徑 (預設: recon/targets.txt)')
    p.add_argument('--col-ip', type=int, default=None,
                   help='IP 欄位 index (0-based，不指定=自動掃描所有欄位)')
    p.add_argument('--col-domain', type=int, default=None,
                   help='Domain 欄位 index (0-based)')
    p.add_argument('--sheet', type=int, default=0,
                   help='Excel sheet index (0-based，預設 0)')
    p.add_argument('--no-header', action='store_true',
                   help='Excel 沒有標題列')
    p.add_argument('--domains-only', action='store_true',
                   help='只輸出 domain（不含 IP）')
    p.add_argument('--ips-only', action='store_true',
                   help='只輸出 IP（不含 domain）')
    p.add_argument('--cidr', action='store_true',
                   help='保留 CIDR 表示法（否則展開 /24 等小範圍）')
    p.add_argument('--split', action='store_true',
                   help='分別輸出 domains.txt 和 ips.txt（方便批量 per-target 處理）')
    args = p.parse_args()

    filepath = args.input
    if not Path(filepath).exists():
        print(f"[!] 找不到檔案: {filepath}", file=sys.stderr)
        sys.exit(1)

    # 解析
    ext = Path(filepath).suffix.lower()
    if ext in ('.xlsx', '.xls'):
        if not HAS_OPENPYXL:
            print("[!] pip3 install openpyxl", file=sys.stderr)
            sys.exit(1)
        ips, domains = parse_excel(
            filepath,
            col_ip=args.col_ip,
            col_domain=args.col_domain,
            sheet=args.sheet,
            skip_header=not args.no_header
        )
    else:
        # txt / csv → 每行當作一個值
        ips, domains = parse_txt(filepath)

    # 過濾
    if args.domains_only:
        ips = set()
    if args.ips_only:
        domains = set()

    total_ips = len(ips)
    total_domains = len(domains)
    print(f"[+] 解析完成：{total_domains} domains，{total_ips} IPs")

    # 輸出
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.split:
        # 分開輸出
        dom_path = out_path.parent / 'domains.txt'
        ip_path = out_path.parent / 'ips.txt'
        with open(dom_path, 'w') as f:
            f.write('\n'.join(sorted(domains)) + '\n' if domains else '')
        with open(ip_path, 'w') as f:
            f.write('\n'.join(sorted(ips)) + '\n' if ips else '')
        print(f"[+] Domains → {dom_path} ({total_domains} 筆)")
        print(f"[+] IPs     → {ip_path} ({total_ips} 筆)")
    else:
        targets = sorted(domains) + sorted(ips)
        with open(out_path, 'w') as f:
            f.write('\n'.join(targets) + '\n' if targets else '')
        print(f"[+] 合併輸出 → {out_path} ({len(targets)} 筆)")

    print()
    print("=== 下一步 ===")
    print(f"# 1. 用 bbot 批量掃描（最推薦）:")
    print(f"  bbot -t {out_path} -p tools/bbot_preset_bugbounty.yml --no-deps")
    print()
    print(f"# 2. 用 auto_hunt.sh 逐一深挖（完整漏洞檢查）:")
    print(f"  while IFS= read -r t; do ./tools/auto_hunt.sh \"$t\"; done < {out_path}")
    print()
    print(f"# 3. 並行 auto_hunt.sh（最多 5 個 target 同時）:")
    print(f"  cat {out_path} | xargs -P5 -I{{}} ./tools/auto_hunt.sh {{}}")

if __name__ == '__main__':
    main()
