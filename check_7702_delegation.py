#!/usr/bin/env python3
"""
Check Ethereum addresses for EIP-7702 Delegated Address.

Inputs (fixed format):
  - CSV `add.csv` with a header row, where the 2nd column holds the EOA address
    (e.g., columns: account, evm_address). No auto-detection is performed.

Output:
  - 脚本会覆盖输入 CSV，在末尾追加或更新两列：
    1) 'delegated_address'：解析到的被委托地址（无则留空）
    2) 'delegated_flag'：是否检测到 7702 授权（1/0）

Notes:
  - Method: RPC via Etherscan proxy `eth_getCode(<EOA>, latest)`. Result hex starting
    with 0xef0100 means delegated per EIP-7702. The script rate-limits requests.
  - API Key: read from .env (ETHERSCAN_API_KEY=...) or the in-file constant below.
"""

from __future__ import annotations

import argparse
import csv
import random
import re
import sys
import time
import os
from typing import Optional, Tuple, List, Dict

try:
    import requests
except ImportError as e:
    print("Missing dependency: requests. Install with: pip install requests", file=sys.stderr)
    raise

try:
    from bs4 import BeautifulSoup  # type: ignore
    HAVE_BS4 = True
except Exception:
    HAVE_BS4 = False


ETHERSCAN_ADDR_URL = "https://etherscan.io/address/{}"
ETHERSCAN_PROXY_API = "https://api.etherscan.io/api"

# Configure your API key here or via .env (ETHERSCAN_API_KEY)
ETHERSCAN_API_KEY_DEFAULT = ""
REQUEST_DELAY_SEC = 1.1
REQUEST_RETRIES = 3
REQUEST_TIMEOUT_SEC = 20.0


def is_valid_eth_address(addr: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", addr.strip()))


def parse_delegated_address_html(html: str) -> Optional[str]:
    """
    Return the delegated address (0x...) if present in the HTML, else None.
    Heuristics:
      1) Look for an element labeled 'Delegated Address' and read the next / near address link.
      2) Fallback to regex scanning around the label.
    """
    # Fast path: regex search around the words 'Delegated Address'
    # This also acts as a fallback if bs4 is unavailable.
    # Try to capture a 0x-address near the label.
    regexes = [
        re.compile(r"Delegated\s*Address[^\n\r]*?(0x[a-fA-F0-9]{40})", re.IGNORECASE | re.DOTALL),
        re.compile(r"(0x[a-fA-F0-9]{40}).{0,40}Delegated\s*Address", re.IGNORECASE | re.DOTALL),
    ]
    for rx in regexes:
        m = rx.search(html)
        if m:
            return m.group(1)

    # If bs4 is available, do a more structured search
    if HAVE_BS4:
        soup = BeautifulSoup(html, "html.parser")

        # 1) Target the typical Etherscan 'More Info' section rows
        #    Known pattern: row id 'ContentPlaceHolder1_trDelegatedAddress'
        row = soup.find(id=re.compile(r"ContentPlaceHolder1_trDelegatedAddress", re.I))
        if row:
            link = row.find("a", href=re.compile(r"/address/0x[0-9a-fA-F]{40}"))
            if link and link.text:
                cand = link.text.strip()
                if is_valid_eth_address(cand):
                    return cand
            # Fallback: any 0x address text within the row
            mrow = re.search(r"0x[a-fA-F0-9]{40}", row.get_text(" ", strip=True) or "")
            if mrow:
                return mrow.group(0)

        # 2) Generic label search for 'Delegated Address'
        def is_label(tag) -> bool:
            try:
                text = tag.get_text(strip=True)
            except Exception:
                return False
            if not text:
                return False
            return text.lower() == "delegated address" or "delegated address" in text.lower()

        label = soup.find(is_label)
        if label is not None:
            link = label.find_next("a", href=re.compile(r"/address/0x[0-9a-fA-F]{40}"))
            if link and link.text:
                candidate = link.text.strip()
                if is_valid_eth_address(candidate):
                    return candidate
            text_after = " ".join(s.get_text(" ", strip=True) for s in label.next_siblings if getattr(s, 'get_text', None))
            m2 = re.search(r"0x[a-fA-F0-9]{40}", text_after)
            if m2:
                return m2.group(0)

    return None


def fetch_address_page(session: requests.Session, address: str, timeout: float) -> Tuple[Optional[str], Optional[int]]:
    url = ETHERSCAN_ADDR_URL.format(address)
    try:
        resp = session.get(url, timeout=timeout)
        return resp.text, resp.status_code
    except requests.RequestException:
        return None, None


def detect_delegated_address(session: requests.Session, address: str, timeout: float, retries: int, retry_base_delay: float) -> Tuple[Optional[str], bool]:
    """
    Returns (delegated_address or None, found_flag)
    found_flag is True if page indicates a delegated address.
    """
    attempt = 0
    while attempt <= retries:
        html, status = fetch_address_page(session, address, timeout)
        if html and status == 200:
            delegated = parse_delegated_address_html(html)
            return delegated, bool(delegated)
        elif status in (429, 503):
            # Rate limited or temporarily unavailable -> backoff
            attempt += 1
            delay = retry_base_delay * (2 ** (attempt - 1)) * (1 + random.uniform(0, 0.25))
            time.sleep(delay)
            continue
        elif status == 404:
            # Address page not found -> treat as not found
            return None, False
        else:
            # Unknown error -> retry a bit, otherwise return not found
            attempt += 1
            time.sleep(retry_base_delay * (1 + random.uniform(0, 0.5)))
            if attempt > retries:
                return None, False


def parse_delegated_from_code_hex(code_hex: str) -> Tuple[Optional[str], bool]:
    """
    Given code hex like '0xEF0100<40 hex of address>...', detect the 7702 marker.
    Returns (delegated_address or None, found_flag).
    """
    if not isinstance(code_hex, str) or not code_hex.startswith("0x"):
        return None, False
    h = code_hex.lower()
    # Minimal length: 0x + 6 (ef0100) + 40 (20B address)
    if len(h) < 2 + 6 + 40:
        # Empty code '0x' or too short -> not delegated
        return None, False
    if not h.startswith("0xef0100", 0, 2 + 6):
        return None, False
    start = 2 + 6
    end = start + 40
    addr_hex = h[start:end]
    if len(addr_hex) != 40 or not re.fullmatch(r"[0-9a-f]{40}", addr_hex):
        return None, True  # Prefix matches but malformed address segment
    return "0x" + addr_hex, True


def get_code_via_etherscan_proxy(session: requests.Session, address: str, api_key: str, timeout: float, base_url: str = ETHERSCAN_PROXY_API) -> Tuple[Optional[str], Optional[int]]:
    params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": address,
        "tag": "latest",
        "apikey": api_key,
    }
    try:
        resp = session.get(base_url, params=params, timeout=timeout)
        if resp.status_code != 200:
            return None, resp.status_code
        data = resp.json()
        # Etherscan proxy returns JSON-RPC-like object with 'result'
        code_hex = data.get("result")
        if isinstance(code_hex, str):
            return code_hex, 200
        return None, 200
    except requests.RequestException:
        return None, None
    except ValueError:
        return None, 200


def get_code_via_jsonrpc(session: requests.Session, address: str, rpc_url: str, timeout: float) -> Tuple[Optional[str], Optional[int]]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getCode",
        "params": [address, "latest"],
    }
    headers = {"Content-Type": "application/json"}
    try:
        resp = session.post(rpc_url, json=payload, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return None, resp.status_code
        data = resp.json()
        code_hex = data.get("result")
        if isinstance(code_hex, str):
            return code_hex, 200
        return None, 200
    except requests.RequestException:
        return None, None
    except ValueError:
        return None, 200


def detect_delegated_address_via_rpc(session: requests.Session, address: str, timeout: float, retries: int, retry_base_delay: float, *,
                                     etherscan_api_key: Optional[str] = None, rpc_url: Optional[str] = None, etherscan_proxy_url: Optional[str] = None) -> Tuple[Optional[str], bool]:
    attempt = 0
    while attempt <= retries:
        if etherscan_api_key:
            code_hex, status = get_code_via_etherscan_proxy(session, address, etherscan_api_key, timeout, base_url=(etherscan_proxy_url or ETHERSCAN_PROXY_API))
        elif rpc_url:
            code_hex, status = get_code_via_jsonrpc(session, address, rpc_url, timeout)
        else:
            # No RPC configured
            return None, False

        if status == 200 and isinstance(code_hex, str):
            delegated, found = parse_delegated_from_code_hex(code_hex)
            return delegated, found
        elif status in (429, 403, 503):
            attempt += 1
            delay = retry_base_delay * (2 ** (attempt - 1)) * (1 + random.uniform(0, 0.25))
            time.sleep(delay)
            continue
        else:
            attempt += 1
            time.sleep(retry_base_delay * (1 + random.uniform(0, 0.5)))
            if attempt > retries:
                return None, False


def clamp_addr_col(idx: int, row_len: int) -> int:
    return max(0, min(idx, max(0, row_len - 1)))


def load_csv_rows(path: str, has_header: bool) -> Tuple[List[str], List[List[str]], bool]:
    """
    Return (headers, rows, has_header) using explicit header flag.
    """
    rows: List[List[str]] = []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for r in reader:
            if r and any(cell.strip() for cell in r):
                rows.append([cell.strip() for cell in r])

    if not rows:
        return [], [], has_header

    if has_header:
        headers = rows[0]
        data_rows = rows[1:]
    else:
        headers = []
        data_rows = rows

    return headers, data_rows, has_header


def write_csv_rows(path: str, headers: List[str], rows: List[List[str]]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if headers:
            writer.writerow(headers)
        writer.writerows(rows)


def load_env_key() -> str:
    # Load from environment first
    key = os.getenv("ETHERSCAN_API_KEY")
    if key:
        return key.strip()
    # Fallback to .env in current directory
    env_path = os.path.join(os.getcwd(), ".env")
    if os.path.isfile(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        if k.strip() == "ETHERSCAN_API_KEY" and v.strip():
                            return v.strip()
        except Exception:
            pass
    # Fallback to in-file constant
    return ETHERSCAN_API_KEY_DEFAULT.strip()


def main():
    parser = argparse.ArgumentParser(description="Check EIP-7702 delegation and append flag to CSV")
    parser.add_argument("--input", "-i", default="add.csv", help="Input CSV path (will be overwritten)")

    args = parser.parse_args()

    # Load CSV with fixed header presence
    headers, rows, has_header = load_csv_rows(args.input, has_header=True)
    if not rows:
        print("No rows found in input.")
        return 1

    # Fixed CSV layout: header present; address is 2nd column (index 1)
    addr_col_idx = 1

    # Prepare output headers: ensure delegated_address + delegated_flag exist (append if missing)
    lower_headers = [h.strip().lower() for h in headers]
    has_addr_col = len(lower_headers) > 1  # we rely on fixed format anyway
    has_existing_addr_val = "delegated_address" in lower_headers
    has_existing_flag = "delegated_flag" in lower_headers

    out_headers: List[str] = headers.copy() if has_header else []
    if not has_existing_addr_val:
        out_headers.append("delegated_address")
    if not has_existing_flag:
        out_headers.append("delegated_flag")

    session = requests.Session()
    # Friendly headers to reduce chance of being blocked
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Connection": "keep-alive",
    })

    out_rows: List[List[str]] = []
    cache: Dict[str, Tuple[Optional[str], bool]] = {}
    total = len(rows)

    # Resolve API key
    api_key = load_env_key()
    if not api_key:
        print("[error] 缺少 Etherscan API Key。请在 .env 中设置 ETHERSCAN_API_KEY=... 或在脚本顶部常量 ETHERSCAN_API_KEY_DEFAULT 填入。", file=sys.stderr)
        return 2

    for idx, r in enumerate(rows, start=1):
        # Normalize row length to at least address column index
        if addr_col_idx >= len(r):
            addr = ""
        else:
            addr = r[addr_col_idx].strip()

        if not is_valid_eth_address(addr):
            delegated = None
            found = False
        else:
            if addr in cache:
                delegated, found = cache[addr]
            else:
                delegated, found = detect_delegated_address_via_rpc(
                    session=session,
                    address=addr,
                    timeout=REQUEST_TIMEOUT_SEC,
                    retries=REQUEST_RETRIES,
                    retry_base_delay=max(0.5, REQUEST_DELAY_SEC),
                    etherscan_api_key=api_key,
                )
                cache[addr] = (delegated, found)

        # Prepare output row
        base_cols: List[str] = r.copy()

        # Ensure row has at least as many columns as headers
        if len(base_cols) < len(out_headers):
            base_cols.extend([""] * (len(out_headers) - len(base_cols)))

        # Compute target indices for delegated_address and delegated_flag in output
        # Recompute lower header names for out_headers
        out_lower = [h.strip().lower() for h in out_headers]
        try:
            delegated_address_idx = out_lower.index("delegated_address")
        except ValueError:
            delegated_address_idx = None  # Should not happen
        try:
            delegated_flag_idx = out_lower.index("delegated_flag")
        except ValueError:
            delegated_flag_idx = None

        # Set values
        if delegated_address_idx is not None:
            base_cols[delegated_address_idx] = delegated or ""
        if delegated_flag_idx is not None:
            base_cols[delegated_flag_idx] = "1" if found else "0"
        out_rows.append(base_cols)

        # Progress and pacing
        print(f"[{idx}/{total}] {addr} -> {'1' if found else '0'}")
        # Sleep a jittered delay between requests to be polite
        if idx < total:
            sleep_s = REQUEST_DELAY_SEC * (1 + random.uniform(0.0, 0.2))
            time.sleep(sleep_s)

    # Overwrite the input CSV as requested
    write_csv_rows(args.input, out_headers, out_rows)
    print(f"Done. Updated: {args.input}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
