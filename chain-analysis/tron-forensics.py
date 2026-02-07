#!/usr/bin/env python3
"""
Tron On-Chain Forensics Script

Queries the TronGrid API to analyze the exposed wallet's transaction history,
deployed contracts, and funding chain.

Advisory: CPK-2026-002
Date: 2026-02-07

Dependencies:
    pip install requests

Usage:
    python3 tron-forensics.py
"""

import json
import hashlib
import requests
from datetime import datetime
from collections import Counter


TRONGRID_BASE = "https://api.trongrid.io"
EXPOSED_WALLET = "TQjrBrzXXWRrCXRWZxf6x5xqVrdgJwcXg5"
EXPOSED_HEX = "41a2031ad5fea0e8c9e79c211d3ce2fea7b3a86939"


def hex_to_base58(hex_addr: str) -> str:
    """Convert a Tron hex address to base58check format."""
    addr_bytes = bytes.fromhex(hex_addr)
    h1 = hashlib.sha256(addr_bytes).digest()
    h2 = hashlib.sha256(h1).digest()
    checksum = h2[:4]
    addr_with_checksum = addr_bytes + checksum
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(addr_with_checksum, 'big')
    result = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        result = alphabet[remainder] + result
    for byte in addr_with_checksum:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result


def get_account(address: str) -> dict:
    """Fetch account details from TronGrid."""
    resp = requests.get(f"{TRONGRID_BASE}/v1/accounts/{address}")
    data = resp.json().get("data", [])
    return data[0] if data else {}


def get_transactions(address: str, limit: int = 200) -> list:
    """Fetch transaction history from TronGrid."""
    resp = requests.get(
        f"{TRONGRID_BASE}/v1/accounts/{address}/transactions",
        params={"limit": limit}
    )
    return resp.json().get("data", [])


def call_contract(contract_hex: str, function_selector: str) -> str:
    """Call a constant contract function (read-only)."""
    resp = requests.post(
        f"{TRONGRID_BASE}/wallet/triggerconstantcontract",
        json={
            "owner_address": EXPOSED_HEX,
            "contract_address": contract_hex,
            "function_selector": function_selector,
            "parameter": ""
        }
    )
    data = resp.json()
    results = data.get("constant_result", [])
    if results and results[0]:
        return results[0]
    err = data.get("result", {}).get("message", "")
    if err:
        try:
            return f"ERROR: {bytes.fromhex(err).decode()}"
        except Exception:
            return f"ERROR: {err}"
    return "NO_RESULT"


def analyze_wallet():
    """Run complete forensic analysis on the exposed wallet."""
    print("=" * 70)
    print("TRON FORENSIC ANALYSIS — CPK-2026-002")
    print("=" * 70)

    # 1. Account info
    print("\n[1] ACCOUNT INFO")
    acct = get_account(EXPOSED_WALLET)
    if acct:
        balance = acct.get("balance", 0) / 1_000_000
        trc20 = acct.get("trc20", [])
        create_time = acct.get("create_time", 0)
        created = datetime.fromtimestamp(create_time / 1000).strftime("%Y-%m-%d") if create_time else "unknown"
        print(f"  Address:  {EXPOSED_WALLET}")
        print(f"  Balance:  {balance} TRX")
        print(f"  Created:  {created}")
        print(f"  TRC20:    {len(trc20)} tokens")
        for t in trc20:
            for contract, bal in t.items():
                print(f"            {contract}: {bal}")
    else:
        print("  Account not found")

    # 2. Transaction breakdown
    print("\n[2] TRANSACTION BREAKDOWN")
    txs = get_transactions(EXPOSED_WALLET)
    types = Counter()
    deployments = []
    transfers = []

    for tx in txs:
        raw = tx.get("raw_data", {})
        contracts = raw.get("contract", [{}])
        ctype = contracts[0].get("type", "") if contracts else ""
        types[ctype] += 1

        param = contracts[0].get("parameter", {}).get("value", {}) if contracts else {}
        ret = tx.get("ret", [{}])
        success = ret[0].get("contractRet", "") if ret else ""
        ts = tx.get("block_timestamp", 0)
        dt = datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M") if ts else "?"
        txid = tx.get("txID", "")

        if ctype == "CreateSmartContract":
            deployments.append({
                "txid": txid,
                "date": dt,
                "success": success == "SUCCESS",
                "contract_address": param.get("new_contract", {}).get("contract_address", "")
            })
        elif ctype == "TransferContract":
            to_addr = param.get("to_address", "")
            amount = param.get("amount", 0) / 1_000_000
            transfers.append({
                "date": dt,
                "to": hex_to_base58(to_addr) if to_addr else "?",
                "to_hex": to_addr,
                "amount_trx": amount,
                "success": success
            })

    print(f"  Total: {len(txs)}")
    for t, c in types.most_common():
        print(f"    {t}: {c}")

    # 3. Successful deployments
    print("\n[3] SUCCESSFUL CONTRACT DEPLOYMENTS")
    successful = [d for d in deployments if d["success"]]
    print(f"  {len(successful)} of {len(deployments)} succeeded")
    for d in successful:
        contract_addr = hex_to_base58(d["contract_address"]) if d["contract_address"] else "?"
        print(f"    {d['date']} | {contract_addr}")
        print(f"      TX: {d['txid']}")

        # Try calling owner()
        if d["contract_address"]:
            owner_result = call_contract(d["contract_address"], "owner()")
            print(f"      owner() → {owner_result[:80]}")

    # 4. Transfers
    print("\n[4] NOTABLE TRANSFERS")
    for t in transfers:
        if t["amount_trx"] >= 1.0:
            direction = "FROM self" if t["to_hex"] == EXPOSED_HEX else f"TO {t['to']}"
            print(f"    {t['date']} | {t['amount_trx']} TRX | {direction}")

    # 5. Funding chain
    print("\n[5] PARENT DEPLOYER ANALYSIS")
    parent = "TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB"
    parent_txs = get_transactions(parent)
    parent_deployments = sum(
        1 for tx in parent_txs
        if tx.get("raw_data", {}).get("contract", [{}])[0].get("type") == "CreateSmartContract"
    )
    print(f"  Address:    {parent}")
    print(f"  Total TXs:  {len(parent_txs)}+")
    print(f"  Deployments: {parent_deployments}+")
    if parent_txs:
        latest = parent_txs[0].get("block_timestamp", 0)
        if latest:
            print(f"  Last active: {datetime.fromtimestamp(latest / 1000).strftime('%Y-%m-%d')}")

    print("\n" + "=" * 70)
    print("Analysis complete. See CHAIN-ANALYSIS.md for interpretation.")
    print("=" * 70)


if __name__ == "__main__":
    analyze_wallet()
