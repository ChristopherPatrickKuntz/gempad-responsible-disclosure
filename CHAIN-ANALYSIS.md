# On-Chain Forensic Analysis — GemPad Tron Infrastructure

**Advisory ID:** CPK-2026-002
**Chain:** Tron Mainnet
**Analysis Date:** 2026-02-07
**Data Source:** TronGrid API v1, TronScan

---

## 1. Exposed Wallet Overview

| Field | Value |
|-------|-------|
| **Address** | `TQjrBrzXXWRrCXRWZxf6x5xqVrdgJwcXg5` |
| **Hex Address** | `41a2031ad5fea0e8c9e79c211d3ce2fea7b3a86939` |
| **Total Transactions** | 50 |
| **Current TRX Balance** | 0.000002 TRX |
| **Current TRC20 Holdings** | 100,000 TREN (test token, 2 holders total) |
| **First Activity** | 2024-08-26 |
| **Last Activity** | 2024-10-14 |

---

## 2. Transaction Breakdown

| Type | Count | Description |
|------|-------|-------------|
| `CreateSmartContract` | 27 | Contract deployment attempts |
| `TransferContract` | 19 | TRX transfers (funding + operations) |
| `TransferAssetContract` | 4 | TRC10/TRC20 token transfers |
| **Total** | **50** | |

### Contract Deployment Results

Of 27 `CreateSmartContract` transactions:
- **4 succeeded** — Contracts deployed to mainnet
- **23 failed** — Reverted during deployment (likely constructor failures, gas issues, or iterative development)

The high failure rate (85%) is consistent with active development/testing on mainnet — deploying, failing, adjusting parameters, and redeploying. This pattern is typical of a developer iterating on contract deployment configuration.

---

## 3. Successfully Deployed Contracts

### Contract 1: `TVFFMNij75aVxTWFfZSYkcqJ6f1Y9pakxd`

| Field | Value |
|-------|-------|
| Hex Address | `41d37301d799eaeff50c8a98a751da40c84fb2dd94` |
| Deployed | 2024-09-03 |
| Deployment TX | `a70177ece31259f450a96da517e2efc096eaa46a545b771c744dbba370679281` |
| TRX Balance | 0.0 |
| TRC20 Holdings | None |
| Post-Deployment Interactions | 0 (only the deployment TX) |
| Source Verified | No |
| ABI Published | No |
| `owner()` Call Result | REVERT |

### Contract 2: `TGLbvmesfmCsg7K5SdyL515ZVwqjY4tmwa`

| Field | Value |
|-------|-------|
| Hex Address | `4145dca0ab579da2eb9a1a3a5e8d1598b7aab63074` |
| Deployed | 2024-09-03 |
| Deployment TX | `00a16483ec5c0598c5caa0e91d6ee09abeb67e08a6149ec3ba22264a25eff68a` |
| TRX Balance | 0.0 |
| TRC20 Holdings | None |
| Post-Deployment Interactions | 0 |
| Source Verified | No |
| ABI Published | No |
| `owner()` Call Result | REVERT |

### Contract 3: `TRJNTmHGgosH6WfWgdcHYqs95pA2kfEft5`

| Field | Value |
|-------|-------|
| Hex Address | `41a829afeca661891423a7321e63aeaae10f7e83ff` |
| Deployed | 2024-09-02 |
| Deployment TX | `81e11c48cc1ecb1d8226eae8962678e602547ac9bdf7717aa54bbffad5e56087` |
| TRX Balance | N/A (account not found via API) |
| TRC20 Holdings | N/A |
| Post-Deployment Interactions | 0 |
| Source Verified | No |
| ABI Published | No |
| `owner()` Call Result | REVERT |

### Contract 4: `TFSTdbFAxGiqCMxZbpwCXmkh82X8j2UeuR`

| Field | Value |
|-------|-------|
| Hex Address | `413c0012813bd90571bbfe88f286ff8cb284aa4f86` |
| Deployed | 2024-09-02 |
| Deployment TX | `205d7ffaebbf83cdbdf111aba1a371a63c72ddffd34cd93773a7e7b34e939bc6` |
| TRX Balance | N/A (account not found via API) |
| TRC20 Holdings | N/A |
| Post-Deployment Interactions | 0 (no transactions at all via API) |
| Source Verified | No |
| ABI Published | No |
| `owner()` Call Result | REVERT |

### Analysis Notes

- All 4 contracts REVERT on `owner()` (selector `0x8da5cb5b`). This could mean:
  - The contracts use a non-standard ownership pattern (e.g., `getOwner()`, `admin()`, or role-based access)
  - The contracts are minimal/proxy contracts without an `owner()` view function
  - The contracts may have self-destructed (accounts 3 and 4 return "not found")
- None of the contracts have post-deployment interactions, suggesting they may be:
  - Factory contracts awaiting initialization
  - Infrastructure contracts referenced by other systems
  - Failed deployment attempts that succeeded technically but weren't used
- All contracts are **unverified** on TronScan — no source code or ABI is published

---

## 4. Funding Chain Analysis

### 4.1 Funding Flow Diagram

```
                    ┌─────────────────────────────────────────┐
                    │  TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB    │
                    │  GemPad Primary Tron Deployer            │
                    │  • 200+ transactions                     │
                    │  • 49+ contract deployments              │
                    │  • Active through Dec 2025               │
                    └──────────────┬──────────────────────────┘
                                   │
                    1,000 TRX      │  2024-08-26 10:27 UTC
                                   │
                    ┌──────────────▼──────────────────────────┐
                    │  TQjrBrzXXWRrCXRWZxf6x5xqVrdgJwcXg5    │
                    │  EXPOSED SUB-DEPLOYER                    │
                    │  Private key in public JS bundle         │
                    │  • 50 transactions                       │
                    │  • 27 deployment attempts (4 success)    │
                    │  • Active: Aug 26 - Oct 14, 2024         │
                    └──┬───────────┬──────────────┬───────────┘
                       │           │              │
          ┌────────────▼─┐  ┌─────▼────────┐  ┌──▼──────────────┐
          │ 500 TRX out  │  │ 450 TRX out  │  │ 394.8 TRX out   │
          │ 2024-08-27   │  │ 2024-09-02   │  │ 2024-10-14      │
          │              │  │              │  │ FINAL DRAIN      │
          │ TAGj6vcS...  │  │ TPNAWPeX...  │  │ TU4MtifH...     │
          └──────────────┘  └──────────────┘  └─────────────────┘
```

### 4.2 Inbound Transfers (Funding)

| Date | From | Amount | Purpose |
|------|------|--------|---------|
| 2024-08-26 10:27 | `TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB` | 1,000 TRX | Initial funding for deployment operations |
| 2024-09-02 02:53 | Self (internal) | 700 TRX | Additional funding (source unclear from API) |

### 4.3 Outbound Transfers

| Date | To | Amount | Purpose |
|------|-----|--------|---------|
| 2024-08-27 13:43 | `TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB` | 500 TRX | Return to parent deployer |
| 2024-09-02 03:00 | `TPNAWPeXXNmGBc3kEnUAGosr6ZXFvnXSt2` | 450 TRX | Operational transfer |
| 2024-09-02 16:46 | `TKKpdsTxVgDiAckU2MMcFG1k7gvW5sfNoU` | 1 TRX | Small test transfer |
| 2024-10-14 00:09 | `TU4MtifHgsXTYV8iXdYP3m1thuZNoTW9LW` | 394.8 TRX | Final drain of remaining balance |

### 4.4 Micro-Transfers (Dust)

Multiple micro-transfers (0.000001–0.000007 TRX) were sent to the wallet's own address throughout its active period. These are consistent with Tron's bandwidth/energy activation patterns — small self-transfers to activate resources for subsequent contract deployments.

---

## 5. Parent Deployer Analysis

### `TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB`

| Field | Value |
|-------|-------|
| Transaction Count | 200+ (API pagination limit reached) |
| Contract Deployments | 49+ |
| Last Activity | 2025-12-11 |
| Recent Activity Types | `TransferContract`, `WithdrawExpireUnfreezeContract` |
| TronScan | [View](https://tronscan.org/#/address/TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB) |

This wallet is GemPad's **primary Tron deployer**:
- 49+ contract deployments far exceeds any personal or test wallet
- Active for 16+ months (Aug 2024 — Dec 2025)
- `WithdrawExpireUnfreezeContract` transactions in Dec 2025 indicate active resource management (staking/freezing TRX for energy)
- Directly funded the exposed sub-deployer with 1,000 TRX specifically for deployment operations

---

## 6. Associated Addresses

| Address | Relationship | Notes |
|---------|-------------|-------|
| `TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB` | Parent deployer (funder) | GemPad's primary Tron deployer, 49+ contracts |
| `TPNAWPeXXNmGBc3kEnUAGosr6ZXFvnXSt2` | Received 450 TRX | Operational wallet, role unknown |
| `TU4MtifHgsXTYV8iXdYP3m1thuZNoTW9LW` | Received 394.8 TRX (final drain) | Sweep destination |
| `TKKpdsTxVgDiAckU2MMcFG1k7gvW5sfNoU` | Received 1 TRX | Test transfer recipient |

---

## 7. Risk Assessment Matrix

| Risk | Likelihood | Impact | Notes |
|------|-----------|--------|-------|
| **Admin function abuse** | High | Critical | Deployer address is typically owner; 4 live contracts |
| **Impersonation via new deployments** | High | High | Attacker can deploy contracts from GemPad's address |
| **Future fund interception** | Medium | High | If any contract sends fees/refunds to the deployer |
| **Social engineering** | Medium | Medium | "Official GemPad deployer" address lends credibility |
| **Key used elsewhere** | Low-Medium | Critical | If same key is reused for other wallets or systems |

---

## 8. Open Questions for Vendor

1. What is the purpose of each of the 4 deployed contracts?
2. Does the deployer address retain admin/owner privileges on any contracts?
3. Are any of these contracts referenced by other GemPad infrastructure (factories, registries)?
4. Is this private key used in any other context (server-side signing, other chains)?
5. Has the key been rotated since it was first deployed to the JavaScript bundle?
6. Are there any funds at risk in contracts administered by this deployer?

---

*This chain analysis is part of the CPK-2026-002 responsible disclosure package. All data was obtained from public blockchain records via the TronGrid API.*
