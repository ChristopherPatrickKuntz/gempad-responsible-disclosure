# GemPad Responsible Disclosure — CPK-2026-002

> **CONFIDENTIAL** — This repository contains full technical details of an unpatched critical vulnerability. Do not share or publish until the disclosure deadline (2026-05-08) or vendor remediation, whichever comes first.

## Repository Structure

```
.
├── README.md                          # This file — overview and index
├── ADVISORY.md                        # Full security advisory (submitted to vendor)
├── METHODOLOGY.md                     # Assessment methodology and tooling
├── CHAIN-ANALYSIS.md                  # Complete on-chain forensic analysis
├── evidence/
│   ├── tronweb-initialization.js      # Extracted vulnerable code snippet
│   ├── wallet-transactions.json       # Full transaction history dump
│   ├── contract-deployments.json      # Deployed contract details
│   └── funding-chain.json             # Wallet funding flow
├── methodology/
│   └── key-derivation.py              # Private key → address derivation script
└── chain-analysis/
    └── tron-forensics.py              # On-chain investigation script
```

## Quick Reference

| Field | Value |
|-------|-------|
| **Advisory ID** | CPK-2026-002 |
| **Target** | GemPad (gempad.app) |
| **Severity** | Critical (CVSS 9.1) |
| **CWE** | CWE-798, CWE-321 |
| **Exposed Key** | `b9205a3a████████████████████████████████████████████d5add12123` |
| **Derived Wallet** | `TQjrBrzXXWRrCXRWZxf6x5xqVrdgJwcXg5` |
| **Contracts Deployed** | 4 (live, unverified on TronScan) |
| **Parent Deployer** | `TAGj6vcSQvgiCLeAm5mhcQouQmydxSiKNB` (49+ contracts) |
| **Discovery Date** | 2026-02-07 |
| **Disclosure Deadline** | 2026-05-08 (90 days) |

## Documents

- **[ADVISORY.md](ADVISORY.md)** — The complete advisory as submitted to GemPad. This is the primary deliverable.
- **[METHODOLOGY.md](METHODOLOGY.md)** — How the vulnerability was found, what tools were used, and the verification process.
- **[CHAIN-ANALYSIS.md](CHAIN-ANALYSIS.md)** — Full on-chain forensic analysis: transaction history, funding chain, deployed contracts, admin surface assessment.

## Disclosure Status

- [x] Vulnerability discovered (2026-02-07)
- [x] On-chain forensics completed (2026-02-07)
- [x] Advisory drafted (2026-02-07)
- [ ] Submitted to vendor
- [ ] Vendor acknowledgment received
- [ ] Vendor remediation confirmed
- [ ] Public disclosure

---

*CPK Solutions — Automated Web3 Security Assessment*
