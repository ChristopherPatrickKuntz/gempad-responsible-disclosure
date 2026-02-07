# Assessment Methodology — GemPad (gempad.app)

**Advisory ID:** CPK-2026-002
**Assessment Type:** Passive External Security Assessment (Sidewalk Mode)
**Date:** 2026-02-07
**Assessor:** Christopher Patrick Kuntz (CPK Solutions)

---

## 1. Assessment Scope

### In Scope
- Publicly accessible web application at `https://gempad.app`
- Client-side JavaScript bundles served to all visitors
- Publicly available blockchain data (Tron mainnet)
- DNS records, HTTP headers, and security configuration

### Out of Scope
- Server-side infrastructure
- Authenticated functionality
- Smart contract source code (not publicly verified)
- Any active exploitation or interaction with deployed contracts

### Assessment Profile
This assessment was conducted in **sidewalk mode** — a passive, non-intrusive scan profile that:
- Does NOT attempt authentication
- Does NOT submit forms or modify state
- Does NOT interact with smart contracts
- Does NOT perform active exploitation
- ONLY analyzes publicly served content and public blockchain data

---

## 2. Discovery Phase

### 2.1 JavaScript Bundle Analysis

CPK Scanner's JavaScript discovery module identified and downloaded all JavaScript bundles served by `gempad.app`. The primary discovery methods:

1. **Katana crawler** — Headless browser-based crawler that follows links, discovers dynamically loaded scripts, and captures the full set of JavaScript assets served during a standard page load
2. **LinkFinder** — Static analysis of discovered JavaScript files to extract additional script references, API endpoints, and URLs
3. **Waymore / GAU** — Historical URL analysis via the Wayback Machine and other URL aggregation sources to identify previously served JavaScript bundles

### 2.2 Secret Detection

Two complementary secret scanning tools were run against the collected JavaScript bundles:

1. **Gitleaks v8.22.1** — Pattern-based secret scanner with 190+ rules (160 default + 30 custom Web3 rules). The custom rules include patterns for blockchain private keys (Ethereum, Tron, Solana, etc.), RPC provider API keys, and DeFi-specific secrets.

2. **TruffleHog v3** — Entropy-based and pattern-based secret scanner that complements Gitleaks with additional detection heuristics.

Both tools flagged the Tron private key in the same JavaScript bundle:
- **File:** `_next/static/chunks/pages/_app-4446b1e51d05e6a6.js`
- **Gitleaks Rule:** `private-key` (generic 64-character hex string in `privateKey:` context)
- **TruffleHog Detector:** High entropy hex string in cryptographic context

### 2.3 Manual Verification Trigger

The automated scan classified the finding as a potential private key. Manual verification was triggered because:
- The key appeared in a TronWeb initialization context (not a test fixture or constant)
- The key was 64 hex characters (valid secp256k1 private key length)
- The surrounding code referenced `api.trongrid.io` (Tron mainnet, not testnet)

---

## 3. Verification Phase

### 3.1 Private Key Derivation

The private key was mathematically verified by deriving the corresponding Tron address:

```python
# Key derivation process (secp256k1 → Keccak-256 → base58check)
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak

private_key_hex = "b9205a3a████████████████████████████████████████████d5add12123"  # Redacted
private_key_bytes = bytes.fromhex(private_key_hex)

# Derive public key (uncompressed, drop 04 prefix)
sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
public_key = sk.get_verifying_key().to_string()

# Keccak-256 hash of public key → last 20 bytes → add 0x41 prefix (Tron)
k = keccak.new(digest_bits=256)
k.update(public_key)
address_bytes = b'\x41' + k.digest()[-20:]

# Base58check encoding
# Result: TQjrBrzXXWRrCXRWZxf6x5xqVrdgJwcXg5
```

**Result:** The private key resolves to `TQjrBrzXXWRrCXRWZxf6x5xqVrdgJwcXg5`, a real Tron mainnet address with transaction history.

### 3.2 On-Chain Validation

Using the TronGrid public API (`api.trongrid.io/v1/`), the derived address was validated:

1. **Account exists** — The address has a valid account record on Tron mainnet
2. **Has transaction history** — 50 transactions confirmed
3. **Deployed contracts** — 27 `CreateSmartContract` transactions, 4 successful
4. **Received funding** — 1,000+ TRX from an active deployer wallet

This confirmed the key is NOT a dummy/test key. It is a live production key with real on-chain activity.

---

## 4. Chain Analysis Phase

Full on-chain forensics were conducted using:

- **TronGrid API v1** — Account data, transaction history, contract details
- **TronScan** — Visual verification of transaction history and contract status
- **Manual transaction decoding** — Parsing `CreateSmartContract` and `TransferContract` transaction types

Detailed chain analysis is documented in [CHAIN-ANALYSIS.md](CHAIN-ANALYSIS.md).

---

## 5. Severity Assessment

### CVSS v3.1 Calculation

```
Attack Vector (AV):        Network     — Key is in a public JavaScript file
Attack Complexity (AC):    Low         — No exploit chain needed, key is plaintext
Privileges Required (PR):  None        — Any internet user can access the file
User Interaction (UI):     None        — No user action required
Scope (S):                 Unchanged   — Impact confined to Tron blockchain
Confidentiality (C):       High        — Full private key exposure
Integrity (I):             High        — Can sign transactions, deploy contracts, call admin functions
Availability (A):          None        — No direct availability impact confirmed

CVSS Score: 9.1 (Critical)
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```

### Severity Justification

The finding is rated **Critical** rather than High because:

1. **Production infrastructure key** — Not a test/dev key. Funded by GemPad's primary deployer.
2. **On-chain deployment history** — 4 live contracts deployed by this key.
3. **DeFi context** — GemPad is a launchpad handling user funds (presales, token locks, liquidity).
4. **Zero attack complexity** — The key is in plaintext in a public file.
5. **Unverified contracts** — The deployed contracts have no published source, making it impossible for users to audit admin functions.

---

## 6. Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| CPK Scanner | v2.x (sidewalk mode) | Orchestration, JavaScript discovery, pattern scanning |
| Katana | Latest | Headless crawling and JS discovery |
| LinkFinder | Latest | JavaScript static analysis for URLs and endpoints |
| Gitleaks | 8.22.1 | Secret pattern detection (190+ rules) |
| TruffleHog | v3 | Entropy-based secret detection |
| Python (ecdsa, pycryptodome) | 3.x | Private key → address derivation |
| TronGrid API | v1 | On-chain data retrieval |
| cURL | Latest | API interaction for chain analysis |

---

## 7. Limitations

1. **No ABI retrieval** — All 4 deployed contracts are unverified on TronScan. We could not retrieve their ABIs to enumerate admin functions. Calling `owner()` on each contract returned REVERT, suggesting either a non-standard ownership pattern, proxy architecture, or self-destruct.

2. **No active testing** — We did not attempt to call any functions on the deployed contracts or sign any transactions with the exposed key. All analysis was read-only.

3. **No bytecode decompilation** — While the contract bytecode is available on-chain, decompilation was not performed as part of this assessment. A full audit would include bytecode analysis to enumerate callable functions.

4. **Historical completeness** — The TronGrid API returns a maximum of 200 transactions per request. The exposed wallet has 50 transactions (within limits), but the parent deployer has 200+ and may have additional history beyond the API pagination limit.

---

*This methodology document is part of the CPK-2026-002 responsible disclosure package.*
