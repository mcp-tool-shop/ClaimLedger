# ClaimLedger

**Cryptographic provenance for scientific claims.**

ClaimLedger is a local-first, cryptographically verifiable ledger for scientific claims, evidence, and reproducibility.

## Why ClaimLedger?

Scientific claims are the atomic unit of research — not papers, not datasets. ClaimLedger provides:

- **Cryptographic accountability**: Every claim is signed with Ed25519, creating an unforgeable record of who asserted what, when
- **Evidence linking**: Claims reference hashed evidence (datasets, code, notebooks) — the hash is the commitment
- **Third-party verification**: Anyone can verify a claim bundle without trusting your infrastructure
- **No central authority**: Works offline, no blockchain required (though anchoring is supported)

## Quick Start

### Verify a claim bundle

```bash
# Verify cryptographic validity
claimledger verify claim.json

# Verify with evidence files
claimledger verify claim.json --evidence ./data/

# Inspect bundle contents
claimledger inspect claim.json
```

### Exit Codes (CI-friendly)

| Code | Meaning |
|------|---------|
| 0 | Valid — signature verified |
| 3 | Broken — tampered content |
| 4 | Invalid input |
| 5 | Error |

## Architecture

```
ClaimLedger.sln
├── Shared.Crypto          ← Ed25519, SHA-256, Canonical JSON (shared with CreatorLedger)
├── ClaimLedger.Domain     ← Claims, Evidence, Researcher identity
├── ClaimLedger.Application← Commands, verification, bundle export
├── ClaimLedger.Infrastructure ← (empty for Phase 1)
├── ClaimLedger.Cli        ← verify / inspect commands
└── ClaimLedger.Tests      ← 42 tests
```

## Claim Bundle Format

```json
{
  "Version": "claim-bundle.v1",
  "Algorithms": {
    "Signature": "Ed25519",
    "Hash": "SHA-256",
    "Encoding": "UTF-8"
  },
  "Claim": {
    "ClaimId": "uuid",
    "Statement": "The claim being asserted",
    "AssertedAtUtc": "2024-06-15T12:00:00Z",
    "Evidence": [
      {
        "Type": "Dataset",
        "Hash": "sha256-hex",
        "Locator": "https://example.com/data.csv"
      }
    ],
    "Signature": "base64"
  },
  "Researcher": {
    "ResearcherId": "uuid",
    "PublicKey": "ed25519:base64",
    "DisplayName": "Dr. Jane Smith"
  }
}
```

## Evidence Types

| Type | Description |
|------|-------------|
| Dataset | Training data, experimental results |
| Code | Source code, scripts, models |
| Paper | Published papers, preprints |
| Notebook | Jupyter notebooks, analysis documents |
| Other | Any other supporting material |

## Signing Contract

Claims are signed using a frozen `ClaimSignable.v1` contract:

```json
{
  "Version": "claim.v1",
  "ClaimId": "uuid",
  "Statement": "string",
  "ResearcherId": "uuid",
  "ResearcherPublicKey": "ed25519:base64",
  "Evidence": [...],
  "AssertedAtUtc": "ISO-8601"
}
```

**Rules:**
- Canonical JSON (no whitespace, explicit field order)
- UTF-8 encoding
- Any change to the contract → version bump to `claim.v2`

## What This Is Not

- **Not a truth oracle**: ClaimLedger verifies *who said what*, not *whether it's true*
- **Not peer review**: Verification is cryptographic, not scientific
- **Not a paper repository**: Claims are atomic; papers are containers
- **Not a blockchain**: Works offline (optional anchoring available)

## Building

```bash
# Build
dotnet build

# Test
dotnet test

# Run CLI
dotnet run --project ClaimLedger.Cli -- verify samples/sample-claim.json
```

## Related Projects

- [CreatorLedger](https://github.com/mcp-tool-shop/CreatorLedger) — Cryptographic provenance for digital assets
- Both share `Shared.Crypto` for Ed25519, SHA-256, and Canonical JSON

## License

MIT
