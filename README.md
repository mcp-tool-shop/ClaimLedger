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

# Verify with attestations and citations
claimledger verify claim.json --attestations --citations

# Verify with revocation checking
claimledger verify claim.json --revocations-dir ./revocations/

# Strict mode: fail if any signer key is revoked
claimledger verify claim.json --revocations-dir ./revocations/ --strict-revocations

# Inspect bundle contents
claimledger inspect claim.json
```

### Exit Codes (CI-friendly)

| Code | Meaning |
|------|---------|
| 0 | Valid — signature verified |
| 3 | Broken — tampered content or invalid signature |
| 4 | Invalid input |
| 5 | Error |
| 6 | Revoked — cryptographically valid but signer key is revoked |

## Architecture

```
ClaimLedger.sln
├── Shared.Crypto          ← Ed25519, SHA-256, Canonical JSON (shared with CreatorLedger)
├── ClaimLedger.Domain     ← Claims, Evidence, Citations, Attestations, Revocations
├── ClaimLedger.Application← Commands, verification, bundle export
├── ClaimLedger.Infrastructure ← (empty)
├── ClaimLedger.Cli        ← verify / inspect / attest / cite / revoke / witness commands
└── ClaimLedger.Tests      ← 137 tests
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

## Attestations

Third parties can attest to claims without modifying the original signature:

```bash
# Create an attestation
claimledger attest claim.json \
  --type REVIEWED \
  --statement "Methodology verified" \
  --attestor-key reviewer.key.json \
  --out claim.attested.json

# List attestations
claimledger attestations claim.attested.json
```

Attestation types: `REVIEWED`, `REPRODUCED`, `INSTITUTION_APPROVED`, `DATA_AVAILABILITY_CONFIRMED`, `WITNESSED_AT`

## Citations

Claims can cite other claims, forming a verifiable graph:

```bash
# Add a citation
claimledger cite claim.json \
  --bundle cited-claim.json \
  --relation CITES \
  --signer-key author.key.json \
  --embed \
  --out claim.cited.json

# List citations
claimledger citations claim.cited.json
```

Citation relations: `CITES`, `DEPENDS_ON`, `REPRODUCES`, `DISPUTES`

## Key Revocation

Revoke compromised or rotated keys:

```bash
# Self-signed revocation (key revokes itself)
claimledger revoke-key author.key.json \
  --reason ROTATED \
  --successor-key new-author.key.json \
  --out revocations/author.revoked.json

# Successor-signed revocation (new key revokes old)
claimledger revoke-key old.key.json \
  --reason COMPROMISED \
  --successor-key new.key.json \
  --successor-signed \
  --out revocations/compromised.revoked.json

# List revocations
claimledger revocations ./revocations/
```

Revocation reasons: `COMPROMISED`, `ROTATED`, `RETIRED`, `OTHER`

See [docs/revocations.md](docs/revocations.md) for detailed revocation semantics.

## Witness Timestamping

Create cryptographic proof that a claim existed at a specific time:

```bash
# Create a witness timestamp
claimledger witness claim.json \
  --witness-key witness-service.key.json \
  --out claim.witnessed.json

# Witness with explicit timestamp
claimledger witness claim.json \
  --witness-key witness-service.key.json \
  --issued-at "2024-06-15T12:00:00Z" \
  --out claim.witnessed.json
```

Witness timestamps are `WITNESSED_AT` attestations that bind to the claim's `claim_core_digest`.

See [docs/timestamping.md](docs/timestamping.md) for detailed timestamping semantics.

## What This Is Not

- **Not a truth oracle**: ClaimLedger verifies *who said what*, not *whether it's true*
- **Not peer review**: Verification is cryptographic, not scientific
- **Not a paper repository**: Claims are atomic; papers are containers
- **Not a blockchain**: Works offline (optional anchoring available)
- **Not a trust system**: No reputation, no roots of trust — just math

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
