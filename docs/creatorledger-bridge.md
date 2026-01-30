# CreatorLedger Bridge

ClaimLedger Phase 10 introduces the **CreatorLedger Bridge**, allowing scientific claims to reference CreatorLedger proof bundles as evidence. This enables cross-system provenance linking between creative asset attestations and scientific claims.

## Overview

CreatorLedger is a separate system that provides cryptographic attestations for creative assets. The bridge allows ClaimLedger to:

1. Reference CreatorLedger bundles as evidence via digest
2. Embed proof bundles in ClaimPacks for offline verification
3. Verify bundle integrity and signatures without network calls

## Evidence Model Extension

### New Evidence Kind

The `EvidenceInfo` type now supports a `Kind` field:

```json
{
  "Type": "application/json",
  "Hash": "abc123...",
  "Kind": "CREATORLEDGER_BUNDLE",
  "EmbeddedPath": "creatorledger/abc123.json",
  "BundleAssetId": "asset_test123"
}
```

#### Evidence Kinds

| Kind | Description |
|------|-------------|
| `FILE` | Raw file evidence (default, backward compatible) |
| `CREATORLEDGER_BUNDLE` | CreatorLedger proof bundle |

The `Kind` field is optional. When absent, `FILE` is assumed for backward compatibility.

### New Fields for CREATORLEDGER_BUNDLE

| Field | Type | Description |
|-------|------|-------------|
| `Kind` | string | Must be `"CREATORLEDGER_BUNDLE"` |
| `Hash` | string | SHA-256 digest of the bundle JSON bytes |
| `EmbeddedPath` | string? | Path to embedded bundle in pack (e.g., `creatorledger/abc123.json`) |
| `BundleAssetId` | string? | The asset ID within the CreatorLedger bundle |

## ClaimPack Structure

### Include Configuration

The manifest `Include` section now supports:

```json
{
  "Include": {
    "ClaimsDir": "claims/",
    "EvidenceDir": "evidence/",
    "RevocationsDir": "revocations/",
    "TsaTrustDir": "tsa-trust/",
    "CreatorLedgerDir": "creatorledger/"
  }
}
```

### Directory Layout

```
my-claim-pack/
├── manifest.json
├── claim.json
├── claims/           # Cited claim bundles
├── evidence/         # Evidence files
├── revocations/      # Revocation bundles
├── tsa-trust/        # TSA certificates
└── creatorledger/    # CreatorLedger proof bundles
    ├── abc123def456.json
    └── fed987cba654.json
```

Bundles are named by their SHA-256 digest (lowercase hex).

## CLI Commands

### Creating Packs with CreatorLedger

```bash
claimledger pack claim.json \
  --out ./my-pack \
  --include-creatorledger ./creatorledger-bundles \
  --strict-creatorledger
```

#### Options

| Option | Description |
|--------|-------------|
| `--include-creatorledger <dir>` | Directory containing CreatorLedger bundles to include |
| `--strict-creatorledger` | Fail if any CREATORLEDGER_BUNDLE evidence cannot be resolved |

### Verifying Packs with CreatorLedger

```bash
claimledger verify-pack ./my-pack \
  --verify-creatorledger \
  --strict-creatorledger
```

#### Options

| Option | Description |
|--------|-------------|
| `--verify-creatorledger` | Verify CreatorLedger bundle evidence |
| `--strict-creatorledger` | Fail if any bundle is missing or invalid |
| `--creatorledger-dir <dir>` | Override directory for resolving bundles |

## Verification Process

When `--verify-creatorledger` is specified:

1. **Find Evidence**: Locate all `CREATORLEDGER_BUNDLE` evidence items
2. **Resolve Bundles**: Match bundles by digest from:
   - Pack's `creatorledger/` directory (if present)
   - External directory via `--creatorledger-dir`
3. **Verify Digest**: Confirm SHA-256 of bundle bytes matches evidence hash
4. **Verify Signatures**: Run full CreatorLedger verification:
   - Check version is `proof.v1`
   - Validate Ed25519 signatures on all attestations
   - Confirm asset ID matches primary attestation
5. **Report Results**: Return verification summary

### Verification Results

```json
{
  "CreatorLedgerResult": {
    "IsValid": true,
    "TotalBundles": 2,
    "BundlesVerified": 2,
    "BundlesMissing": 0,
    "BundlesFailed": 0,
    "Results": [
      {
        "EvidenceHash": "abc123...",
        "Status": "VERIFIED",
        "AssetId": "asset_test123",
        "ContentHash": "def456...",
        "TrustLevel": "Verified Original"
      }
    ]
  }
}
```

### Trust Levels

| Level | Description |
|-------|-------------|
| `Signed` | Valid Ed25519 signature, no blockchain anchor |
| `Verified Original` | Anchored to blockchain |
| `Derived` | Derived from another asset |

## Strict vs Non-Strict Mode

| Scenario | Strict | Non-Strict |
|----------|--------|------------|
| Bundle missing | FAIL | WARN (continue) |
| Invalid signature | FAIL | FAIL |
| Digest mismatch | FAIL | FAIL |
| No CL evidence | PASS | PASS |

## CreatorLedger Bundle Format

The bridge expects CreatorLedger `proof.v1` bundles:

```json
{
  "Version": "proof.v1",
  "Algorithms": {
    "Signature": "Ed25519",
    "Hash": "SHA-256",
    "Encoding": "UTF-8"
  },
  "AssetId": "asset_test123",
  "Attestations": [
    {
      "AttestationId": "att_abc123",
      "AssetId": "asset_test123",
      "ContentHash": "def456...",
      "CreatorId": "creator_xyz",
      "CreatorPublicKey": "ed25519:...",
      "AttestedAtUtc": "2024-01-15T10:30:00Z",
      "Signature": "..."
    }
  ],
  "Anchor": {
    "ChainName": "Bitcoin",
    "TransactionId": "tx_...",
    "BlockNumber": 800000
  }
}
```

## Interface for Custom Verifiers

```csharp
public interface ICreatorLedgerVerifier
{
    /// <summary>
    /// Verifies a CreatorLedger proof bundle from its JSON bytes.
    /// </summary>
    CreatorLedgerVerificationResult Verify(byte[] bundleBytes);

    /// <summary>
    /// Computes the canonical digest of a bundle.
    /// </summary>
    string ComputeBundleDigest(byte[] bundleBytes);
}
```

This allows future extension to custom or alternative verification implementations.

## Example Workflow

### 1. Attest Asset in CreatorLedger

```bash
# In CreatorLedger
creatorledger attest --asset-id asset_123 --content ./photo.jpg
creatorledger export --asset-id asset_123 --out proof.json
```

### 2. Create Claim Referencing Bundle

```json
{
  "Claim": {
    "Statement": "This photo was taken at location X on date Y",
    "Evidence": [
      {
        "Type": "application/json",
        "Hash": "<sha256 of proof.json>",
        "Kind": "CREATORLEDGER_BUNDLE",
        "BundleAssetId": "asset_123"
      }
    ]
  }
}
```

### 3. Package with Bundle

```bash
claimledger pack claim.json \
  --out ./photo-claim-pack \
  --include-creatorledger ./proofs \
  --strict-creatorledger
```

### 4. Verify Offline

```bash
claimledger verify-pack ./photo-claim-pack \
  --verify-creatorledger \
  --strict-creatorledger
```

## Security Considerations

1. **Digest Binding**: Evidence hash must match exact bundle bytes
2. **Signature Verification**: All attestation signatures are cryptographically verified
3. **No Network Calls**: Verification is fully offline
4. **Trust Anchors**: Blockchain anchors provide additional assurance but are not required

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All verification passed |
| 3 | Signature/integrity failure (BROKEN) |
| 4 | Invalid input (missing files, bad format) |

## Backward Compatibility

- Bundles without `Kind` field treat evidence as `FILE`
- Existing packs without `CreatorLedgerDir` continue to work
- New fields are omitted when `null` (JSON serialization)
