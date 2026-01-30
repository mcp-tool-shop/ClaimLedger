# ClaimPack

ClaimPack is a portable artifact that contains everything needed to verify a claim offline end-to-end.

## What ClaimPack Solves

When sharing scientific claims, recipients need:
- The claim bundle itself
- Any cited claims (for citation verification)
- Evidence files (to verify hashes match)
- Revocation records (to check if keys are revoked)
- TSA trust anchors (to verify RFC 3161 timestamps)

A ClaimPack bundles all of this into a single directory (or zip) with a cryptographic manifest.

## Pack Layout

```
my-claim.pack/
├── manifest.json           ← Integrity index (ClaimPackManifest.v1)
├── claim.json              ← Root claim bundle
├── claims/                 ← Cited claim bundles (optional)
│   ├── <digest>.json
│   └── ...
├── evidence/               ← Evidence files (optional)
│   ├── data.csv
│   └── ...
├── revocations/            ← Revocation records (optional)
│   └── *.json
└── tsa-trust/              ← TSA certificates (optional)
    └── *.pem
```

## Manifest Format

```json
{
  "Contract": "ClaimPackManifest.v1",
  "PackId": "uuid",
  "CreatedAt": "ISO-8601",
  "RootClaimPath": "claim.json",
  "RootClaimCoreDigest": "sha256-hex",
  "Include": {
    "ClaimsDir": "claims/",
    "EvidenceDir": "evidence/",
    "RevocationsDir": "revocations/",
    "TsaTrustDir": "tsa-trust/"
  },
  "Files": [
    {
      "Path": "claim.json",
      "MediaType": "application/json",
      "Sha256Hex": "hash",
      "SizeBytes": 1234
    }
  ]
}
```

## CLI Usage

### Create a Pack

```bash
# Minimal pack (just the claim)
claimledger pack claim.json --out my-claim.pack/

# With citations included
claimledger pack claim.json --out my-claim.pack/ --include-citations

# With evidence
claimledger pack claim.json --out my-claim.pack/ --evidence ./data/

# With revocations
claimledger pack claim.json --out my-claim.pack/ --revocations ./revocations/

# With TSA trust anchors
claimledger pack claim.json --out my-claim.pack/ --tsa-trust ./tsa-certs/

# Full example
claimledger pack claim.json --out my-claim.pack/ \
  --include-citations \
  --evidence ./data/ \
  --revocations ./revocations/ \
  --tsa-trust ./tsa-certs/
```

### Verify a Pack

```bash
# Basic verification
claimledger verify-pack my-claim.pack/

# Strict mode (fails on any issue)
claimledger verify-pack my-claim.pack/ --strict

# Strict citation resolution
claimledger verify-pack my-claim.pack/ --strict-citations

# Strict revocation checking
claimledger verify-pack my-claim.pack/ --strict-revocations

# Strict TSA trust validation
claimledger verify-pack my-claim.pack/ --strict-tsa

# All strict
claimledger verify-pack my-claim.pack/ --strict
```

### Inspect a Pack

```bash
# Show manifest details
claimledger pack-inspect my-claim.pack/

# Show file inventory
claimledger pack-inspect my-claim.pack/ --files
```

## Verification Semantics

### 1. Manifest Enforcement

- All paths in `Files[]` are validated for safety (no `..`, no absolute paths)
- All files must exist with matching hash and size
- No duplicate paths allowed
- In strict mode: no extra files outside manifest

### 2. Root Claim Integrity

- Load `claim.json` and compute `claim_core_digest`
- Must match `RootClaimCoreDigest` in manifest
- In strict mode: fails if mismatch; otherwise warns

### 3. Citation Verification

- If `Include.ClaimsDir` exists, load cited bundles
- Resolve citations from embedded bundles or `claims/` directory
- Verify all citation signatures
- In strict mode: fails if any citation unresolved

### 4. Attestation Verification

- Verify all attestation signatures in the root bundle
- Check attestation bindings to `claim_core_digest`

### 5. Revocation Checking

- If `Include.RevocationsDir` exists, load revocation records
- Check if any signer key is revoked
- Exit code 6 (REVOKED) if claim signed with revoked key in strict mode

### 6. TSA Timestamp Verification

- If `Include.TsaTrustDir` exists, load TSA certificates
- Verify RFC 3161 timestamp tokens
- In strict mode: fails if timestamp untrusted

### 7. Evidence Verification (Strict Only)

- If `Include.EvidenceDir` exists and strict mode enabled
- Verify evidence files match hashes in claim
- Fails if any evidence missing

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid — pack verified |
| 3 | Broken — tampered content, invalid signature, or strict mode failure |
| 4 | Invalid input — missing manifest, invalid paths, malformed JSON |
| 5 | Error — unexpected failure |
| 6 | Revoked — signer key is revoked |

## Security Notes

### Path Safety

The pack validator rejects:
- Path traversal (`..`, `../`)
- Absolute paths (`/etc/passwd`, `C:\Windows`)
- UNC paths (`\\server\share`)
- Windows reserved names (`CON`, `PRN`, `NUL`, `COM1`, etc.)
- Null bytes in paths

### Manifest Trust

The manifest is trusted as the source of truth for file inventory. If an attacker modifies the manifest:
- Hash mismatches will be detected
- The `RootClaimCoreDigest` binding catches manifest tampering

### Offline Verification

ClaimPack is designed for offline verification:
- No network calls during verification
- TSA trust anchors must be pre-distributed
- CRL/OCSP checking not performed

## Examples

### Creating a Pack for Publication

```bash
# Start with a signed claim
claimledger verify claim.json

# Create a full pack
claimledger pack claim.json \
  --out publication.pack/ \
  --include-citations \
  --evidence ./experiments/ \
  --tsa-trust ./tsa-certs/

# Verify before distribution
claimledger verify-pack publication.pack/ --strict
```

### Receiving and Verifying a Pack

```bash
# Verify the pack
claimledger verify-pack received.pack/

# If verification passes, inspect the claim
claimledger inspect received.pack/claim.json

# Check specific attestations
claimledger attestations received.pack/claim.json
```

### Adding Revocations After Key Rotation

```bash
# Generate revocation
claimledger revoke-key old.key.json \
  --reason ROTATED \
  --successor-key new.key.json \
  --out revocations/old.revoked.json

# Rebuild pack with revocations
claimledger pack claim.json \
  --out updated.pack/ \
  --revocations ./revocations/
```

## Best Practices

1. **Always verify before distributing**: Run `verify-pack --strict` before sharing
2. **Include evidence for reproducibility**: If claims reference data, include it
3. **Distribute TSA certificates**: For long-term archives, include TSA trust anchors
4. **Use strict mode for critical verification**: Catches issues that non-strict mode warns about
5. **Keep packs immutable**: Don't modify pack contents after creation

## Manifest Signatures (Phase 8)

ClaimPack supports optional manifest signatures for container authenticity. This allows pack creators to cryptographically sign the manifest, providing:
- **Authorship proof**: The claim author signed this exact pack
- **Distribution integrity**: A publisher vouches for this distribution
- **Multi-party trust**: Multiple signers can co-sign the same pack

### Manifest Signature Format

```json
{
  "Contract": "ClaimPackManifest.v1",
  "PackId": "...",
  "CreatedAt": "...",
  "RootClaimPath": "claim.json",
  "RootClaimCoreDigest": "...",
  "Include": { ... },
  "Files": [ ... ],
  "manifest_signatures": [
    {
      "signable": {
        "contract": "ClaimPackManifestSignable.v1",
        "manifest_sha256_hex": "<hash of canonical manifest>",
        "pack_id": "<from manifest>",
        "root_claim_core_digest": "<from manifest>",
        "created_at": "<from manifest>"
      },
      "signature": {
        "alg": "Ed25519",
        "public_key": "<signer public key>",
        "sig": "<Ed25519 signature>"
      },
      "signer": {
        "kind": "CLAIM_AUTHOR",
        "identity": {
          "researcher_id": "did:key:...",
          "display_name": "Dr. Jane Smith",
          "public_key": "<signer public key>"
        }
      }
    }
  ]
}
```

### Signer Roles

| Kind | Meaning |
|------|---------|
| `CLAIM_AUTHOR` | The person who created the claim also packaged it |
| `PUBLISHER` | A trusted distributor vouches for pack integrity |

Both roles are independently valid ("Either" model). A pack can have signatures from multiple signers with different roles.

### Canonical Hash Computation

The `manifest_sha256_hex` is computed by:
1. Serialize the manifest **excluding** `manifest_signatures`
2. Use canonical JSON (sorted keys, no whitespace)
3. SHA-256 hash the UTF-8 bytes
4. Output as lowercase hex

This ensures signatures remain valid when new signatures are appended.

### CLI: Signing a Pack

```bash
# Sign as claim author
claimledger pack-sign my-claim.pack/ \
  --signer-key author.key.json \
  --signer-kind CLAIM_AUTHOR

# Sign as publisher (different output directory)
claimledger pack-sign my-claim.pack/ \
  --signer-key publisher.key.json \
  --signer-kind PUBLISHER \
  --out distributed.pack/

# Co-sign (add second signature)
claimledger pack-sign my-claim.pack/ \
  --signer-key second-author.key.json \
  --signer-kind CLAIM_AUTHOR
```

Options:
- `--signer-key <path>` — Ed25519 private key (ResearcherId.vN.json)
- `--signer-kind <kind>` — `CLAIM_AUTHOR` or `PUBLISHER`
- `--out <dir>` — Output directory (default: modify in-place)

### CLI: Verifying Manifest Signatures

```bash
# Verify pack with manifest signature checking
claimledger verify-pack my-claim.pack/ --verify-manifest-signatures

# Strict mode: fail if no valid manifest signatures
claimledger verify-pack my-claim.pack/ --strict-manifest-signatures

# Combined with other strict flags
claimledger verify-pack my-claim.pack/ \
  --strict \
  --strict-manifest-signatures
```

Flags:
- `--verify-manifest-signatures` — Check signatures if present, warn if invalid
- `--strict-manifest-signatures` — Fail if no valid signatures present

### Manifest Signature Verification

When `--verify-manifest-signatures` is enabled:

1. **Manifest hash binding**: Recompute canonical hash, verify it matches `signable.manifest_sha256_hex`
2. **Cryptographic verification**: Verify Ed25519 signature over canonical signable JSON
3. **Revocation checking**: If revocations directory exists, check if signer key is revoked

Verification results:
- **Valid**: At least one signature passes all checks
- **Broken**: Signatures present but all fail verification
- **Warning**: No signatures present (non-strict mode)
- **Fail**: No valid signatures (strict mode)

### Security Considerations

**What manifest signatures protect:**
- Manifest tampering (changing file hashes, pack ID, etc.)
- File substitution (adding/removing files from manifest)
- Root claim binding (ensures pack contains intended claim)

**What manifest signatures do NOT protect:**
- Individual claim signatures (verified separately)
- Evidence file authenticity (hashes already in manifest)
- Citation chain validity (verified during pack verification)

**Key revocation:**
- If a manifest signer's key is revoked, that signature becomes invalid
- Other valid signatures still count
- With `--strict-manifest-signatures`, at least one valid (non-revoked) signature required

### Examples

#### Publisher Workflow

```bash
# Receive pack from author
claimledger verify-pack received.pack/ --verify-manifest-signatures

# Add publisher signature for distribution
claimledger pack-sign received.pack/ \
  --signer-key publisher.key.json \
  --signer-kind PUBLISHER \
  --out published.pack/

# Verify before publishing
claimledger verify-pack published.pack/ --strict --strict-manifest-signatures
```

#### Multi-Author Collaboration

```bash
# First author creates and signs
claimledger pack claim.json --out collab.pack/
claimledger pack-sign collab.pack/ \
  --signer-key alice.key.json \
  --signer-kind CLAIM_AUTHOR

# Second author co-signs
claimledger pack-sign collab.pack/ \
  --signer-key bob.key.json \
  --signer-kind CLAIM_AUTHOR

# Now pack has two author signatures
```

#### Verifying Provenance

```bash
# Check who signed the pack
claimledger verify-pack paper.pack/ --verify-manifest-signatures

# Output shows:
# Manifest Signatures: 2 valid
#   [1] CLAIM_AUTHOR: did:key:z6Mk... (Dr. Alice)
#   [2] PUBLISHER: did:key:z6Mk... (Journal Corp)
```

## Pack Diff and Update Validation (Phase 9)

ClaimLedger provides tools for comparing pack versions and validating updates against policies.

### Update Classification

When comparing two packs, the diff engine classifies the update:

| Class | Meaning |
|-------|---------|
| `IDENTICAL` | No changes at all |
| `APPEND_ONLY` | Only additions, no removals or modifications to protected content |
| `MODIFIED` | Changes present but not destructive |
| `BREAKING` | Root digest changed, or removals/modifications to protected content |

### CLI: Diffing Packs

```bash
# Text output (human-readable)
claimledger pack-diff ./packA ./packB

# JSON output
claimledger pack-diff ./packA ./packB --format json

# Save report to file
claimledger pack-diff ./packA ./packB --out diff-report.json

# Fail if update class is MODIFIED or worse
claimledger pack-diff ./packA ./packB --fail-on MODIFIED

# Fail only if BREAKING
claimledger pack-diff ./packA ./packB --fail-on BREAKING
```

### CLI: Validating Updates

```bash
# Validate against APPEND_ONLY policy (default)
claimledger pack-validate-update ./packA ./packB

# Explicit policy
claimledger pack-validate-update ./packA ./packB --policy APPEND_ONLY

# Allow modifications (but not breaking changes)
claimledger pack-validate-update ./packA ./packB --policy ALLOW_MODIFIED

# Save validation report
claimledger pack-validate-update ./packA ./packB --out validation.json
```

### Update Policies

**APPEND_ONLY** (recommended for production):
- Root claim core digest must not change
- No file removals
- No file modifications (except claim.json/manifest.json for semantic appends)
- No attestation, timestamp, or manifest signature removals/modifications
- No revocation removals
- Allowed: new attestations, timestamps, manifest signatures, revocations, files

**ALLOW_MODIFIED**:
- No BREAKING changes allowed
- File modifications permitted
- Semantic modifications permitted

### Policy Violation Types

| Violation | Description |
|-----------|-------------|
| `ROOT_DIGEST_CHANGED` | Root claim core digest was modified |
| `FILE_REMOVED` | A file was removed from the pack |
| `FILE_MODIFIED` | A file's content was changed |
| `ATTESTATION_REMOVED` | An attestation was removed |
| `EXISTING_ATTESTATION_MODIFIED` | An attestation was modified |
| `TIMESTAMP_REMOVED` | A timestamp receipt was removed |
| `EXISTING_TIMESTAMP_MODIFIED` | A timestamp receipt was modified |
| `MANIFEST_SIGNATURE_REMOVED` | A manifest signature was removed |
| `EXISTING_MANIFEST_SIGNATURE_MODIFIED` | A manifest signature was modified |
| `REVOCATION_REMOVED` | A revocation record was removed |
| `CITATION_CHANGED` | A citation was added, removed, or modified |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Diff computed / policy passed |
| 2 | Policy violation |
| 4 | Invalid input |
| 5 | Error |

### Diff Report Format

```json
{
  "Contract": "ClaimPackDiffReport.v1",
  "GeneratedAt": "2024-01-15T10:30:00Z",
  "PackA": {
    "PackId": "uuid",
    "RootClaimCoreDigest": "sha256-hex",
    "CreatedAt": "ISO-8601",
    "FileCount": 5
  },
  "PackB": { ... },
  "UpdateClass": "APPEND_ONLY",
  "Files": {
    "Added": [...],
    "Removed": [...],
    "Modified": [...],
    "UnchangedCount": 4
  },
  "Semantics": {
    "RootDigestChanged": false,
    "Attestations": { "Added": [...], "Removed": [], "Modified": [], "UnchangedCount": 1 },
    "Timestamps": { ... },
    "ManifestSignatures": { ... },
    "Revocations": { ... },
    "Citations": { ... }
  }
}
```

### Examples

#### CI Pipeline Validation

```bash
# Validate that a PR only adds content (no breaking changes)
claimledger pack-validate-update ./main-pack ./pr-pack --policy APPEND_ONLY
if [ $? -eq 2 ]; then
    echo "Policy violation: update contains breaking changes"
    exit 1
fi
```

#### Comparing Pack Versions

```bash
# See what changed between versions
claimledger pack-diff ./v1.pack ./v2.pack

# Output:
# Pack Diff Report
# ================
# Pack A: abc123...
# Pack B: def456...
# Update Class: APPEND_ONLY
#
# File Changes:
#   Added: 1
#   Unchanged: 5
#
# Semantic Changes:
#   Attestations: +2 added
```

## Backwards Compatibility

- Phase 1-6 bundles work unchanged in packs
- `manifest.json` is a new file; existing verifiers ignore it
- Non-pack verification still works with `claimledger verify`
- Unsigned manifests remain valid (manifest_signatures is optional)
- Adding signatures does not break existing pack consumers
- Pack diff tools work with any ClaimPackManifest.v1 pack
