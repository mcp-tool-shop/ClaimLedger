# Publish Command

The `publish` command creates a ready-to-share ClaimPack from a claim bundle. It orchestrates pack creation, optional signing, and runs a verification gate to ensure the artifact is valid before distribution.

## Quick Start

```bash
# Basic publish to directory
claimledger publish claim.json --out ./dist/my-pack

# Publish as ZIP
claimledger publish claim.json --out ./dist/my-pack.zip

# Publish with evidence
claimledger publish claim.json --out ./dist/my-pack \
  --evidence ./data

# Publish signed (publisher)
claimledger publish claim.json --out ./dist/my-pack.zip \
  --sign-pack \
  --publisher-key publisher.key.json \
  --publisher-identity publisher.identity.json

# Publish with full options
claimledger publish claim.json --out ./dist/my-pack.zip \
  --evidence ./data \
  --creatorledger ./proofs \
  --revocations ./revocations \
  --tsa-trust ./tsa-certs \
  --sign-pack \
  --publisher-key publisher.key.json \
  --publisher-identity publisher.identity.json \
  --author-key author.key.json \
  --author-identity author.identity.json \
  --report ./dist/publish-report.json
```

## What Publish Does

The command performs these steps in order:

1. **Build Pack**: Creates a pack directory with the claim bundle, evidence, citations, CreatorLedger bundles, revocations, and TSA trust anchors.

2. **Sign Manifest** (if `--sign-pack`): Adds publisher and/or author signatures to the manifest.

3. **Verification Gate**: Runs `verify-pack` with strict flags to ensure the artifact is valid. Publishing fails if verification fails.

4. **Emit Artifact**: Creates the output as a directory or ZIP file.

5. **Emit Report**: Writes a JSON report describing what was published.

## CLI Options

### Required

| Option | Description |
|--------|-------------|
| `<claim>` | Path to the input claim bundle JSON file |
| `--out, -o` | Output path (directory or .zip file) |

### Output Format

| Option | Default | Description |
|--------|---------|-------------|
| `--zip` | Auto | Output as ZIP (auto-detected if `--out` ends with `.zip`) |

### Include Options

| Option | Default | Description |
|--------|---------|-------------|
| `--evidence, -e` | - | Directory containing evidence files |
| `--creatorledger` | - | Directory containing CreatorLedger proof bundles |
| `--revocations` | - | Directory containing revocation files |
| `--tsa-trust` | - | Directory containing TSA trust anchor certificates |
| `--include-citations` | true | Include embedded citations in the pack |
| `--include-attestations` | true | Include attestations in verification |
| `--include-timestamps` | true | Include timestamp receipts in verification |

### Signing Options

| Option | Description |
|--------|-------------|
| `--sign-pack` | Sign the pack manifest |
| `--publisher-key` | Path to publisher private key JSON file |
| `--publisher-identity` | Path to publisher identity JSON file |
| `--author-key` | Path to author private key JSON file |
| `--author-identity` | Path to author identity JSON file |

### Verification Options

| Option | Default | Description |
|--------|---------|-------------|
| `--strict` | true | Run strict verification gate |

### Report Options

| Option | Description |
|--------|-------------|
| `--report` | Path to write publish report JSON |

## Key Files

### Private Key File Format

```json
{
  "private_key": "hex-encoded-32-byte-ed25519-seed"
}
```

### Identity File Format

```json
{
  "researcher_id": "uuid",
  "public_key": "hex-encoded-32-byte-ed25519-public-key",
  "display_name": "Optional Display Name"
}
```

## Publish Report

The report captures exactly what happened during publishing.

### Contract: PublishReport.v1

```json
{
  "contract": "PublishReport.v1",
  "published_at": "2024-01-15T10:30:00Z",
  "input_claim_path": "claim.json",
  "output_path": "./dist/claimpack.zip",
  "output_kind": "ZIP",
  "root_claim_core_digest": "abc123...",
  "pack_id": "uuid",
  "manifest_sha256_hex": "def456...",
  "included": {
    "citations": true,
    "attestations": true,
    "timestamps": false,
    "evidence": true,
    "creatorledger": false,
    "revocations": false,
    "tsa_trust": false
  },
  "counts": {
    "claims": 3,
    "evidence_files": 4,
    "creatorledger_bundles": 0,
    "revocations": 0,
    "timestamp_receipts": 0,
    "attestations": 2,
    "manifest_signatures": 1
  },
  "signing": {
    "publisher_signed": true,
    "author_signed": false
  },
  "verification_gate": {
    "strict": true,
    "exit_code": 0,
    "result": "PASS",
    "notes": [
      "Building pack...",
      "Pack created with 8 files",
      "Signing manifest as publisher...",
      "Publisher signature added",
      "Running verification gate...",
      "Verification gate PASSED"
    ]
  }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Published successfully |
| 3 | Verification gate failed (broken) |
| 4 | Invalid input (missing files, bad keys) |
| 5 | Internal error |
| 6 | Revoked signer detected |

## Common Workflows

### Publish a Claim with Evidence

```bash
# Organize your files
my-claim/
├── claim.json
└── data/
    ├── results.csv
    ├── analysis.pdf
    └── raw/
        └── measurements.json

# Publish with evidence
claimledger publish my-claim/claim.json \
  --out dist/my-claim-pack.zip \
  --evidence my-claim/data
```

### Publish with CreatorLedger Evidence

```bash
# When your claim references CreatorLedger bundles
claimledger publish claim.json \
  --out dist/pack.zip \
  --creatorledger ./creatorledger-proofs
```

### Publish with TSA Timestamps

```bash
# If your claim has RFC 3161 timestamp receipts
claimledger publish claim.json \
  --out dist/pack.zip \
  --tsa-trust ./tsa-certificates
```

### Publish Signed as Publisher

```bash
# Generate keys first (see identity documentation)
claimledger publish claim.json \
  --out dist/pack.zip \
  --sign-pack \
  --publisher-key my-publisher.key.json \
  --publisher-identity my-publisher.identity.json
```

### Publish with Full Audit Trail

```bash
claimledger publish claim.json \
  --out dist/pack.zip \
  --evidence ./data \
  --sign-pack \
  --publisher-key publisher.key.json \
  --publisher-identity publisher.identity.json \
  --report dist/publish-report.json

# The report can be used in CI/CD for auditing
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Publish ClaimPack
  run: |
    claimledger publish claim.json \
      --out dist/claimpack.zip \
      --evidence ./data \
      --sign-pack \
      --publisher-key ${{ secrets.PUBLISHER_KEY_PATH }} \
      --publisher-identity ./publisher.identity.json \
      --report dist/publish-report.json

- name: Upload Artifacts
  uses: actions/upload-artifact@v3
  with:
    name: claimpack
    path: |
      dist/claimpack.zip
      dist/publish-report.json

- name: Verify Report
  run: |
    # Check that gate passed
    jq -e '.verification_gate.result == "PASS"' dist/publish-report.json
```

### Using the Report in Scripts

```bash
# Extract key information
PACK_ID=$(jq -r '.pack_id' publish-report.json)
DIGEST=$(jq -r '.root_claim_core_digest' publish-report.json)
GATE_RESULT=$(jq -r '.verification_gate.result' publish-report.json)

echo "Published pack $PACK_ID"
echo "Root digest: $DIGEST"
echo "Gate: $GATE_RESULT"

# Fail CI if gate didn't pass
if [ "$GATE_RESULT" != "PASS" ]; then
  echo "Verification gate failed!"
  exit 1
fi
```

## Best Practices

1. **Always use strict mode** (default): Publishing should be a gate that ensures quality.

2. **Sign your packs**: Publisher signatures provide accountability.

3. **Include evidence**: Self-contained packs are more valuable.

4. **Generate reports**: Use them for audit trails and CI/CD.

5. **Verify before distributing**: The publish command does this automatically.

## Troubleshooting

### "Missing evidence file for hash"

Your claim references evidence with a hash that doesn't match any file in the evidence directory. Either:
- Add the correct evidence file
- Use `--strict=false` (not recommended for production)

### "CreatorLedger bundle not found"

Your claim references a CreatorLedger bundle that's not in the `--creatorledger` directory. Ensure the bundle file is present and its hash matches.

### "--sign-pack requires --publisher-key and/or --author-key"

When signing, you must provide at least one key pair. Include both the key and identity files:

```bash
--publisher-key publisher.key.json \
--publisher-identity publisher.identity.json
```

### "Verification gate failed"

The pack failed integrity verification. Check the report's `verification_gate.notes` for details. Common causes:
- Invalid signatures
- Missing files
- Hash mismatches
- Revoked keys
