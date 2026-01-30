# Witness Timestamping

ClaimLedger supports witness timestamping — a cryptographic proof that a claim existed at a specific point in time.

## What Witness Timestamping Does

A witness timestamp is a special attestation that says:

> "I, the witness, observed claim X at time T"

The witness:
1. Computes the `claim_core_digest` of the bundle
2. Creates an attestation binding that digest to `issued_at`
3. Signs the attestation with their Ed25519 key

## When to Use Witness Timestamping

| Scenario | Benefit |
|----------|---------|
| Priority disputes | Prove you made a claim before a competitor |
| Grant compliance | Demonstrate claims were made during funding period |
| Legal/IP protection | Establish prior art |
| Archive snapshots | Create verifiable checkpoints |

## CLI Usage

### Create a Witness Timestamp

```bash
# Witness a claim bundle
claimledger witness claim.json \
  --witness-key witness-service.key.json \
  --out claim.witnessed.json

# Witness with explicit timestamp
claimledger witness claim.json \
  --witness-key witness-service.key.json \
  --issued-at "2024-06-15T12:00:00Z" \
  --out claim.witnessed.json

# Witness with custom statement
claimledger witness claim.json \
  --witness-key witness-service.key.json \
  --statement "Archived by Example University Library" \
  --out claim.witnessed.json
```

### Verify Witnessed Claims

```bash
# Verify all attestations including witness timestamps
claimledger verify claim.witnessed.json --attestations

# Verify with revocation checking (witness keys can be revoked too)
claimledger verify claim.witnessed.json \
  --attestations \
  --revocations-dir ./revocations/ \
  --strict-revocations
```

## Attestation Format

Witness attestations use the `WITNESSED_AT` type:

```json
{
  "attestation_id": "uuid",
  "claim_core_digest": "sha256-hex",
  "attestor": {
    "researcher_id": "uuid",
    "public_key": "ed25519:base64",
    "display_name": "Witness Service"
  },
  "attestation_type": "WITNESSED_AT",
  "statement": "Witnessed claim existence",
  "issued_at_utc": "2024-06-15T12:00:00.0000000Z",
  "signature": "base64"
}
```

## Claim Core Digest

The `claim_core_digest` is computed from:
- Claim ID
- Statement
- Researcher ID
- Researcher public key
- Evidence list (types, hashes, locators)
- Asserted at timestamp
- **Citations** (included in core digest)

**NOT included** (append-only):
- Attestations (including witness timestamps)

This means:
- Multiple witnesses can attest to the same claim
- Adding attestations doesn't change the claim's identity
- Witness timestamps bind to the claim's content, not its attestation history

## Multiple Witnesses

You can have multiple witness attestations on a single claim:

```bash
# First witness
claimledger witness claim.json \
  --witness-key alice.key.json \
  --out claim.witnessed.json

# Second witness (appends to existing)
claimledger witness claim.witnessed.json \
  --witness-key bob.key.json \
  --out claim.multi-witnessed.json
```

All witnesses attest to the same `claim_core_digest`:

```json
{
  "attestations": [
    {
      "attestation_type": "WITNESSED_AT",
      "claim_core_digest": "abc123...",
      "attestor": { "display_name": "Alice" },
      "issued_at_utc": "2024-06-15T10:00:00Z"
    },
    {
      "attestation_type": "WITNESSED_AT",
      "claim_core_digest": "abc123...",
      "attestor": { "display_name": "Bob" },
      "issued_at_utc": "2024-06-15T11:00:00Z"
    }
  ]
}
```

## Revocation and Witness Keys

Witness keys can be revoked just like any other key:

```bash
# Revoke a witness key
claimledger revoke-key old-witness.key.json \
  --reason ROTATED \
  --successor-key new-witness.key.json \
  --out revocations/witness-2024.revoked.json
```

When verifying:

| Revoked At | Witnessed At | Valid? |
|------------|--------------|--------|
| 2024-06-15 12:00 | 2024-06-15 11:59 | Yes (witnessed before revocation) |
| 2024-06-15 12:00 | 2024-06-15 12:00 | **No** (boundary case) |
| 2024-06-15 12:00 | 2024-06-15 12:01 | **No** (witnessed after revocation) |

## Trust Model

ClaimLedger doesn't tell you *which* witnesses to trust. It only verifies:

1. The attestation signature is valid
2. The witness key wasn't revoked at the time of witnessing
3. The `claim_core_digest` matches the claim

You decide:
- Which witness services are authoritative for your use case
- Whether multiple witnesses are required
- How to handle key compromise scenarios

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid — all attestations verified |
| 3 | Broken — tampered attestation or invalid signature |
| 6 | Revoked — witness key was revoked at time of witnessing |

## Running a Witness Service

To operate a witness service:

1. **Generate a dedicated key pair**:
   ```bash
   claimledger generate-key --out witness-service.key.json
   ```

2. **Publish your public key** so others can verify your timestamps

3. **Accept claim bundles** and create witness attestations

4. **Rotate keys periodically** with proper revocation:
   ```bash
   claimledger revoke-key old.key.json \
     --reason ROTATED \
     --successor-key new.key.json \
     --out revocations/witness-rotation.revoked.json
   ```

5. **Publish your revocations** alongside your public key

## Comparison with Other Timestamping

| Feature | ClaimLedger | RFC 3161 (TSA) | Blockchain |
|---------|-------------|----------------|------------|
| Central authority | No | Yes (TSA) | No (consensus) |
| Works offline | Yes | No | No |
| Multiple witnesses | Yes | Possible | Inherent |
| Key revocation | Yes | CA-based | N/A |
| Cost | Free | Usually paid | Gas fees |
| Latency | Instant | Seconds | Minutes-hours |

## Backwards Compatibility

- Phase 1-4 bundles verify unchanged
- `WITNESSED_AT` is a new attestation type, not a breaking change
- Existing attestation types (`REVIEWED`, `REPRODUCED`, etc.) work alongside witness timestamps
