# Key Revocation

ClaimLedger supports offline, cryptographic key revocation. When a signing key is compromised or rotated, you can revoke it without any central authority or network access.

## What Revocation Does

A revocation is a signed statement that says:

> "Public key X is revoked as of time T"

Any signature made by key X at or after time T is considered invalid.

## What Revocation Does NOT Do

- **No trust lists**: There's no "approved revokers" list
- **No central authority**: Revocations are verified locally
- **No network calls**: Everything works offline
- **No reputation**: Revocation is binary, not weighted

## Revocation Contract: `IdentityRevocation.v1`

```json
{
  "contract": "IdentityRevocation.v1",
  "revocation_id": "uuid",
  "researcher_id": "uuid",
  "revoked_public_key": "ed25519:base64",
  "revoked_at": "2024-06-15T12:00:00Z",
  "reason": "ROTATED",
  "issuer_mode": "SELF",
  "successor_public_key": "ed25519:base64",
  "notes": "Annual key rotation"
}
```

## Issuer Modes

Who can sign a revocation?

### SELF (Planned Rotation)

The revoked key signs its own revocation. Use this for:
- Planned key rotation
- Retirement
- Preemptive revocation before a suspected compromise

```bash
claimledger revoke-key author.key.json \
  --reason ROTATED \
  --successor-key new-author.key.json \
  --out revocation.json
```

### SUCCESSOR (Compromise Recovery)

The new key signs the revocation of the old key. Use this when:
- The old key may be compromised
- You can't use the old key to sign

```bash
claimledger revoke-key old.key.json \
  --reason COMPROMISED \
  --successor-key new.key.json \
  --successor-signed \
  --out revocation.json
```

## Time Semantics

The core rule:

> A signature made at time `t_signed` is **invalid** if `revoked_at <= t_signed`

### Examples

| Revoked At | Signed At | Valid? |
|------------|-----------|--------|
| 2024-06-15 12:00 | 2024-06-15 11:59 | Yes (before revocation) |
| 2024-06-15 12:00 | 2024-06-15 12:00 | **No** (at revocation) |
| 2024-06-15 12:00 | 2024-06-15 12:01 | **No** (after revocation) |

The boundary case (`revoked_at == signed_at`) is **invalid**. This is the conservative choice.

## Multiple Revocations

If multiple valid revocations exist for the same key, the **earliest** `revoked_at` wins.

```
Revocation 1: revoked_at = 2024-06-15
Revocation 2: revoked_at = 2024-06-01  ← This one applies
```

## Successor Chains

You can chain key rotations:

```
Key A → Key B → Key C
```

Each revocation is independent:
- A revokes itself, declares B as successor
- B revokes itself, declares C as successor

The verifier tracks each key's revocation time independently.

## Revocation Reasons

| Reason | When to Use |
|--------|-------------|
| `COMPROMISED` | Key was stolen or leaked |
| `ROTATED` | Planned key rotation (should have successor) |
| `RETIRED` | Identity is no longer active |
| `OTHER` | Unspecified reason |

## CLI Commands

### Create a Revocation

```bash
# Self-signed (most common)
claimledger revoke-key author.key.json \
  --reason ROTATED \
  --successor-key new-author.key.json \
  --notes "Annual rotation" \
  --out revocations/author-2024.revoked.json

# Successor-signed (for compromises)
claimledger revoke-key compromised.key.json \
  --reason COMPROMISED \
  --successor-key recovery.key.json \
  --successor-signed \
  --revoked-at "2024-06-01T00:00:00Z" \
  --out revocations/compromised.revoked.json
```

### Verify with Revocation Checking

```bash
# Load revocations, warn on revoked keys
claimledger verify claim.json --revocations-dir ./revocations/

# Strict mode: fail if any signer is revoked
claimledger verify claim.json --revocations-dir ./revocations/ --strict-revocations
```

### List Revocations

```bash
claimledger revocations ./revocations/
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid |
| 3 | Broken (tampered or bad signature) |
| 6 | Revoked (cryptographically valid but signer key revoked) |

Exit code 6 is distinct from 3 because:
- **3** = integrity failure (signature doesn't match)
- **6** = policy failure (signature is valid but key is revoked)

CI pipelines can treat these differently.

## Directory Structure

Organize revocations by identity or date:

```
revocations/
├── alice-2024-01.revoked.json
├── alice-2024-06.revoked.json
├── bob-compromised.revoked.json
└── retired/
    └── charlie.revoked.json
```

The verifier loads all `*.json` files recursively.

## Backward Compatibility

- If `--revocations-dir` is not provided, revocation checking is skipped
- Phase 1-3 bundles verify unchanged
- Exit code 6 only occurs when revocations are loaded

## Security Considerations

### Backdating Revocations

You can set `revoked_at` in the past. This invalidates all signatures made between then and now. Use with caution.

### No Un-Revocation

Revocations are permanent. If you revoke by mistake, issue a new key and re-sign your claims.

### Revocation Distribution

ClaimLedger doesn't distribute revocations. You must:
1. Publish revocations alongside your bundles
2. Share them via your own channels
3. Bundle them with your claim collections

This is intentional — no central revocation list means no single point of failure.
