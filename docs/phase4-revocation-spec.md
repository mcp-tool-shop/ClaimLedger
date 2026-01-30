# Phase 4: Key Revocation & Succession

## Problem Statement

Once keys are in use, compromises happen. Without revocation:
- A stolen key can sign claims forever
- No way to rotate keys safely
- No way to retire an identity

## Design Constraints (Non-Negotiable)

1. **Offline** — Verification never fetches anything
2. **No trust lists** — No "approved revokers" or "root authorities"
3. **Deterministic** — Same inputs always produce same verification result
4. **Backwards compatible** — Phase 1-3 bundles still verify unchanged
5. **Self-sovereign** — Only the key owner can revoke (or designated recovery key)

## New Frozen Contract: `IdentityRevocation.v1`

### Signable Fields (Canonical JSON)

```json
{
  "contract": "IdentityRevocation.v1",
  "revocation_id": "uuid",
  "researcher_id": "uuid",
  "revoked_public_key": "ed25519:base64",
  "revoked_at": "RFC3339 UTC",
  "reason": "COMPROMISED | ROTATED | RETIRED | OTHER",
  "issuer_mode": "SELF | SUCCESSOR",
  "successor_public_key": "ed25519:base64 | null",
  "notes": "optional string | null"
}
```

### Field Semantics

| Field | Required | Description |
|-------|----------|-------------|
| `contract` | Yes | Always `"IdentityRevocation.v1"` |
| `revocation_id` | Yes | Unique identifier for this revocation |
| `researcher_id` | Yes | The identity whose key is being revoked |
| `revoked_public_key` | Yes | The specific key being revoked |
| `revoked_at` | Yes | Effective revocation time (claims signed after this are invalid) |
| `reason` | Yes | Why the key is being revoked |
| `issuer_mode` | Yes | Who signed: `SELF` (revoked key) or `SUCCESSOR` (new key) |
| `successor_public_key` | Conditional | **Required** if `issuer_mode == SUCCESSOR`. Optional otherwise. |
| `notes` | No | Human-readable context |

### Signature Rules

A revocation is valid if signed by **either**:

1. **The key being revoked** (self-revocation) — `issuer_mode == SELF`
2. **The successor key** — `issuer_mode == SUCCESSOR`, requires `successor_public_key`

Recovery keys are deferred to Phase 4.1.

### Issuer Mode Verification

| Mode | Signature Key Must Equal | `successor_public_key` |
|------|--------------------------|------------------------|
| `SELF` | `revoked_public_key` | Optional (may declare successor) |
| `SUCCESSOR` | `successor_public_key` | **Required** |

This makes the signing authority machine-verifiable, not implicit.

### Key Matching

Primary match is always by **public key bytes** (`revoked_public_key`).

Key IDs (if used elsewhere) are convenience identifiers only — never authoritative for revocation matching. The verifier matches on the full public key.

### Revocation Reasons

| Reason | Meaning |
|--------|---------|
| `COMPROMISED` | Key was stolen or leaked |
| `ROTATED` | Planned key rotation (should have `successor_public_key`) |
| `RETIRED` | Identity is no longer active |
| `OTHER` | Unspecified reason |

## Revocation Bundle Format

A revocation bundle is a self-contained JSON file:

```json
{
  "Version": "revocation-bundle.v1",
  "Revocation": {
    "RevocationId": "uuid",
    "ResearcherId": "uuid",
    "RevokedPublicKey": "ed25519:base64",
    "RevokedAt": "2024-06-15T12:00:00Z",
    "Reason": "ROTATED",
    "SuccessorPublicKey": "ed25519:base64",
    "Notes": "Annual key rotation",
    "Signature": "base64"
  },
  "Identity": {
    "ResearcherId": "uuid",
    "DisplayName": "Dr. Jane Smith"
  }
}
```

## Verification Rules

### Core Rule

> A signature is **invalid** if signed by a key that was revoked at or before the signature timestamp.

Formally: if `revoked_at <= signed_at`, the signature is invalid.

### Verification Modes

| Flag | Behavior |
|------|----------|
| (none) | Ignore revocations, verify as Phase 3 |
| `--revocations-dir <path>` | Load revocations, warn on revoked keys |
| `--strict-revocations` | Fail verification if signer key is revoked |

### Verification Algorithm

```
For each signature (claim, citation, attestation):
  1. Extract signer_public_key and signed_at timestamp
  2. If signed_at is missing:
     - In strict mode: FAIL (cannot verify against revocation time)
     - In non-strict mode: Skip revocation check, add warning
  3. Look up revocations for signer_public_key (match on full public key bytes)
  4. If any revocation has revoked_at <= signed_at:
     - In strict mode: FAIL
     - In warn mode: Add warning
  5. Continue with cryptographic verification
```

### Timestamp Sources

Each signed object has an unambiguous `signed_at` source:

| Object | Timestamp Field |
|--------|-----------------|
| Claim | `AssertedAtUtc` |
| Citation | `IssuedAtUtc` |
| Attestation | `IssuedAtUtc` |

All three are **required** fields in their respective contracts, so missing timestamps should not occur in valid bundles.

### Successor Chain Verification (Optional)

If a claim was signed by key A, and key A was revoked with successor B:
- The claim is still valid if `signed_at < revoked_at`
- New claims should use key B
- Verifier can optionally trace successor chains for identity continuity

## CLI Surface

### Create Revocation

```bash
# Self-revocation (key revokes itself)
claimledger revoke-key \
  --key-file author.key.json \
  --reason ROTATED \
  --successor-key new-author.key.json \
  --notes "Annual rotation" \
  --out revocation.json

# Revoke with specific time (for backdating compromises)
claimledger revoke-key \
  --key-file author.key.json \
  --reason COMPROMISED \
  --revoked-at "2024-06-01T00:00:00Z" \
  --out revocation.json
```

### Verify with Revocations

```bash
# Warn mode
claimledger verify claim.json --revocations-dir ./revocations/

# Strict mode
claimledger verify claim.json --revocations-dir ./revocations/ --strict-revocations
```

### List Revocations

```bash
claimledger revocations ./revocations/
```

### Inspect Revocation

```bash
claimledger inspect-revocation revocation.json
```

## Edge Cases

### Multiple Revocations for Same Key

If multiple revocations exist for the same key, use the **earliest** `revoked_at`.

### Revocation of Revocation?

Not supported. Revocations are permanent. If you revoked by mistake, issue a new key.

### Successor Key Already Revoked

Valid scenario. The chain is: A → B → C. Each revocation is independent.

### Revoked Key Signs Revocation

Valid. A compromised key can still revoke itself (the attacker would be announcing their own compromise, which is fine).

### Backdated Revocation

Allowed but dangerous. If you set `revoked_at` in the past, it invalidates claims signed between then and now. Use with caution.

## Test Cases (Target: 25-30)

### Revocation Domain Tests
1. RevocationReason_AllTypesAreValid
2. RevocationReason_InvalidType_ReturnsFalse
3. Revocation_Create_SelfSigned_Verifies
4. Revocation_Create_SuccessorSigned_Verifies
5. Revocation_TamperedReason_FailsVerification
6. Revocation_TamperedRevokedAt_FailsVerification
7. Revocation_TamperedSuccessor_FailsVerification
8. RevocationId_New_GeneratesUniqueIds
9. RevocationId_Parse_RoundTrips

### Revocation Verification Tests
10. Verify_NoRevocations_PassesAsPhase3
11. Verify_KeyNotRevoked_Passes
12. Verify_KeyRevokedAfterClaim_Passes (claim before revocation)
13. Verify_KeyRevokedBeforeClaim_Fails (claim after revocation)
14. Verify_KeyRevokedExactlyAtClaim_Fails (boundary: revoked_at == signed_at)
15. Verify_StrictMode_FailsOnRevokedKey
16. Verify_WarnMode_WarnsOnRevokedKey
17. Verify_MultipleRevocations_UsesEarliest
18. Verify_Citation_SignerRevoked_Fails
19. Verify_Attestation_SignerRevoked_Fails

### Successor Chain Tests
20. Revocation_WithSuccessor_ContainsNewKey
21. Verify_SuccessorChain_TracesIdentity
22. Revocation_SuccessorAlsoRevoked_ValidChain

### Revocation Bundle Tests
23. RevocationBundle_Serialize_RoundTrips
24. RevocationBundle_Load_FromDirectory
25. RevocationBundle_InvalidSignature_Rejected

### CLI Tests
26. Cli_RevokeKey_CreatesValidBundle
27. Cli_Verify_WithRevocationsDir_LoadsRevocations
28. Cli_Verify_StrictRevocations_FailsOnRevoked
29. Cli_Revocations_ListsAll
30. Cli_InspectRevocation_ShowsDetails

## File Structure

```
ClaimLedger.Domain/
  Primitives/
    RevocationId.cs          # NEW
  Revocations/
    RevocationReason.cs      # NEW
    RevocationSignable.cs    # NEW (frozen contract)
    Revocation.cs            # NEW (domain entity)

ClaimLedger.Application/
  Revocations/
    CreateRevocationCommand.cs      # NEW
    VerifyRevocationsQuery.cs       # NEW
  Export/
    RevocationBundle.cs             # NEW

ClaimLedger.Cli/
  Program.cs                        # Add revoke-key, revocations, inspect-revocation commands
  Verification/
    BundleVerifier.cs               # Update to accept revocation registry
    RevocationRegistry.cs           # NEW (loads revocations from directory)

ClaimLedger.Tests/
  Domain/
    RevocationTests.cs              # NEW
  Application/
    RevocationTests.cs              # NEW
```

## Definition of Done

- [ ] `IdentityRevocation.v1` contract frozen and documented
- [ ] `RevocationReason` enum with validation
- [ ] `Revocation` domain entity with create/verify
- [ ] `RevocationBundle` export format
- [ ] `CreateRevocationCommand` handler
- [ ] `VerifyRevocationsQuery` handler (integrates with claim/citation/attestation verification)
- [ ] `RevocationRegistry` loads from directory
- [ ] CLI: `revoke-key`, `revocations`, `inspect-revocation`
- [ ] CLI: `verify --revocations-dir --strict-revocations`
- [ ] 25+ tests passing
- [ ] Phase 1-3 bundles still verify unchanged (backward compat)
- [ ] README updated with Phase 4 docs

## Open Questions (Deferred to Phase 4.1)

1. **Recovery keys** — Pre-registered keys that can revoke on behalf of the identity
2. **Revocation distribution** — How do verifiers discover revocations? (Out of scope for Phase 4)
3. **Grace periods** — Should there be a "pending" state before revocation takes effect?
4. **Revocation receipts** — Third-party attestation that a revocation was seen at time T
