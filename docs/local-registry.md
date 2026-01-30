# Local Registry

A local, offline registry that indexes multiple ClaimPacks for citation resolution and CreatorLedger bundle verification.

## Overview

The local registry provides:
- **Citation Resolution**: Resolve `claim_core_digest` references across packs
- **CreatorLedger Bundle Resolution**: Resolve `bundle_digest` for evidence verification
- **Offline Operation**: No network required after initial indexing
- **Staleness Detection**: Warns when pack contents have changed since indexing

## Registry Structure

```
my-registry/
├── index.json           # ClaimRegistryIndex.v1
└── packs/               # Symlinks or references to pack locations
    ├── pack-abc123      # -> /path/to/pack1
    └── pack-def456      # -> /path/to/pack2
```

### Index Contract: ClaimRegistryIndex.v1

```json
{
  "Contract": "ClaimRegistryIndex.v1",
  "RegistryId": "uuid",
  "CreatedAt": "2024-01-15T10:30:00Z",
  "UpdatedAt": "2024-01-15T11:00:00Z",
  "Packs": [
    {
      "PackId": "uuid",
      "Path": "/absolute/path/to/pack",
      "Kind": "Directory",
      "ManifestHash": "sha256-hex",
      "RootClaimCoreDigest": "sha256-hex",
      "AddedAt": "2024-01-15T10:30:00Z"
    }
  ],
  "Claims": {
    "abc123...": [
      { "PackId": "uuid", "Path": "claim.json" },
      { "PackId": "uuid2", "Path": "claims/abc123.json" }
    ]
  },
  "CreatorLedgerBundles": {
    "def456...": [
      { "PackId": "uuid", "Path": "creatorledger/def456.json" }
    ]
  }
}
```

## CLI Commands

### Initialize Registry

```bash
claimledger registry init /path/to/registry
```

Creates a new empty registry at the specified path.

### Add Pack to Registry

```bash
claimledger registry add /path/to/registry /path/to/pack
```

Indexes a ClaimPack into the registry. The pack is scanned for:
- Root claim bundle
- Embedded citations (`claims/` directory)
- CreatorLedger bundles (`creatorledger/` directory)

### Build/Refresh Registry

```bash
claimledger registry build /path/to/registry
```

Re-scans all registered packs and rebuilds the index. Use this after:
- Modifying pack contents
- Adding/removing files from packs
- Detecting stale entries

### Query Registry

```bash
# Query by claim digest
claimledger registry query /path/to/registry --claim abc123...

# Query by bundle digest
claimledger registry query /path/to/registry --bundle def456...

# List all packs
claimledger registry query /path/to/registry --list-packs

# Query by prefix (for autocomplete)
claimledger registry query /path/to/registry --claim abc --prefix
```

## Integration with verify-pack

### Basic Usage

```bash
# Verify pack with registry for citation resolution
claimledger verify-pack /path/to/pack --registry /path/to/registry

# Verify with CreatorLedger bundle resolution
claimledger verify-pack /path/to/pack --registry /path/to/registry --verify-creatorledger
```

### Strict Mode

```bash
# Fail if any citation cannot be resolved via registry
claimledger verify-pack /path/to/pack --registry /path/to/registry --strict-registry
```

Strict mode fails on:
- Unresolvable citations (not in registry)
- Unresolvable CreatorLedger bundles
- Stale pack entries (manifest hash mismatch)
- Ambiguous digests (multiple packs with same digest)

### Resolution Precedence

1. **Pack-local first**: Embedded citations and bundles are used first
2. **Registry fallback**: Only consult registry for unresolved references

This ensures self-contained packs remain verifiable without registry access.

## Staleness Detection

The registry tracks `ManifestHash` for each pack. On verification:

1. Registry resolver computes current manifest hash
2. Compares with stored hash
3. If mismatch:
   - **Non-strict**: Warning + continue
   - **Strict**: Fail with `Stale` status

### Handling Stale Entries

```bash
# Rebuild to update all entries
claimledger registry build /path/to/registry

# Or re-add the specific pack
claimledger registry add /path/to/registry /path/to/changed-pack
```

## Ambiguity Handling

When multiple packs contain the same `claim_core_digest`:

- **Registry stores all locations**: Each digest maps to a list of pack locations
- **Resolution returns first match**: Deterministic ordering by PackId
- **Strict mode**: Can be configured to fail on ambiguous digests

## API Usage

### RegistryResolver

```csharp
// Load resolver
var result = await RegistryResolver.LoadAsync("/path/to/registry");
if (!result.Success)
    throw new Exception(result.Error);

var resolver = result.Resolver;

// Resolve claim by digest
var claimResult = await resolver.ResolveClaimAsync("abc123...");
if (claimResult.Status == ResolveStatus.Resolved)
{
    var bundle = claimResult.Bundle;
    // Use resolved bundle
}

// Resolve CreatorLedger bundle
var bundleResult = await resolver.ResolveCreatorLedgerBundleAsync("def456...");
if (bundleResult.Status == ResolveStatus.Resolved)
{
    var bundleBytes = bundleResult.BundleBytes;
    // Verify bundle
}

// Check for warnings/errors
foreach (var warning in resolver.Warnings)
    Console.WriteLine($"Warning: {warning}");
```

### Resolution Status

| Status | Description |
|--------|-------------|
| `Resolved` | Successfully found and loaded |
| `NotFound` | Digest not in registry index |
| `Ambiguous` | Multiple packs have this digest |
| `PackNotFound` | Pack path no longer exists |
| `Stale` | Pack manifest has changed |
| `FileNotFound` | Indexed file missing from pack |
| `InvalidContent` | File exists but cannot be parsed |

## Best Practices

### Registry Organization

1. **One registry per project**: Keep related packs together
2. **Absolute paths**: Registry stores absolute pack paths
3. **Regular rebuilds**: Run `build` after pack modifications

### Verification Workflow

```bash
# 1. Initialize registry once
claimledger registry init ./my-registry

# 2. Add packs as they're created
claimledger registry add ./my-registry ./new-pack

# 3. Verify with registry
claimledger verify-pack ./some-pack --registry ./my-registry --verify-citations

# 4. Rebuild periodically
claimledger registry build ./my-registry
```

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
- name: Initialize Registry
  run: claimledger registry init ./registry

- name: Index All Packs
  run: |
    for pack in ./packs/*; do
      claimledger registry add ./registry "$pack"
    done

- name: Verify with Strict Mode
  run: |
    claimledger verify-pack ./my-pack \
      --registry ./registry \
      --strict-registry \
      --verify-citations \
      --verify-creatorledger
```

## Limitations

- **Directory packs only**: ZIP support not yet implemented
- **Local filesystem**: No remote/cloud registry support
- **Manual refresh**: No file watcher for automatic updates
- **No deduplication**: Same content in multiple packs is indexed multiple times

## Future Enhancements

- ZIP pack support
- Remote registry synchronization
- File system watcher for auto-refresh
- Content-addressed deduplication
- Registry signing/verification
