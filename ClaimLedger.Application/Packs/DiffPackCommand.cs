using System.Text.Json;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Domain.Packs;

namespace ClaimLedger.Application.Packs;

/// <summary>
/// Command to diff two ClaimPacks.
/// </summary>
public sealed record DiffPackCommand(
    string PackADirectory,
    string PackBDirectory);

/// <summary>
/// Result of pack diff.
/// </summary>
public sealed class DiffPackResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public int ExitCode { get; init; }
    public ClaimPackDiffReport? Report { get; init; }
}

/// <summary>
/// Command to validate a pack update against a policy.
/// </summary>
public sealed record ValidateUpdateCommand(
    string PackADirectory,
    string PackBDirectory,
    string Policy = PackUpdatePolicy.AppendOnly,
    bool Strict = false);

/// <summary>
/// Result of pack update validation.
/// </summary>
public sealed class ValidateUpdateResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public int ExitCode { get; init; }
    public ClaimPackDiffReport? Report { get; init; }
    public PolicyValidationResult? Validation { get; init; }
}

/// <summary>
/// Handles diffing two ClaimPacks.
/// </summary>
public static class DiffPackHandler
{
    /// <summary>
    /// Computes the diff between two packs.
    /// </summary>
    public static async Task<DiffPackResult> HandleAsync(DiffPackCommand command)
    {
        // Load pack A
        var packAResult = await LoadPackAsync(command.PackADirectory, "A");
        if (!packAResult.Success)
        {
            return new DiffPackResult
            {
                Success = false,
                Error = packAResult.Error,
                ExitCode = 4
            };
        }

        // Load pack B
        var packBResult = await LoadPackAsync(command.PackBDirectory, "B");
        if (!packBResult.Success)
        {
            return new DiffPackResult
            {
                Success = false,
                Error = packBResult.Error,
                ExitCode = 4
            };
        }

        // Compute diff
        var report = ComputeDiff(
            packAResult.Manifest!, packAResult.Bundle!, command.PackADirectory,
            packBResult.Manifest!, packBResult.Bundle!, command.PackBDirectory);

        return new DiffPackResult
        {
            Success = true,
            ExitCode = 0,
            Report = report
        };
    }

    /// <summary>
    /// Loads a pack's manifest and root bundle.
    /// </summary>
    private static async Task<(bool Success, string? Error, ClaimPackManifest? Manifest, ClaimBundle? Bundle)> LoadPackAsync(
        string packDir, string label)
    {
        if (!Directory.Exists(packDir))
        {
            return (false, $"Pack {label} directory not found: {packDir}", null, null);
        }

        var manifestPath = Path.Combine(packDir, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            return (false, $"Pack {label} missing manifest.json", null, null);
        }

        ClaimPackManifest manifest;
        try
        {
            var manifestJson = await File.ReadAllTextAsync(manifestPath);
            manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)
                ?? throw new JsonException("Manifest is null");
        }
        catch (Exception ex)
        {
            return (false, $"Pack {label} invalid manifest: {ex.Message}", null, null);
        }

        var rootClaimPath = Path.Combine(packDir, manifest.RootClaimPath);
        if (!File.Exists(rootClaimPath))
        {
            return (false, $"Pack {label} missing root claim", null, null);
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(rootClaimPath);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            return (false, $"Pack {label} invalid root claim: {ex.Message}", null, null);
        }

        return (true, null, manifest, bundle);
    }

    /// <summary>
    /// Computes the diff report between two packs.
    /// </summary>
    public static ClaimPackDiffReport ComputeDiff(
        ClaimPackManifest manifestA, ClaimBundle bundleA, string dirA,
        ClaimPackManifest manifestB, ClaimBundle bundleB, string dirB)
    {
        // Build file inventory diffs
        var filesA = manifestA.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);
        var filesB = manifestB.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);

        var added = new List<FileChange>();
        var removed = new List<FileChange>();
        var modified = new List<FileModification>();
        var unchangedCount = 0;

        // Find removed and modified
        foreach (var (path, entryA) in filesA)
        {
            if (!filesB.TryGetValue(path, out var entryB))
            {
                removed.Add(new FileChange
                {
                    Path = path,
                    Sha256Hex = entryA.Sha256Hex,
                    SizeBytes = entryA.SizeBytes
                });
            }
            else if (!string.Equals(entryA.Sha256Hex, entryB.Sha256Hex, StringComparison.OrdinalIgnoreCase))
            {
                modified.Add(new FileModification
                {
                    Path = path,
                    OldSha256Hex = entryA.Sha256Hex,
                    NewSha256Hex = entryB.Sha256Hex,
                    OldSizeBytes = entryA.SizeBytes,
                    NewSizeBytes = entryB.SizeBytes
                });
            }
            else
            {
                unchangedCount++;
            }
        }

        // Find added
        foreach (var (path, entryB) in filesB)
        {
            if (!filesA.ContainsKey(path))
            {
                added.Add(new FileChange
                {
                    Path = path,
                    Sha256Hex = entryB.Sha256Hex,
                    SizeBytes = entryB.SizeBytes
                });
            }
        }

        var fileDiff = new FileInventoryDiff
        {
            Added = added,
            Removed = removed,
            Modified = modified,
            UnchangedCount = unchangedCount
        };

        // Compute semantic diffs
        var digestA = ClaimCoreDigest.Compute(bundleA).ToString();
        var digestB = ClaimCoreDigest.Compute(bundleB).ToString();
        var rootDigestChanged = !string.Equals(digestA, digestB, StringComparison.OrdinalIgnoreCase);

        var attestationDiff = ComputeAttestationDiff(bundleA, bundleB);
        var timestampDiff = ComputeTimestampDiff(bundleA, bundleB);
        var manifestSigDiff = ComputeManifestSignatureDiff(manifestA, manifestB);
        var revocationDiff = ComputeRevocationDiff(dirA, dirB);
        var citationDiff = ComputeCitationDiff(bundleA, bundleB);

        var semantics = new SemanticDiff
        {
            RootDigestChanged = rootDigestChanged,
            Attestations = attestationDiff,
            Timestamps = timestampDiff,
            ManifestSignatures = manifestSigDiff,
            Revocations = revocationDiff,
            Citations = citationDiff
        };

        // Compute update class
        var updateClass = ComputeUpdateClass(fileDiff, semantics);

        return new ClaimPackDiffReport
        {
            GeneratedAt = DateTimeOffset.UtcNow.ToString("O"),
            PackA = new PackReference
            {
                PackId = manifestA.PackId,
                RootClaimCoreDigest = manifestA.RootClaimCoreDigest,
                CreatedAt = manifestA.CreatedAt,
                FileCount = manifestA.Files.Count
            },
            PackB = new PackReference
            {
                PackId = manifestB.PackId,
                RootClaimCoreDigest = manifestB.RootClaimCoreDigest,
                CreatedAt = manifestB.CreatedAt,
                FileCount = manifestB.Files.Count
            },
            UpdateClass = updateClass,
            Files = fileDiff,
            Semantics = semantics
        };
    }

    /// <summary>
    /// Computes attestation diff.
    /// </summary>
    private static ElementDiff<AttestationRef> ComputeAttestationDiff(ClaimBundle bundleA, ClaimBundle bundleB)
    {
        var attestationsA = (bundleA.Attestations ?? Array.Empty<AttestationInfo>())
            .ToDictionary(a => a.AttestationId, StringComparer.OrdinalIgnoreCase);
        var attestationsB = (bundleB.Attestations ?? Array.Empty<AttestationInfo>())
            .ToDictionary(a => a.AttestationId, StringComparer.OrdinalIgnoreCase);

        var added = new List<AttestationRef>();
        var removed = new List<AttestationRef>();
        var modified = new List<AttestationRef>();
        var unchangedCount = 0;

        foreach (var (id, attA) in attestationsA)
        {
            if (!attestationsB.TryGetValue(id, out var attB))
            {
                removed.Add(ToRef(attA));
            }
            else if (!AttestationsEqual(attA, attB))
            {
                modified.Add(ToRef(attB));
            }
            else
            {
                unchangedCount++;
            }
        }

        foreach (var (id, attB) in attestationsB)
        {
            if (!attestationsA.ContainsKey(id))
            {
                added.Add(ToRef(attB));
            }
        }

        return new ElementDiff<AttestationRef>
        {
            Added = added,
            Removed = removed,
            Modified = modified,
            UnchangedCount = unchangedCount
        };
    }

    private static bool AttestationsEqual(AttestationInfo a, AttestationInfo b)
    {
        return string.Equals(a.AttestationId, b.AttestationId, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(a.ClaimCoreDigest, b.ClaimCoreDigest, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(a.Attestor.PublicKey, b.Attestor.PublicKey, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(a.AttestationType, b.AttestationType, StringComparison.OrdinalIgnoreCase) &&
               a.Statement == b.Statement &&
               a.Signature == b.Signature;
    }

    private static AttestationRef ToRef(AttestationInfo att)
    {
        return new AttestationRef
        {
            AttestationId = att.AttestationId,
            AttestorPublicKey = att.Attestor.PublicKey,
            AttestationType = att.AttestationType
        };
    }

    /// <summary>
    /// Computes timestamp diff.
    /// </summary>
    private static ElementDiff<TimestampRef> ComputeTimestampDiff(ClaimBundle bundleA, ClaimBundle bundleB)
    {
        var timestampsA = (bundleA.TimestampReceipts ?? Array.Empty<TimestampReceiptInfo>())
            .ToDictionary(t => t.ReceiptId, StringComparer.OrdinalIgnoreCase);
        var timestampsB = (bundleB.TimestampReceipts ?? Array.Empty<TimestampReceiptInfo>())
            .ToDictionary(t => t.ReceiptId, StringComparer.OrdinalIgnoreCase);

        var added = new List<TimestampRef>();
        var removed = new List<TimestampRef>();
        var modified = new List<TimestampRef>();
        var unchangedCount = 0;

        foreach (var (id, tsA) in timestampsA)
        {
            if (!timestampsB.TryGetValue(id, out var tsB))
            {
                removed.Add(ToRef(tsA));
            }
            else if (!TimestampsEqual(tsA, tsB))
            {
                modified.Add(ToRef(tsB));
            }
            else
            {
                unchangedCount++;
            }
        }

        foreach (var (id, tsB) in timestampsB)
        {
            if (!timestampsA.ContainsKey(id))
            {
                added.Add(ToRef(tsB));
            }
        }

        return new ElementDiff<TimestampRef>
        {
            Added = added,
            Removed = removed,
            Modified = modified,
            UnchangedCount = unchangedCount
        };
    }

    private static bool TimestampsEqual(TimestampReceiptInfo a, TimestampReceiptInfo b)
    {
        return string.Equals(a.ReceiptId, b.ReceiptId, StringComparison.OrdinalIgnoreCase) &&
               a.TsaTokenDerBase64 == b.TsaTokenDerBase64;
    }

    private static TimestampRef ToRef(TimestampReceiptInfo ts)
    {
        return new TimestampRef
        {
            ReceiptId = ts.ReceiptId,
            TsaPolicyOid = ts.Tsa.PolicyOid,
            GenTime = ts.IssuedAt
        };
    }

    /// <summary>
    /// Computes manifest signature diff.
    /// </summary>
    private static ElementDiff<ManifestSignatureRef> ComputeManifestSignatureDiff(
        ClaimPackManifest manifestA, ClaimPackManifest manifestB)
    {
        // Key by (manifest_sha256, signer_pubkey)
        var sigsA = (manifestA.ManifestSignatures ?? Array.Empty<ManifestSignatureEntry>())
            .ToDictionary(s => (s.Signable.ManifestSha256Hex.ToLowerInvariant(), s.Signature.PublicKey.ToLowerInvariant()));
        var sigsB = (manifestB.ManifestSignatures ?? Array.Empty<ManifestSignatureEntry>())
            .ToDictionary(s => (s.Signable.ManifestSha256Hex.ToLowerInvariant(), s.Signature.PublicKey.ToLowerInvariant()));

        var added = new List<ManifestSignatureRef>();
        var removed = new List<ManifestSignatureRef>();
        var modified = new List<ManifestSignatureRef>();
        var unchangedCount = 0;

        foreach (var (key, sigA) in sigsA)
        {
            if (!sigsB.TryGetValue(key, out var sigB))
            {
                removed.Add(ToRef(sigA));
            }
            else if (!ManifestSignaturesEqual(sigA, sigB))
            {
                modified.Add(ToRef(sigB));
            }
            else
            {
                unchangedCount++;
            }
        }

        foreach (var (key, sigB) in sigsB)
        {
            if (!sigsA.ContainsKey(key))
            {
                added.Add(ToRef(sigB));
            }
        }

        return new ElementDiff<ManifestSignatureRef>
        {
            Added = added,
            Removed = removed,
            Modified = modified,
            UnchangedCount = unchangedCount
        };
    }

    private static bool ManifestSignaturesEqual(ManifestSignatureEntry a, ManifestSignatureEntry b)
    {
        return string.Equals(a.Signable.ManifestSha256Hex, b.Signable.ManifestSha256Hex, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(a.Signature.PublicKey, b.Signature.PublicKey, StringComparison.OrdinalIgnoreCase) &&
               a.Signature.Sig == b.Signature.Sig;
    }

    private static ManifestSignatureRef ToRef(ManifestSignatureEntry sig)
    {
        return new ManifestSignatureRef
        {
            ManifestSha256Hex = sig.Signable.ManifestSha256Hex,
            SignerPublicKey = sig.Signature.PublicKey,
            SignerKind = sig.Signer.Kind
        };
    }

    /// <summary>
    /// Computes revocation diff by scanning revocation directories.
    /// </summary>
    private static ElementDiff<RevocationRef> ComputeRevocationDiff(string dirA, string dirB)
    {
        var revsA = LoadRevocationRefs(dirA);
        var revsB = LoadRevocationRefs(dirB);

        var added = new List<RevocationRef>();
        var removed = new List<RevocationRef>();
        var unchangedCount = 0;

        foreach (var (id, revA) in revsA)
        {
            if (!revsB.TryGetValue(id, out var revB))
            {
                removed.Add(revA);
            }
            else
            {
                unchangedCount++;
            }
        }

        foreach (var (id, revB) in revsB)
        {
            if (!revsA.ContainsKey(id))
            {
                added.Add(revB);
            }
        }

        // Revocations don't have a "modified" concept - same ID means same revocation
        return new ElementDiff<RevocationRef>
        {
            Added = added,
            Removed = removed,
            Modified = Array.Empty<RevocationRef>(),
            UnchangedCount = unchangedCount
        };
    }

    private static Dictionary<string, RevocationRef> LoadRevocationRefs(string packDir)
    {
        var result = new Dictionary<string, RevocationRef>(StringComparer.OrdinalIgnoreCase);

        var manifestPath = Path.Combine(packDir, "manifest.json");
        if (!File.Exists(manifestPath)) return result;

        try
        {
            var manifestJson = File.ReadAllText(manifestPath);
            var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson);
            if (manifest?.Include.RevocationsDir == null) return result;

            var revocationsDir = Path.Combine(packDir, manifest.Include.RevocationsDir.TrimEnd('/'));
            if (!Directory.Exists(revocationsDir)) return result;

            foreach (var file in Directory.GetFiles(revocationsDir, "*.json", SearchOption.AllDirectories))
            {
                try
                {
                    var json = File.ReadAllText(file);
                    var bundle = JsonSerializer.Deserialize<RevocationBundle>(json);
                    if (bundle?.Revocation != null)
                    {
                        var id = bundle.Revocation.RevocationId;
                        result[id] = new RevocationRef
                        {
                            RevocationId = id,
                            RevokedPublicKey = bundle.Revocation.RevokedPublicKey,
                            Reason = bundle.Revocation.Reason
                        };
                    }
                }
                catch
                {
                    // Skip invalid files
                }
            }
        }
        catch
        {
            // Return empty on any error
        }

        return result;
    }

    /// <summary>
    /// Computes citation diff.
    /// </summary>
    private static ElementDiff<CitationRef> ComputeCitationDiff(ClaimBundle bundleA, ClaimBundle bundleB)
    {
        var citationsA = (bundleA.Citations ?? Array.Empty<CitationInfo>())
            .ToDictionary(c => c.CitationId, StringComparer.OrdinalIgnoreCase);
        var citationsB = (bundleB.Citations ?? Array.Empty<CitationInfo>())
            .ToDictionary(c => c.CitationId, StringComparer.OrdinalIgnoreCase);

        var added = new List<CitationRef>();
        var removed = new List<CitationRef>();
        var modified = new List<CitationRef>();
        var unchangedCount = 0;

        foreach (var (id, citA) in citationsA)
        {
            if (!citationsB.TryGetValue(id, out var citB))
            {
                removed.Add(ToRef(citA));
            }
            else if (!CitationsEqual(citA, citB))
            {
                modified.Add(ToRef(citB));
            }
            else
            {
                unchangedCount++;
            }
        }

        foreach (var (id, citB) in citationsB)
        {
            if (!citationsA.ContainsKey(id))
            {
                added.Add(ToRef(citB));
            }
        }

        return new ElementDiff<CitationRef>
        {
            Added = added,
            Removed = removed,
            Modified = modified,
            UnchangedCount = unchangedCount
        };
    }

    private static bool CitationsEqual(CitationInfo a, CitationInfo b)
    {
        return string.Equals(a.CitationId, b.CitationId, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(a.CitedClaimCoreDigest, b.CitedClaimCoreDigest, StringComparison.OrdinalIgnoreCase) &&
               a.Relation == b.Relation &&
               a.Signature == b.Signature;
    }

    private static CitationRef ToRef(CitationInfo cit)
    {
        return new CitationRef
        {
            CitationId = cit.CitationId,
            CitedClaimCoreDigest = cit.CitedClaimCoreDigest,
            Relation = cit.Relation
        };
    }

    /// <summary>
    /// Computes the update classification.
    /// </summary>
    public static string ComputeUpdateClass(FileInventoryDiff files, SemanticDiff semantics)
    {
        // BREAKING: root digest changed, any removals, or any modifications to protected content
        if (semantics.RootDigestChanged)
            return UpdateClass.Breaking;

        if (files.Removed.Count > 0)
            return UpdateClass.Breaking;

        // Any semantic removals are breaking
        if (semantics.Attestations.Removed.Count > 0 ||
            semantics.Timestamps.Removed.Count > 0 ||
            semantics.ManifestSignatures.Removed.Count > 0 ||
            semantics.Revocations.Removed.Count > 0 ||
            semantics.Citations.Removed.Count > 0)
            return UpdateClass.Breaking;

        // Any semantic modifications are breaking (citations are especially critical since they're in core digest)
        if (semantics.Citations.Modified.Count > 0)
            return UpdateClass.Breaking;

        // IDENTICAL: no changes at all
        if (files.Added.Count == 0 && files.Modified.Count == 0 &&
            semantics.Attestations.Added.Count == 0 && semantics.Attestations.Modified.Count == 0 &&
            semantics.Timestamps.Added.Count == 0 && semantics.Timestamps.Modified.Count == 0 &&
            semantics.ManifestSignatures.Added.Count == 0 && semantics.ManifestSignatures.Modified.Count == 0 &&
            semantics.Revocations.Added.Count == 0 &&
            semantics.Citations.Added.Count == 0)
            return UpdateClass.Identical;

        // Check if file modifications are "acceptable" for APPEND_ONLY
        // claim.json and manifest.json can change if only semantic appends occurred
        // (attestations, timestamps, manifest signatures - these don't change root digest)
        var hasSemanticAppends = semantics.Attestations.Added.Count > 0 ||
                                  semantics.Timestamps.Added.Count > 0 ||
                                  semantics.ManifestSignatures.Added.Count > 0;

        var hasSemanticModifications = semantics.Attestations.Modified.Count > 0 ||
                                        semantics.Timestamps.Modified.Count > 0 ||
                                        semantics.ManifestSignatures.Modified.Count > 0;

        // If there are semantic modifications (to existing entries), it's MODIFIED
        if (hasSemanticModifications)
            return UpdateClass.Modified;

        // Check if file modifications are only to claim.json or manifest.json
        // and are explained by semantic appends
        var unexplainedModifications = files.Modified
            .Where(f => !IsAppendableBundleFile(f.Path))
            .ToList();

        if (unexplainedModifications.Count > 0)
            return UpdateClass.Modified;

        // If claim.json/manifest.json changed but root digest is same and semantic content was appended,
        // that's APPEND_ONLY (the file changed because we appended attestations/timestamps/signatures)
        if (files.Modified.Count > 0 && !hasSemanticAppends)
            return UpdateClass.Modified;

        // APPEND_ONLY: only additions, no removals or modifications
        return UpdateClass.AppendOnly;
    }

    /// <summary>
    /// Checks if a file path is one that can be modified during semantic appends.
    /// claim.json changes when attestations/timestamps are added.
    /// manifest.json changes when manifest signatures are added.
    /// </summary>
    internal static bool IsAppendableBundleFile(string path)
    {
        var normalized = path.ToLowerInvariant().Replace('\\', '/');
        return normalized == "claim.json" || normalized == "manifest.json";
    }
}

/// <summary>
/// Handles validating pack updates against a policy.
/// </summary>
public static class ValidateUpdateHandler
{
    /// <summary>
    /// Validates a pack update against a policy.
    /// </summary>
    public static async Task<ValidateUpdateResult> HandleAsync(ValidateUpdateCommand command)
    {
        // First compute the diff
        var diffResult = await DiffPackHandler.HandleAsync(new DiffPackCommand(
            command.PackADirectory,
            command.PackBDirectory));

        if (!diffResult.Success)
        {
            return new ValidateUpdateResult
            {
                Success = false,
                Error = diffResult.Error,
                ExitCode = diffResult.ExitCode
            };
        }

        var report = diffResult.Report!;

        // Validate against policy
        var validation = ValidatePolicy(report, command.Policy, command.Strict);

        return new ValidateUpdateResult
        {
            Success = validation.Passed,
            ExitCode = validation.Passed ? 0 : 2, // 2 = policy violation
            Report = report,
            Validation = validation
        };
    }

    /// <summary>
    /// Validates a diff report against a policy.
    /// </summary>
    public static PolicyValidationResult ValidatePolicy(
        ClaimPackDiffReport report,
        string policy,
        bool strict)
    {
        var violations = new List<PolicyViolation>();

        // APPEND_ONLY policy
        if (policy == PackUpdatePolicy.AppendOnly)
        {
            // Root digest must not change
            if (report.Semantics.RootDigestChanged)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.RootDigestChanged,
                    Path = "claim.json",
                    Details = $"Old: {report.PackA.RootClaimCoreDigest}, New: {report.PackB.RootClaimCoreDigest}"
                });
            }

            // No file removals
            foreach (var file in report.Files.Removed)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.FileRemoved,
                    Path = file.Path
                });
            }

            // No file modifications (except claim.json/manifest.json when explained by semantic appends)
            var hasSemanticAppends = report.Semantics.Attestations.Added.Count > 0 ||
                                      report.Semantics.Timestamps.Added.Count > 0 ||
                                      report.Semantics.ManifestSignatures.Added.Count > 0;

            foreach (var file in report.Files.Modified)
            {
                // Allow claim.json and manifest.json modifications if there are semantic appends
                // These files change when attestations, timestamps, or manifest signatures are added
                var isAllowedModification = hasSemanticAppends && DiffPackHandler.IsAppendableBundleFile(file.Path);

                if (!isAllowedModification)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.FileModified,
                        Path = file.Path,
                        Details = $"Hash changed: {file.OldSha256Hex} -> {file.NewSha256Hex}"
                    });
                }
            }

            // No attestation removals or modifications
            foreach (var att in report.Semantics.Attestations.Removed)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.AttestationRemoved,
                    Path = att.AttestationId
                });
            }
            foreach (var att in report.Semantics.Attestations.Modified)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.ExistingAttestationModified,
                    Path = att.AttestationId
                });
            }

            // No timestamp removals or modifications
            foreach (var ts in report.Semantics.Timestamps.Removed)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.TimestampRemoved,
                    Path = ts.ReceiptId
                });
            }
            foreach (var ts in report.Semantics.Timestamps.Modified)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.ExistingTimestampModified,
                    Path = ts.ReceiptId
                });
            }

            // No manifest signature removals or modifications
            foreach (var sig in report.Semantics.ManifestSignatures.Removed)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.ManifestSignatureRemoved,
                    Path = sig.SignerPublicKey,
                    Details = $"Kind: {sig.SignerKind}"
                });
            }
            foreach (var sig in report.Semantics.ManifestSignatures.Modified)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.ExistingManifestSignatureModified,
                    Path = sig.SignerPublicKey
                });
            }

            // No revocation removals
            foreach (var rev in report.Semantics.Revocations.Removed)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.RevocationRemoved,
                    Path = rev.RevocationId
                });
            }

            // No citation changes (additions, removals, or modifications)
            // Citations are part of core digest, so any change should have triggered ROOT_DIGEST_CHANGED
            // But we check explicitly for clarity
            foreach (var cit in report.Semantics.Citations.Removed)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.CitationRemoved,
                    Path = cit.CitationId
                });
            }
            foreach (var cit in report.Semantics.Citations.Modified)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.CitationChanged,
                    Path = cit.CitationId
                });
            }
            foreach (var cit in report.Semantics.Citations.Added)
            {
                violations.Add(new PolicyViolation
                {
                    Type = PolicyViolationType.CitationChanged,
                    Path = cit.CitationId,
                    Details = "Citation added (changes core digest)"
                });
            }
        }
        // ALLOW_MODIFIED policy
        else if (policy == PackUpdatePolicy.AllowModified)
        {
            // Only flag BREAKING changes
            if (report.UpdateClass == UpdateClass.Breaking)
            {
                if (report.Semantics.RootDigestChanged)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.RootDigestChanged,
                        Path = "claim.json",
                        Details = $"Old: {report.PackA.RootClaimCoreDigest}, New: {report.PackB.RootClaimCoreDigest}"
                    });
                }

                foreach (var file in report.Files.Removed)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.FileRemoved,
                        Path = file.Path
                    });
                }

                // Semantic removals
                foreach (var att in report.Semantics.Attestations.Removed)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.AttestationRemoved,
                        Path = att.AttestationId
                    });
                }
                foreach (var ts in report.Semantics.Timestamps.Removed)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.TimestampRemoved,
                        Path = ts.ReceiptId
                    });
                }
                foreach (var sig in report.Semantics.ManifestSignatures.Removed)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.ManifestSignatureRemoved,
                        Path = sig.SignerPublicKey
                    });
                }
                foreach (var rev in report.Semantics.Revocations.Removed)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.RevocationRemoved,
                        Path = rev.RevocationId
                    });
                }
                foreach (var cit in report.Semantics.Citations.Removed)
                {
                    violations.Add(new PolicyViolation
                    {
                        Type = PolicyViolationType.CitationRemoved,
                        Path = cit.CitationId
                    });
                }
            }
        }

        return new PolicyValidationResult
        {
            Passed = violations.Count == 0,
            Policy = policy,
            UpdateClass = report.UpdateClass,
            Violations = violations
        };
    }
}
