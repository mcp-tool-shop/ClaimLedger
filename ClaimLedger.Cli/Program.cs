using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Citations;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Packs;
using ClaimLedger.Application.Publish;
using ClaimLedger.Application.Registry;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Application.Timestamps;
using ClaimLedger.Cli.Verification;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using Shared.Crypto;

namespace ClaimLedger.Cli;

/// <summary>
/// ClaimLedger CLI - Cryptographic provenance verification for scientific claims.
/// </summary>
public static partial class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("ClaimLedger - Cryptographic provenance verification for scientific claims");

        rootCommand.AddCommand(CreateVerifyCommand());
        rootCommand.AddCommand(CreateInspectCommand());
        rootCommand.AddCommand(CreateAttestCommand());
        rootCommand.AddCommand(CreateAttestationsCommand());
        rootCommand.AddCommand(CreateCiteCommand());
        rootCommand.AddCommand(CreateCitationsCommand());
        rootCommand.AddCommand(CreateRevokeKeyCommand());
        rootCommand.AddCommand(CreateRevocationsCommand());
        rootCommand.AddCommand(CreateWitnessCommand());
        rootCommand.AddCommand(CreateTsaRequestCommand());
        rootCommand.AddCommand(CreateTsaAttachCommand());
        rootCommand.AddCommand(CreateTimestampsCommand());
        rootCommand.AddCommand(CreatePackCommand());
        rootCommand.AddCommand(CreateVerifyPackCommand());
        rootCommand.AddCommand(CreatePackInspectCommand());
        rootCommand.AddCommand(CreatePackSignCommand());
        rootCommand.AddCommand(CreatePackDiffCommand());
        rootCommand.AddCommand(CreatePackValidateUpdateCommand());
        rootCommand.AddCommand(CreateRegistryCommand());
        rootCommand.AddCommand(CreatePublishCommand());

        return await rootCommand.InvokeAsync(args);
    }

    private static Command CreateVerifyCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");
        var evidenceOption = new Option<DirectoryInfo?>(
            "--evidence",
            "Directory containing evidence files to verify against claimed hashes");
        evidenceOption.AddAlias("-e");

        var attestationsOption = new Option<bool>(
            "--attestations",
            "Also verify all attestations in the bundle");
        attestationsOption.AddAlias("-a");

        var citationsOption = new Option<bool>(
            "--citations",
            "Also verify all citations in the bundle");
        citationsOption.AddAlias("-c");

        var strictCitationsOption = new Option<bool>(
            "--strict-citations",
            "Fail if any citation cannot be resolved to a known bundle");

        var claimDirOption = new Option<DirectoryInfo?>(
            "--claim-dir",
            "Directory containing claim bundles for citation resolution");

        var revocationsDirOption = new Option<DirectoryInfo?>(
            "--revocations-dir",
            "Directory containing revocation bundles to check against");

        var strictRevocationsOption = new Option<bool>(
            "--strict-revocations",
            "Fail if any signer key is revoked");

        var tsaOption = new Option<bool>(
            "--tsa",
            "Also verify RFC 3161 timestamp receipts");

        var tsaTrustDirOption = new Option<DirectoryInfo?>(
            "--tsa-trust-dir",
            "Directory containing TSA trust anchors (certificates)");

        var strictTsaOption = new Option<bool>(
            "--strict-tsa",
            "Fail if any TSA receipt is untrusted or invalid");

        var command = new Command("verify", "Verify a claim bundle's cryptographic validity")
        {
            bundleArg,
            evidenceOption,
            attestationsOption,
            citationsOption,
            strictCitationsOption,
            claimDirOption,
            revocationsDirOption,
            strictRevocationsOption,
            tsaOption,
            tsaTrustDirOption,
            strictTsaOption
        };

        command.SetHandler(async context =>
        {
            var bundle = context.ParseResult.GetValueForArgument(bundleArg);
            var evidenceDir = context.ParseResult.GetValueForOption(evidenceOption);
            var verifyAttestations = context.ParseResult.GetValueForOption(attestationsOption);
            var verifyCitations = context.ParseResult.GetValueForOption(citationsOption);
            var strictCitations = context.ParseResult.GetValueForOption(strictCitationsOption);
            var claimDir = context.ParseResult.GetValueForOption(claimDirOption);
            var revocationsDir = context.ParseResult.GetValueForOption(revocationsDirOption);
            var strictRevocations = context.ParseResult.GetValueForOption(strictRevocationsOption);
            var verifyTsa = context.ParseResult.GetValueForOption(tsaOption);
            var tsaTrustDir = context.ParseResult.GetValueForOption(tsaTrustDirOption);
            var strictTsa = context.ParseResult.GetValueForOption(strictTsaOption);

            var exitCode = await VerifyBundle(bundle, evidenceDir, verifyAttestations, verifyCitations,
                strictCitations, claimDir, revocationsDir, strictRevocations, verifyTsa, tsaTrustDir, strictTsa);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static Command CreateInspectCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var command = new Command("inspect", "Inspect a claim bundle without verification")
        {
            bundleArg
        };

        command.SetHandler(async (FileInfo bundle) =>
        {
            var exitCode = await InspectBundle(bundle);
            Environment.ExitCode = exitCode;
        }, bundleArg);

        return command;
    }

    private static Command CreateAttestCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");
        var typeOption = new Option<string>(
            "--type",
            "Attestation type: REVIEWED, REPRODUCED, INSTITUTION_APPROVED, DATA_AVAILABILITY_CONFIRMED")
        { IsRequired = true };
        typeOption.AddAlias("-t");

        var statementOption = new Option<string>(
            "--statement",
            "Attestation statement (what you are attesting)")
        { IsRequired = true };
        statementOption.AddAlias("-s");

        var attestorKeyOption = new Option<FileInfo>(
            "--attestor-key",
            "Path to attestor private key JSON file")
        { IsRequired = true };
        attestorKeyOption.AddAlias("-k");

        var outputOption = new Option<FileInfo?>(
            "--out",
            "Output path for attested bundle (default: <input>.attested.json)");
        outputOption.AddAlias("-o");

        var expiresOption = new Option<string?>(
            "--expires",
            "Expiration date (ISO-8601 format, optional)");

        var command = new Command("attest", "Create an attestation for a claim bundle")
        {
            bundleArg,
            typeOption,
            statementOption,
            attestorKeyOption,
            outputOption,
            expiresOption
        };

        command.SetHandler(async (FileInfo bundle, string type, string statement, FileInfo attestorKey, FileInfo? output, string? expires) =>
        {
            var exitCode = await CreateAttestation(bundle, type, statement, attestorKey, output, expires);
            Environment.ExitCode = exitCode;
        }, bundleArg, typeOption, statementOption, attestorKeyOption, outputOption, expiresOption);

        return command;
    }

    private static Command CreateAttestationsCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var command = new Command("attestations", "List attestations in a claim bundle")
        {
            bundleArg
        };

        command.SetHandler(async (FileInfo bundle) =>
        {
            var exitCode = await ListAttestations(bundle);
            Environment.ExitCode = exitCode;
        }, bundleArg);

        return command;
    }

    private static async Task<int> VerifyBundle(
        FileInfo bundleFile,
        DirectoryInfo? evidenceDir,
        bool verifyAttestations,
        bool verifyCitations = false,
        bool strictCitations = false,
        DirectoryInfo? claimDir = null,
        DirectoryInfo? revocationsDir = null,
        bool strictRevocations = false,
        bool verifyTsa = false,
        DirectoryInfo? tsaTrustDir = null,
        bool strictTsa = false)
    {
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        string bundleJson;
        try
        {
            bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        // Build evidence hash -> file path mapping
        Dictionary<string, string>? evidenceFiles = null;
        if (evidenceDir != null && evidenceDir.Exists)
        {
            evidenceFiles = new Dictionary<string, string>();
            foreach (var file in evidenceDir.GetFiles("*", SearchOption.AllDirectories))
            {
                try
                {
                    using var stream = File.OpenRead(file.FullName);
                    var hash = ContentHash.Compute(stream);
                    evidenceFiles[hash.ToString()] = file.FullName;
                }
                catch
                {
                    // Skip files we can't hash
                }
            }
        }

        // Build resolved bundles mapping for citation verification
        Dictionary<string, ClaimBundle>? resolvedBundles = null;
        if (claimDir != null && claimDir.Exists)
        {
            resolvedBundles = await LoadClaimBundlesFromDirectory(claimDir);
        }

        // Load revocations if provided
        RevocationRegistry? revocationRegistry = null;
        if (revocationsDir != null && revocationsDir.Exists)
        {
            revocationRegistry = await LoadRevocationsFromDirectory(revocationsDir);
        }

        var result = BundleVerifier.Verify(bundleJson, evidenceFiles);

        if (result.Status == VerificationStatus.Valid && result.Bundle != null)
        {
            var bundle = result.Bundle;
            Console.WriteLine($"\u2714 Valid");
            Console.WriteLine($"  Claim:      {Truncate(bundle.Claim.ClaimId, 8)}...");
            Console.WriteLine($"  Statement:  {Truncate(bundle.Claim.Statement, 60)}");
            Console.WriteLine($"  Researcher: {bundle.Researcher.DisplayName ?? "Anonymous"} ({Truncate(bundle.Researcher.PublicKey, 12)}...)");
            Console.WriteLine($"  Asserted:   {bundle.Claim.AssertedAtUtc}");
            Console.WriteLine($"  Evidence:   {bundle.Claim.Evidence.Count} reference(s)");
            Console.WriteLine($"  Signature:  Ed25519 \u2714 valid");

            if (evidenceFiles != null && evidenceFiles.Count > 0)
            {
                var matched = bundle.Claim.Evidence.Count(e => evidenceFiles.ContainsKey(e.Hash));
                Console.WriteLine($"  Files:      {matched}/{bundle.Claim.Evidence.Count} evidence files verified");
            }

            // Verify citations if requested
            if (verifyCitations && bundle.Citations != null && bundle.Citations.Count > 0)
            {
                var citationResult = VerifyCitationsHandler.Handle(
                    new VerifyCitationsQuery(bundle, strictCitations, resolvedBundles));

                Console.WriteLine();
                Console.WriteLine($"  Citations: {bundle.Citations.Count}");

                foreach (var check in citationResult.Results)
                {
                    var status = check.IsValid ? "\u2714" : "\u2718";
                    var resolved = check.IsResolved ? "resolved" : "unresolved";
                    var reason = check.IsValid ? resolved : check.FailureReason;
                    Console.WriteLine($"    {status} [{check.CitedDigest[..8]}...] {reason}");
                }

                if (citationResult.UnresolvedDigests.Count > 0 && !strictCitations)
                {
                    Console.WriteLine($"    \u26A0 {citationResult.UnresolvedDigests.Count} citation(s) unresolved (use --claim-dir to provide bundles)");
                }

                if (!citationResult.AllValid)
                {
                    Console.WriteLine();
                    Console.WriteLine("  \u2718 One or more citations failed verification");
                    return 3;
                }
            }
            else if (verifyCitations)
            {
                Console.WriteLine();
                Console.WriteLine("  Citations: none");
            }

            // Verify attestations if requested
            if (verifyAttestations && bundle.Attestations != null && bundle.Attestations.Count > 0)
            {
                var attestationResult = VerifyAttestationsHandler.Handle(
                    new VerifyAttestationsQuery(bundle, DateTimeOffset.UtcNow));

                Console.WriteLine();
                Console.WriteLine($"  Attestations: {bundle.Attestations.Count}");

                foreach (var check in attestationResult.Results)
                {
                    var status = check.IsValid ? "\u2714" : "\u2718";
                    Console.WriteLine($"    {status} {Truncate(check.AttestationId, 8)}... {(check.IsValid ? "valid" : check.FailureReason)}");
                }

                if (!attestationResult.AllValid)
                {
                    Console.WriteLine();
                    Console.WriteLine("  \u2718 One or more attestations failed verification");
                    return 3;
                }
            }
            else if (verifyAttestations)
            {
                Console.WriteLine();
                Console.WriteLine("  Attestations: none");
            }

            // Verify against revocations if provided
            if (revocationRegistry != null)
            {
                var revocationResult = VerifyAgainstRevocationsHandler.Handle(
                    new VerifyAgainstRevocationsQuery(bundle, revocationRegistry, strictRevocations));

                var revokedCount = revocationResult.Checks.Count(c => c.IsRevoked);
                if (revokedCount > 0 || revocationsDir != null)
                {
                    Console.WriteLine();
                    Console.WriteLine($"  Revocations: {revocationRegistry.GetAll().Count} loaded");

                    foreach (var check in revocationResult.Checks.Where(c => c.IsRevoked))
                    {
                        Console.WriteLine($"    \u2718 {check.SignatureType} signer revoked at {check.RevokedAtUtc} ({check.RevocationReason})");
                    }

                    if (revokedCount == 0)
                    {
                        Console.WriteLine($"    \u2714 No signer keys revoked");
                    }
                }

                foreach (var warning in revocationResult.Warnings)
                {
                    Console.WriteLine($"  \u26A0 {warning}");
                }

                if (!revocationResult.IsValid)
                {
                    Console.WriteLine();
                    Console.WriteLine("  \u2718 One or more signer keys are revoked");
                    return 6; // REVOKED - cryptographically valid but signer key revoked
                }
            }

            // Verify TSA timestamp receipts if requested
            if (verifyTsa && bundle.TimestampReceipts != null && bundle.TimestampReceipts.Count > 0)
            {
                // Load trust anchors if provided
                X509Certificate2Collection? trustAnchors = null;
                if (tsaTrustDir != null && tsaTrustDir.Exists)
                {
                    trustAnchors = TsaTrustVerifier.LoadCertificatesFromDirectory(tsaTrustDir.FullName);
                }

                var tsaResult = VerifyTimestampsHandler.Handle(
                    new VerifyTimestampsQuery(bundle, trustAnchors, strictTsa));

                Console.WriteLine();
                Console.WriteLine($"  Timestamps: {bundle.TimestampReceipts.Count}");

                foreach (var check in tsaResult.Results)
                {
                    var status = check.IsValid ? "\u2714" : "\u2718";
                    var trustStatus = check.IsTrusted ? "trusted" : "untrusted";
                    var info = check.IsValid ? $"{check.IssuedAt:O} ({trustStatus})" : check.Error;
                    Console.WriteLine($"    {status} {Truncate(check.ReceiptId, 8)}... {info}");
                    if (!string.IsNullOrEmpty(check.Warning))
                    {
                        Console.WriteLine($"      \u26A0 {check.Warning}");
                    }
                }

                if (tsaResult.EarliestTrustedTimestamp.HasValue)
                {
                    Console.WriteLine($"    Earliest trusted: {tsaResult.EarliestTrustedTimestamp.Value:O}");
                }

                if (!tsaResult.AllValid)
                {
                    Console.WriteLine();
                    Console.WriteLine("  \u2718 One or more timestamp receipts failed verification");
                    return 3; // BROKEN - invalid timestamp receipt
                }
            }
            else if (verifyTsa)
            {
                Console.WriteLine();
                Console.WriteLine("  Timestamps: none");
            }

            foreach (var warning in result.Warnings)
            {
                Console.WriteLine($"  \u26A0 {warning}");
            }
        }
        else if (result.Status == VerificationStatus.Broken)
        {
            Console.WriteLine($"\u2718 Broken");
            Console.WriteLine($"  {result.Message}");
            Console.WriteLine();
            Console.WriteLine("  Claim has been tampered with or signature is invalid");
        }
        else
        {
            Console.WriteLine($"\u2718 {result.Status}");
            Console.WriteLine($"  {result.Message}");
        }

        return result.ExitCode;
    }

    private static async Task<Dictionary<string, ClaimBundle>> LoadClaimBundlesFromDirectory(DirectoryInfo dir)
    {
        var result = new Dictionary<string, ClaimBundle>();

        foreach (var file in dir.GetFiles("*.json", SearchOption.AllDirectories))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file.FullName);
                var bundle = JsonSerializer.Deserialize<ClaimBundle>(json);
                if (bundle?.Claim != null)
                {
                    var digest = ClaimCoreDigest.Compute(bundle);
                    result[digest.ToString()] = bundle;
                }
            }
            catch
            {
                // Skip files that aren't valid claim bundles
            }
        }

        return result;
    }

    private static async Task<RevocationRegistry> LoadRevocationsFromDirectory(DirectoryInfo dir)
    {
        var registry = new RevocationRegistry();

        foreach (var file in dir.GetFiles("*.json", SearchOption.AllDirectories))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file.FullName);
                var bundle = JsonSerializer.Deserialize<RevocationBundle>(json);
                if (bundle?.Revocation != null)
                {
                    var revocation = RevocationRegistry.LoadFromBundle(bundle);
                    if (revocation != null)
                    {
                        registry.Add(revocation);
                    }
                }
            }
            catch
            {
                // Skip files that aren't valid revocation bundles
            }
        }

        return registry;
    }

    private static async Task<int> InspectBundle(FileInfo bundleFile)
    {
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        string bundleJson;
        try
        {
            bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        var result = BundleInspector.Inspect(bundleJson);

        if (result.IsSuccess && result.Bundle != null)
        {
            Console.WriteLine(BundleInspector.FormatForDisplay(result.Bundle));
            return 0;
        }
        else
        {
            Console.WriteLine($"Error: {result.ErrorMessage}");
            return 4;
        }
    }

    private static async Task<int> CreateAttestation(
        FileInfo bundleFile,
        string type,
        string statement,
        FileInfo attestorKeyFile,
        FileInfo? outputFile,
        string? expiresStr)
    {
        // Validate attestation type
        if (!AttestationType.IsValid(type))
        {
            Console.WriteLine($"Error: Invalid attestation type: {type}");
            Console.WriteLine($"Valid types: {string.Join(", ", AttestationType.All)}");
            return 4;
        }

        // Read bundle
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        // Read attestor key
        if (!attestorKeyFile.Exists)
        {
            Console.WriteLine($"Error: Attestor key file not found: {attestorKeyFile.FullName}");
            return 4;
        }

        AttestorKeyFile attestorKey;
        try
        {
            var keyJson = await File.ReadAllTextAsync(attestorKeyFile.FullName);
            attestorKey = JsonSerializer.Deserialize<AttestorKeyFile>(keyJson)
                ?? throw new JsonException("Key file is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading attestor key: {ex.Message}");
            return 5;
        }

        // Parse expiration if provided
        DateTimeOffset? expiresAt = null;
        if (!string.IsNullOrEmpty(expiresStr))
        {
            if (!DateTimeOffset.TryParse(expiresStr, out var parsed))
            {
                Console.WriteLine($"Error: Invalid expiration date: {expiresStr}");
                return 4;
            }
            expiresAt = parsed;
        }

        // Compute claim_core_digest
        var claimCoreDigest = ClaimCoreDigest.Compute(bundle);

        // Parse keys
        Ed25519PublicKey publicKey;
        Ed25519PrivateKey privateKey;
        try
        {
            publicKey = Ed25519PublicKey.Parse(attestorKey.PublicKey);
            var privateKeyBytes = Convert.FromBase64String(attestorKey.PrivateKey);
            privateKey = Ed25519PrivateKey.FromBytes(privateKeyBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing attestor keys: {ex.Message}");
            return 5;
        }

        // Build and sign attestation
        var attestationId = Domain.Primitives.AttestationId.New();
        var issuedAt = DateTimeOffset.UtcNow;

        var signable = new AttestationSignable
        {
            Contract = "AttestationSignable.v1",
            AttestationId = attestationId.ToString(),
            ClaimCoreDigest = claimCoreDigest.ToString(),
            Attestor = new AttestorIdentity
            {
                ResearcherId = attestorKey.ResearcherId,
                PublicKey = attestorKey.PublicKey,
                DisplayName = attestorKey.DisplayName
            },
            AttestationType = type,
            Statement = statement,
            IssuedAtUtc = issuedAt.ToString("O"),
            ExpiresAtUtc = expiresAt?.ToString("O"),
            Policy = null
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = privateKey.Sign(bytes);

        // Create attestation info
        var attestationInfo = new AttestationInfo
        {
            AttestationId = attestationId.ToString(),
            ClaimCoreDigest = claimCoreDigest.ToString(),
            Attestor = new AttestorInfo
            {
                ResearcherId = attestorKey.ResearcherId,
                PublicKey = attestorKey.PublicKey,
                DisplayName = attestorKey.DisplayName
            },
            AttestationType = type,
            Statement = statement,
            IssuedAtUtc = issuedAt.ToString("O"),
            ExpiresAtUtc = expiresAt?.ToString("O"),
            Signature = signature.ToString()
        };

        // Add to bundle
        var existingAttestations = bundle.Attestations ?? Array.Empty<AttestationInfo>();
        var newBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = bundle.Claim,
            Researcher = bundle.Researcher,
            Citations = bundle.Citations,
            Attestations = existingAttestations.Append(attestationInfo).ToList()
        };

        // Determine output path
        var outputPath = outputFile?.FullName
            ?? Path.Combine(
                Path.GetDirectoryName(bundleFile.FullName) ?? ".",
                Path.GetFileNameWithoutExtension(bundleFile.Name) + ".attested.json");

        // Write output
        try
        {
            var outputJson = JsonSerializer.Serialize(newBundle, JsonOptions);
            await File.WriteAllTextAsync(outputPath, outputJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing output: {ex.Message}");
            return 5;
        }

        Console.WriteLine($"\u2714 Attestation created");
        Console.WriteLine($"  ID:        {attestationId}");
        Console.WriteLine($"  Type:      {type}");
        Console.WriteLine($"  Statement: {Truncate(statement, 50)}");
        Console.WriteLine($"  Attestor:  {attestorKey.DisplayName ?? "Anonymous"}");
        Console.WriteLine($"  Output:    {outputPath}");

        return 0;
    }

    private static Command CreateCiteCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var digestOption = new Option<string?>(
            "--digest",
            "Cited claim's claim_core_digest (hex SHA-256)");
        digestOption.AddAlias("-d");

        var citedBundleOption = new Option<FileInfo?>(
            "--bundle",
            "Path to cited claim bundle (computes digest automatically)");
        citedBundleOption.AddAlias("-b");

        var relationOption = new Option<string>(
            "--relation",
            "Citation relation: CITES, DEPENDS_ON, REPRODUCES, DISPUTES")
        { IsRequired = true };
        relationOption.AddAlias("-r");

        var locatorOption = new Option<string?>(
            "--locator",
            "Optional locator (DOI, URL, filename)");
        locatorOption.AddAlias("-l");

        var notesOption = new Option<string?>(
            "--notes",
            "Optional notes about this citation");
        notesOption.AddAlias("-n");

        var signerKeyOption = new Option<FileInfo>(
            "--signer-key",
            "Path to signer private key JSON file (claim author)")
        { IsRequired = true };
        signerKeyOption.AddAlias("-k");

        var embedOption = new Option<bool>(
            "--embed",
            "Embed the cited bundle in the citation for offline verification");

        var outputOption = new Option<FileInfo?>(
            "--out",
            "Output path for cited bundle (default: <input>.cited.json)");
        outputOption.AddAlias("-o");

        var command = new Command("cite", "Add a citation to another claim")
        {
            bundleArg,
            digestOption,
            citedBundleOption,
            relationOption,
            locatorOption,
            notesOption,
            signerKeyOption,
            embedOption,
            outputOption
        };

        command.SetHandler(async context =>
        {
            var bundle = context.ParseResult.GetValueForArgument(bundleArg);
            var digest = context.ParseResult.GetValueForOption(digestOption);
            var citedBundle = context.ParseResult.GetValueForOption(citedBundleOption);
            var relation = context.ParseResult.GetValueForOption(relationOption)!;
            var locator = context.ParseResult.GetValueForOption(locatorOption);
            var notes = context.ParseResult.GetValueForOption(notesOption);
            var signerKey = context.ParseResult.GetValueForOption(signerKeyOption)!;
            var embed = context.ParseResult.GetValueForOption(embedOption);
            var output = context.ParseResult.GetValueForOption(outputOption);

            var exitCode = await CreateCitation(bundle, digest, citedBundle, relation, locator, notes, signerKey, embed, output);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static Command CreateCitationsCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var command = new Command("citations", "List citations in a claim bundle")
        {
            bundleArg
        };

        command.SetHandler(async (FileInfo bundle) =>
        {
            var exitCode = await ListCitations(bundle);
            Environment.ExitCode = exitCode;
        }, bundleArg);

        return command;
    }

    private static async Task<int> CreateCitation(
        FileInfo bundleFile,
        string? digestStr,
        FileInfo? citedBundleFile,
        string relation,
        string? locator,
        string? notes,
        FileInfo signerKeyFile,
        bool embed,
        FileInfo? outputFile)
    {
        // Validate relation
        if (!CitationRelation.IsValid(relation))
        {
            Console.WriteLine($"Error: Invalid citation relation: {relation}");
            Console.WriteLine($"Valid relations: {string.Join(", ", CitationRelation.All)}");
            return 4;
        }

        // Must provide either digest or cited bundle
        if (string.IsNullOrEmpty(digestStr) && citedBundleFile == null)
        {
            Console.WriteLine("Error: Must provide either --digest or --bundle");
            return 4;
        }

        // Read citing bundle
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        // Read cited bundle if provided
        ClaimBundle? citedBundle = null;
        Digest256 citedDigest;

        if (citedBundleFile != null)
        {
            if (!citedBundleFile.Exists)
            {
                Console.WriteLine($"Error: Cited bundle file not found: {citedBundleFile.FullName}");
                return 4;
            }

            try
            {
                var citedJson = await File.ReadAllTextAsync(citedBundleFile.FullName);
                citedBundle = JsonSerializer.Deserialize<ClaimBundle>(citedJson)
                    ?? throw new JsonException("Cited bundle is null");
                citedDigest = ClaimCoreDigest.Compute(citedBundle);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading cited bundle: {ex.Message}");
                return 5;
            }
        }
        else
        {
            try
            {
                citedDigest = Digest256.Parse(digestStr!);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing digest: {ex.Message}");
                return 4;
            }
        }

        // Read signer key
        if (!signerKeyFile.Exists)
        {
            Console.WriteLine($"Error: Signer key file not found: {signerKeyFile.FullName}");
            return 4;
        }

        AttestorKeyFile signerKey;
        try
        {
            var keyJson = await File.ReadAllTextAsync(signerKeyFile.FullName);
            signerKey = JsonSerializer.Deserialize<AttestorKeyFile>(keyJson)
                ?? throw new JsonException("Key file is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading signer key: {ex.Message}");
            return 5;
        }

        // Verify signer is the claim author
        if (signerKey.ResearcherId != bundle.Researcher.ResearcherId)
        {
            Console.WriteLine("Error: Signer must be the claim author");
            Console.WriteLine($"  Claim author:  {bundle.Researcher.ResearcherId}");
            Console.WriteLine($"  Signer:        {signerKey.ResearcherId}");
            return 4;
        }

        // Parse keys and sign
        Ed25519PrivateKey privateKey;
        try
        {
            var privateKeyBytes = Convert.FromBase64String(signerKey.PrivateKey);
            privateKey = Ed25519PrivateKey.FromBytes(privateKeyBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing signer keys: {ex.Message}");
            return 5;
        }

        // Build and sign citation
        var citationId = Domain.Primitives.CitationId.New();
        var issuedAt = DateTimeOffset.UtcNow;

        var signable = new CitationSignable
        {
            CitationId = citationId.ToString(),
            CitedClaimCoreDigest = citedDigest.ToString(),
            Relation = relation,
            Locator = locator,
            Notes = notes,
            IssuedAt = issuedAt.ToString("O")
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = privateKey.Sign(bytes);

        // Create citation info
        var citationInfo = new CitationInfo
        {
            CitationId = citationId.ToString(),
            CitedClaimCoreDigest = citedDigest.ToString(),
            Relation = relation,
            Locator = locator,
            Notes = notes,
            IssuedAtUtc = issuedAt.ToString("O"),
            Signature = signature.ToString(),
            Embedded = embed ? citedBundle : null
        };

        // Add to bundle
        var existingCitations = bundle.Citations ?? Array.Empty<CitationInfo>();
        var newBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = bundle.Claim,
            Researcher = bundle.Researcher,
            Citations = existingCitations.Append(citationInfo).ToList(),
            Attestations = bundle.Attestations
        };

        // Determine output path
        var outputPath = outputFile?.FullName
            ?? Path.Combine(
                Path.GetDirectoryName(bundleFile.FullName) ?? ".",
                Path.GetFileNameWithoutExtension(bundleFile.Name) + ".cited.json");

        // Write output
        try
        {
            var outputJson = JsonSerializer.Serialize(newBundle, JsonOptions);
            await File.WriteAllTextAsync(outputPath, outputJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing output: {ex.Message}");
            return 5;
        }

        Console.WriteLine($"\u2714 Citation created");
        Console.WriteLine($"  ID:       {citationId}");
        Console.WriteLine($"  Relation: {relation}");
        Console.WriteLine($"  Digest:   {citedDigest.ToString()[..16]}...");
        if (!string.IsNullOrEmpty(locator))
            Console.WriteLine($"  Locator:  {locator}");
        if (embed && citedBundle != null)
            Console.WriteLine($"  Embedded: yes");
        Console.WriteLine($"  Output:   {outputPath}");

        return 0;
    }

    private static async Task<int> ListCitations(FileInfo bundleFile)
    {
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        Console.WriteLine($"Claim: {Truncate(bundle.Claim.ClaimId, 8)}...");
        Console.WriteLine($"  {Truncate(bundle.Claim.Statement, 60)}");
        Console.WriteLine();

        if (bundle.Citations == null || bundle.Citations.Count == 0)
        {
            Console.WriteLine("Citations: none");
            return 0;
        }

        Console.WriteLine($"Citations: {bundle.Citations.Count}");
        Console.WriteLine();

        foreach (var citation in bundle.Citations)
        {
            Console.WriteLine($"  [{citation.Relation}] {Truncate(citation.CitationId, 8)}...");
            Console.WriteLine($"    Digest:   {Truncate(citation.CitedClaimCoreDigest, 16)}...");
            if (!string.IsNullOrEmpty(citation.Locator))
                Console.WriteLine($"    Locator:  {citation.Locator}");
            if (!string.IsNullOrEmpty(citation.Notes))
                Console.WriteLine($"    Notes:    {Truncate(citation.Notes, 50)}");
            Console.WriteLine($"    Issued:   {citation.IssuedAtUtc}");
            Console.WriteLine($"    Embedded: {(citation.Embedded != null ? "yes" : "no")}");
            Console.WriteLine();
        }

        return 0;
    }

    private static async Task<int> ListAttestations(FileInfo bundleFile)
    {
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        Console.WriteLine($"Claim: {Truncate(bundle.Claim.ClaimId, 8)}...");
        Console.WriteLine($"  {Truncate(bundle.Claim.Statement, 60)}");
        Console.WriteLine();

        if (bundle.Attestations == null || bundle.Attestations.Count == 0)
        {
            Console.WriteLine("Attestations: none");
            return 0;
        }

        Console.WriteLine($"Attestations: {bundle.Attestations.Count}");
        Console.WriteLine();

        foreach (var attestation in bundle.Attestations)
        {
            Console.WriteLine($"  [{attestation.AttestationType}] {Truncate(attestation.AttestationId, 8)}...");
            Console.WriteLine($"    Statement: {Truncate(attestation.Statement, 50)}");
            Console.WriteLine($"    Attestor:  {attestation.Attestor.DisplayName ?? "Anonymous"} ({Truncate(attestation.Attestor.PublicKey, 12)}...)");
            Console.WriteLine($"    Issued:    {attestation.IssuedAtUtc}");
            if (!string.IsNullOrEmpty(attestation.ExpiresAtUtc))
            {
                Console.WriteLine($"    Expires:   {attestation.ExpiresAtUtc}");
            }
            Console.WriteLine();
        }

        return 0;
    }

    private static Command CreateRevokeKeyCommand()
    {
        var keyFileArg = new Argument<FileInfo>("key-file", "Path to key file to revoke");

        var reasonOption = new Option<string>(
            "--reason",
            "Revocation reason: COMPROMISED, ROTATED, RETIRED, OTHER")
        { IsRequired = true };
        reasonOption.AddAlias("-r");

        var successorKeyOption = new Option<FileInfo?>(
            "--successor-key",
            "Path to successor key file (for rotation)");
        successorKeyOption.AddAlias("-s");

        var revokedAtOption = new Option<string?>(
            "--revoked-at",
            "Revocation time (ISO-8601, default: now)");

        var notesOption = new Option<string?>(
            "--notes",
            "Optional notes about this revocation");
        notesOption.AddAlias("-n");

        var outputOption = new Option<FileInfo?>(
            "--out",
            "Output path for revocation bundle (default: <key-file>.revoked.json)");
        outputOption.AddAlias("-o");

        var successorSignedOption = new Option<bool>(
            "--successor-signed",
            "Sign with successor key instead of revoked key (requires --successor-key)");

        var command = new Command("revoke-key", "Create a key revocation")
        {
            keyFileArg,
            reasonOption,
            successorKeyOption,
            revokedAtOption,
            notesOption,
            outputOption,
            successorSignedOption
        };

        command.SetHandler(async context =>
        {
            var keyFile = context.ParseResult.GetValueForArgument(keyFileArg);
            var reason = context.ParseResult.GetValueForOption(reasonOption)!;
            var successorKey = context.ParseResult.GetValueForOption(successorKeyOption);
            var revokedAtStr = context.ParseResult.GetValueForOption(revokedAtOption);
            var notes = context.ParseResult.GetValueForOption(notesOption);
            var output = context.ParseResult.GetValueForOption(outputOption);
            var successorSigned = context.ParseResult.GetValueForOption(successorSignedOption);

            var exitCode = await CreateRevocation(keyFile, reason, successorKey, revokedAtStr, notes, output, successorSigned);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static Command CreateRevocationsCommand()
    {
        var dirArg = new Argument<DirectoryInfo>("directory", "Directory containing revocation bundles");

        var command = new Command("revocations", "List revocations in a directory")
        {
            dirArg
        };

        command.SetHandler(async (DirectoryInfo dir) =>
        {
            var exitCode = await ListRevocations(dir);
            Environment.ExitCode = exitCode;
        }, dirArg);

        return command;
    }

    private static async Task<int> CreateRevocation(
        FileInfo keyFile,
        string reason,
        FileInfo? successorKeyFile,
        string? revokedAtStr,
        string? notes,
        FileInfo? outputFile,
        bool successorSigned)
    {
        // Validate reason
        if (!RevocationReason.IsValid(reason))
        {
            Console.WriteLine($"Error: Invalid revocation reason: {reason}");
            Console.WriteLine($"Valid reasons: {string.Join(", ", RevocationReason.All)}");
            return 4;
        }

        // Successor-signed requires successor key
        if (successorSigned && successorKeyFile == null)
        {
            Console.WriteLine("Error: --successor-signed requires --successor-key");
            return 4;
        }

        // Read key to revoke
        if (!keyFile.Exists)
        {
            Console.WriteLine($"Error: Key file not found: {keyFile.FullName}");
            return 4;
        }

        AttestorKeyFile revokedKey;
        try
        {
            var keyJson = await File.ReadAllTextAsync(keyFile.FullName);
            revokedKey = JsonSerializer.Deserialize<AttestorKeyFile>(keyJson)
                ?? throw new JsonException("Key file is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading key file: {ex.Message}");
            return 5;
        }

        // Read successor key if provided
        AttestorKeyFile? successorKey = null;
        if (successorKeyFile != null)
        {
            if (!successorKeyFile.Exists)
            {
                Console.WriteLine($"Error: Successor key file not found: {successorKeyFile.FullName}");
                return 4;
            }

            try
            {
                var successorJson = await File.ReadAllTextAsync(successorKeyFile.FullName);
                successorKey = JsonSerializer.Deserialize<AttestorKeyFile>(successorJson)
                    ?? throw new JsonException("Successor key file is null");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading successor key file: {ex.Message}");
                return 5;
            }
        }

        // Parse revoked-at if provided
        DateTimeOffset revokedAt = DateTimeOffset.UtcNow;
        if (!string.IsNullOrEmpty(revokedAtStr))
        {
            if (!DateTimeOffset.TryParse(revokedAtStr, out revokedAt))
            {
                Console.WriteLine($"Error: Invalid revoked-at date: {revokedAtStr}");
                return 4;
            }
        }

        // Parse keys
        var researcherId = ResearcherId.Parse(revokedKey.ResearcherId);
        var revokedPublicKey = Ed25519PublicKey.Parse(revokedKey.PublicKey);
        var revokedPrivateKeyBytes = Convert.FromBase64String(revokedKey.PrivateKey);
        var revokedPrivateKey = Ed25519PrivateKey.FromBytes(revokedPrivateKeyBytes);

        Ed25519PublicKey? successorPublicKey = null;
        Ed25519PrivateKey? successorPrivateKey = null;
        if (successorKey != null)
        {
            successorPublicKey = Ed25519PublicKey.Parse(successorKey.PublicKey);
            var successorPrivateKeyBytes = Convert.FromBase64String(successorKey.PrivateKey);
            successorPrivateKey = Ed25519PrivateKey.FromBytes(successorPrivateKeyBytes);
        }

        // Create revocation
        Domain.Revocations.Revocation revocation;
        if (successorSigned && successorPublicKey != null && successorPrivateKey != null)
        {
            revocation = Domain.Revocations.Revocation.CreateSuccessorSigned(
                researcherId,
                revokedPublicKey,
                successorPublicKey,
                successorPrivateKey,
                revokedAt,
                reason,
                notes);
        }
        else
        {
            revocation = Domain.Revocations.Revocation.CreateSelfSigned(
                researcherId,
                revokedPublicKey,
                revokedPrivateKey,
                revokedAt,
                reason,
                successorPublicKey,
                notes);
        }

        // Export to bundle
        var bundle = ExportRevocationBundleHandler.Handle(revocation, revokedKey.DisplayName);

        // Determine output path
        var outputPath = outputFile?.FullName
            ?? Path.Combine(
                Path.GetDirectoryName(keyFile.FullName) ?? ".",
                Path.GetFileNameWithoutExtension(keyFile.Name) + ".revoked.json");

        // Write output
        try
        {
            var outputJson = JsonSerializer.Serialize(bundle, JsonOptions);
            await File.WriteAllTextAsync(outputPath, outputJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing output: {ex.Message}");
            return 5;
        }

        Console.WriteLine($"\u2714 Key revoked");
        Console.WriteLine($"  ID:         {revocation.Id}");
        Console.WriteLine($"  Reason:     {reason}");
        Console.WriteLine($"  Revoked At: {revokedAt:O}");
        Console.WriteLine($"  Issuer:     {revocation.IssuerMode}");
        if (successorPublicKey != null)
            Console.WriteLine($"  Successor:  {Truncate(successorPublicKey.ToString(), 16)}...");
        Console.WriteLine($"  Output:     {outputPath}");

        return 0;
    }

    private static async Task<int> ListRevocations(DirectoryInfo dir)
    {
        if (!dir.Exists)
        {
            Console.WriteLine($"Error: Directory not found: {dir.FullName}");
            return 4;
        }

        var registry = await LoadRevocationsFromDirectory(dir);
        var revocations = registry.GetAll();

        if (revocations.Count == 0)
        {
            Console.WriteLine("No revocations found");
            return 0;
        }

        Console.WriteLine($"Revocations: {revocations.Count}");
        Console.WriteLine();

        foreach (var revocation in revocations.OrderBy(r => r.RevokedAtUtc))
        {
            Console.WriteLine($"  [{revocation.Reason}] {Truncate(revocation.Id.ToString(), 8)}...");
            Console.WriteLine($"    Key:        {Truncate(revocation.RevokedPublicKey.ToString(), 16)}...");
            Console.WriteLine($"    Revoked At: {revocation.RevokedAtUtc:O}");
            Console.WriteLine($"    Issuer:     {revocation.IssuerMode}");
            if (revocation.SuccessorPublicKey != null)
                Console.WriteLine($"    Successor:  {Truncate(revocation.SuccessorPublicKey.ToString(), 16)}...");
            if (!string.IsNullOrEmpty(revocation.Notes))
                Console.WriteLine($"    Notes:      {Truncate(revocation.Notes, 50)}");
            Console.WriteLine();
        }

        return 0;
    }

    private static Command CreateWitnessCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var witnessKeyOption = new Option<FileInfo>(
            "--witness-key",
            "Path to witness private key JSON file")
        { IsRequired = true };
        witnessKeyOption.AddAlias("-k");

        var issuedAtOption = new Option<string?>(
            "--issued-at",
            "Witness timestamp (ISO-8601 UTC, default: now)");
        issuedAtOption.AddAlias("-t");

        var statementOption = new Option<string?>(
            "--statement",
            "Optional statement (default: 'Witnessed claim existence')");
        statementOption.AddAlias("-s");

        var outputOption = new Option<FileInfo?>(
            "--out",
            "Output path for witnessed bundle (default: <input>.witnessed.json)");
        outputOption.AddAlias("-o");

        var command = new Command("witness", "Create a witness timestamp attestation for a claim")
        {
            bundleArg,
            witnessKeyOption,
            issuedAtOption,
            statementOption,
            outputOption
        };

        command.SetHandler(async context =>
        {
            var bundle = context.ParseResult.GetValueForArgument(bundleArg);
            var witnessKey = context.ParseResult.GetValueForOption(witnessKeyOption)!;
            var issuedAtStr = context.ParseResult.GetValueForOption(issuedAtOption);
            var statement = context.ParseResult.GetValueForOption(statementOption);
            var output = context.ParseResult.GetValueForOption(outputOption);

            var exitCode = await CreateWitnessAttestation(bundle, witnessKey, issuedAtStr, statement, output);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> CreateWitnessAttestation(
        FileInfo bundleFile,
        FileInfo witnessKeyFile,
        string? issuedAtStr,
        string? statement,
        FileInfo? outputFile)
    {
        // Read bundle
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        // Read witness key
        if (!witnessKeyFile.Exists)
        {
            Console.WriteLine($"Error: Witness key file not found: {witnessKeyFile.FullName}");
            return 4;
        }

        AttestorKeyFile witnessKey;
        try
        {
            var keyJson = await File.ReadAllTextAsync(witnessKeyFile.FullName);
            witnessKey = JsonSerializer.Deserialize<AttestorKeyFile>(keyJson)
                ?? throw new JsonException("Key file is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading witness key: {ex.Message}");
            return 5;
        }

        // Parse issued-at if provided, default to now
        DateTimeOffset issuedAt = DateTimeOffset.UtcNow;
        if (!string.IsNullOrEmpty(issuedAtStr))
        {
            if (!DateTimeOffset.TryParse(issuedAtStr, out issuedAt))
            {
                Console.WriteLine($"Error: Invalid issued-at date: {issuedAtStr}");
                return 4;
            }
        }

        // Default statement
        var attestationStatement = statement ?? "Witnessed claim existence";

        // Compute claim_core_digest
        var claimCoreDigest = ClaimCoreDigest.Compute(bundle);

        // Parse keys
        Ed25519PublicKey publicKey;
        Ed25519PrivateKey privateKey;
        try
        {
            publicKey = Ed25519PublicKey.Parse(witnessKey.PublicKey);
            var privateKeyBytes = Convert.FromBase64String(witnessKey.PrivateKey);
            privateKey = Ed25519PrivateKey.FromBytes(privateKeyBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing witness keys: {ex.Message}");
            return 5;
        }

        // Build and sign witness attestation
        var attestationId = Domain.Primitives.AttestationId.New();

        var signable = new AttestationSignable
        {
            Contract = "AttestationSignable.v1",
            AttestationId = attestationId.ToString(),
            ClaimCoreDigest = claimCoreDigest.ToString(),
            Attestor = new AttestorIdentity
            {
                ResearcherId = witnessKey.ResearcherId,
                PublicKey = witnessKey.PublicKey,
                DisplayName = witnessKey.DisplayName
            },
            AttestationType = AttestationType.WitnessedAt,
            Statement = attestationStatement,
            IssuedAtUtc = issuedAt.ToString("O"),
            ExpiresAtUtc = null,
            Policy = null
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = privateKey.Sign(bytes);

        // Create attestation info
        var attestationInfo = new AttestationInfo
        {
            AttestationId = attestationId.ToString(),
            ClaimCoreDigest = claimCoreDigest.ToString(),
            Attestor = new AttestorInfo
            {
                ResearcherId = witnessKey.ResearcherId,
                PublicKey = witnessKey.PublicKey,
                DisplayName = witnessKey.DisplayName
            },
            AttestationType = AttestationType.WitnessedAt,
            Statement = attestationStatement,
            IssuedAtUtc = issuedAt.ToString("O"),
            ExpiresAtUtc = null,
            Signature = signature.ToString()
        };

        // Add to bundle (append-only)
        var existingAttestations = bundle.Attestations ?? Array.Empty<AttestationInfo>();
        var newBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = bundle.Claim,
            Researcher = bundle.Researcher,
            Citations = bundle.Citations,
            Attestations = existingAttestations.Append(attestationInfo).ToList()
        };

        // Determine output path
        var outputPath = outputFile?.FullName
            ?? Path.Combine(
                Path.GetDirectoryName(bundleFile.FullName) ?? ".",
                Path.GetFileNameWithoutExtension(bundleFile.Name) + ".witnessed.json");

        // Write output
        try
        {
            var outputJson = JsonSerializer.Serialize(newBundle, JsonOptions);
            await File.WriteAllTextAsync(outputPath, outputJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing output: {ex.Message}");
            return 5;
        }

        Console.WriteLine($"\u2714 Witness timestamp created");
        Console.WriteLine($"  ID:          {attestationId}");
        Console.WriteLine($"  Witnessed:   {issuedAt:O}");
        Console.WriteLine($"  Digest:      {Truncate(claimCoreDigest.ToString(), 16)}...");
        Console.WriteLine($"  Witness:     {witnessKey.DisplayName ?? "Anonymous"} ({Truncate(witnessKey.PublicKey, 12)}...)");
        Console.WriteLine($"  Output:      {outputPath}");

        return 0;
    }

    private static string Truncate(string s, int maxLength)
        => s.Length <= maxLength ? s : s[..maxLength];

    private static Command CreateTsaRequestCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var outputOption = new Option<FileInfo?>(
            "--out",
            "Output path for timestamp request (.tsq file)");
        outputOption.AddAlias("-o");

        var nonceOption = new Option<string?>(
            "--nonce",
            "Optional nonce (hex) for the request");

        var noCertReqOption = new Option<bool>(
            "--no-cert-req",
            "Don't request the TSA to include its certificate in the response");

        var command = new Command("tsa-request", "Create an RFC 3161 timestamp request for a claim")
        {
            bundleArg,
            outputOption,
            nonceOption,
            noCertReqOption
        };

        command.SetHandler(async context =>
        {
            var bundle = context.ParseResult.GetValueForArgument(bundleArg);
            var output = context.ParseResult.GetValueForOption(outputOption);
            var nonceHex = context.ParseResult.GetValueForOption(nonceOption);
            var noCertReq = context.ParseResult.GetValueForOption(noCertReqOption);

            var exitCode = await CreateTsaRequest(bundle, output, nonceHex, noCertReq);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> CreateTsaRequest(
        FileInfo bundleFile,
        FileInfo? outputFile,
        string? nonceHex,
        bool noCertReq)
    {
        // Read bundle
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        // Parse nonce if provided
        byte[]? nonce = null;
        if (!string.IsNullOrEmpty(nonceHex))
        {
            try
            {
                nonce = Convert.FromHexString(nonceHex);
            }
            catch
            {
                Console.WriteLine($"Error: Invalid nonce hex: {nonceHex}");
                return 4;
            }
        }

        // Create the request
        var requestBytes = CreateTsaRequestHandler.Handle(new CreateTsaRequestCommand(
            bundle,
            IncludeCertRequest: !noCertReq,
            Nonce: nonce));

        // Determine output path
        var outputPath = outputFile?.FullName
            ?? Path.Combine(
                Path.GetDirectoryName(bundleFile.FullName) ?? ".",
                Path.GetFileNameWithoutExtension(bundleFile.Name) + ".tsq");

        // Write output
        try
        {
            await File.WriteAllBytesAsync(outputPath, requestBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing output: {ex.Message}");
            return 5;
        }

        var digest = ClaimCoreDigest.Compute(bundle);

        Console.WriteLine($"\u2714 TSA request created");
        Console.WriteLine($"  Digest:  {Truncate(digest.ToString(), 16)}...");
        Console.WriteLine($"  Size:    {requestBytes.Length} bytes");
        Console.WriteLine($"  Output:  {outputPath}");
        Console.WriteLine();
        Console.WriteLine("  Send this .tsq file to a TSA service (e.g., FreeTSA, DigiCert)");
        Console.WriteLine("  Then attach the response with: claimledger tsa-attach");

        return 0;
    }

    private static Command CreateTsaAttachCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var tokenOption = new Option<FileInfo>(
            "--token",
            "Path to TSA response token file (.tsr)")
        { IsRequired = true };
        tokenOption.AddAlias("-t");

        var outputOption = new Option<FileInfo?>(
            "--out",
            "Output path for bundle with timestamp (default: <input>.tsa.json)");
        outputOption.AddAlias("-o");

        var command = new Command("tsa-attach", "Attach an RFC 3161 timestamp token to a claim")
        {
            bundleArg,
            tokenOption,
            outputOption
        };

        command.SetHandler(async context =>
        {
            var bundle = context.ParseResult.GetValueForArgument(bundleArg);
            var token = context.ParseResult.GetValueForOption(tokenOption)!;
            var output = context.ParseResult.GetValueForOption(outputOption);

            var exitCode = await AttachTsaToken(bundle, token, output);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> AttachTsaToken(
        FileInfo bundleFile,
        FileInfo tokenFile,
        FileInfo? outputFile)
    {
        // Read bundle
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        // Read token
        if (!tokenFile.Exists)
        {
            Console.WriteLine($"Error: Token file not found: {tokenFile.FullName}");
            return 4;
        }

        byte[] tokenBytes;
        try
        {
            tokenBytes = await File.ReadAllBytesAsync(tokenFile.FullName);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading token: {ex.Message}");
            return 5;
        }

        // Attach the token
        var result = AttachTsaTokenHandler.Handle(new AttachTsaTokenCommand(bundle, tokenBytes));

        if (!result.Success)
        {
            Console.WriteLine($"\u2718 Failed to attach token");
            Console.WriteLine($"  {result.Error}");
            return 3;
        }

        // Add receipt to bundle
        var newBundle = AddTimestampToBundleHandler.Handle(
            new AddTimestampToBundleCommand(bundle, result.Receipt!));

        // Determine output path
        var outputPath = outputFile?.FullName
            ?? Path.Combine(
                Path.GetDirectoryName(bundleFile.FullName) ?? ".",
                Path.GetFileNameWithoutExtension(bundleFile.Name) + ".tsa.json");

        // Write output
        try
        {
            var outputJson = JsonSerializer.Serialize(newBundle, JsonOptions);
            await File.WriteAllTextAsync(outputPath, outputJson);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing output: {ex.Message}");
            return 5;
        }

        var receipt = result.Receipt!;
        Console.WriteLine($"\u2714 Timestamp attached");
        Console.WriteLine($"  ID:        {receipt.ReceiptId}");
        Console.WriteLine($"  Issued At: {receipt.IssuedAt:O}");
        Console.WriteLine($"  TSA:       {receipt.Tsa.CertSubject ?? "Unknown"}");
        Console.WriteLine($"  Output:    {outputPath}");

        return 0;
    }

    private static Command CreateTimestampsCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to claim bundle JSON file");

        var command = new Command("timestamps", "List RFC 3161 timestamp receipts in a claim bundle")
        {
            bundleArg
        };

        command.SetHandler(async (FileInfo bundle) =>
        {
            var exitCode = await ListTimestamps(bundle);
            Environment.ExitCode = exitCode;
        }, bundleArg);

        return command;
    }

    private static async Task<int> ListTimestamps(FileInfo bundleFile)
    {
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        Console.WriteLine($"Claim: {Truncate(bundle.Claim.ClaimId, 8)}...");
        Console.WriteLine($"  {Truncate(bundle.Claim.Statement, 60)}");
        Console.WriteLine();

        if (bundle.TimestampReceipts == null || bundle.TimestampReceipts.Count == 0)
        {
            Console.WriteLine("Timestamps: none");
            return 0;
        }

        Console.WriteLine($"Timestamps: {bundle.TimestampReceipts.Count}");
        Console.WriteLine();

        foreach (var receipt in bundle.TimestampReceipts)
        {
            Console.WriteLine($"  [{receipt.Contract}] {Truncate(receipt.ReceiptId, 8)}...");
            Console.WriteLine($"    Issued At: {receipt.IssuedAt}");
            Console.WriteLine($"    Digest:    {Truncate(receipt.Subject.DigestHex, 16)}...");
            Console.WriteLine($"    Imprint:   {Truncate(receipt.MessageImprintHex, 16)}...");
            if (!string.IsNullOrEmpty(receipt.Tsa.PolicyOid))
                Console.WriteLine($"    Policy:    {receipt.Tsa.PolicyOid}");
            if (!string.IsNullOrEmpty(receipt.Tsa.CertFingerprintSha256Hex))
                Console.WriteLine($"    Cert:      {Truncate(receipt.Tsa.CertFingerprintSha256Hex, 16)}...");
            Console.WriteLine();
        }

        return 0;
    }

    private static Command CreatePackCommand()
    {
        var bundleArg = new Argument<FileInfo>("bundle", "Path to root claim bundle JSON file");

        var outputOption = new Option<DirectoryInfo>(
            "--out",
            "Output directory for the pack")
        { IsRequired = true };
        outputOption.AddAlias("-o");

        var includeCitationsOption = new Option<bool>(
            "--include-citations",
            "Include cited claim bundles in the pack");

        var evidenceOption = new Option<DirectoryInfo?>(
            "--include-evidence",
            "Directory containing evidence files to include");

        var revocationsOption = new Option<DirectoryInfo?>(
            "--include-revocations",
            "Directory containing revocation bundles to include");

        var tsaTrustOption = new Option<DirectoryInfo?>(
            "--include-tsa-trust",
            "Directory containing TSA trust anchors to include");

        var creatorLedgerOption = new Option<DirectoryInfo?>(
            "--include-creatorledger",
            "Directory containing CreatorLedger proof bundles to include");

        var strictCreatorLedgerOption = new Option<bool>(
            "--strict-creatorledger",
            "Fail if any CREATORLEDGER_BUNDLE evidence cannot be resolved");

        var command = new Command("pack", "Create a portable ClaimPack from a claim bundle")
        {
            bundleArg,
            outputOption,
            includeCitationsOption,
            evidenceOption,
            revocationsOption,
            tsaTrustOption,
            creatorLedgerOption,
            strictCreatorLedgerOption
        };

        command.SetHandler(async context =>
        {
            var bundle = context.ParseResult.GetValueForArgument(bundleArg);
            var output = context.ParseResult.GetValueForOption(outputOption)!;
            var includeCitations = context.ParseResult.GetValueForOption(includeCitationsOption);
            var evidence = context.ParseResult.GetValueForOption(evidenceOption);
            var revocations = context.ParseResult.GetValueForOption(revocationsOption);
            var tsaTrust = context.ParseResult.GetValueForOption(tsaTrustOption);
            var creatorLedger = context.ParseResult.GetValueForOption(creatorLedgerOption);
            var strictCL = context.ParseResult.GetValueForOption(strictCreatorLedgerOption);

            var exitCode = await CreatePack(bundle, output, includeCitations, evidence, revocations, tsaTrust, creatorLedger, strictCL);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> CreatePack(
        FileInfo bundleFile,
        DirectoryInfo outputDir,
        bool includeCitations,
        DirectoryInfo? evidenceDir,
        DirectoryInfo? revocationsDir,
        DirectoryInfo? tsaTrustDir,
        DirectoryInfo? creatorLedgerDir,
        bool strictCreatorLedger)
    {
        // Read bundle
        if (!bundleFile.Exists)
        {
            Console.WriteLine($"Error: Bundle file not found: {bundleFile.FullName}");
            return 4;
        }

        ClaimBundle bundle;
        try
        {
            var bundleJson = await File.ReadAllTextAsync(bundleFile.FullName);
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading bundle: {ex.Message}");
            return 5;
        }

        // Create pack
        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle,
            outputDir.FullName,
            includeCitations,
            evidenceDir?.FullName,
            revocationsDir?.FullName,
            tsaTrustDir?.FullName,
            null, // ResolvedCitations
            creatorLedgerDir?.FullName,
            strictCreatorLedger));

        if (!result.Success)
        {
            Console.WriteLine($"\u2718 Pack creation failed");
            Console.WriteLine($"  {result.Error}");
            return 5;
        }

        var digest = ClaimCoreDigest.Compute(bundle);

        Console.WriteLine($"\u2714 ClaimPack created");
        Console.WriteLine($"  Pack ID:   {result.Manifest!.PackId}");
        Console.WriteLine($"  Digest:    {Truncate(digest.ToString(), 16)}...");
        Console.WriteLine($"  Files:     {result.FilesWritten}");
        Console.WriteLine($"  Output:    {result.PackDirectory}");

        return 0;
    }

    private static Command CreateVerifyPackCommand()
    {
        var packArg = new Argument<DirectoryInfo>("pack", "Path to ClaimPack directory");

        var strictOption = new Option<bool>(
            "--strict",
            "Enable all strict verification modes");

        var strictCitationsOption = new Option<bool>(
            "--strict-citations",
            "Fail if any citation cannot be resolved");

        var strictRevocationsOption = new Option<bool>(
            "--strict-revocations",
            "Fail if any signer key is revoked");

        var strictTsaOption = new Option<bool>(
            "--strict-tsa",
            "Fail if any TSA receipt is untrusted");

        var verifyManifestSignaturesOption = new Option<bool>(
            "--verify-manifest-signatures",
            "Verify manifest signatures if present");

        var strictManifestSignaturesOption = new Option<bool>(
            "--strict-manifest-signatures",
            "Require at least one valid manifest signature");

        var noCitationsOption = new Option<bool>(
            "--no-citations",
            "Skip citation verification");

        var noAttestationsOption = new Option<bool>(
            "--no-attestations",
            "Skip attestation verification");

        var noTsaOption = new Option<bool>(
            "--no-tsa",
            "Skip TSA timestamp verification");

        var verifyCreatorLedgerOption = new Option<bool>(
            "--verify-creatorledger",
            "Verify CreatorLedger bundle evidence");

        var strictCreatorLedgerOption = new Option<bool>(
            "--strict-creatorledger",
            "Fail if any CreatorLedger bundle is missing or invalid");

        var creatorLedgerDirOption = new Option<DirectoryInfo?>(
            "--creatorledger-dir",
            "Override directory for resolving CreatorLedger bundles");

        var registryOption = new Option<DirectoryInfo?>(
            "--registry",
            "Registry for resolving citations and bundles");

        var strictRegistryOption = new Option<bool>(
            "--strict-registry",
            "Fail if registry resolution fails");

        var command = new Command("verify-pack", "Verify a ClaimPack with one command")
        {
            packArg,
            strictOption,
            strictCitationsOption,
            strictRevocationsOption,
            strictTsaOption,
            verifyManifestSignaturesOption,
            strictManifestSignaturesOption,
            noCitationsOption,
            noAttestationsOption,
            noTsaOption,
            verifyCreatorLedgerOption,
            strictCreatorLedgerOption,
            creatorLedgerDirOption,
            registryOption,
            strictRegistryOption
        };

        command.SetHandler(async context =>
        {
            var pack = context.ParseResult.GetValueForArgument(packArg);
            var strict = context.ParseResult.GetValueForOption(strictOption);
            var strictCitations = context.ParseResult.GetValueForOption(strictCitationsOption);
            var strictRevocations = context.ParseResult.GetValueForOption(strictRevocationsOption);
            var strictTsa = context.ParseResult.GetValueForOption(strictTsaOption);
            var verifyManifestSigs = context.ParseResult.GetValueForOption(verifyManifestSignaturesOption);
            var strictManifestSigs = context.ParseResult.GetValueForOption(strictManifestSignaturesOption);
            var noCitations = context.ParseResult.GetValueForOption(noCitationsOption);
            var noAttestations = context.ParseResult.GetValueForOption(noAttestationsOption);
            var noTsa = context.ParseResult.GetValueForOption(noTsaOption);
            var verifyCreatorLedger = context.ParseResult.GetValueForOption(verifyCreatorLedgerOption);
            var strictCreatorLedger = context.ParseResult.GetValueForOption(strictCreatorLedgerOption);
            var creatorLedgerDir = context.ParseResult.GetValueForOption(creatorLedgerDirOption);
            var registry = context.ParseResult.GetValueForOption(registryOption);
            var strictRegistry = context.ParseResult.GetValueForOption(strictRegistryOption);

            var exitCode = await VerifyPack(pack, strict, strictCitations, strictRevocations, strictTsa,
                strictManifestSigs, !noCitations, !noAttestations, !noTsa, verifyManifestSigs || strictManifestSigs,
                verifyCreatorLedger || strictCreatorLedger, strictCreatorLedger, creatorLedgerDir,
                registry, strictRegistry);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> VerifyPack(
        DirectoryInfo packDir,
        bool strict,
        bool strictCitations,
        bool strictRevocations,
        bool strictTsa,
        bool strictManifestSignatures,
        bool verifyCitations,
        bool verifyAttestations,
        bool verifyTsa,
        bool verifyManifestSignatures,
        bool verifyCreatorLedger,
        bool strictCreatorLedger,
        DirectoryInfo? creatorLedgerDir,
        DirectoryInfo? registryDir,
        bool strictRegistry)
    {
        if (!packDir.Exists)
        {
            Console.WriteLine($"Error: Pack directory not found: {packDir.FullName}");
            return 4;
        }

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir.FullName,
            strict,
            strictCitations,
            strictRevocations,
            strictTsa,
            strictManifestSignatures,
            verifyCitations,
            verifyAttestations,
            verifyTsa,
            verifyManifestSignatures,
            verifyCreatorLedger,
            strictCreatorLedger,
            creatorLedgerDir?.FullName,
            registryDir?.FullName,
            strictRegistry));

        if (result.IsValid)
        {
            Console.WriteLine($"\u2714 Valid ClaimPack");
            Console.WriteLine($"  Pack ID:   {result.Manifest?.PackId}");
            Console.WriteLine($"  Digest:    {Truncate(result.RootClaimCoreDigest ?? "", 16)}...");
            Console.WriteLine($"  Statement: {Truncate(result.RootBundle?.Claim.Statement ?? "", 50)}");

            if (result.ManifestCheck != null)
            {
                Console.WriteLine($"  Files:     {result.ManifestCheck.FilesChecked} verified");
            }

            if (result.CitationsResult != null && result.CitationsResult.Results.Count > 0)
            {
                Console.WriteLine($"  Citations: {result.CitationsResult.Results.Count} verified");
            }

            if (result.AttestationsResult != null && result.AttestationsResult.Results.Count > 0)
            {
                Console.WriteLine($"  Attestations: {result.AttestationsResult.Results.Count} verified");
            }

            if (result.TimestampsResult != null && result.TimestampsResult.Results.Count > 0)
            {
                var trusted = result.TimestampsResult.Results.Count(r => r.IsTrusted);
                Console.WriteLine($"  Timestamps: {result.TimestampsResult.Results.Count} ({trusted} trusted)");
            }

            if (result.ManifestSignaturesResult != null && result.ManifestSignaturesResult.TotalSignatures > 0)
            {
                Console.WriteLine($"  Manifest Signatures: {result.ManifestSignaturesResult.ValidSignatures}/{result.ManifestSignaturesResult.TotalSignatures} valid");
            }

            if (result.CreatorLedgerResult != null && result.CreatorLedgerResult.TotalBundles > 0)
            {
                Console.WriteLine($"  CreatorLedger: {result.CreatorLedgerResult.BundlesVerified}/{result.CreatorLedgerResult.TotalBundles} verified");
            }

            if (result.RegistryResult != null && result.RegistryResult.UsedRegistry)
            {
                var regResolved = result.RegistryResult.CitationsResolvedViaRegistry + result.RegistryResult.BundlesResolvedViaRegistry;
                if (regResolved > 0)
                {
                    Console.WriteLine($"  Registry:    {regResolved} resolved via registry");
                }
            }

            foreach (var warning in result.Warnings)
            {
                Console.WriteLine($"  \u26A0 {warning}");
            }
        }
        else
        {
            var statusWord = result.ExitCode switch
            {
                3 => "Broken",
                4 => "Invalid",
                6 => "Revoked",
                _ => "Failed"
            };

            Console.WriteLine($"\u2718 {statusWord}");
            Console.WriteLine($"  {result.Error}");
        }

        return result.ExitCode;
    }

    private static Command CreatePackInspectCommand()
    {
        var packArg = new Argument<DirectoryInfo>("pack", "Path to ClaimPack directory");

        var command = new Command("pack-inspect", "Inspect a ClaimPack without verification")
        {
            packArg
        };

        command.SetHandler(async (DirectoryInfo pack) =>
        {
            var exitCode = await InspectPack(pack);
            Environment.ExitCode = exitCode;
        }, packArg);

        return command;
    }

    private static async Task<int> InspectPack(DirectoryInfo packDir)
    {
        if (!packDir.Exists)
        {
            Console.WriteLine($"Error: Pack directory not found: {packDir.FullName}");
            return 4;
        }

        var manifestPath = Path.Combine(packDir.FullName, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            Console.WriteLine($"Error: Pack missing manifest.json");
            return 4;
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
            Console.WriteLine($"Error reading manifest: {ex.Message}");
            return 5;
        }

        // Load root claim for display
        ClaimBundle? rootBundle = null;
        var rootClaimPath = Path.Combine(packDir.FullName, manifest.RootClaimPath);
        if (File.Exists(rootClaimPath))
        {
            try
            {
                var rootClaimJson = await File.ReadAllTextAsync(rootClaimPath);
                rootBundle = JsonSerializer.Deserialize<ClaimBundle>(rootClaimJson);
            }
            catch
            {
                // Ignore parse errors for inspection
            }
        }

        Console.WriteLine("ClaimPack");
        Console.WriteLine($"  Contract:   {manifest.Contract}");
        Console.WriteLine($"  Pack ID:    {manifest.PackId}");
        Console.WriteLine($"  Created:    {manifest.CreatedAt}");
        Console.WriteLine($"  Root Digest: {Truncate(manifest.RootClaimCoreDigest, 16)}...");
        Console.WriteLine();

        if (rootBundle != null)
        {
            Console.WriteLine("Root Claim");
            Console.WriteLine($"  Claim ID:   {Truncate(rootBundle.Claim.ClaimId, 8)}...");
            Console.WriteLine($"  Statement:  {Truncate(rootBundle.Claim.Statement, 50)}");
            Console.WriteLine($"  Researcher: {rootBundle.Researcher.DisplayName ?? "Anonymous"}");
            Console.WriteLine($"  Asserted:   {rootBundle.Claim.AssertedAtUtc}");
            Console.WriteLine($"  Evidence:   {rootBundle.Claim.Evidence.Count} reference(s)");
            Console.WriteLine($"  Citations:  {rootBundle.Citations?.Count ?? 0}");
            Console.WriteLine($"  Attestations: {rootBundle.Attestations?.Count ?? 0}");
            Console.WriteLine($"  Timestamps: {rootBundle.TimestampReceipts?.Count ?? 0}");
            Console.WriteLine();
        }

        Console.WriteLine("Included Directories");
        if (manifest.Include.ClaimsDir != null)
            Console.WriteLine($"  Claims:      {manifest.Include.ClaimsDir}");
        if (manifest.Include.EvidenceDir != null)
            Console.WriteLine($"  Evidence:    {manifest.Include.EvidenceDir}");
        if (manifest.Include.RevocationsDir != null)
            Console.WriteLine($"  Revocations: {manifest.Include.RevocationsDir}");
        if (manifest.Include.TsaTrustDir != null)
            Console.WriteLine($"  TSA Trust:   {manifest.Include.TsaTrustDir}");
        Console.WriteLine();

        Console.WriteLine($"File Inventory ({manifest.Files.Count} files)");
        foreach (var file in manifest.Files)
        {
            var sizeKb = file.SizeBytes / 1024.0;
            Console.WriteLine($"  {file.Path} ({sizeKb:F1} KB)");
        }

        // Display manifest signatures if present
        if (manifest.ManifestSignatures != null && manifest.ManifestSignatures.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"Manifest Signatures ({manifest.ManifestSignatures.Count})");
            foreach (var sig in manifest.ManifestSignatures)
            {
                Console.WriteLine($"  [{sig.Signer.Kind}] {sig.Signer.Identity.DisplayName ?? sig.Signer.Identity.ResearcherId}");
                Console.WriteLine($"    Public Key: {Truncate(sig.Signature.PublicKey, 16)}...");
            }
        }

        return 0;
    }

    private static Command CreatePackSignCommand()
    {
        var packArg = new Argument<DirectoryInfo>("pack", "Path to ClaimPack directory");

        var keyOption = new Option<FileInfo>(
            "--signer-key",
            "Path to signer key file (JSON with ResearcherId, PublicKey, PrivateKey)");
        keyOption.AddAlias("-k");
        keyOption.IsRequired = true;

        var kindOption = new Option<string>(
            "--signer-kind",
            () => ManifestSignerKind.ClaimAuthor,
            $"Signer kind: {ManifestSignerKind.ClaimAuthor} or {ManifestSignerKind.Publisher}");
        kindOption.AddAlias("--kind");

        var outOption = new Option<DirectoryInfo?>(
            "--out",
            "Output directory (default: update in place)");
        outOption.AddAlias("-o");

        var command = new Command("pack-sign", "Sign a ClaimPack manifest")
        {
            packArg,
            keyOption,
            kindOption,
            outOption
        };

        command.SetHandler(async context =>
        {
            var pack = context.ParseResult.GetValueForArgument(packArg);
            var keyFile = context.ParseResult.GetValueForOption(keyOption)!;
            var kind = context.ParseResult.GetValueForOption(kindOption)!;
            var output = context.ParseResult.GetValueForOption(outOption);

            var exitCode = await SignPack(pack, keyFile, kind, output);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> SignPack(
        DirectoryInfo packDir,
        FileInfo keyFile,
        string signerKind,
        DirectoryInfo? outputDir)
    {
        if (!packDir.Exists)
        {
            Console.WriteLine($"Error: Pack directory not found: {packDir.FullName}");
            return 4;
        }

        if (!keyFile.Exists)
        {
            Console.WriteLine($"Error: Key file not found: {keyFile.FullName}");
            return 4;
        }

        // Load signer key
        AttestorKeyFile signerKey;
        try
        {
            var keyJson = await File.ReadAllTextAsync(keyFile.FullName);
            signerKey = JsonSerializer.Deserialize<AttestorKeyFile>(keyJson)
                ?? throw new JsonException("Key file is null");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading key file: {ex.Message}");
            return 4;
        }

        Ed25519PublicKey publicKey;
        Ed25519PrivateKey privateKey;
        try
        {
            publicKey = Ed25519PublicKey.Parse(signerKey.PublicKey);
            var privateKeyBytes = Convert.FromBase64String(signerKey.PrivateKey);
            privateKey = Ed25519PrivateKey.FromBytes(privateKeyBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing signer keys: {ex.Message}");
            return 4;
        }

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir.FullName,
            privateKey,
            publicKey,
            signerKind,
            signerKey.ResearcherId,
            signerKey.DisplayName,
            outputDir?.FullName));

        if (!result.Success)
        {
            Console.WriteLine($"Error: {result.Error}");
            return 5;
        }

        Console.WriteLine($"\u2714 Pack signed successfully");
        Console.WriteLine($"  Signer Kind: {signerKind}");
        Console.WriteLine($"  Signer:      {signerKey.DisplayName ?? signerKey.ResearcherId}");
        Console.WriteLine($"  Total Signatures: {result.TotalSignatures}");

        return 0;
    }

    private static Command CreatePackDiffCommand()
    {
        var packAArg = new Argument<DirectoryInfo>("pack-a", "Path to base pack (old version)");
        var packBArg = new Argument<DirectoryInfo>("pack-b", "Path to updated pack (new version)");

        var formatOption = new Option<string>(
            "--format",
            () => "text",
            "Output format: text or json");
        formatOption.AddAlias("-f");

        var outOption = new Option<FileInfo?>(
            "--out",
            "Write diff report to file");
        outOption.AddAlias("-o");

        var failOnOption = new Option<string?>(
            "--fail-on",
            "Exit with code 2 if update class is at least this level: MODIFIED, BREAKING");

        var command = new Command("pack-diff", "Compare two ClaimPacks and show differences")
        {
            packAArg,
            packBArg,
            formatOption,
            outOption,
            failOnOption
        };

        command.SetHandler(async context =>
        {
            var packA = context.ParseResult.GetValueForArgument(packAArg);
            var packB = context.ParseResult.GetValueForArgument(packBArg);
            var format = context.ParseResult.GetValueForOption(formatOption)!;
            var output = context.ParseResult.GetValueForOption(outOption);
            var failOn = context.ParseResult.GetValueForOption(failOnOption);

            var exitCode = await DiffPacks(packA, packB, format, output, failOn);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> DiffPacks(
        DirectoryInfo packADir,
        DirectoryInfo packBDir,
        string format,
        FileInfo? outputFile,
        string? failOn)
    {
        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(
            packADir.FullName,
            packBDir.FullName));

        if (!result.Success)
        {
            Console.WriteLine($"Error: {result.Error}");
            return result.ExitCode;
        }

        var report = result.Report!;

        if (format.Equals("json", StringComparison.OrdinalIgnoreCase))
        {
            var json = JsonSerializer.Serialize(report, JsonOptions);
            if (outputFile != null)
            {
                await File.WriteAllTextAsync(outputFile.FullName, json);
                Console.WriteLine($"Diff report written to: {outputFile.FullName}");
            }
            else
            {
                Console.WriteLine(json);
            }
        }
        else
        {
            // Text format
            PrintDiffReport(report);

            if (outputFile != null)
            {
                var json = JsonSerializer.Serialize(report, JsonOptions);
                await File.WriteAllTextAsync(outputFile.FullName, json);
                Console.WriteLine($"\nDiff report written to: {outputFile.FullName}");
            }
        }

        // Check fail-on condition
        if (failOn != null)
        {
            var shouldFail = failOn.ToUpperInvariant() switch
            {
                "MODIFIED" => report.UpdateClass == UpdateClass.Modified || report.UpdateClass == UpdateClass.Breaking,
                "BREAKING" => report.UpdateClass == UpdateClass.Breaking,
                _ => false
            };

            if (shouldFail)
            {
                Console.WriteLine($"\n\u2717 Update class {report.UpdateClass} meets or exceeds --fail-on {failOn}");
                return 2;
            }
        }

        return 0;
    }

    private static void PrintDiffReport(ClaimPackDiffReport report)
    {
        Console.WriteLine($"Pack Diff Report");
        Console.WriteLine($"================");
        Console.WriteLine();
        Console.WriteLine($"Pack A: {report.PackA.PackId}");
        Console.WriteLine($"  Root Digest: {report.PackA.RootClaimCoreDigest}");
        Console.WriteLine($"  Created:     {report.PackA.CreatedAt}");
        Console.WriteLine($"  Files:       {report.PackA.FileCount}");
        Console.WriteLine();
        Console.WriteLine($"Pack B: {report.PackB.PackId}");
        Console.WriteLine($"  Root Digest: {report.PackB.RootClaimCoreDigest}");
        Console.WriteLine($"  Created:     {report.PackB.CreatedAt}");
        Console.WriteLine($"  Files:       {report.PackB.FileCount}");
        Console.WriteLine();
        Console.WriteLine($"Update Class: {report.UpdateClass}");
        Console.WriteLine();

        // File changes
        Console.WriteLine("File Changes:");
        Console.WriteLine($"  Added:     {report.Files.Added.Count}");
        Console.WriteLine($"  Removed:   {report.Files.Removed.Count}");
        Console.WriteLine($"  Modified:  {report.Files.Modified.Count}");
        Console.WriteLine($"  Unchanged: {report.Files.UnchangedCount}");

        if (report.Files.Added.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("  Added files:");
            foreach (var f in report.Files.Added)
                Console.WriteLine($"    + {f.Path}");
        }

        if (report.Files.Removed.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("  Removed files:");
            foreach (var f in report.Files.Removed)
                Console.WriteLine($"    - {f.Path}");
        }

        if (report.Files.Modified.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("  Modified files:");
            foreach (var f in report.Files.Modified)
                Console.WriteLine($"    ~ {f.Path}");
        }

        Console.WriteLine();

        // Semantic changes
        Console.WriteLine("Semantic Changes:");
        if (report.Semantics.RootDigestChanged)
            Console.WriteLine("  \u2717 Root claim core digest CHANGED");
        else
            Console.WriteLine("  \u2714 Root claim core digest unchanged");

        PrintElementDiff("Attestations", report.Semantics.Attestations, a => a.AttestationId);
        PrintElementDiff("Timestamps", report.Semantics.Timestamps, t => t.ReceiptId);
        PrintElementDiff("Manifest Signatures", report.Semantics.ManifestSignatures, s => $"{s.SignerKind}:{s.SignerPublicKey[..8]}...");
        PrintElementDiff("Revocations", report.Semantics.Revocations, r => r.RevocationId);
        PrintElementDiff("Citations", report.Semantics.Citations, c => c.CitationId);
    }

    private static void PrintElementDiff<T>(string name, ElementDiff<T> diff, Func<T, string> getLabel)
    {
        if (diff.Added.Count == 0 && diff.Removed.Count == 0 && diff.Modified.Count == 0)
        {
            Console.WriteLine($"  {name}: no changes ({diff.UnchangedCount} unchanged)");
            return;
        }

        Console.WriteLine($"  {name}:");
        Console.WriteLine($"    Added: {diff.Added.Count}, Removed: {diff.Removed.Count}, Modified: {diff.Modified.Count}, Unchanged: {diff.UnchangedCount}");

        foreach (var item in diff.Added)
            Console.WriteLine($"      + {getLabel(item)}");
        foreach (var item in diff.Removed)
            Console.WriteLine($"      - {getLabel(item)}");
        foreach (var item in diff.Modified)
            Console.WriteLine($"      ~ {getLabel(item)}");
    }

    private static Command CreatePackValidateUpdateCommand()
    {
        var packAArg = new Argument<DirectoryInfo>("pack-a", "Path to base pack (old version)");
        var packBArg = new Argument<DirectoryInfo>("pack-b", "Path to updated pack (new version)");

        var policyOption = new Option<string>(
            "--policy",
            () => PackUpdatePolicy.AppendOnly,
            $"Update policy: {PackUpdatePolicy.AppendOnly} or {PackUpdatePolicy.AllowModified}");
        policyOption.AddAlias("-p");

        var outOption = new Option<FileInfo?>(
            "--out",
            "Write validation report to file");
        outOption.AddAlias("-o");

        var command = new Command("pack-validate-update", "Validate a pack update against a policy")
        {
            packAArg,
            packBArg,
            policyOption,
            outOption
        };

        command.SetHandler(async context =>
        {
            var packA = context.ParseResult.GetValueForArgument(packAArg);
            var packB = context.ParseResult.GetValueForArgument(packBArg);
            var policy = context.ParseResult.GetValueForOption(policyOption)!;
            var output = context.ParseResult.GetValueForOption(outOption);

            var exitCode = await ValidatePackUpdate(packA, packB, policy, output);
            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> ValidatePackUpdate(
        DirectoryInfo packADir,
        DirectoryInfo packBDir,
        string policy,
        FileInfo? outputFile)
    {
        if (!PackUpdatePolicy.IsValid(policy))
        {
            Console.WriteLine($"Error: Invalid policy '{policy}'. Use {PackUpdatePolicy.AppendOnly} or {PackUpdatePolicy.AllowModified}");
            return 4;
        }

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packADir.FullName,
            packBDir.FullName,
            policy));

        if (result.Error != null && result.Validation == null)
        {
            Console.WriteLine($"Error: {result.Error}");
            return result.ExitCode;
        }

        var validation = result.Validation!;
        var report = result.Report!;

        Console.WriteLine($"Pack Update Validation");
        Console.WriteLine($"=====================");
        Console.WriteLine();
        Console.WriteLine($"Policy:       {validation.Policy}");
        Console.WriteLine($"Update Class: {validation.UpdateClass}");
        Console.WriteLine($"Result:       {(validation.Passed ? "\u2714 PASS" : "\u2717 FAIL")}");

        if (validation.Violations.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"Violations ({validation.Violations.Count}):");
            foreach (var violation in validation.Violations)
            {
                Console.WriteLine($"  [{violation.Type}] {violation.Path}");
                if (violation.Details != null)
                    Console.WriteLine($"    {violation.Details}");
            }
        }

        if (outputFile != null)
        {
            var outputData = new
            {
                Diff = report,
                Validation = validation
            };
            var json = JsonSerializer.Serialize(outputData, JsonOptions);
            await File.WriteAllTextAsync(outputFile.FullName, json);
            Console.WriteLine($"\nReport written to: {outputFile.FullName}");
        }

        return result.ExitCode;
    }

    #region Registry Commands

    private static Command CreateRegistryCommand()
    {
        var registryCommand = new Command("registry", "Manage local claim registries for offline resolution");

        registryCommand.AddCommand(CreateRegistryInitCommand());
        registryCommand.AddCommand(CreateRegistryAddCommand());
        registryCommand.AddCommand(CreateRegistryBuildCommand());
        registryCommand.AddCommand(CreateRegistryQueryCommand());

        return registryCommand;
    }

    private static Command CreateRegistryInitCommand()
    {
        var pathArg = new Argument<DirectoryInfo>("path", "Path to create registry at");

        var command = new Command("init", "Initialize a new registry")
        {
            pathArg
        };

        command.SetHandler(async (DirectoryInfo path) =>
        {
            var result = await InitRegistryHandler.HandleAsync(new InitRegistryCommand(path.FullName));

            if (result.Success)
            {
                Console.WriteLine($"\u2714 Registry initialized");
                Console.WriteLine($"  Registry ID: {result.RegistryId}");
                Console.WriteLine($"  Index:       {result.IndexPath}");
            }
            else
            {
                Console.WriteLine($"\u2718 Failed to initialize registry");
                Console.WriteLine($"  {result.Error}");
                Environment.ExitCode = 5;
            }
        }, pathArg);

        return command;
    }

    private static Command CreateRegistryAddCommand()
    {
        var registryArg = new Argument<DirectoryInfo>("registry", "Path to registry");
        var packArg = new Argument<string>("pack", "Path to pack (directory or .zip)");

        var copyOption = new Option<bool>(
            "--copy",
            "Copy pack into registry instead of referencing by path");

        var command = new Command("add", "Add a pack to the registry")
        {
            registryArg,
            packArg,
            copyOption
        };

        command.SetHandler(async (DirectoryInfo registry, string pack, bool copy) =>
        {
            var result = await AddPackToRegistryHandler.HandleAsync(
                new AddPackToRegistryCommand(registry.FullName, pack, copy));

            if (result.Success)
            {
                Console.WriteLine($"\u2714 Pack added to registry");
                Console.WriteLine($"  Pack ID:   {result.PackId}");
                Console.WriteLine($"  Digest:    {Truncate(result.RootDigest ?? "", 16)}...");
                Console.WriteLine($"  Claims:    {result.ClaimsIndexed}");
                Console.WriteLine($"  Bundles:   {result.CreatorLedgerBundlesIndexed}");
            }
            else
            {
                Console.WriteLine($"\u2718 Failed to add pack");
                Console.WriteLine($"  {result.Error}");
                Environment.ExitCode = 5;
            }
        }, registryArg, packArg, copyOption);

        return command;
    }

    private static Command CreateRegistryBuildCommand()
    {
        var registryArg = new Argument<DirectoryInfo>("registry", "Path to registry");

        var scanOption = new Option<DirectoryInfo?>(
            "--scan",
            "Directory to scan for new packs");

        var forceOption = new Option<bool>(
            "--force",
            "Force full rebuild of index");

        var command = new Command("build", "Rebuild or refresh registry index")
        {
            registryArg,
            scanOption,
            forceOption
        };

        command.SetHandler(async (DirectoryInfo registry, DirectoryInfo? scan, bool force) =>
        {
            var result = await BuildRegistryHandler.HandleAsync(
                new BuildRegistryCommand(registry.FullName, scan?.FullName, force));

            if (result.Success)
            {
                Console.WriteLine($"\u2714 Registry built");
                if (result.PacksScanned > 0)
                    Console.WriteLine($"  Scanned: {result.PacksScanned}");
                if (result.PacksAdded > 0)
                    Console.WriteLine($"  Added:   {result.PacksAdded}");
                if (result.PacksRemoved > 0)
                    Console.WriteLine($"  Removed: {result.PacksRemoved}");
                if (result.PacksStale > 0)
                    Console.WriteLine($"  Stale:   {result.PacksStale}");

                foreach (var warning in result.Warnings)
                {
                    Console.WriteLine($"  \u26A0 {warning}");
                }
            }
            else
            {
                Console.WriteLine($"\u2718 Failed to build registry");
                Console.WriteLine($"  {result.Error}");
                Environment.ExitCode = 5;
            }
        }, registryArg, scanOption, forceOption);

        return command;
    }

    private static Command CreateRegistryQueryCommand()
    {
        var registryArg = new Argument<DirectoryInfo>("registry", "Path to registry");

        var claimDigestOption = new Option<string?>(
            "--claim-digest",
            "Query for claim by digest (or prefix)");

        var bundleDigestOption = new Option<string?>(
            "--creatorledger-digest",
            "Query for CreatorLedger bundle by digest (or prefix)");

        var pickFirstOption = new Option<bool>(
            "--pick-first",
            "If prefix is ambiguous, return first match");

        var command = new Command("query", "Query registry for claims or bundles")
        {
            registryArg,
            claimDigestOption,
            bundleDigestOption,
            pickFirstOption
        };

        command.SetHandler(async (DirectoryInfo registry, string? claimDigest, string? bundleDigest, bool pickFirst) =>
        {
            if (string.IsNullOrEmpty(claimDigest) && string.IsNullOrEmpty(bundleDigest))
            {
                Console.WriteLine("Error: Specify --claim-digest or --creatorledger-digest");
                Environment.ExitCode = 4;
                return;
            }

            var result = await QueryRegistryHandler.HandleAsync(
                new QueryRegistryCommand(registry.FullName, claimDigest, bundleDigest, pickFirst));

            if (!result.Success)
            {
                if (result.IsAmbiguous)
                {
                    Console.WriteLine($"\u26A0 Ambiguous query");
                    Console.WriteLine($"  {result.Error}");
                    Console.WriteLine();
                    Console.WriteLine("Candidates:");
                    foreach (var match in result.Matches)
                    {
                        Console.WriteLine($"  {match.Digest}");
                        Console.WriteLine($"    Pack: {match.PackId}");
                        Console.WriteLine($"    Path: {match.RelativePath}");
                    }
                }
                else
                {
                    Console.WriteLine($"\u2718 Query failed");
                    Console.WriteLine($"  {result.Error}");
                }
                Environment.ExitCode = result.ExitCode;
                return;
            }

            if (result.Matches.Count == 0)
            {
                Console.WriteLine("No matches found");
                return;
            }

            Console.WriteLine($"\u2714 Found {result.Matches.Count} match(es):");
            foreach (var match in result.Matches)
            {
                Console.WriteLine();
                Console.WriteLine($"  Kind:   {match.Kind}");
                Console.WriteLine($"  Digest: {match.Digest}");
                Console.WriteLine($"  Pack:   {match.PackId}");
                Console.WriteLine($"  Path:   {match.RelativePath}");
                Console.WriteLine($"  Full:   {match.FullPath}");
            }
        }, registryArg, claimDigestOption, bundleDigestOption, pickFirstOption);

        return command;
    }

    #endregion
}

/// <summary>
/// Attestor key file format for CLI.
/// </summary>
public sealed class AttestorKeyFile
{
    public required string ResearcherId { get; init; }
    public required string PublicKey { get; init; }
    public required string PrivateKey { get; init; }
    public string? DisplayName { get; init; }
}

// Publish command is defined in Program.Publish.cs
