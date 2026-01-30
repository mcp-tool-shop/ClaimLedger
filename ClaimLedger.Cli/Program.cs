using System.CommandLine;
using System.Text.Json;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Citations;
using ClaimLedger.Application.Export;
using ClaimLedger.Cli.Verification;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Citations;
using Shared.Crypto;

namespace ClaimLedger.Cli;

/// <summary>
/// ClaimLedger CLI - Cryptographic provenance verification for scientific claims.
/// </summary>
public static class Program
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

        var command = new Command("verify", "Verify a claim bundle's cryptographic validity")
        {
            bundleArg,
            evidenceOption,
            attestationsOption,
            citationsOption,
            strictCitationsOption,
            claimDirOption
        };

        command.SetHandler(async (FileInfo bundle, DirectoryInfo? evidenceDir, bool verifyAttestations,
            bool verifyCitations, bool strictCitations, DirectoryInfo? claimDir) =>
        {
            var exitCode = await VerifyBundle(bundle, evidenceDir, verifyAttestations, verifyCitations, strictCitations, claimDir);
            Environment.ExitCode = exitCode;
        }, bundleArg, evidenceOption, attestationsOption, citationsOption, strictCitationsOption, claimDirOption);

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
        DirectoryInfo? claimDir = null)
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

    private static string Truncate(string s, int maxLength)
        => s.Length <= maxLength ? s : s[..maxLength];
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
