using System.CommandLine;
using System.Text.Json;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Export;
using ClaimLedger.Cli.Verification;
using ClaimLedger.Domain.Attestations;
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

        var command = new Command("verify", "Verify a claim bundle's cryptographic validity")
        {
            bundleArg,
            evidenceOption,
            attestationsOption
        };

        command.SetHandler(async (FileInfo bundle, DirectoryInfo? evidenceDir, bool verifyAttestations) =>
        {
            var exitCode = await VerifyBundle(bundle, evidenceDir, verifyAttestations);
            Environment.ExitCode = exitCode;
        }, bundleArg, evidenceOption, attestationsOption);

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

    private static async Task<int> VerifyBundle(FileInfo bundleFile, DirectoryInfo? evidenceDir, bool verifyAttestations)
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
