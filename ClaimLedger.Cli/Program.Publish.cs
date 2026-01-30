using System.CommandLine;
using System.Text.Json;
using ClaimLedger.Application.Publish;

namespace ClaimLedger.Cli;

public static partial class Program
{
    private static Command CreatePublishCommand()
    {
        // Required arguments
        var claimArg = new Argument<FileInfo>("claim", "Path to claim bundle JSON file");

        // Output options
        var outOption = new Option<string>(
            "--out",
            "Output path (directory or .zip file)")
        { IsRequired = true };
        outOption.AddAlias("-o");

        var zipOption = new Option<bool>(
            "--zip",
            "Output as ZIP archive (auto-detected if --out ends with .zip)");

        // Include options
        var evidenceOption = new Option<DirectoryInfo?>(
            "--evidence",
            "Directory containing evidence files to include");
        evidenceOption.AddAlias("-e");

        var creatorLedgerOption = new Option<DirectoryInfo?>(
            "--creatorledger",
            "Directory containing CreatorLedger proof bundles to include");

        var revocationsOption = new Option<DirectoryInfo?>(
            "--revocations",
            "Directory containing revocation files to include");

        var tsaTrustOption = new Option<DirectoryInfo?>(
            "--tsa-trust",
            "Directory containing TSA trust anchor certificates");

        var includeCitationsOption = new Option<bool>(
            "--include-citations",
            () => true,
            "Include embedded citations in the pack");

        var includeAttestationsOption = new Option<bool>(
            "--include-attestations",
            () => true,
            "Include attestations in verification");

        var includeTimestampsOption = new Option<bool>(
            "--include-timestamps",
            () => true,
            "Include timestamp receipts in verification");

        // Signing options
        var signPackOption = new Option<bool>(
            "--sign-pack",
            "Sign the pack manifest");

        var publisherKeyOption = new Option<FileInfo?>(
            "--publisher-key",
            "Path to publisher private key JSON file");

        var publisherIdentityOption = new Option<FileInfo?>(
            "--publisher-identity",
            "Path to publisher identity JSON file");

        var authorKeyOption = new Option<FileInfo?>(
            "--author-key",
            "Path to author private key JSON file");

        var authorIdentityOption = new Option<FileInfo?>(
            "--author-identity",
            "Path to author identity JSON file");

        // Verification options
        var strictOption = new Option<bool>(
            "--strict",
            () => true,
            "Run strict verification gate (default: true for publishing)");

        // Report option
        var reportOption = new Option<FileInfo?>(
            "--report",
            "Path to write publish report JSON");

        var command = new Command("publish", "Publish a claim bundle as a ready-to-share ClaimPack")
        {
            claimArg,
            outOption,
            zipOption,
            evidenceOption,
            creatorLedgerOption,
            revocationsOption,
            tsaTrustOption,
            includeCitationsOption,
            includeAttestationsOption,
            includeTimestampsOption,
            signPackOption,
            publisherKeyOption,
            publisherIdentityOption,
            authorKeyOption,
            authorIdentityOption,
            strictOption,
            reportOption
        };

        command.SetHandler(async context =>
        {
            var claim = context.ParseResult.GetValueForArgument(claimArg);
            var outPath = context.ParseResult.GetValueForOption(outOption)!;
            var zip = context.ParseResult.GetValueForOption(zipOption);
            var evidence = context.ParseResult.GetValueForOption(evidenceOption);
            var creatorLedger = context.ParseResult.GetValueForOption(creatorLedgerOption);
            var revocations = context.ParseResult.GetValueForOption(revocationsOption);
            var tsaTrust = context.ParseResult.GetValueForOption(tsaTrustOption);
            var includeCitations = context.ParseResult.GetValueForOption(includeCitationsOption);
            var includeAttestations = context.ParseResult.GetValueForOption(includeAttestationsOption);
            var includeTimestamps = context.ParseResult.GetValueForOption(includeTimestampsOption);
            var signPack = context.ParseResult.GetValueForOption(signPackOption);
            var publisherKey = context.ParseResult.GetValueForOption(publisherKeyOption);
            var publisherIdentity = context.ParseResult.GetValueForOption(publisherIdentityOption);
            var authorKey = context.ParseResult.GetValueForOption(authorKeyOption);
            var authorIdentity = context.ParseResult.GetValueForOption(authorIdentityOption);
            var strict = context.ParseResult.GetValueForOption(strictOption);
            var report = context.ParseResult.GetValueForOption(reportOption);

            var exitCode = await Publish(
                claim, outPath, zip,
                evidence, creatorLedger, revocations, tsaTrust,
                includeCitations, includeAttestations, includeTimestamps,
                signPack,
                publisherKey, publisherIdentity,
                authorKey, authorIdentity,
                strict, report);

            context.ExitCode = exitCode;
        });

        return command;
    }

    private static async Task<int> Publish(
        FileInfo claimFile,
        string outPath,
        bool zip,
        DirectoryInfo? evidenceDir,
        DirectoryInfo? creatorLedgerDir,
        DirectoryInfo? revocationsDir,
        DirectoryInfo? tsaTrustDir,
        bool includeCitations,
        bool includeAttestations,
        bool includeTimestamps,
        bool signPack,
        FileInfo? publisherKeyFile,
        FileInfo? publisherIdentityFile,
        FileInfo? authorKeyFile,
        FileInfo? authorIdentityFile,
        bool strict,
        FileInfo? reportFile)
    {
        var command = new PublishCommand(
            InputClaimPath: claimFile.FullName,
            OutputPath: outPath,
            Zip: zip,
            EvidenceDirectory: evidenceDir?.FullName,
            CreatorLedgerDirectory: creatorLedgerDir?.FullName,
            RevocationsDirectory: revocationsDir?.FullName,
            TsaTrustDirectory: tsaTrustDir?.FullName,
            IncludeCitations: includeCitations,
            IncludeAttestations: includeAttestations,
            IncludeTimestamps: includeTimestamps,
            SignPack: signPack,
            PublisherKeyPath: publisherKeyFile?.FullName,
            PublisherIdentityPath: publisherIdentityFile?.FullName,
            AuthorKeyPath: authorKeyFile?.FullName,
            AuthorIdentityPath: authorIdentityFile?.FullName,
            Strict: strict,
            ReportPath: reportFile?.FullName);

        var result = await PublishHandler.HandleAsync(command);

        if (result.Success)
        {
            Console.WriteLine("✓ Published successfully");
            Console.WriteLine($"  Output: {result.OutputPath}");

            if (result.Report != null)
            {
                Console.WriteLine($"  Pack ID: {result.Report.PackId}");
                Console.WriteLine($"  Root digest: {result.Report.RootClaimCoreDigest}");
                Console.WriteLine($"  Manifest hash: {result.Report.ManifestSha256Hex}");

                if (result.Report.Counts.Claims > 1)
                    Console.WriteLine($"  Claims: {result.Report.Counts.Claims}");
                if (result.Report.Counts.EvidenceFiles > 0)
                    Console.WriteLine($"  Evidence files: {result.Report.Counts.EvidenceFiles}");
                if (result.Report.Counts.CreatorLedgerBundles > 0)
                    Console.WriteLine($"  CreatorLedger bundles: {result.Report.Counts.CreatorLedgerBundles}");
                if (result.Report.Counts.ManifestSignatures > 0)
                    Console.WriteLine($"  Manifest signatures: {result.Report.Counts.ManifestSignatures}");

                if (result.Report.Signing.PublisherSigned)
                    Console.WriteLine("  Signed by: Publisher");
                if (result.Report.Signing.AuthorSigned)
                    Console.WriteLine("  Signed by: Author");
            }

            return 0;
        }
        else
        {
            Console.WriteLine($"✗ Publish failed: {result.Error}");

            if (result.Report?.VerificationGate != null)
            {
                Console.WriteLine($"  Gate result: {result.Report.VerificationGate.Result}");
                foreach (var note in result.Report.VerificationGate.Notes)
                {
                    Console.WriteLine($"  {note}");
                }
            }

            return result.ExitCode;
        }
    }
}
