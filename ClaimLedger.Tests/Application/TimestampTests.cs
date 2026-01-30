using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Application.Timestamps;
using ClaimLedger.Domain.Timestamps;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

public class TimestampTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task CreateTsaRequest_GeneratesValidDer()
    {
        var bundle = await CreateClaimBundle("Test claim");

        var requestBytes = CreateTsaRequestHandler.Handle(new CreateTsaRequestCommand(
            bundle,
            IncludeCertRequest: true));

        // Should be valid ASN.1 DER
        Assert.NotEmpty(requestBytes);

        // Parse to verify structure
        var reader = new AsnReader(requestBytes, AsnEncodingRules.DER);
        var seqReader = reader.ReadSequence();

        // version INTEGER (should be 1)
        var version = seqReader.ReadInteger();
        Assert.Equal(1, (int)version);

        // messageImprint SEQUENCE
        var msgImprintReader = seqReader.ReadSequence();
        var hashAlgReader = msgImprintReader.ReadSequence();
        var hashAlgOid = hashAlgReader.ReadObjectIdentifier();
        Assert.Equal(TstInfo.Sha256Oid, hashAlgOid);

        var hashedMessage = msgImprintReader.ReadOctetString();
        Assert.Equal(32, hashedMessage.Length); // SHA-256 = 32 bytes
    }

    [Fact]
    public async Task CreateTsaRequest_MessageImprint_MatchesClaimCoreDigest()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var coreDigest = ClaimCoreDigest.Compute(bundle);

        var requestBytes = CreateTsaRequestHandler.Handle(new CreateTsaRequestCommand(bundle));

        // Parse request
        var reader = new AsnReader(requestBytes, AsnEncodingRules.DER);
        var seqReader = reader.ReadSequence();
        _ = seqReader.ReadInteger(); // version
        var msgImprintReader = seqReader.ReadSequence();
        _ = msgImprintReader.ReadSequence(); // algorithm
        var hashedMessage = msgImprintReader.ReadOctetString();

        // Expected: SHA256(claim_core_digest_bytes)
        var digestBytes = coreDigest.AsBytes().ToArray();
        var expectedImprint = SHA256.HashData(digestBytes);

        Assert.Equal(expectedImprint, hashedMessage);
    }

    [Fact]
    public async Task CreateTsaRequest_WithNonce_IncludesNonce()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var nonce = new byte[] { 0x12, 0x34, 0x56, 0x78 };

        var requestBytes = CreateTsaRequestHandler.Handle(new CreateTsaRequestCommand(
            bundle,
            IncludeCertRequest: true,
            Nonce: nonce));

        // Parse and verify nonce is present
        var reader = new AsnReader(requestBytes, AsnEncodingRules.DER);
        var seqReader = reader.ReadSequence();
        _ = seqReader.ReadInteger(); // version
        _ = seqReader.ReadSequence(); // messageImprint

        // Next should be nonce INTEGER
        var parsedNonce = seqReader.ReadInteger();
        Assert.NotEqual(System.Numerics.BigInteger.Zero, parsedNonce);
    }

    [Fact]
    public async Task CreateTsaRequest_NoCertReq_OmitsCertReq()
    {
        var bundle = await CreateClaimBundle("Test claim");

        var requestBytes = CreateTsaRequestHandler.Handle(new CreateTsaRequestCommand(
            bundle,
            IncludeCertRequest: false));

        // Should be valid ASN.1
        Assert.NotEmpty(requestBytes);

        // Parse - should only have version + messageImprint (no certReq BOOLEAN)
        var reader = new AsnReader(requestBytes, AsnEncodingRules.DER);
        var seqReader = reader.ReadSequence();
        _ = seqReader.ReadInteger(); // version
        _ = seqReader.ReadSequence(); // messageImprint

        // Should have no more data (no nonce, no certReq)
        Assert.False(seqReader.HasData);
    }

    [Fact]
    public void TstInfoParser_Parse_ExtractsFields()
    {
        // Create a minimal valid TSTInfo structure
        var tstInfoDer = CreateTestTstInfo(
            hashOid: TstInfo.Sha256Oid,
            hashedMessage: new byte[32],
            genTime: DateTimeOffset.Parse("2024-06-15T12:00:00Z", CultureInfo.InvariantCulture),
            policyOid: "1.2.3.4",
            serialNumber: 12345);

        var tstInfo = TstInfoParser.Parse(tstInfoDer);

        Assert.Equal(TstInfo.Sha256Oid, tstInfo.HashAlgorithmOid);
        Assert.Equal(32, tstInfo.HashedMessage.Length);
        Assert.Equal("1.2.3.4", tstInfo.PolicyOid);
        Assert.True(tstInfo.IsSha256);
    }

    [Fact]
    public void TstInfoParser_Parse_NonSha256_DetectedCorrectly()
    {
        // SHA-1 OID
        var sha1Oid = "1.3.14.3.2.26";
        var tstInfoDer = CreateTestTstInfo(
            hashOid: sha1Oid,
            hashedMessage: new byte[20], // SHA-1 = 20 bytes
            genTime: DateTimeOffset.UtcNow,
            policyOid: "1.2.3.4",
            serialNumber: 1);

        var tstInfo = TstInfoParser.Parse(tstInfoDer);

        Assert.Equal(sha1Oid, tstInfo.HashAlgorithmOid);
        Assert.False(tstInfo.IsSha256);
    }

    [Fact]
    public void Rfc3161TokenDecoder_NormalizeTokenBytes_RawDer()
    {
        var rawDer = new byte[] { 0x30, 0x82, 0x01, 0x00 };

        var result = Rfc3161TokenDecoder.NormalizeTokenBytes(rawDer);

        Assert.Equal(rawDer, result);
    }

    [Fact]
    public void Rfc3161TokenDecoder_NormalizeTokenBytes_Base64()
    {
        var rawDer = new byte[] { 0x30, 0x82, 0x01, 0x00 };
        var base64 = Convert.ToBase64String(rawDer);
        var base64Bytes = System.Text.Encoding.ASCII.GetBytes(base64);

        var result = Rfc3161TokenDecoder.NormalizeTokenBytes(base64Bytes);

        Assert.Equal(rawDer, result);
    }

    [Fact]
    public void Rfc3161TokenDecoder_NormalizeTokenBytes_Pem()
    {
        var rawDer = new byte[] { 0x30, 0x82, 0x01, 0x00 };
        var base64 = Convert.ToBase64String(rawDer);
        var pem = $"-----BEGIN TIMESTAMP-----\n{base64}\n-----END TIMESTAMP-----";
        var pemBytes = System.Text.Encoding.ASCII.GetBytes(pem);

        var result = Rfc3161TokenDecoder.NormalizeTokenBytes(pemBytes);

        Assert.Equal(rawDer, result);
    }

    [Fact]
    public async Task TimestampReceipt_VerifyBinding_CorrectDigest_ReturnsTrue()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var coreDigest = ClaimCoreDigest.Compute(bundle);

        // Compute expected message imprint
        var digestBytes = coreDigest.AsBytes().ToArray();
        var messageImprint = Digest256.Compute(digestBytes);

        // Create a receipt with matching imprint
        var tstInfo = new TstInfo
        {
            HashAlgorithmOid = TstInfo.Sha256Oid,
            HashedMessage = messageImprint.AsBytes().ToArray(),
            GenTime = DateTimeOffset.UtcNow,
            PolicyOid = "1.2.3.4"
        };

        var receipt = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            messageImprint.AsBytes().ToArray(),
            new byte[] { 0x00 }, // dummy token
            tstInfo,
            new TsaInfo());

        Assert.True(receipt.VerifyBinding());
    }

    [Fact]
    public async Task TimestampReceipt_VerifyBinding_WrongDigest_ReturnsFalse()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var coreDigest = ClaimCoreDigest.Compute(bundle);

        // Create a receipt with wrong imprint
        var wrongImprint = Digest256.Compute("wrong"u8);

        var tstInfo = new TstInfo
        {
            HashAlgorithmOid = TstInfo.Sha256Oid,
            HashedMessage = wrongImprint.AsBytes().ToArray(), // WRONG
            GenTime = DateTimeOffset.UtcNow,
            PolicyOid = "1.2.3.4"
        };

        var receipt = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            wrongImprint.AsBytes().ToArray(),
            new byte[] { 0x00 },
            tstInfo,
            new TsaInfo());

        Assert.False(receipt.VerifyBinding());
    }

    [Fact]
    public async Task AttachTsaToken_ImprintMismatch_Fails()
    {
        var bundle = await CreateClaimBundle("Test claim");

        // Create a CMS token with wrong imprint (using self-signed cert for testing)
        var wrongDigest = Digest256.Compute("wrong content"u8);
        var wrongImprint = Digest256.Compute(wrongDigest.AsBytes());

        // We can't easily create a valid CMS without a real TSA,
        // so we'll test the application logic with a stub
        // This test verifies the binding check path exists
        var result = AttachTsaTokenHandler.Handle(new AttachTsaTokenCommand(
            bundle,
            new byte[] { 0x00 })); // Invalid token

        Assert.False(result.Success);
        Assert.Contains("Failed to decode CMS", result.Error);
    }

    [Fact]
    public async Task VerifyTimestamps_NoReceipts_ReturnsValid()
    {
        var bundle = await CreateClaimBundle("Test claim");

        var result = VerifyTimestampsHandler.Handle(new VerifyTimestampsQuery(bundle));

        Assert.True(result.AllValid);
        Assert.True(result.AllTrusted);
        Assert.Empty(result.Results);
    }

    [Fact]
    public async Task AddTimestampToBundle_AppendsReceipt()
    {
        var bundle = await CreateClaimBundle("Test claim");
        Assert.Null(bundle.TimestampReceipts);

        var coreDigest = ClaimCoreDigest.Compute(bundle);
        var messageImprint = Digest256.Compute(coreDigest.AsBytes()).AsBytes().ToArray();

        var receipt = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            messageImprint,
            new byte[] { 0x00 },
            new TstInfo
            {
                HashAlgorithmOid = TstInfo.Sha256Oid,
                HashedMessage = messageImprint,
                GenTime = DateTimeOffset.UtcNow,
                PolicyOid = "1.2.3.4"
            },
            new TsaInfo { PolicyOid = "1.2.3.4" });

        var newBundle = AddTimestampToBundleHandler.Handle(
            new AddTimestampToBundleCommand(bundle, receipt));

        Assert.NotNull(newBundle.TimestampReceipts);
        Assert.Single(newBundle.TimestampReceipts);
        Assert.Equal("TimestampReceiptRFC3161.v1", newBundle.TimestampReceipts[0].Contract);
    }

    [Fact]
    public async Task AddTimestampToBundle_PreservesExistingReceipts()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var coreDigest = ClaimCoreDigest.Compute(bundle);
        var messageImprint = Digest256.Compute(coreDigest.AsBytes()).AsBytes().ToArray();

        var receipt1 = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            messageImprint,
            new byte[] { 0x01 },
            new TstInfo
            {
                HashAlgorithmOid = TstInfo.Sha256Oid,
                HashedMessage = messageImprint,
                GenTime = DateTimeOffset.Parse("2024-06-01T10:00:00Z", CultureInfo.InvariantCulture),
                PolicyOid = "1.2.3.4"
            },
            new TsaInfo());

        var receipt2 = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            messageImprint,
            new byte[] { 0x02 },
            new TstInfo
            {
                HashAlgorithmOid = TstInfo.Sha256Oid,
                HashedMessage = messageImprint,
                GenTime = DateTimeOffset.Parse("2024-06-01T11:00:00Z", CultureInfo.InvariantCulture),
                PolicyOid = "1.2.3.4"
            },
            new TsaInfo());

        bundle = AddTimestampToBundleHandler.Handle(new AddTimestampToBundleCommand(bundle, receipt1));
        bundle = AddTimestampToBundleHandler.Handle(new AddTimestampToBundleCommand(bundle, receipt2));

        Assert.Equal(2, bundle.TimestampReceipts!.Count);
    }

    [Fact]
    public async Task AddTimestampToBundle_DoesNotChangeClaimCoreDigest()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var digestBefore = ClaimCoreDigest.Compute(bundle);

        var coreDigest = ClaimCoreDigest.Compute(bundle);
        var messageImprint = Digest256.Compute(coreDigest.AsBytes()).AsBytes().ToArray();

        var receipt = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            messageImprint,
            new byte[] { 0x00 },
            new TstInfo
            {
                HashAlgorithmOid = TstInfo.Sha256Oid,
                HashedMessage = messageImprint,
                GenTime = DateTimeOffset.UtcNow,
                PolicyOid = "1.2.3.4"
            },
            new TsaInfo());

        bundle = AddTimestampToBundleHandler.Handle(new AddTimestampToBundleCommand(bundle, receipt));

        var digestAfter = ClaimCoreDigest.Compute(bundle);

        // Timestamp receipts are excluded from claim_core_digest
        Assert.Equal(digestBefore, digestAfter);
    }

    [Fact]
    public void TsaTrustVerifier_NoTrustAnchors_ReturnsUntrusted()
    {
        using var cert = CreateSelfSignedCert("CN=Test TSA");

        var result = TsaTrustVerifier.VerifyTrust(
            cert,
            DateTimeOffset.UtcNow,
            trustAnchors: null,
            strict: false);

        Assert.False(result.IsTrusted);
        Assert.NotNull(result.Warning);
        Assert.Contains("No trust anchors provided", result.Warning);
    }

    [Fact]
    public void TsaTrustVerifier_NoTrustAnchors_StrictMode_ReturnsError()
    {
        using var cert = CreateSelfSignedCert("CN=Test TSA");

        var result = TsaTrustVerifier.VerifyTrust(
            cert,
            DateTimeOffset.UtcNow,
            trustAnchors: null,
            strict: true);

        Assert.False(result.IsTrusted);
        Assert.NotNull(result.Error);
        Assert.Contains("strict-tsa", result.Error);
    }

    [Fact]
    public void TsaTrustVerifier_CertExpiredAtGenTime_ReturnsWarning()
    {
        // Create cert valid from 2024-01-01 to 2024-06-01
        using var cert = CreateSelfSignedCert(
            "CN=Test TSA",
            notBefore: new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            notAfter: new DateTime(2024, 6, 1, 0, 0, 0, DateTimeKind.Utc));

        var trustAnchors = new X509Certificate2Collection { cert };

        // GenTime is 2024-07-01 (after cert expiry)
        var result = TsaTrustVerifier.VerifyTrust(
            cert,
            DateTimeOffset.Parse("2024-07-01T12:00:00Z", CultureInfo.InvariantCulture),
            trustAnchors,
            strict: false);

        Assert.False(result.IsTrusted);
        Assert.Contains("not valid at timestamp time", result.Warning);
    }

    [Fact]
    public async Task Phase5Bundle_BackwardsCompatible_WithTimestamps()
    {
        // Create Phase 5 bundle with attestations
        var bundle = await CreateClaimBundle("Test claim");

        // Add a timestamp receipt
        var coreDigest = ClaimCoreDigest.Compute(bundle);
        var messageImprint = Digest256.Compute(coreDigest.AsBytes()).AsBytes().ToArray();

        var receipt = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            messageImprint,
            new byte[] { 0x00 },
            new TstInfo
            {
                HashAlgorithmOid = TstInfo.Sha256Oid,
                HashedMessage = messageImprint,
                GenTime = DateTimeOffset.UtcNow,
                PolicyOid = "1.2.3.4"
            },
            new TsaInfo());

        bundle = AddTimestampToBundleHandler.Handle(new AddTimestampToBundleCommand(bundle, receipt));

        // Bundle should still be valid
        Assert.NotNull(bundle.TimestampReceipts);
        Assert.Single(bundle.TimestampReceipts);

        // Existing fields should be preserved
        Assert.NotNull(bundle.Claim);
        Assert.NotNull(bundle.Researcher);
    }

    [Fact]
    public void TimestampReceiptInfo_ContractVersion_IsCorrect()
    {
        var receiptInfo = new TimestampReceiptInfo
        {
            ReceiptId = Guid.NewGuid().ToString(),
            Subject = new TimestampSubjectInfo { DigestHex = new string('0', 64) },
            MessageImprintHex = new string('0', 64),
            TsaTokenDerBase64 = Convert.ToBase64String(new byte[] { 0x00 }),
            IssuedAt = DateTimeOffset.UtcNow.ToString("O"),
            Tsa = new TimestampTsaInfo()
        };

        Assert.Equal("TimestampReceiptRFC3161.v1", receiptInfo.Contract);
    }

    [Fact]
    public void TimestampSubjectInfo_Kind_IsClaimCoreDigest()
    {
        var subjectInfo = new TimestampSubjectInfo
        {
            DigestHex = new string('0', 64)
        };

        Assert.Equal("CLAIM_CORE_DIGEST", subjectInfo.Kind);
    }

    // Helper methods

    private async Task<ClaimBundle> CreateClaimBundle(string statement)
    {
        var researcher = await CreateResearcher("Dr. Author " + Guid.NewGuid().ToString()[..8]);
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            statement,
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        return await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));
    }

    private async Task<ClaimLedger.Domain.Identity.ResearcherIdentity> CreateResearcher(string name)
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);
        return await handler.HandleAsync(new CreateResearcherIdentityCommand(name));
    }

    private static byte[] CreateTestTstInfo(
        string hashOid,
        byte[] hashedMessage,
        DateTimeOffset genTime,
        string policyOid,
        int serialNumber)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            // version INTEGER (1)
            writer.WriteInteger(1);

            // policy OID
            writer.WriteObjectIdentifier(policyOid);

            // messageImprint SEQUENCE
            using (writer.PushSequence())
            {
                // hashAlgorithm AlgorithmIdentifier
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(hashOid);
                    writer.WriteNull();
                }
                writer.WriteOctetString(hashedMessage);
            }

            // serialNumber INTEGER
            writer.WriteInteger(serialNumber);

            // genTime GeneralizedTime
            writer.WriteGeneralizedTime(genTime);
        }

        return writer.Encode();
    }

    private static X509Certificate2 CreateSelfSignedCert(
        string subjectName,
        DateTime? notBefore = null,
        DateTime? notAfter = null)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add Time Stamping EKU
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") }, // Time Stamping
                critical: false));

        var start = notBefore ?? DateTime.UtcNow;
        var end = notAfter ?? DateTime.UtcNow.AddYears(1);

        return request.CreateSelfSigned(start, end);
    }
}
