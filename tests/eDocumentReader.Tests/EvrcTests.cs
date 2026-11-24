using System.Text;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace eDocumentReader.Tests;

public class EvrcTests
{
    private static byte[] Ascii(string s) => Encoding.Latin1.GetBytes(s);

    private static byte[] RegistrationA(byte[] charset, byte[] ownerStatus) => BerTlv.EncodeConstructed(0x71,
        BerTlv.Encode(0x80, Ascii("01")),
        BerTlv.Encode(0x9F33, Ascii("Österreich")),
        BerTlv.Encode(0x9F37, charset),
        BerTlv.Encode(0x81, Ascii("W-12345X")),
        BerTlv.Encode(0x82, Ascii("19990126")),
        BerTlv.EncodeConstructed(0xA1, BerTlv.EncodeConstructed(0xA2, BerTlv.Encode(0x83, Ascii("Muster"))), BerTlv.Encode(0x86, ownerStatus)));

    [Fact]
    public void Registration_ConformingData_IsDecodedWithoutFindings()
    {
        var fields = Evrc.ParseRegistration(RegistrationA([0x00], [0x00]), "EF.Registration_A", [0x00]);
        Assert.Equal("Österreich", fields.Single(f => f.TagHex == "9F33").Value);
        Assert.Equal("00 – ist Eigentümer", fields.Single(f => f.TagHex == "86").Value);
        Assert.StartsWith("19990126 (26.01.1999)", fields.Single(f => f.TagHex == "82").Value);
        Assert.All(fields, f => Assert.Empty(f.Findings));
    }

    [Fact]
    public void Registration_DeviationsOfTheAustrianCard_AreReported()
    {
        // Seen on a real card: '9F37' as ASCII "00", '86' as free text instead of a code.
        var fields = Evrc.ParseRegistration(RegistrationA(Ascii("00"), Ascii("Besitzer")), "EF.Registration_A", Ascii("00"));
        Assert.Contains(fields.Single(f => f.TagHex == "9F37").Findings, x => x.Contains("ASCII"));
        var owner = fields.Single(f => f.TagHex == "86");
        Assert.Equal("Besitzer", owner.Value);
        Assert.Contains(owner.Findings, x => x.Contains("Text statt"));
    }

    [Theory]
    [InlineData(new byte[] { 0x01 }, "iso-8859-5")]
    [InlineData(new byte[] { 0x02 }, "iso-8859-7")]
    [InlineData(new byte[] { 0x00 }, "iso-8859-1")]
    public void Charset_FollowsTable2(byte[] value, string expected)
    {
        Assert.Equal(expected, Evrc.Charset(value, out var finding).WebName);
        Assert.Null(finding);
    }

    [Fact]
    public void Registration_InvalidDate_IsReported()
    {
        var data = BerTlv.EncodeConstructed(0x71, BerTlv.Encode(0x82, Ascii("26.01.99")));
        Assert.Contains(Evrc.ParseRegistration(data, "A", [0x00]).Single(f => f.TagHex == "82").Findings, x => x.Contains("JJJJMMTT"));
    }

    [Fact]
    public void Fcp_FileSizeFromTag80()
    {
        // FCP of the real card: '80' = 1000 (allocated), proprietary 'C5' = 016A (used)
        var fcp = eDocumentReader.Core.Util.Hex.Parse("62 1A 80 02 10 00 C5 02 01 6A 82 01 01 83 02 D0 01 88 01 08 8A 01 05 A1 03 8B 01 02");
        Assert.Equal(4096, Evrc.FileSize(fcp));
    }

    [Fact]
    public void ReadSelected_StopsAt6282()
    {
        var transport = new ScriptedTransport(
            ("00 B0 00 00 FF", "01 02 03 04 6282"));
        var data = new FileReader(new CardChannel(transport, Logger.Null)) { MaxChunk = 0xFF }.ReadSelected(4096, "EF.Test");
        Assert.Equal([1, 2, 3, 4], data);
    }

    [Theory]
    [InlineData("SHA256withECDSA", "ECDSA DER, SHA-256")]
    [InlineData("SHA256withPLAIN-ECDSA", "ECDSA plain r‖s, SHA-256")]
    [InlineData("SHA1withECDSA", "ECDSA DER, SHA-1")]
    public void Signature_EcdsaVariantsAreIdentified(string algorithm, string expected)
    {
        var (cert, key) = IssuerCertificate();
        var data = RegistrationA([0x00], [0x00]);
        var signer = SignerUtilities.GetSigner(algorithm);
        signer.Init(true, key);
        signer.BlockUpdate(data, 0, data.Length);
        var signature = signer.GenerateSignature();

        var ok = Evrc.VerifySignature("A", data, signature, cert.GetEncoded());
        Assert.True(ok.Valid);
        Assert.StartsWith(expected, ok.Detail);

        data[^1] ^= 1;
        Assert.False(Evrc.VerifySignature("A", data, signature, cert.GetEncoded()).Valid);
    }

    [Fact]
    public void Signature_MissingFiles_AreNotJudged() =>
        Assert.Null(Evrc.VerifySignature("B", [1], null, null).Valid);

    private static (X509Certificate Cert, ECPrivateKeyParameters Key) IssuerCertificate()
    {
        var curve = ECNamedCurveTable.GetByName("brainpoolP224r1");
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        var pair = gen.GenerateKeyPair();
        var cg = new X509V3CertificateGenerator();
        var dn = new X509Name("CN=Signaturdienst Test,C=AT");
        cg.SetSerialNumber(BigInteger.One);
        cg.SetIssuerDN(dn);
        cg.SetSubjectDN(dn);
        cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(1));
        cg.SetPublicKey(pair.Public);
        return (cg.Generate(new Asn1SignatureFactory("SHA256withECDSA", pair.Private)), (ECPrivateKeyParameters)pair.Private);
    }
}

public class IdlMrzTests
{
    // Synthetic line of the same shape as a test card (no personal data).
    private const string Line = "D1ZZTEST000000000<<<<<<<<<<<<";

    [Fact]
    public void BapInput_IsCharacters2To29()
    {
        var full = Line + eDocumentReader.Core.Documents.Mrz.ComputeCheckDigit(Line);
        var mrz = eDocumentReader.Core.Documents.IdlMrz.Parse(full);
        Assert.True(mrz.CheckDigitValid);
        Assert.Equal('1', mrz.Configuration);
        Assert.Equal(full[1..29], mrz.BapKeySeedInformation);
        Assert.Equal(28, mrz.BapKeySeedInformation.Length);
    }

    [Theory]
    [InlineData("P<D<<MUSTERMANN<<ERIKA<<<<<<<<")]
    [InlineData("D123")]
    public void NonIdlInput_IsRejected(string text) => Assert.False(eDocumentReader.Core.Documents.IdlMrz.LooksLikeIdlMrz(text));
}

public class CommandChainingTests
{
    [Fact]
    public void SendChained_SplitsIntoBlocksWithChainingBit()
    {
        var data = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();
        var first = "10 2A 00 BE C0 " + string.Join(" ", data.Take(192).Select(b => b.ToString("X2")));
        var last = "00 2A 00 BE 08 " + string.Join(" ", data.Skip(192).Select(b => b.ToString("X2")));
        var transport = new ScriptedTransport((first, "9000"), (last, "9000"));
        var r = eDocumentReader.Core.Protocols.TerminalAuthentication.SendChained(
            new CardChannel(transport, Logger.Null), 0x2A, 0x00, 0xBE, data, 192, "PSO");
        Assert.True(r.Status.IsSuccess);
    }

    [Fact]
    public void SendChained_ShortDataIsSentUnchained()
    {
        var transport = new ScriptedTransport(("00 2A 00 BE 02 01 02", "9000"));
        Assert.True(eDocumentReader.Core.Protocols.TerminalAuthentication.SendChained(
            new CardChannel(transport, Logger.Null), 0x2A, 0x00, 0xBE, [1, 2], 192, "PSO").Status.IsSuccess);
    }
}
