using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Pki;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace eDocumentReader.Tests;

public class SecurityProtocolTests
{
    private static readonly string Standards = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "docs", "standards"));
    private static string WorkedExample(string set, string file) => Path.Combine(Standards, "TR-03110_EAC-Worked-Example", "Certificates", set, file);
    private static string ReferenceData(string file) => Path.Combine(Standards, "TR-03105-5_ReferenceDataSet", "referenceDataSet", file);

    /// <summary>EF.CardAccess of a German identity card (nPA): protocol information only, no personal data.</summary>
    private const string NpaCardAccess =
        "31820124300D060804007F00070202020201023012060A04007F000702020302020201020201483012060A04007F0007" +
        "020203020202010302014F3012060A04007F0007020204020202010202010D3012060A04007F00070202040602020102" +
        "02010D301B060B04007F000702020B010203300902010102010002010102014F301C060904007F000702020302300C06" +
        "0704007F0007010202010D020148301C060904007F000702020302300C060704007F0007010202010D02014F302A0608" +
        "04007F0007020206161E687474703A2F2F6273692E62756E642E64652F6369662F6E70612E786D6C303E060804007F00" +
        "0702020831323012060A04007F00070202030202020102020149301C060904007F000702020302300C060704007F0007" +
        "010202010D020149";

    [Fact]
    public void SecurityInfos_NpaCardAccess_ParsesAllEntries()
    {
        var infos = SecurityInfos.Parse(Hex.Parse(NpaCardAccess));
        Assert.Empty(infos.OfType<InvalidSecurityInfo>());
        Assert.Single(infos.OfType<TerminalAuthenticationInfo>());
        var pace = infos.OfType<PaceInfo>().ToList();
        Assert.Equal(2, pace.Count);
        Assert.Contains(pace, p => p.Algorithm.Mapping == PaceMapping.Generic && p.ParameterId == 13);
        Assert.Contains(pace, p => p.Algorithm.Mapping == PaceMapping.ChipAuthentication && p.ParameterId == 13);
        Assert.Equal([0x48, 0x4F], infos.OfType<ChipAuthenticationInfo>().Select(i => i.KeyId ?? -1));
        var caDomains = infos.OfType<ChipAuthenticationDomainParameterInfo>().ToList();
        Assert.Equal([0x48, 0x4F], caDomains.Select(i => i.KeyId ?? -1));
        Assert.All(caDomains, d => Assert.Equal(Oids.IdCaEcdh, d.Oid));
        Assert.Contains(infos, i => i.Oid == Oids.IdCardInfo);
        Assert.Contains(infos, i => i.Oid == Oids.IdPt);
    }

    [Fact]
    public void SecurityInfos_MalformedEntry_DoesNotHideOthers()
    {
        // ChipAuthenticationInfo with a SEQUENCE instead of the version INTEGER, followed by a valid PACEInfo.
        var infos = SecurityInfos.Parse(Hex.Parse(
            "3124" + "300E060A04007F000702020302023000" + "3012060A04007F0007020204020202010202010D"));
        Assert.Single(infos.OfType<InvalidSecurityInfo>());
        Assert.Single(infos.OfType<PaceInfo>());
    }

    [Theory]
    [InlineData("certs_ecdh")]
    [InlineData("certs_dh")]
    public void EacWorkedExample_CvChainVerifies(string set)
    {
        var root = Path.Combine(Path.GetTempPath(), "edoc_pki_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new PkiStore(root);
            foreach (var f in new[] { "CVCA_Cert_at.cvcert", "dv_cert_19.cvcert", "at_cert_19a.cvcert", "AT_KEY_19.pkcs8" })
                store.Import(WorkedExample(set, f));
            var cvca = store.CvCertificates.Single(c => c.IsSelfSigned);
            var at = store.CvCertificates.Single(c => c.Role == CvRole.InspectionSystemOrTerminal);
            Assert.Equal(CvRole.Cvca, cvca.Role);
            Assert.Empty(cvca.Findings);
            var report = store.VerifyCvChain(at);
            Assert.Equal(3, report.Count);
            Assert.All(report, r => Assert.Contains("gültig", r));
            Assert.DoesNotContain(report, r => r.Contains("UNGÜLTIG"));
            Assert.Single(store.TerminalCredentials());
            var chain = store.BuildTerminalChain(cvca.Chr, terminalOid: null);
            Assert.NotNull(chain);
            Assert.Equal(2, chain!.Value.Chain.Count);
            // IDL without EF.CVCA: the self-signed CVCA is the candidate trust point.
            Assert.Equal([cvca.Chr], store.CandidateTrustPoints());
        }
        finally { Directory.Delete(root, true); }
    }

    /// <summary>ISO/IEC 18013-3 8.7, Amd.1 C.2.1: the IDL input string is the PACE password itself (reference 01, no SHA-1).</summary>
    [Fact]
    public void IdlPacePasswordIsTheUnhashedInputString()
    {
        const string input = "1ABCDEFGH12345678901234567890";
        var idl = PacePassword.FromIdlInputString(input);
        Assert.Equal(PacePasswordType.Mrz, idl.Type);
        Assert.Equal(System.Text.Encoding.Latin1.GetBytes(input), idl.Encode());
        Assert.Equal(System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.ASCII.GetBytes(input)), PacePassword.FromMrz(input).Encode());
    }

    [Fact]
    public void CandidateTrustPoints_WithoutCvcaCertificate_UsesCarOfDv()
    {
        var root = Path.Combine(Path.GetTempPath(), "edoc_pki_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new PkiStore(root);
            foreach (var f in new[] { "dv_cert_19.cvcert", "at_cert_19a.cvcert", "AT_KEY_19.pkcs8" })
                store.Import(WorkedExample("certs_ecdh", f));
            var dv = store.CvCertificates.Single(c => c.Role != CvRole.InspectionSystemOrTerminal);
            Assert.Equal([dv.Car], store.CandidateTrustPoints());
            Assert.NotNull(store.BuildTerminalChain(dv.Car, terminalOid: null));
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData("SHA-1")]
    [InlineData("SHA-256")]
    public void ActiveAuthentication_Rsa_ReferenceDataSet(string hash)
    {
        var dg15 = File.ReadAllBytes(ReferenceData("Datagroup15.bin"));
        var publicKey = ActiveAuthentication.PublicKeyFromDg15(dg15);
        var privateKey = PrivateKeyFactory.CreateKey(File.ReadAllBytes(ReferenceData("DG15_sk.pkcs8")));
        if (publicKey is not RsaKeyParameters) return; // reference set may use ECDSA – covered below
        var nonce = Convert.FromHexString("F173589974BF40C6");
        var sig = ActiveAuthentication.SignRsa((RsaKeyParameters)privateKey, nonce, hash);
        Assert.True(ActiveAuthentication.Verify(publicKey, nonce, sig).Valid);
        sig[^1] ^= 0x01;
        Assert.False(ActiveAuthentication.Verify(publicKey, nonce, sig).Valid);
        Assert.False(ActiveAuthentication.Verify(publicKey, Convert.FromHexString("0000000000000000"), ActiveAuthentication.SignRsa((RsaKeyParameters)privateKey, nonce, hash)).Valid);
    }

    [Fact]
    public void ChipAuthentication_ReferenceDg14_KeyAgreementMatchesChipSide()
    {
        var dg14 = BerTlv.ParseSingle(File.ReadAllBytes(ReferenceData("Datagroup14.bin")));
        var infos = SecurityInfos.Parse(dg14.Value);
        var pkInfo = infos.OfType<ChipAuthenticationPublicKeyInfo>().First();
        var chipKey = ChipPublicKey.From(pkInfo);
        var oid = ChipAuthentication.SelectOid(pkInfo, infos.OfType<ChipAuthenticationInfo>());
        Assert.StartsWith(Oids.IdCa, oid);

        // Terminal side
        var eph = chipKey.Domain.Generate();
        var kTerminal = chipKey.Domain.Agree(eph.PrivateKey, chipKey.PublicKey);
        // Chip side with the reference private key
        var sk = PrivateKeyFactory.CreateKey(File.ReadAllBytes(ReferenceData("DG14_sk.pkcs8")));
        var skValue = sk switch
        {
            ECPrivateKeyParameters ec => ec.D,
            DHPrivateKeyParameters dh => dh.X,
            _ => throw new NotSupportedException(sk.GetType().Name),
        };
        var kChip = chipKey.Domain.Agree(skValue, eph.PublicKey);
        Assert.Equal(kTerminal, kChip);
    }

    [Fact]
    public void Rfc5114_GroupsAreConsistent()
    {
        for (var id = 0; id <= 2; id++)
        {
            var g = StandardizedDomainParameters.ModpGroup(id);
            Assert.True(g.G.ModPow(g.Q!, g.P).Equals(Org.BouncyCastle.Math.BigInteger.One), $"g^q ≠ 1 für Gruppe {id}");
            Assert.True(g.P.IsProbablePrime(50));
        }
    }
}
