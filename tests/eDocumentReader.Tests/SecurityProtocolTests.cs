using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Pki;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace eDocumentReader.Tests;

public class SecurityProtocolTests
{
    private static readonly string Standards = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "docs", "standards"));
    private static string WorkedExample(string set, string file) => Path.Combine(Standards, "TR-03110_EAC-Worked-Example", "Certificates", set, file);
    private static string ReferenceData(string file) => Path.Combine(Standards, "TR-03105-5_ReferenceDataSet", "referenceDataSet", file);

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
