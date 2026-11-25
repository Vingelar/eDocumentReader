using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace eDocumentReader.Tests;

/// <summary>
/// PACE-CAM (ICAO 9303-11 4.4.3.3.3, 4.4.3.5): the reader against a simulated chip that maps with
/// SK_Map,IC = SK_IC · CA_IC and returns A_IC, and the terminal check PK_Map,IC = CA_IC · PK_IC with EF.CardSecurity.
/// All keys are synthetic test values.
/// </summary>
public class PaceCamTests
{
    private const string CamOid = "0.4.0.127.0.7.2.2.4.6.2";

    /// <summary>Chip side of PACE (GM or CAM) on standardized domain parameters with AES-128 and a CAN.</summary>
    private sealed class PaceChip(int paramId, string oid, BigInteger skIc, string can, bool corruptAic = false) : ICardTransport
    {
        private readonly Org.BouncyCastle.Asn1.X9.X9ECParameters domain = StandardizedDomainParameters.Curve(paramId);
        private readonly SecureRandom random = new();
        private byte[] s = [];
        private BigInteger skMap = BigInteger.Zero, caIc = BigInteger.Zero, skEph = BigInteger.Zero;
        private ECPoint g = null!;
        private byte[] pkEphIc = [], pkEphPcd = [], ksEnc = [], ksMac = [];
        private bool Cam => oid == CamOid;

        public string Name => "PACE chip";
        public byte[] Atr => Hex.Parse("3B80800101");
        public string Protocol => "T=1";
        public CardInterface Interface => CardInterface.Contactless;
        public byte[] Control(uint controlCode, byte[] input) => throw new NotSupportedException();
        public void Reset(bool cold) { }
        public void Dispose() { }

        private BigInteger Scalar()
        {
            BigInteger k;
            do k = new BigInteger(domain.N.BitLength, random); while (k.SignValue == 0 || k.CompareTo(domain.N) >= 0);
            return k;
        }

        private static byte[] Field(BigInteger v) => KeyAgreementDomain.FixedLength(v, 32);

        private static byte[] Ok(byte[] data) => [.. BerTlv.Encode(0x7C, data), 0x90, 0x00];

        public byte[] Transmit(byte[] command)
        {
            var apdu = CommandApdu.Parse(command);
            if (apdu.Ins == 0x22) return [0x90, 0x00];
            var data = BerTlv.ParseSingle(apdu.Data).Children;
            if (data.Count == 0)
            {
                s = new byte[16];
                random.NextBytes(s);
                var kPi = Kdf.Derive(System.Text.Encoding.Latin1.GetBytes(can), Kdf.CounterPassword, SessionKeyType.Aes128);
                return Ok(BerTlv.Encode(0x80, SymmetricCrypto.CbcEncrypt(CipherAlgorithm.Aes, kPi, new byte[16], s)));
            }
            var o = data[0];
            switch (o.Tag)
            {
                case 0x81:
                {
                    // CAM: CA_IC random, SK_Map,IC = SK_IC · CA_IC mod n (so CA_IC = SK_IC^-1 · SK_Map,IC).
                    caIc = Scalar();
                    skMap = Cam ? skIc.Multiply(caIc).Mod(domain.N) : Scalar();
                    var pcd = domain.Curve.DecodePoint(o.Value);
                    var h = pcd.Multiply(skMap).Normalize();
                    g = domain.G.Multiply(new BigInteger(1, s)).Add(h).Normalize();
                    return Ok(BerTlv.Encode(0x82, domain.G.Multiply(skMap).Normalize().GetEncoded(false)));
                }
                case 0x83:
                {
                    pkEphPcd = o.Value;
                    skEph = Scalar();
                    pkEphIc = g.Multiply(skEph).Normalize().GetEncoded(false);
                    var k = Field(g.Curve.DecodePoint(pkEphPcd).Multiply(skEph).Normalize().AffineXCoord.ToBigInteger());
                    ksEnc = Kdf.Derive(k, Kdf.CounterEnc, SessionKeyType.Aes128);
                    ksMac = Kdf.Derive(k, Kdf.CounterMac, SessionKeyType.Aes128);
                    return Ok(BerTlv.Encode(0x84, pkEphIc));
                }
                case 0x85:
                {
                    var expected = SymmetricCrypto.Mac(CipherAlgorithm.Aes, ksMac, Pace.AuthTokenInput(oid, pkEphIc));
                    if (!expected.AsSpan().SequenceEqual(o.Value)) return [0x63, 0x00];
                    var response = new List<byte>(BerTlv.Encode(0x86, SymmetricCrypto.Mac(CipherAlgorithm.Aes, ksMac, Pace.AuthTokenInput(oid, pkEphPcd))));
                    if (Cam)
                    {
                        var iv = SymmetricCrypto.EcbEncryptBlock(CipherAlgorithm.Aes, ksEnc, Enumerable.Repeat((byte)0xFF, 16).ToArray());
                        var aIc = SymmetricCrypto.CbcEncrypt(CipherAlgorithm.Aes, ksEnc, iv, SymmetricCrypto.Pad(Field(caIc), 16));
                        if (corruptAic) aIc[0] ^= 1;
                        response.AddRange(BerTlv.Encode(0x8A, aIc));
                    }
                    return Ok([.. response]);
                }
            }
            return [0x6A, 0x80];
        }
    }

    private static PaceInfo Info(string oid, int paramId) => new(oid, 2, paramId, DerNull.Instance);

    private static byte[] KeyInfo(ECPoint pk, int paramId, int keyId) =>
        new DerSequence(new DerObjectIdentifier(Oids.IdPkEcdh),
            new DerSequence(new DerSequence(new DerObjectIdentifier(Oids.EcPublicKey), new DerInteger(paramId)), new DerBitString(pk.GetEncoded(false))),
            new DerInteger(keyId)).GetEncoded();

    private static ChipAuthenticationPublicKeyInfo KeyInfoRecord(ECPoint pk, int paramId, int keyId) =>
        SecurityInfos.Parse(new DerSet(Asn1Object.FromByteArray(KeyInfo(pk, paramId, keyId))).GetEncoded()).OfType<ChipAuthenticationPublicKeyInfo>().Single();

    [Theory]
    [InlineData(13)]
    [InlineData(12)]
    public void PaceCam_ReaderVerifiesChipAuthenticationMapping(int paramId)
    {
        var domain = StandardizedDomainParameters.Curve(paramId);
        var skIc = new BigInteger(1, Hex.Parse("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")).Mod(domain.N);
        var pkIc = domain.G.Multiply(skIc).Normalize();
        var chip = new PaceChip(paramId, CamOid, skIc, "123456");
        var result = Pace.Perform(new CardChannel(chip, Logger.Null), Info(CamOid, paramId), PacePassword.FromCan("123456"));

        Assert.True(result.ChipAuthenticationMapping);
        Assert.NotNull(result.ChipAuthenticationData);
        Assert.Equal(32, result.ChipAuthenticationData!.Length);
        Assert.NotNull(Pace.VerifyChipAuthenticationMapping(result, [KeyInfoRecord(pkIc, paramId, 1)]));
        // Another chip key (a cloned chip without SK_IC) fails the check.
        Assert.Null(Pace.VerifyChipAuthenticationMapping(result, [KeyInfoRecord(domain.G.Multiply(skIc.Add(BigInteger.One)).Normalize(), paramId, 1)]));
    }

    [Fact]
    public void PaceCam_CorruptedAicFailsTheCheck()
    {
        // A changed first block still decrypts with valid padding (in the last block), but CA_IC is wrong.
        var domain = StandardizedDomainParameters.Curve(13);
        var skIc = BigInteger.ValueOf(7);
        var chip = new PaceChip(13, CamOid, skIc, "123456", corruptAic: true);
        var result = Pace.Perform(new CardChannel(chip, Logger.Null), Info(CamOid, 13), PacePassword.FromCan("123456"));
        Assert.Null(Pace.VerifyChipAuthenticationMapping(result, [KeyInfoRecord(domain.G.Multiply(skIc).Normalize(), 13, 1)]));
    }

    [Fact]
    public void DecryptChipAuthenticationData_BadPaddingIsRejected()
    {
        var ks = Hex.Parse("000102030405060708090A0B0C0D0E0F");
        var iv = SymmetricCrypto.EcbEncryptBlock(CipherAlgorithm.Aes, ks, Enumerable.Repeat((byte)0xFF, 16).ToArray());
        var aic = SymmetricCrypto.CbcEncrypt(CipherAlgorithm.Aes, ks, iv, new byte[48]); // no '80' padding
        Assert.Throws<ProtocolException>(() => Pace.DecryptChipAuthenticationData(CipherAlgorithm.Aes, ks, aic));
    }

    [Fact]
    public void PaceGm_HasNoChipAuthenticationData()
    {
        var chip = new PaceChip(13, "0.4.0.127.0.7.2.2.4.2.2", BigInteger.ValueOf(7), "123456");
        var result = Pace.Perform(new CardChannel(chip, Logger.Null), Info("0.4.0.127.0.7.2.2.4.2.2", 13), PacePassword.FromCan("123456"));
        Assert.False(result.ChipAuthenticationMapping);
        Assert.Null(result.ChipAuthenticationData);
    }

    [Fact]
    public void DecryptChipAuthenticationData_UsesIvOfAllOnes()
    {
        var ks = Hex.Parse("000102030405060708090A0B0C0D0E0F");
        var ca = Hex.Parse("1111111111111111111111111111111111111111111111111111111111111111");
        var iv = SymmetricCrypto.EcbEncryptBlock(CipherAlgorithm.Aes, ks, Enumerable.Repeat((byte)0xFF, 16).ToArray());
        var aic = SymmetricCrypto.CbcEncrypt(CipherAlgorithm.Aes, ks, iv, SymmetricCrypto.Pad(ca, 16));
        Assert.Equal(48, aic.Length);
        Assert.Equal(ca, Pace.DecryptChipAuthenticationData(CipherAlgorithm.Aes, ks, aic));
        // With a zero IV the first block would be wrong.
        Assert.NotEqual(ca, SymmetricCrypto.CbcDecrypt(CipherAlgorithm.Aes, ks, new byte[16], aic)[..32]);
    }

    [Fact]
    public void CardSecurity_SignedSecurityObject_ParsesAndVerifies()
    {
        var domain = StandardizedDomainParameters.Curve(13);
        var pkIc = domain.G.Multiply(BigInteger.ValueOf(12345)).Normalize();
        var infos = new DerSet(new Asn1Encodable[]
        {
            Asn1Object.FromByteArray(KeyInfo(pkIc, 13, 1)),
            new DerSequence(new DerObjectIdentifier(CamOid), new DerInteger(2), new DerInteger(13)),
        }).GetEncoded();

        // Self-signed test DS (ECDSA P-256).
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers(), new SecureRandom()));
        var ds = gen.GenerateKeyPair();
        var certGen = new X509V3CertificateGenerator();
        var dn = new X509Name("CN=Test DS,C=UT");
        certGen.SetSerialNumber(BigInteger.One);
        certGen.SetIssuerDN(dn);
        certGen.SetSubjectDN(dn);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGen.SetPublicKey(ds.Public);
        var cert = certGen.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", ds.Private));
        var cms = new CmsSignedDataGenerator();
        cms.AddSigner(ds.Private, cert, CmsSignedGenerator.DigestSha256);
        cms.AddCertificate(cert);
        var signed = cms.Generate(new CmsProcessableByteArray(new DerObjectIdentifier(CardSecurity.SecurityObjectOid), infos), true).GetEncoded("DER");

        var cardSecurity = new CardSecurity(signed);
        Assert.Empty(cardSecurity.Findings);
        Assert.Single(cardSecurity.Infos.OfType<ChipAuthenticationPublicKeyInfo>());
        Assert.Single(cardSecurity.Infos.OfType<PaceInfo>(), p => p.Algorithm.Mapping == PaceMapping.ChipAuthentication);
        var check = cardSecurity.Verify(null);
        Assert.True(check.SignatureValid, check.SignatureDetail);
        Assert.False(check.Valid); // no CSCA store: chain not verified

        signed[^5] ^= 0x01;
        Assert.False(new CardSecurity(signed).Verify(null).SignatureValid);
    }

    private static DerObjectIdentifier SecObjectIdentifiers() => Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1;
}
