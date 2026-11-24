using System.Text;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace eDocumentReader.Core.Pki;

public enum CvRole { InspectionSystemOrTerminal = 0, DvForeign = 1, DvDomestic = 2, Cvca = 3 }

/// <summary>Public key data object '7F49' (TR-03110-3 D.3).</summary>
public sealed record CvPublicKey(string Oid, IReadOnlyDictionary<uint, byte[]> Elements)
{
    public bool IsEc => Oid.StartsWith(TaOids.Ecdsa, StringComparison.Ordinal);
    public bool IsRsa => Oid.StartsWith(TaOids.Rsa, StringComparison.Ordinal);
    public bool HasDomainParameters => IsEc && Elements.ContainsKey(0x81);

    public ECDomainParameters? EcDomain()
    {
        if (!HasDomainParameters) return null;
        var p = new BigInteger(1, Elements[0x81]);
        var a = new BigInteger(1, Elements[0x82]);
        var b = new BigInteger(1, Elements[0x83]);
        var n = new BigInteger(1, Elements[0x85]);
        var h = Elements.TryGetValue(0x87, out var f) ? new BigInteger(1, f) : BigInteger.One;
        var curve = new FpCurve(p, a, b, n, h);
        return new ECDomainParameters(curve, curve.DecodePoint(Elements[0x84]), n, h);
    }

    public AsymmetricKeyParameter ToKey(ECDomainParameters? inheritedDomain)
    {
        if (IsRsa) return new RsaKeyParameters(false, new BigInteger(1, Elements[0x81]), new BigInteger(1, Elements[0x82]));
        if (IsEc)
        {
            var domain = EcDomain() ?? inheritedDomain ?? throw new InvalidOperationException(T("EC-Domain-Parameter fehlen (vom CVCA-Zertifikat erben).", "EC domain parameters missing (inherit from the CVCA certificate)."));
            return new ECPublicKeyParameters(domain.Curve.DecodePoint(Elements[0x86]), domain);
        }
        throw new NotSupportedException(T($"Schlüsselalgorithmus {Oid}", $"Key algorithm {Oid}"));
    }
}

/// <summary>Card verifiable certificate according to BSI TR-03110-3 Appendix C (profile Table 23) and D.2/D.3.</summary>
public sealed class CvCertificate
{
    public byte[] Encoded { get; }
    public byte[] Body { get; }
    public byte[] Signature { get; }
    public int ProfileIdentifier { get; }
    public string Car { get; }
    public string Chr { get; }
    public CvPublicKey PublicKey { get; }
    public string ChatOid { get; }
    public byte[] ChatTemplate { get; }
    public DateOnly EffectiveDate { get; }
    public DateOnly ExpirationDate { get; }
    public byte[]? Extensions { get; }
    public List<string> Findings { get; } = [];

    public CvCertificate(byte[] encoded)
    {
        Encoded = encoded;
        var cert = BerTlv.ParseSingle(encoded);
        if (cert.Tag != 0x7F21) throw new FormatException(T($"Kein CV-Zertifikat (Tag {cert.TagHex} statt 7F21).", $"Not a CV certificate (tag {cert.TagHex} instead of 7F21)."));
        var body = cert.Find(0x7F4E) ?? throw new FormatException(T("Certificate Body (7F4E) fehlt.", "Certificate Body (7F4E) missing."));
        Body = body.Encode();
        Signature = cert.Find(0x5F37)?.Value ?? throw new FormatException(T("Signatur (5F37) fehlt.", "Signature (5F37) missing."));

        uint[] order = [0x5F29, 0x42, 0x7F49, 0x5F20, 0x7F4C, 0x5F25, 0x5F24];
        var actual = body.Children.Select(c => c.Tag).Where(t => t != 0x65).ToArray();
        if (!actual.SequenceEqual(order)) Findings.Add(T($"Reihenfolge/Vollständigkeit der Body-Elemente abweichend von TR-03110-3 Table 23: {string.Join(" ", actual.Select(t => t.ToString("X")))}", $"Order/completeness of the body elements differs from TR-03110-3 Table 23: {string.Join(" ", actual.Select(t => t.ToString("X")))}"));

        ProfileIdentifier = body.Find(0x5F29)?.Value is { Length: 1 } pid ? pid[0] : -1;
        if (ProfileIdentifier != 0) Findings.Add($"Certificate Profile Identifier {ProfileIdentifier} ≠ 0 (TR-03110-3 C.1.1).");
        Car = Encoding.Latin1.GetString(body.Find(0x42)?.Value ?? []);
        Chr = Encoding.Latin1.GetString(body.Find(0x5F20)?.Value ?? []);
        var pk = body.Find(0x7F49) ?? throw new FormatException(T("Public Key (7F49) fehlt.", "Public Key (7F49) missing."));
        var oid = DerObjectIdentifier.FromContents(pk.Find(0x06)?.Value ?? throw new FormatException(T("Public-Key-OID fehlt.", "Public key OID missing."))).Id;
        PublicKey = new CvPublicKey(oid, pk.Children.Where(c => c.Tag != 0x06).ToDictionary(c => c.Tag, c => c.Value));
        var chat = body.Find(0x7F4C) ?? throw new FormatException(T("CHAT (7F4C) fehlt.", "CHAT (7F4C) missing."));
        ChatOid = DerObjectIdentifier.FromContents(chat.Find(0x06)?.Value ?? []).Id;
        ChatTemplate = chat.Find(0x53)?.Value ?? [];
        EffectiveDate = ParseDate(body.Find(0x5F25)?.Value, "Effective Date");
        ExpirationDate = ParseDate(body.Find(0x5F24)?.Value, "Expiration Date");
        Extensions = body.Find(0x65)?.Value;
        if (ExpirationDate < EffectiveDate) Findings.Add(T("Ablaufdatum liegt vor dem Gültigkeitsbeginn.", "Expiration date lies before the effective date."));
    }

    private DateOnly ParseDate(byte[]? v, string name)
    {
        // TR-03110-3 D.2: 6 digits YYMMDD, each digit encoded as unpacked BCD in one byte.
        if (v is not { Length: 6 } || v.Any(b => b > 9)) { Findings.Add(T($"{name} nicht als 6 entpackte BCD-Ziffern kodiert.", $"{name} not encoded as 6 unpacked BCD digits.")); return DateOnly.MinValue; }
        try { return new DateOnly(2000 + v[0] * 10 + v[1], v[2] * 10 + v[3], v[4] * 10 + v[5]); }
        catch { Findings.Add(T($"{name} ist kein gültiges Datum.", $"{name} is not a valid date.")); return DateOnly.MinValue; }
    }

    public CvRole Role => ChatTemplate.Length > 0 ? (CvRole)(ChatTemplate[0] >> 6) : CvRole.InspectionSystemOrTerminal;
    public bool IsSelfSigned => Car == Chr;
    public string ChrCountry => Chr.Length >= 2 ? Chr[..2] : Chr;
    public string ChrSequence => Chr.Length >= 5 ? Chr[^5..] : "";

    public string TerminalType => ChatOid switch
    {
        TaOids.IdIs => "Inspection System (ePassport)",
        TaOids.IdAt => "Authentication Terminal (eID)",
        TaOids.IdSt => "Signature Terminal",
        _ => ChatOid,
    };

    public string DescribeAuthorization()
    {
        if (ChatTemplate.Length == 0) return "-";
        var role = Role switch { CvRole.Cvca => "CVCA", CvRole.DvDomestic => T("DV (offiziell national)", "DV (official domestic)"), CvRole.DvForeign => T("DV (nicht-offiziell/ausländisch)", "DV (non-official/foreign)"), _ => ChatOid == TaOids.IdIs ? "Inspection System" : "Terminal" };
        if (ChatOid != TaOids.IdIs) return T($"{role}, Rechte {Hex.Compact(ChatTemplate)}", $"{role}, rights {Hex.Compact(ChatTemplate)}");
        var rights = new List<string>();
        // TR-03110-4 C.1 (Inspection Systems): bit 1 = read DG4 (iris), bit 0 = read DG3 (fingerprint)
        if ((ChatTemplate[^1] & 0x01) != 0) rights.Add(T("DG3 (Fingerabdruck)", "DG3 (fingerprint)"));
        if ((ChatTemplate[^1] & 0x02) != 0) rights.Add(T("DG4 (Iris)", "DG4 (iris)"));
        return T($"{role}, Lesen: {(rights.Count == 0 ? "keine" : string.Join(", ", rights))}", $"{role}, read: {(rights.Count == 0 ? "none" : string.Join(", ", rights))}");
    }

    public bool AllowsDataGroup(int dg) => dg switch { 3 => (ChatTemplate[^1] & 0x01) != 0, 4 => (ChatTemplate[^1] & 0x02) != 0, _ => false };

    /// <summary>Verifies the signature over the encoded body with the issuer's public key (TR-03110-3 C.1.8).</summary>
    public bool VerifySignature(CvPublicKey issuerKey, ECDomainParameters? domain)
    {
        var key = issuerKey.ToKey(domain);
        var signer = SignerUtilities.GetSigner(TaOids.SignatureAlgorithm(issuerKey.Oid));
        signer.Init(false, key);
        signer.BlockUpdate(Body, 0, Body.Length);
        return signer.VerifySignature(Signature);
    }

    public string Describe() =>
        T($"CHR {Chr}  CAR {Car}  {TerminalType}  {DescribeAuthorization()}  gültig {EffectiveDate:yyyy-MM-dd}–{ExpirationDate:yyyy-MM-dd}  Schlüssel {TaOids.Name(PublicKey.Oid)}", $"CHR {Chr}  CAR {Car}  {TerminalType}  {DescribeAuthorization()}  valid {EffectiveDate:yyyy-MM-dd}–{ExpirationDate:yyyy-MM-dd}  key {TaOids.Name(PublicKey.Oid)}");

    public override string ToString() => $"CVC {Chr} (CAR {Car})";
}

/// <summary>Terminal Authentication algorithm OIDs (TR-03110-3 A.6.4) and CHAT terminal types (TR-03110-4).</summary>
public static class TaOids
{
    public const string IdTa = "0.4.0.127.0.7.2.2.2";
    public const string Rsa = IdTa + ".1";
    public const string Ecdsa = IdTa + ".2";
    public const string IdRoles = "0.4.0.127.0.7.3.1.2";
    public const string IdIs = IdRoles + ".1";
    public const string IdAt = IdRoles + ".2";
    public const string IdSt = IdRoles + ".3";

    public static string SignatureAlgorithm(string oid) => oid switch
    {
        Rsa + ".1" => "SHA1withRSA",
        Rsa + ".2" => "SHA256withRSA",
        Rsa + ".3" => "SHA1withRSAandMGF1",
        Rsa + ".4" => "SHA256withRSAandMGF1",
        Rsa + ".5" => "SHA512withRSA",
        Rsa + ".6" => "SHA512withRSAandMGF1",
        Ecdsa + ".1" => "SHA1withPLAIN-ECDSA",
        Ecdsa + ".2" => "SHA224withPLAIN-ECDSA",
        Ecdsa + ".3" => "SHA256withPLAIN-ECDSA",
        Ecdsa + ".4" => "SHA384withPLAIN-ECDSA",
        Ecdsa + ".5" => "SHA512withPLAIN-ECDSA",
        _ => throw new NotSupportedException(T($"TA-Algorithmus {oid}", $"TA algorithm {oid}")),
    };

    public static string Name(string oid) => oid switch
    {
        Rsa + ".1" => "id-TA-RSA-v1-5-SHA-1",
        Rsa + ".2" => "id-TA-RSA-v1-5-SHA-256",
        Rsa + ".3" => "id-TA-RSA-PSS-SHA-1",
        Rsa + ".4" => "id-TA-RSA-PSS-SHA-256",
        Rsa + ".5" => "id-TA-RSA-v1-5-SHA-512",
        Rsa + ".6" => "id-TA-RSA-PSS-SHA-512",
        Ecdsa + ".1" => "id-TA-ECDSA-SHA-1",
        Ecdsa + ".2" => "id-TA-ECDSA-SHA-224",
        Ecdsa + ".3" => "id-TA-ECDSA-SHA-256",
        Ecdsa + ".4" => "id-TA-ECDSA-SHA-384",
        Ecdsa + ".5" => "id-TA-ECDSA-SHA-512",
        _ => oid,
    };
}
