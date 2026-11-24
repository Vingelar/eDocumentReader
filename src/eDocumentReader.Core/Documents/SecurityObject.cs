using System.Security.Cryptography;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;

namespace eDocumentReader.Core.Documents;

public sealed record DataGroupHash(int DataGroup, byte[] Hash);

public sealed record HashCheck(int DataGroup, bool? Match, byte[] Expected, byte[]? Actual);

/// <summary>
/// Document Security Object EF.SOD (ICAO 9303-10 4.6.2, 9303-11 5.1) – CMS SignedData with LDSSecurityObject
/// (eContentType id-icao-mrtd-security-ldsSecurityObject 2.23.136.1.1.1).
/// </summary>
public sealed class SecurityObject
{
    public const string LdsSecurityObjectOid = "2.23.136.1.1.1";
    public CmsSignedData SignedData { get; }
    public string ContentType { get; }
    public int Version { get; }
    public string HashAlgorithmOid { get; }
    public List<DataGroupHash> Hashes { get; } = [];
    public string? LdsVersion { get; }
    public string? UnicodeVersion { get; }
    public List<X509Certificate> Certificates { get; } = [];
    public List<string> Findings { get; } = [];

    public SecurityObject(byte[] efSod)
    {
        var outer = BerTlv.ParseSingle(efSod);
        if (outer.Tag != 0x77) Findings.Add($"EF.SOD beginnt mit Tag {outer.TagHex} statt '77' (ICAO 9303-10 Table 34).");
        SignedData = new CmsSignedData(outer.Value);
        ContentType = SignedData.SignedContentType.Id;
        if (ContentType != LdsSecurityObjectOid) Findings.Add($"eContentType {ContentType} ≠ {LdsSecurityObjectOid}.");
        var sd = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(SignedData.ContentInfo.Content);
        var content = Asn1OctetString.GetInstance(sd.EncapContentInfo.Content).GetOctets();
        var lds = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(content));
        Version = DerInteger.GetInstance(lds[0]).IntValueExact;
        HashAlgorithmOid = DerObjectIdentifier.GetInstance(Asn1Sequence.GetInstance(lds[1])[0]).Id;
        foreach (var e in Asn1Sequence.GetInstance(lds[2]))
        {
            var dgh = Asn1Sequence.GetInstance(e);
            Hashes.Add(new DataGroupHash(DerInteger.GetInstance(dgh[0]).IntValueExact, Asn1OctetString.GetInstance(dgh[1]).GetOctets()));
        }
        if (lds.Count > 3)
        {
            var info = Asn1Sequence.GetInstance(lds[3]);
            LdsVersion = info[0].ToString();
            UnicodeVersion = info[1].ToString();
            if (Version != 1) Findings.Add($"LDSSecurityObject mit ldsVersionInfo muss Version 1 haben (ist {Version}).");
        }
        else if (Version != 0) Findings.Add($"LDSSecurityObject ohne ldsVersionInfo muss Version 0 haben (ist {Version}).");
        foreach (var c in SignedData.GetCertificates().EnumerateMatches(null)) Certificates.Add(c);
        if (Certificates.Count == 0) Findings.Add("Kein Document-Signer-Zertifikat im SOD enthalten (ICAO 9303-11 5.1: DS-Zertifikat SOLL enthalten sein).");
    }

    public HashAlgorithmName HashName => HashAlgorithmOid switch
    {
        "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
        "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
        "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
        "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
        "2.16.840.1.101.3.4.2.4" => new HashAlgorithmName("SHA224"),
        _ => throw new NotSupportedException($"Hashalgorithmus {HashAlgorithmOid}"),
    };

    public byte[] Hash(byte[] data)
    {
        if (HashName.Name == "SHA224") return Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("SHA-224", data);
        using var h = IncrementalHash.CreateHash(HashName);
        h.AppendData(data);
        return h.GetHashAndReset();
    }

    public HashCheck CheckDataGroup(int dg, byte[]? content)
    {
        var expected = Hashes.FirstOrDefault(h => h.DataGroup == dg)?.Hash;
        if (expected == null) return new HashCheck(dg, null, [], content == null ? null : Hash(content));
        if (content == null) return new HashCheck(dg, null, expected, null);
        var actual = Hash(content);
        return new HashCheck(dg, actual.AsSpan().SequenceEqual(expected), expected, actual);
    }

    /// <summary>Verifies the CMS signature with the embedded Document Signer certificate (no chain validation).</summary>
    public (bool Valid, X509Certificate? Signer, string Detail) VerifySignature()
    {
        var signers = SignedData.GetSignerInfos().GetSigners().ToList();
        if (signers.Count != 1) return (false, null, $"{signers.Count} SignerInfos (genau 1 erwartet, ICAO 9303-10 4.6.2.2).");
        var signer = signers[0];
        var cert = Certificates.FirstOrDefault(c => signer.SignerID.Match(c));
        if (cert == null) return (false, null, "Signer-Zertifikat nicht im SOD gefunden – CSCA/DS aus PKI-Speicher erforderlich.");
        try
        {
            var ok = signer.Verify(cert);
            return (ok, cert, ok ? $"Signatur gültig ({Oids.Name(signer.SignatureAlgorithm.Algorithm.Id)}, Digest {signer.DigestAlgorithmID.Algorithm.Id})" : "Signatur UNGÜLTIG");
        }
        catch (Exception ex)
        {
            return (false, cert, $"Signaturprüfung fehlgeschlagen: {ex.Message}");
        }
    }

    public void Log(Logger log)
    {
        log.Info(LogCategory.Parser, $"EF.SOD: LDSSecurityObject v{Version}, Hash {HashName.Name}, {Hashes.Count} DG-Hashes{(LdsVersion != null ? $", LDS {LdsVersion}, Unicode {UnicodeVersion}" : "")}", null, "ICAO 9303-10 4.6.2");
        foreach (var h in Hashes) log.Detail(LogCategory.Parser, $"SOD Hash DG{h.DataGroup}", h.Hash);
        foreach (var f in Findings) log.Warning(LogCategory.Parser, f);
    }

    public static string Describe(X509Certificate c) =>
        $"Subject: {c.SubjectDN}{Environment.NewLine}Issuer: {c.IssuerDN}{Environment.NewLine}Serial: {Hex.Compact(c.SerialNumber.ToByteArrayUnsigned())}{Environment.NewLine}Gültig: {c.NotBefore:yyyy-MM-dd} – {c.NotAfter:yyyy-MM-dd}";
}
