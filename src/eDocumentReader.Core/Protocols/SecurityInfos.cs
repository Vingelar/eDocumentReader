using Org.BouncyCastle.Asn1;
using eDocumentReader.Core.Crypto;

namespace eDocumentReader.Core.Protocols;

public enum PaceMapping { Generic, Integrated, ChipAuthentication }
public enum KeyAgreement { Dh, Ecdh }

public abstract record SecurityInfo(string Oid, Asn1Encodable Raw)
{
    public virtual string Description => Oids.Name(Oid);
}

public sealed record PaceInfo(string Oid, int Version, int? ParameterId, Asn1Encodable Raw) : SecurityInfo(Oid, Raw)
{
    public PaceAlgorithm Algorithm { get; } = PaceAlgorithm.FromOid(Oid) ?? throw new NotSupportedException($"Unbekannte PACE-OID {Oid}");
    public override string Description => $"PACEInfo {Oids.Name(Oid)}, Version {Version}, Domain-Parameter {(ParameterId is { } p ? $"{p} ({StandardizedDomainParameters.Name(p)})" : "explizit")}";
}

public sealed record PaceDomainParameterInfo(string Oid, Asn1Encodable DomainParameter, int? ParameterId, Asn1Encodable Raw) : SecurityInfo(Oid, Raw);

public sealed record ChipAuthenticationInfo(string Oid, int Version, int? KeyId, Asn1Encodable Raw) : SecurityInfo(Oid, Raw)
{
    public override string Description => $"ChipAuthenticationInfo {Oids.Name(Oid)}, Version {Version}{(KeyId is { } k ? $", KeyID {k}" : "")}";
}

public sealed record ChipAuthenticationPublicKeyInfo(string Oid, Asn1Encodable PublicKey, int? KeyId, Asn1Encodable Raw) : SecurityInfo(Oid, Raw)
{
    public override string Description => $"ChipAuthenticationPublicKeyInfo {Oids.Name(Oid)}{(KeyId is { } k ? $", KeyID {k}" : "")}";
}

public sealed record TerminalAuthenticationInfo(string Oid, int Version, Asn1Encodable Raw) : SecurityInfo(Oid, Raw)
{
    public override string Description => $"TerminalAuthenticationInfo, Version {Version}";
}

public sealed record ActiveAuthenticationInfo(string Oid, int Version, string SignatureAlgorithm, Asn1Encodable Raw) : SecurityInfo(Oid, Raw)
{
    public override string Description => $"ActiveAuthenticationInfo, Signaturalgorithmus {Oids.Name(SignatureAlgorithm)}";
}

public sealed record UnknownSecurityInfo(string Oid, Asn1Encodable Raw) : SecurityInfo(Oid, Raw);

public sealed record PaceAlgorithm(string Oid, KeyAgreement KeyAgreement, PaceMapping Mapping, SessionKeyType KeyType)
{
    public static PaceAlgorithm? FromOid(string oid)
    {
        if (!oid.StartsWith(Oids.IdPace + ".", StringComparison.Ordinal)) return null;
        var parts = oid[(Oids.IdPace.Length + 1)..].Split('.');
        if (parts.Length != 2) return null;
        (KeyAgreement, PaceMapping)? km = parts[0] switch
        {
            "1" => (KeyAgreement.Dh, PaceMapping.Generic),
            "2" => (KeyAgreement.Ecdh, PaceMapping.Generic),
            "3" => (KeyAgreement.Dh, PaceMapping.Integrated),
            "4" => (KeyAgreement.Ecdh, PaceMapping.Integrated),
            "6" => (KeyAgreement.Ecdh, PaceMapping.ChipAuthentication),
            _ => null,
        };
        SessionKeyType? kt = parts[1] switch { "1" => SessionKeyType.DesEde, "2" => SessionKeyType.Aes128, "3" => SessionKeyType.Aes192, "4" => SessionKeyType.Aes256, _ => null };
        return km is { } k && kt is { } t ? new PaceAlgorithm(oid, k.Item1, k.Item2, t) : null;
    }
}

/// <summary>SecurityInfos (EF.CardAccess, EF.DG14, EF.CardSecurity) according to ICAO 9303-11 9.2 / TR-03110-3 A.1.</summary>
public static class SecurityInfos
{
    public static List<SecurityInfo> Parse(byte[] encoded)
    {
        var result = new List<SecurityInfo>();
        var set = Asn1Set.GetInstance(Asn1Object.FromByteArray(encoded));
        foreach (var element in set)
        {
            var seq = Asn1Sequence.GetInstance(element);
            var oid = DerObjectIdentifier.GetInstance(seq[0]).Id;
            result.Add(ParseOne(oid, seq));
        }
        return result;
    }

    private static int? OptInt(Asn1Sequence seq, int index) => seq.Count > index && seq[index] is DerInteger i ? i.IntValueExact : null;

    private static SecurityInfo ParseOne(string oid, Asn1Sequence seq)
    {
        if (oid.StartsWith(Oids.IdPace + ".", StringComparison.Ordinal) && PaceAlgorithm.FromOid(oid) != null)
            return new PaceInfo(oid, DerInteger.GetInstance(seq[1]).IntValueExact, OptInt(seq, 2), seq);
        if (oid is Oids.IdPaceDhGm or Oids.IdPaceEcdhGm or Oids.IdPaceDhIm or Oids.IdPaceEcdhIm or Oids.IdPaceEcdhCam)
            return new PaceDomainParameterInfo(oid, seq[1], OptInt(seq, 2), seq);
        if (oid.StartsWith(Oids.IdPkDh, StringComparison.Ordinal) || oid.StartsWith(Oids.IdPkEcdh, StringComparison.Ordinal))
            return new ChipAuthenticationPublicKeyInfo(oid, seq[1], OptInt(seq, 2), seq);
        if (oid.StartsWith(Oids.IdCa + ".", StringComparison.Ordinal))
            return new ChipAuthenticationInfo(oid, DerInteger.GetInstance(seq[1]).IntValueExact, OptInt(seq, 2), seq);
        if (oid == Oids.IdTa)
            return new TerminalAuthenticationInfo(oid, DerInteger.GetInstance(seq[1]).IntValueExact, seq);
        if (oid == Oids.IdAa)
            return new ActiveAuthenticationInfo(oid, DerInteger.GetInstance(seq[1]).IntValueExact, DerObjectIdentifier.GetInstance(seq[2]).Id, seq);
        return new UnknownSecurityInfo(oid, seq);
    }
}

public static class Oids
{
    public const string BsiDe = "0.4.0.127.0.7";
    public const string IdPk = BsiDe + ".2.2.1";
    public const string IdPkDh = IdPk + ".1";
    public const string IdPkEcdh = IdPk + ".2";
    public const string IdTa = BsiDe + ".2.2.2";
    public const string IdCa = BsiDe + ".2.2.3";
    public const string IdPace = BsiDe + ".2.2.4";
    public const string IdPaceDhGm = IdPace + ".1";
    public const string IdPaceEcdhGm = IdPace + ".2";
    public const string IdPaceDhIm = IdPace + ".3";
    public const string IdPaceEcdhIm = IdPace + ".4";
    public const string IdPaceEcdhCam = IdPace + ".6";
    public const string IdRi = BsiDe + ".2.2.5";
    public const string IdAa = "2.23.136.1.1.5";
    public const string EcPublicKey = "1.2.840.10045.2.1";
    public const string DhPublicNumber = "1.2.840.10046.2.1";

    private static readonly string[] Ciphers = ["", "3DES-CBC-CBC", "AES-CBC-CMAC-128", "AES-CBC-CMAC-192", "AES-CBC-CMAC-256"];

    public static string Name(string oid)
    {
        if (PaceAlgorithm.FromOid(oid) is { } p)
            return $"id-PACE-{(p.KeyAgreement == KeyAgreement.Ecdh ? "ECDH" : "DH")}-{p.Mapping switch { PaceMapping.Generic => "GM", PaceMapping.Integrated => "IM", _ => "CAM" }}-{Ciphers[(int)p.KeyType + 1]}";
        if (oid.StartsWith(IdCa + ".", StringComparison.Ordinal))
        {
            var rest = oid[(IdCa.Length + 1)..].Split('.');
            var ka = rest[0] == "1" ? "DH" : "ECDH";
            return rest.Length == 2 && int.TryParse(rest[1], out var c) && c is >= 1 and <= 4 ? $"id-CA-{ka}-{Ciphers[c]}" : $"id-CA-{ka}";
        }
        return oid switch
        {
            IdTa => "id-TA",
            IdAa => "id-AA",
            IdPkDh => "id-PK-DH",
            IdPkEcdh => "id-PK-ECDH",
            EcPublicKey => "ecPublicKey",
            DhPublicNumber => "dhpublicnumber",
            "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
            "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224",
            "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
            "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
            "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
            _ => oid,
        };
    }
}
