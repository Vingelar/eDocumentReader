using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;

namespace eDocumentReader.Core.Crypto;

/// <summary>Standardized domain parameters, ICAO 9303-11 Table 12 / BSI TR-03110-3 A.2.1.1.</summary>
public static class StandardizedDomainParameters
{
    public static string Name(int id) => id switch
    {
        0 => "1024-bit MODP/160 (RFC 5114)",
        1 => "2048-bit MODP/224 (RFC 5114)",
        2 => "2048-bit MODP/256 (RFC 5114)",
        8 => "NIST P-192 (secp192r1)",
        9 => "brainpoolP192r1",
        10 => "NIST P-224 (secp224r1)",
        11 => "brainpoolP224r1",
        12 => "NIST P-256 (secp256r1)",
        13 => "brainpoolP256r1",
        14 => "brainpoolP320r1",
        15 => "NIST P-384 (secp384r1)",
        16 => "brainpoolP384r1",
        17 => "brainpoolP512r1",
        18 => "NIST P-521 (secp521r1)",
        _ => "RFU",
    };

    public static bool IsEc(int id) => id is >= 8 and <= 18;

    /// <summary>MODP groups with prime order subgroup, RFC 5114 sections 2.1–2.3 (IDs 0–2).</summary>
    public static DhDomain ModpGroup(int id)
    {
        var (p, g, q) = id switch
        {
            0 => (Rfc5114.G0P, Rfc5114.G0G, Rfc5114.G0Q),
            1 => (Rfc5114.G1P, Rfc5114.G1G, Rfc5114.G1Q),
            2 => (Rfc5114.G2P, Rfc5114.G2G, Rfc5114.G2Q),
            _ => throw new NotSupportedException(T($"Domain-Parameter-ID {id} ist RFU.", $"Domain parameter ID {id} is RFU.")),
        };
        return new DhDomain(new Org.BouncyCastle.Math.BigInteger(p, 16), new Org.BouncyCastle.Math.BigInteger(g, 16), new Org.BouncyCastle.Math.BigInteger(q, 16));
    }

    public static X9ECParameters Curve(int id)
    {
        var name = id switch
        {
            8 => "secp192r1",
            9 => "brainpoolP192r1",
            10 => "secp224r1",
            11 => "brainpoolP224r1",
            12 => "secp256r1",
            13 => "brainpoolP256r1",
            14 => "brainpoolP320r1",
            15 => "secp384r1",
            16 => "brainpoolP384r1",
            17 => "brainpoolP512r1",
            18 => "secp521r1",
            _ => throw new NotSupportedException(T($"Domain-Parameter-ID {id} ist keine elliptische Kurve oder RFU.", $"Domain parameter ID {id} is not an elliptic curve or RFU.")),
        };
        return CustomNamedCurves.GetByName(name) ?? ECNamedCurveTable.GetByName(name)
            ?? throw new NotSupportedException(T($"Kurve {name} nicht verfügbar.", $"Curve {name} not available."));
    }
}
