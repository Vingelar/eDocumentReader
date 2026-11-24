using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace eDocumentReader.Core.Crypto;

/// <summary>Ephemeral key pair on a key agreement domain (DH or ECDH). Public key encoded as in ICAO 9303-11 9.4.5.</summary>
public sealed record EphemeralKeyPair(BigInteger PrivateKey, byte[] PublicKey);

/// <summary>
/// Domain parameters for DH / ECDH key agreement (ICAO 9303-11 9.4 / 9.5, BSI TR-03110-3 A.2).
/// Public keys: ECDH = uncompressed point; DH = unsigned integer (9303-11 9.4.5).
/// Shared secret: ECDH = x-coordinate (FE2OS), DH = Z as octet string of length |p| (9303-11 9.6).
/// </summary>
public abstract class KeyAgreementDomain
{
    public abstract bool IsEc { get; }
    public abstract EphemeralKeyPair Generate(BigInteger? privateKey = null);
    public abstract byte[] Agree(BigInteger privateKey, byte[] peerPublicKey);
    public abstract void Validate(byte[] publicKey);
    /// <summary>Compressed representation Comp(PK) (TR-03110-3 A.2.2.3): ECDH x-coordinate, DH SHA-1(PK).</summary>
    public abstract byte[] Compress(byte[] publicKey);

    /// <summary>Parses AlgorithmIdentifier parameters: standardized domain parameter id (INTEGER) or explicit parameters.</summary>
    public static KeyAgreementDomain FromParameters(Asn1Encodable? parameters, bool ec)
    {
        if (parameters is DerInteger id) return Standardized(id.IntValueExact);
        if (parameters == null) throw new NotSupportedException("Domain-Parameter fehlen.");
        var seq = Asn1Sequence.GetInstance(parameters);
        if (ec) return new EcDomain(X9ECParameters.GetInstance(seq));
        // DH: DomainParameters ::= SEQUENCE { p, g, q, j OPTIONAL, ... } (ANSI X9.42) or PKCS#3 DHParameter (p, g, l)
        var p = DerInteger.GetInstance(seq[0]).Value;
        var g = DerInteger.GetInstance(seq[1]).Value;
        var q = seq.Count > 2 && seq[2] is DerInteger qi && qi.Value.BitLength > 32 ? qi.Value : null;
        return new DhDomain(p, g, q);
    }

    public static KeyAgreementDomain Standardized(int id) => StandardizedDomainParameters.IsEc(id)
        ? new EcDomain(StandardizedDomainParameters.Curve(id))
        : StandardizedDomainParameters.ModpGroup(id);

    public static byte[] FixedLength(BigInteger value, int length)
    {
        var raw = value.ToByteArrayUnsigned();
        if (raw.Length == length) return raw;
        if (raw.Length > length) throw new CryptographicException("Wert länger als Feldgröße.");
        var r = new byte[length];
        raw.CopyTo(r, length - raw.Length);
        return r;
    }

    protected static BigInteger RandomBelow(BigInteger n)
    {
        var random = new SecureRandom();
        BigInteger k;
        do k = new BigInteger(n.BitLength, random); while (k.SignValue <= 0 || k.CompareTo(n) >= 0);
        return k;
    }
}

public sealed class EcDomain(X9ECParameters parameters) : KeyAgreementDomain
{
    public X9ECParameters Parameters { get; } = parameters;
    public ECPoint Generator { get; init; } = parameters.G;
    public override bool IsEc => true;
    public int FieldLength => (Parameters.Curve.FieldSize + 7) / 8;

    public EcDomain WithGenerator(ECPoint g) => new(Parameters) { Generator = g };

    public override EphemeralKeyPair Generate(BigInteger? privateKey = null)
    {
        var sk = privateKey ?? RandomBelow(Parameters.N);
        return new EphemeralKeyPair(sk, Generator.Multiply(sk).Normalize().GetEncoded(false));
    }

    public ECPoint Decode(byte[] encoded)
    {
        var p = Parameters.Curve.DecodePoint(encoded).Normalize();
        if (p.IsInfinity || !p.IsValid()) throw new CryptographicException("Öffentlicher Schlüssel liegt nicht auf der Kurve.");
        return p;
    }

    public override void Validate(byte[] publicKey) => Decode(publicKey);

    public override byte[] Agree(BigInteger privateKey, byte[] peerPublicKey)
    {
        var s = Decode(peerPublicKey).Multiply(privateKey).Normalize();
        if (s.IsInfinity) throw new CryptographicException("Gemeinsames Geheimnis ist der Punkt im Unendlichen.");
        return FixedLength(s.AffineXCoord.ToBigInteger(), FieldLength);
    }

    public override byte[] Compress(byte[] publicKey) => FixedLength(Decode(publicKey).AffineXCoord.ToBigInteger(), FieldLength);
}

public sealed class DhDomain(BigInteger p, BigInteger g, BigInteger? q) : KeyAgreementDomain
{
    public BigInteger P { get; } = p;
    public BigInteger G { get; } = g;
    public BigInteger? Q { get; } = q;
    public override bool IsEc => false;
    public int Length => (P.BitLength + 7) / 8;

    public DhDomain WithGenerator(BigInteger generator) => new(P, generator, Q);

    public override EphemeralKeyPair Generate(BigInteger? privateKey = null)
    {
        var sk = privateKey ?? RandomBelow(Q ?? P.Subtract(BigInteger.Two));
        return new EphemeralKeyPair(sk, FixedLength(G.ModPow(sk, P), Length));
    }

    public override void Validate(byte[] publicKey)
    {
        var y = new BigInteger(1, publicKey);
        if (y.CompareTo(BigInteger.One) <= 0 || y.CompareTo(P.Subtract(BigInteger.One)) >= 0)
            throw new CryptographicException("DH-Schlüssel außerhalb ]1, p-1[.");
        if (Q != null && !y.ModPow(Q, P).Equals(BigInteger.One))
            throw new CryptographicException("DH-Schlüssel liegt nicht in der Untergruppe der Ordnung q.");
    }

    public override byte[] Agree(BigInteger privateKey, byte[] peerPublicKey)
    {
        Validate(peerPublicKey);
        return FixedLength(new BigInteger(1, peerPublicKey).ModPow(privateKey, P), Length);
    }

    public override byte[] Compress(byte[] publicKey) => SHA1.HashData(publicKey);
}
