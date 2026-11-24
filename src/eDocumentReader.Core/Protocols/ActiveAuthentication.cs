using System.Security.Cryptography;
using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace eDocumentReader.Core.Protocols;

public sealed record ActiveAuthenticationResult(bool Valid, string Detail, byte[] Nonce, byte[] Signature);

/// <summary>Active Authentication according to ICAO 9303-11 6.1 (RSA: ISO/IEC 9796-2 scheme 1; ECDSA: TR-03111 plain format).</summary>
public static class ActiveAuthentication
{
    private const string Ref = "ICAO 9303-11 6.1";

    /// <summary>Parses EF.DG15 (tag '6F') → SubjectPublicKeyInfo.</summary>
    public static AsymmetricKeyParameter PublicKeyFromDg15(byte[] dg15)
    {
        var tlv = BerTlv.ParseSingle(dg15);
        return PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(tlv.Value)));
    }

    public static ActiveAuthenticationResult Perform(IApduChannel channel, AsymmetricKeyParameter publicKey, string? ecdsaSignatureOid = null, byte[]? nonce = null)
    {
        var log = channel.Logger;
        nonce ??= RandomNumberGenerator.GetBytes(8);
        log.Info(LogCategory.Protocol, $"Active Authentication ({(publicKey is RsaKeyParameters ? "RSA" : "ECDSA")})", null, Ref);
        log.Detail(LogCategory.Crypto, "RND.IFD", nonce, Ref);
        var response = channel.Transmit(new CommandApdu(0x00, 0x88, 0x00, 0x00, nonce, 256), "INTERNAL AUTHENTICATE (Active Authentication)");
        if (!response.Status.IsSuccess)
            throw new ProtocolException(T($"INTERNAL AUTHENTICATE abgelehnt: {response.Status} {response.Status.Description}", $"INTERNAL AUTHENTICATE rejected: {response.Status} {response.Status.Description}"), response.Status);
        log.Detail(LogCategory.Crypto, T("Signatur σ", "Signature σ"), response.Data, Ref);
        var result = Verify(publicKey, nonce, response.Data, ecdsaSignatureOid, log);
        if (result.Valid) log.Info(LogCategory.Protocol, T("Active Authentication erfolgreich: ", "Active Authentication successful: ") + result.Detail, null, Ref);
        else log.Error(LogCategory.Protocol, T("Active Authentication FEHLGESCHLAGEN: ", "Active Authentication FAILED: ") + result.Detail, null, Ref);
        return result;
    }

    public static ActiveAuthenticationResult Verify(AsymmetricKeyParameter publicKey, byte[] nonce, byte[] signature, string? ecdsaSignatureOid = null, Logger? log = null)
    {
        log ??= Logger.Null;
        return publicKey switch
        {
            RsaKeyParameters rsa => VerifyRsa(rsa, nonce, signature, log),
            ECPublicKeyParameters ec => VerifyEcdsa(ec, nonce, signature, ecdsaSignatureOid, log),
            _ => new ActiveAuthenticationResult(false, T($"Schlüsseltyp {publicKey.GetType().Name} nicht unterstützt.", $"Key type {publicKey.GetType().Name} not supported."), nonce, signature),
        };
    }

    private static ActiveAuthenticationResult VerifyRsa(RsaKeyParameters key, byte[] nonce, byte[] signature, Logger log)
    {
        var n = key.Modulus;
        var s = new BigInteger(1, signature);
        if (s.CompareTo(n) >= 0) return new(false, T("Signaturwert ≥ Modulus.", "Signature value ≥ modulus."), nonce, signature);
        var j = s.ModPow(key.Exponent, n);
        // ISO/IEC 9796-2: the representative ends with nibble 'C'; otherwise the signer returned min(σ, n-σ) (B.6 / alternative).
        if ((j.IntValue & 0x0F) != 0x0C) j = n.Subtract(j);
        var k = (n.BitLength + 7) / 8;
        var f = Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(k, j);
        // Leading zero bytes due to modulus bit length not multiple of 8
        var start = 0;
        while (start < f.Length && f[start] == 0) start++;
        f = f[start..];
        log.Detail(LogCategory.Crypto, "F = σ^e mod n", f, "ISO/IEC 9796-2");
        if ((f[0] & 0xC0) != 0x40) return new(false, T($"Header {f[0]:X2}: Bits 8..7 ≠ 01 (ISO/IEC 9796-2).", $"Header {f[0]:X2}: bits 8..7 ≠ 01 (ISO/IEC 9796-2)."), nonce, signature);
        var partialRecovery = (f[0] & 0x20) != 0;
        string hashName;
        int trailerLength;
        if (f[^1] == 0xBC) { hashName = "SHA-1"; trailerLength = 1; }
        else if (f[^1] == 0xCC)
        {
            trailerLength = 2;
            hashName = f[^2] switch { 0x33 => "SHA-1", 0x38 => "SHA-224", 0x34 => "SHA-256", 0x36 => "SHA-384", 0x35 => "SHA-512", _ => "" };
            if (hashName == "") return new(false, T($"Unbekannter Trailer {f[^2]:X2}CC (9303-11 6.1.2.2).", $"Unknown trailer {f[^2]:X2}CC (9303-11 6.1.2.2)."), nonce, signature);
        }
        else return new(false, T($"Ungültiger Trailer {f[^1]:X2}.", $"Invalid trailer {f[^1]:X2}."), nonce, signature);
        var digest = DigestUtilities.GetDigest(hashName);
        var hLen = digest.GetDigestSize();
        if (f.Length < 1 + hLen + trailerLength) return new(false, T("Signaturrepräsentant zu kurz.", "Signature representative too short."), nonce, signature);
        var d = f[^(hLen + trailerLength)..^trailerLength];
        var m1 = f[1..^(hLen + trailerLength)];
        // Header nibble: '6A' = partial recovery (M2 = RND.IFD not contained). Leading '4B…' padding bytes may precede M1 (B.4).
        byte[] mStar = partialRecovery ? [.. m1, .. nonce] : m1;
        var calc = DigestUtilities.CalculateDigest(hashName, mStar);
        log.Detail(LogCategory.Crypto, T("M1 (wiederhergestellt)", "M1 (recovered)"), m1, Ref);
        log.Detail(LogCategory.Crypto, T($"D (aus Signatur, {hashName})", $"D (from signature, {hashName})"), d, Ref);
        log.Detail(LogCategory.Crypto, "D* = H(M1 || RND.IFD)", calc, Ref);
        var ok = calc.AsSpan().SequenceEqual(d);
        if (!partialRecovery) log.Warning(LogCategory.Protocol, T("Header zeigt vollständige Wiederherstellung an – erwartet ist '6A' (partielle Wiederherstellung).", "Header indicates full recovery – '6A' (partial recovery) is expected."), null, Ref);
        return new(ok, ok ? T($"RSA {n.BitLength} Bit, {hashName}, Trailer-Option {trailerLength}", $"RSA {n.BitLength} bit, {hashName}, trailer option {trailerLength}") : T("Hashwert stimmt nicht überein.", "Hash value does not match."), nonce, signature);
    }

    private static ActiveAuthenticationResult VerifyEcdsa(ECPublicKeyParameters key, byte[] nonce, byte[] signature, string? signatureOid, Logger log)
    {
        // Hash algorithm from ActiveAuthenticationInfo in DG14 (9303-11 9.2.10); default must not be SHA-1 for ECDSA.
        var hash = signatureOid switch
        {
            // ecdsa-plain-signatures, BSI TR-03111 5.2.1 (bsi-de 1 1 4 1 n) – the OIDs ICAO 9303-11 9.2.10 refers to
            "0.4.0.127.0.7.1.1.4.1.1" => "SHA-1",
            "0.4.0.127.0.7.1.1.4.1.2" => "SHA-224",
            "0.4.0.127.0.7.1.1.4.1.3" => "SHA-256",
            "0.4.0.127.0.7.1.1.4.1.4" => "SHA-384",
            "0.4.0.127.0.7.1.1.4.1.5" => "SHA-512",
            "1.2.840.10045.4.3.1" => "SHA-224",
            "1.2.840.10045.4.3.2" => "SHA-256",
            "1.2.840.10045.4.3.3" => "SHA-384",
            "1.2.840.10045.4.3.4" => "SHA-512",
            "1.2.840.10045.4.1" => "SHA-1",
            null => null,
            _ => null,
        };
        if (hash == null) return new(false, T($"ECDSA-Signaturalgorithmus {(signatureOid ?? "fehlt (ActiveAuthenticationInfo in DG14 erforderlich)")}", $"ECDSA signature algorithm {(signatureOid ?? "missing (ActiveAuthenticationInfo in DG14 required)")}"), nonce, signature);
        if (hash == "SHA-1") log.Warning(LogCategory.Protocol, T("SHA-1 ist für ECDSA-AA nicht zulässig (9303-11 6.1.2.3).", "SHA-1 is not allowed for ECDSA AA (9303-11 6.1.2.3)."), null, Ref);
        var signer = SignerUtilities.GetSigner(hash.Replace("-", "") + "withPLAIN-ECDSA");
        signer.Init(false, key);
        signer.BlockUpdate(nonce, 0, nonce.Length);
        var ok = signer.VerifySignature(signature);
        return new(ok, ok ? T($"ECDSA {key.Parameters.N.BitLength} Bit, {hash}", $"ECDSA {key.Parameters.N.BitLength} bit, {hash}") : T("ECDSA-Signatur ungültig.", "ECDSA signature invalid."), nonce, signature);
    }

    /// <summary>Card side (simulator / tests): RSA ISO/IEC 9796-2 scheme 1 signature with partial recovery (B.6).</summary>
    public static byte[] SignRsa(RsaKeyParameters privateKey, byte[] nonce, string hashName = "SHA-1")
    {
        var digest = DigestUtilities.GetDigest(hashName);
        var hLen = digest.GetDigestSize();
        byte[] trailer = hashName switch { "SHA-1" => [0xBC], "SHA-224" => [0x38, 0xCC], "SHA-256" => [0x34, 0xCC], "SHA-384" => [0x36, 0xCC], _ => [0x35, 0xCC] };
        var kBytes = (privateKey.Modulus.BitLength - 1) / 8 + 1;
        var m1Length = kBytes - 1 - hLen - trailer.Length;
        if (privateKey.Modulus.BitLength % 8 != 0 && privateKey.Modulus.BitLength % 8 < 4) m1Length--;
        var m1 = RandomNumberGenerator.GetBytes(m1Length);
        var h = DigestUtilities.CalculateDigest(hashName, [.. m1, .. nonce]);
        byte[] f = [0x6A, .. m1, .. h, .. trailer];
        var sig = new BigInteger(1, f).ModPow(privateKey.Exponent, privateKey.Modulus);
        var alt = privateKey.Modulus.Subtract(sig);
        if (alt.CompareTo(sig) < 0) sig = alt;
        return Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(kBytes, sig);
    }

    public static string Describe(AsymmetricKeyParameter key) => key switch
    {
        RsaKeyParameters r => T($"RSA {r.Modulus.BitLength} Bit, e={Hex.Compact(r.Exponent.ToByteArrayUnsigned())}", $"RSA {r.Modulus.BitLength} bit, e={Hex.Compact(r.Exponent.ToByteArrayUnsigned())}"),
        ECPublicKeyParameters e => T($"EC {e.Parameters.N.BitLength} Bit", $"EC {e.Parameters.N.BitLength} bit"),
        _ => key.GetType().Name,
    };
}
