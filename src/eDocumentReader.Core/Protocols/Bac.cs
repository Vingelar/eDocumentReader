using System.Security.Cryptography;
using System.Text;
using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Protocols;

public sealed class ProtocolException(string message, StatusWord? status = null) : Exception(message)
{
    public StatusWord? Status { get; } = status;
}

/// <summary>
/// Basic Access Control according to ICAO 9303-11 clause 4.3 (key derivation 9.7.2, SSC 9.8.6.3).
/// The same mechanism is used by BAP configuration 1 (ISO/IEC 18013-3 8.2.3) with a different key seed input.
/// </summary>
public static class Bac
{
    private const string Ref = "ICAO 9303-11 4.3";

    /// <summary>Kseed = first 16 bytes of SHA-1(MRZ_information) (9303-11 9.7.2).</summary>
    public static byte[] KeySeed(string mrzInformation) => SHA1.HashData(Encoding.ASCII.GetBytes(mrzInformation))[..16];

    public static (byte[] KEnc, byte[] KMac) DocumentKeys(string mrzInformation)
    {
        var seed = KeySeed(mrzInformation);
        return (Kdf.Derive(seed, Kdf.CounterEnc, SessionKeyType.DesEde), Kdf.Derive(seed, Kdf.CounterMac, SessionKeyType.DesEde));
    }

    /// <summary>
    /// Performs BAC. Optional <paramref name="rndIfd"/> / <paramref name="kIfd"/> allow deterministic runs (tests).
    /// </summary>
    public static SecureChannel Perform(IApduChannel channel, string mrzInformation, byte[]? rndIfd = null, byte[]? kIfd = null)
    {
        var log = channel.Logger;
        log.Info(LogCategory.Protocol, "BAC: Start", null, Ref);
        log.Detail(LogCategory.Crypto, $"MRZ_information = {mrzInformation}", null, "9303-11 9.7.2");
        var seed = KeySeed(mrzInformation);
        log.Detail(LogCategory.Crypto, "Kseed = SHA-1(MRZ_information)[0..15]", seed, "9303-11 9.7.2");
        var (kEnc, kMac) = DocumentKeys(mrzInformation);
        log.Detail(LogCategory.Crypto, "KEnc = KDF(Kseed, 1)", kEnc, "9303-11 9.7.1");
        log.Detail(LogCategory.Crypto, "KMAC = KDF(Kseed, 2)", kMac, "9303-11 9.7.1");

        var challenge = channel.Transmit(new CommandApdu(0x00, 0x84, 0x00, 0x00, null, 8), "GET CHALLENGE");
        if (!challenge.Status.IsSuccess || challenge.Data.Length != 8)
            throw new ProtocolException($"GET CHALLENGE fehlgeschlagen: {challenge.Status} {challenge.Status.Description}", challenge.Status);
        var rndIc = challenge.Data;
        rndIfd ??= RandomNumberGenerator.GetBytes(8);
        kIfd ??= RandomNumberGenerator.GetBytes(16);
        log.Detail(LogCategory.Crypto, "RND.IC", rndIc, Ref);
        log.Detail(LogCategory.Crypto, "RND.IFD", rndIfd, Ref);
        log.Detail(LogCategory.Crypto, "K.IFD", kIfd, Ref);

        byte[] s = [.. rndIfd, .. rndIc, .. kIfd];
        var eIfd = SymmetricCrypto.CbcEncrypt(CipherAlgorithm.DesEde, kEnc, new byte[8], s);
        var mIfd = SymmetricCrypto.RetailMac(kMac, SymmetricCrypto.Pad(eIfd, 8));
        log.Detail(LogCategory.Crypto, "S = RND.IFD || RND.IC || K.IFD", s, Ref);
        log.Detail(LogCategory.Crypto, "E.IFD = E(KEnc, S)", eIfd, Ref);
        log.Detail(LogCategory.Crypto, "M.IFD = MAC(KMAC, E.IFD)", mIfd, Ref);

        var response = channel.Transmit(new CommandApdu(0x00, 0x82, 0x00, 0x00, [.. eIfd, .. mIfd], 0x28), "EXTERNAL AUTHENTICATE (BAC)");
        if (!response.Status.IsSuccess)
            throw new ProtocolException($"BAC: EXTERNAL AUTHENTICATE abgelehnt: {response.Status} {response.Status.Description} (falsche MRZ-Daten?)", response.Status);
        if (response.Data.Length != 40) throw new ProtocolException($"BAC: Antwortlänge {response.Data.Length} ≠ 40.");

        var eIc = response.Data[..32];
        var mIc = response.Data[32..];
        var expectedMac = SymmetricCrypto.RetailMac(kMac, SymmetricCrypto.Pad(eIc, 8));
        if (!expectedMac.AsSpan().SequenceEqual(mIc))
            throw new ProtocolException($"BAC: M.IC ungültig (erhalten {Hex.Compact(mIc)}, berechnet {Hex.Compact(expectedMac)}).");
        var r = SymmetricCrypto.CbcDecrypt(CipherAlgorithm.DesEde, kEnc, new byte[8], eIc);
        log.Detail(LogCategory.Crypto, "R = D(KEnc, E.IC) = RND.IC || RND.IFD || K.IC", r, Ref);
        if (!r.AsSpan(0, 8).SequenceEqual(rndIc)) throw new ProtocolException("BAC: RND.IC in der Antwort stimmt nicht.");
        if (!r.AsSpan(8, 8).SequenceEqual(rndIfd)) throw new ProtocolException("BAC: RND.IFD in der Antwort stimmt nicht.");
        var kIc = r[16..32];

        var sessionSeed = new byte[16];
        for (var i = 0; i < 16; i++) sessionSeed[i] = (byte)(kIfd[i] ^ kIc[i]);
        var ksEnc = Kdf.Derive(sessionSeed, Kdf.CounterEnc, SessionKeyType.DesEde);
        var ksMac = Kdf.Derive(sessionSeed, Kdf.CounterMac, SessionKeyType.DesEde);
        byte[] ssc = [.. rndIc[4..], .. rndIfd[4..]];
        log.Detail(LogCategory.Crypto, "Kseed(Sitzung) = K.IFD ⊕ K.IC", sessionSeed, Ref);
        log.Detail(LogCategory.Crypto, "KSEnc", ksEnc, "9303-11 9.7.1");
        log.Detail(LogCategory.Crypto, "KSMAC", ksMac, "9303-11 9.7.1");
        log.Detail(LogCategory.Crypto, "SSC = RND.IC[4..7] || RND.IFD[4..7]", ssc, "9303-11 9.8.6.3");
        log.Info(LogCategory.Protocol, "BAC erfolgreich – Secure Messaging (3DES) aktiv", null, Ref);
        return new SecureChannel(channel, SessionKeyType.DesEde, ksEnc, ksMac, ssc, "BAC");
    }
}
