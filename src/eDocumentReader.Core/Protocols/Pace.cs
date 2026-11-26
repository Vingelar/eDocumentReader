using System.Security.Cryptography;
using System.Text;
using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace eDocumentReader.Core.Protocols;

/// <summary>Password reference for MSE:Set AT, ICAO 9303-11 Table 9 (TR-03110-3 D.2.1.1).</summary>
public enum PacePasswordType : byte { Mrz = 1, Can = 2, Pin = 3, Puk = 4 }

public sealed record PacePassword(PacePasswordType Type, string Value)
{
    /// <summary>IDL input string (ISO/IEC 18013-3 8.7, Amd.1 C.2.1): reference 01 like the MRZ, but K = KDF(input string) without SHA-1.</summary>
    public bool IsIdlInputString { get; init; }

    public static PacePassword FromMrz(string mrzInformation) => new(PacePasswordType.Mrz, mrzInformation);
    public static PacePassword FromCan(string can) => new(PacePasswordType.Can, can);
    public static PacePassword FromIdlInputString(string inputString) => new(PacePasswordType.Mrz, inputString) { IsIdlInputString = true };

    /// <summary>
    /// f(π): SHA-1(MRZ_information) for the MRZ (9303-11 4.4.4 / 9.7.3); the ISO 8859-1 encoding for the CAN and for
    /// the IDL input string (ISO/IEC 18013-3 8.7, Amd.1 C.2.1).
    /// </summary>
    public byte[] Encode() => Type == PacePasswordType.Mrz && !IsIdlInputString
        ? SHA1.HashData(Encoding.ASCII.GetBytes(Value))
        : Encoding.Latin1.GetBytes(Value);

    public string Description => IsIdlInputString ? T("Mrz (IDL-Input-String, ISO/IEC 18013-3 8.7)", "Mrz (IDL input string, ISO/IEC 18013-3 8.7)") : Type.ToString();
}

/// <summary>Deterministic values for tests (ICAO 9303-11 Appendix G).</summary>
public sealed record PaceTestValues(BigInteger MapPrivateKey, BigInteger EphemeralPrivateKey);

public sealed record PaceResult(SecureChannel Channel, PaceInfo Info, byte[] ChipEphemeralPublicKey, byte[]? EncryptedChipAuthenticationData)
{
    /// <summary>PK_Map,IC of the mapping step (needed for the PACE-CAM check PK_Map,IC = CA_IC · PK_IC).</summary>
    public byte[]? ChipMappingPublicKey { get; init; }
    /// <summary>PACE-CAM only: CA_IC = D(KS_Enc, A_IC) without padding (ICAO 9303-11 4.4.3.5).</summary>
    public byte[]? ChipAuthenticationData { get; init; }
    public bool ChipAuthenticationMapping => Info.Algorithm.Mapping == PaceMapping.ChipAuthentication;

    /// <summary>Comp(PK_eph,PICC) – ID_PICC for Terminal Authentication v1 with dynamic binding (TR-03110-1 3.5).</summary>
    public required byte[] CompressedChipEphemeralKey { get; init; }
    public required byte[] CompressedTerminalEphemeralKey { get; init; }
}

/// <summary>
/// PACE according to ICAO 9303-11 clause 4.4 (APDUs 4.4.4, mapping 4.4.3.3): ECDH with generic mapping and with
/// Chip Authentication Mapping (4.4.3.3.3; the terminal side of the mapping equals GM, plus A_IC in step 4).
/// </summary>
public static class Pace
{
    private const string Ref = "ICAO 9303-11 4.4";

    public static PaceResult Perform(IApduChannel channel, PaceInfo info, PacePassword password, bool includeParameterId = false, PaceTestValues? test = null)
    {
        var log = channel.Logger;
        var alg = info.Algorithm;
        log.Info(LogCategory.Protocol, T($"PACE: Start mit {info.Description}, Passwort {password.Description}", $"PACE: start with {info.Description}, password {password.Description}"), null, Ref);
        if (alg.KeyAgreement != KeyAgreement.Ecdh || alg.Mapping is not (PaceMapping.Generic or PaceMapping.ChipAuthentication)
            || (alg.Mapping == PaceMapping.ChipAuthentication && alg.KeyType == SessionKeyType.DesEde))
            throw new NotSupportedException(T($"PACE-Variante {Oids.Name(info.Oid)} ist noch nicht implementiert.", $"PACE variant {Oids.Name(info.Oid)} is not implemented yet."));
        if (info.ParameterId is not { } paramId || !StandardizedDomainParameters.IsEc(paramId))
            throw new NotSupportedException(T("Explizite Domain-Parameter (PACEDomainParameterInfo) sind noch nicht implementiert.", "Explicit domain parameters (PACEDomainParameterInfo) are not implemented yet."));
        var domain = StandardizedDomainParameters.Curve(paramId);
        var cipher = Kdf.Algorithm(alg.KeyType);

        // Kπ = KDF(f(π), 3)
        var fpi = password.Encode();
        var kPi = Kdf.Derive(fpi, Kdf.CounterPassword, alg.KeyType);
        log.Detail(LogCategory.Crypto, "f(π)", fpi, "9303-11 9.7.3");
        log.Detail(LogCategory.Crypto, "Kπ = KDF(f(π), 3)", kPi, "9303-11 9.7.3");

        // MSE:Set AT (9303-11 4.4.4.1)
        var oidBytes = new DerObjectIdentifier(info.Oid).GetEncoded()[2..];
        var mseData = new List<byte>();
        mseData.AddRange(BerTlv.Encode(0x80, oidBytes));
        mseData.AddRange(BerTlv.Encode(0x83, [(byte)password.Type]));
        if (includeParameterId) mseData.AddRange(BerTlv.Encode(0x84, [(byte)paramId]));
        var mse = channel.Transmit(new CommandApdu(0x00, 0x22, 0xC1, 0xA4, [.. mseData]), "MSE:Set AT (PACE)");
        if (!mse.Status.IsSuccess)
        {
            if (mse.Status.Sw1 == 0x63) log.Warning(LogCategory.Protocol, T($"MSE:Set AT: Passwort-Fehlbedienungszähler {mse.Status.Sw2 & 0x0F}", $"MSE:Set AT: password retry counter {mse.Status.Sw2 & 0x0F}"), null, "TR-03110-3 B.11.1");
            else throw new ProtocolException(T($"MSE:Set AT abgelehnt: {mse.Status} {mse.Status.Description}", $"MSE:Set AT rejected: {mse.Status} {mse.Status.Description}"), mse.Status);
        }

        // Step 1: encrypted nonce
        var r1 = GeneralAuthenticate(channel, [], chained: true, "GENERAL AUTHENTICATE (1: Encrypted Nonce)");
        var z = Expect(r1, 0x80, "Encrypted Nonce");
        var s = SymmetricCrypto.CbcDecrypt(cipher, kPi, new byte[SymmetricCrypto.BlockSize(cipher)], z);
        log.Detail(LogCategory.Crypto, T("z (verschlüsselte Nonce)", "z (encrypted nonce)"), z, Ref);
        log.Detail(LogCategory.Crypto, "s = D(Kπ, z)", s, Ref);

        // Step 2: generic mapping (9303-11 4.4.3.3.1): Ĝ = s·G + H, H = SK_map,PCD · PK_map,IC
        var n = domain.N;
        var skMap = test?.MapPrivateKey ?? RandomScalar(n);
        var pkMap = domain.G.Multiply(skMap).Normalize();
        log.Detail(LogCategory.Crypto, "SK_map,PCD", skMap.ToByteArrayUnsigned(), Ref);
        log.Detail(LogCategory.Crypto, "PK_map,PCD", pkMap.GetEncoded(false), Ref);
        var r2 = GeneralAuthenticate(channel, BerTlv.Encode(0x81, pkMap.GetEncoded(false)), chained: true, "GENERAL AUTHENTICATE (2: Map Nonce)");
        var pkMapIcBytes = Expect(r2, 0x82, "Mapping Data");
        var pkMapIc = DecodeAndValidate(domain, pkMapIcBytes, "PK_map,IC");
        log.Detail(LogCategory.Crypto, "PK_map,IC", pkMapIcBytes, Ref);
        var h = pkMapIc.Multiply(skMap).Normalize();
        if (h.IsInfinity) throw new ProtocolException(T("PACE: H ist der Punkt im Unendlichen.", "PACE: H is the point at infinity."));
        var gMapped = domain.G.Multiply(new BigInteger(1, s)).Add(h).Normalize();
        log.Detail(LogCategory.Crypto, "H = SK_map,PCD · PK_map,IC", h.GetEncoded(false), Ref);
        log.Detail(LogCategory.Crypto, "Ĝ = s·G + H", gMapped, Ref);

        // Step 3: key agreement on Ĝ
        var skEph = test?.EphemeralPrivateKey ?? RandomScalar(n);
        var pkEph = gMapped.Multiply(skEph).Normalize();
        log.Detail(LogCategory.Crypto, "SK_eph,PCD", skEph.ToByteArrayUnsigned(), Ref);
        log.Detail(LogCategory.Crypto, "PK_eph,PCD", pkEph.GetEncoded(false), Ref);
        var r3 = GeneralAuthenticate(channel, BerTlv.Encode(0x83, pkEph.GetEncoded(false)), chained: true, "GENERAL AUTHENTICATE (3: Key Agreement)");
        var pkEphIcBytes = Expect(r3, 0x84, "Ephemeral Public Key");
        var pkEphIc = DecodeAndValidate(domain, pkEphIcBytes, "PK_eph,IC", gMapped.Curve);
        log.Detail(LogCategory.Crypto, "PK_eph,IC", pkEphIcBytes, Ref);
        // 9303-11 4.4.1 / TR-03110-2 3.2: the terminal SHALL check that PK_eph,IC ≠ PK_eph,PCD
        if (pkEphIc.Equals(pkEph)) throw new ProtocolException(T("PACE: PK_eph,IC ist identisch mit PK_eph,PCD (Reflexionsangriff).", "PACE: PK_eph,IC equals PK_eph,PCD (reflection attack)."));
        var shared = pkEphIc.Multiply(skEph).Normalize();
        var k = FieldBytes(shared.AffineXCoord.ToBigInteger(), domain);
        log.Detail(LogCategory.Crypto, "K = x(SK_eph,PCD · PK_eph,IC)", k, Ref);
        var ksEnc = Kdf.Derive(k, Kdf.CounterEnc, alg.KeyType);
        var ksMac = Kdf.Derive(k, Kdf.CounterMac, alg.KeyType);
        log.Detail(LogCategory.Crypto, "KSEnc = KDF(K, 1)", ksEnc, "9303-11 9.7.1");
        log.Detail(LogCategory.Crypto, "KSMAC = KDF(K, 2)", ksMac, "9303-11 9.7.1");

        // Step 4: mutual authentication (tokens over the other party's ephemeral public key, 9303-11 4.4.3.4 / 9.4.?)
        var tPcd = SymmetricCrypto.Mac(cipher, ksMac, MacInput(cipher, AuthTokenInput(info.Oid, pkEphIcBytes)));
        var tIcExpected = SymmetricCrypto.Mac(cipher, ksMac, MacInput(cipher, AuthTokenInput(info.Oid, pkEph.GetEncoded(false))));
        log.Detail(LogCategory.Crypto, "T_PCD = MAC(KSMAC, PK_eph,IC)", tPcd, Ref);
        var r4 = GeneralAuthenticate(channel, BerTlv.Encode(0x85, tPcd), chained: false, "GENERAL AUTHENTICATE (4: Mutual Authentication)");
        var tIc = Expect(r4, 0x86, "Authentication Token");
        if (!tIc.AsSpan().SequenceEqual(tIcExpected))
            throw new ProtocolException(T($"PACE: Authentisierungstoken des Chips ungültig (erhalten {Hex.Compact(tIc)}, erwartet {Hex.Compact(tIcExpected)}).", $"PACE: authentication token of the chip invalid (received {Hex.Compact(tIc)}, expected {Hex.Compact(tIcExpected)})."));
        log.Detail(LogCategory.Crypto, T("T_IC korrekt", "T_IC correct"), tIc, Ref);
        var car1 = r4.FirstOrDefault(o => o.Tag == 0x87);
        var car2 = r4.FirstOrDefault(o => o.Tag == 0x88);
        if (car1 != null) log.Info(LogCategory.Protocol, T($"CAR (aktuell): {Encoding.ASCII.GetString(car1.Value)}", $"CAR (current): {Encoding.ASCII.GetString(car1.Value)}"), null, "TR-03110-3 B.11");
        if (car2 != null) log.Info(LogCategory.Protocol, T($"CAR (vorherig): {Encoding.ASCII.GetString(car2.Value)}", $"CAR (previous): {Encoding.ASCII.GetString(car2.Value)}"), null, "TR-03110-3 B.11");

        byte[]? caIc = null;
        if (alg.Mapping == PaceMapping.ChipAuthentication)
        {
            // ICAO 9303-11 4.4.3.5: A_IC in '8A' is mandatory for CAM; CA_IC = D(KS_Enc, A_IC), IV = E(KS_Enc, -1).
            var aIc = Expect(r4, 0x8A, "Encrypted Chip Authentication Data");
            caIc = DecryptChipAuthenticationData(cipher, ksEnc, aIc);
            log.Detail(LogCategory.Crypto, "A_IC", aIc, "9303-11 4.4.3.5");
            log.Detail(LogCategory.Crypto, "CA_IC = D(KSEnc, A_IC)", caIc, "9303-11 4.4.3.5");
        }

        log.Info(LogCategory.Protocol, T($"PACE erfolgreich – Secure Messaging ({(cipher == CipherAlgorithm.Aes ? "AES" : "3DES")}) aktiv", $"PACE successful – secure messaging ({(cipher == CipherAlgorithm.Aes ? "AES" : "3DES")}) active"), null, Ref);
        var sm = new SecureChannel(channel, alg.KeyType, ksEnc, ksMac, new byte[SymmetricCrypto.BlockSize(cipher)], "PACE");
        return new PaceResult(sm, info, pkEphIcBytes, r4.FirstOrDefault(o => o.Tag == 0x8A)?.Value)
        {
            ChipMappingPublicKey = pkMapIcBytes,
            ChipAuthenticationData = caIc,
            CompressedChipEphemeralKey = FieldBytes(pkEphIc.AffineXCoord.ToBigInteger(), domain),
            CompressedTerminalEphemeralKey = FieldBytes(pkEph.AffineXCoord.ToBigInteger(), domain),
        };
    }

    /// <summary>
    /// CA_IC from the Encrypted Chip Authentication Data (ICAO 9303-11 4.4.3.5): AES-CBC decryption with KS_Enc and
    /// IV = E(KS_Enc, -1), then removal of the ISO/IEC 9797-1 method 2 padding.
    /// </summary>
    public static byte[] DecryptChipAuthenticationData(CipherAlgorithm cipher, byte[] ksEnc, byte[] aIc)
    {
        var block = SymmetricCrypto.BlockSize(cipher);
        if (cipher != CipherAlgorithm.Aes || aIc.Length == 0 || aIc.Length % block != 0)
            throw new ProtocolException(T($"PACE-CAM: A_IC hat {aIc.Length} Byte (Vielfaches der AES-Blockgröße erwartet).", $"PACE-CAM: A_IC has {aIc.Length} bytes (multiple of the AES block size expected)."));
        var iv = SymmetricCrypto.EcbEncryptBlock(cipher, ksEnc, Enumerable.Repeat((byte)0xFF, block).ToArray());
        try { return SymmetricCrypto.Unpad(SymmetricCrypto.CbcDecrypt(cipher, ksEnc, iv, aIc)); }
        catch (CryptographicException ex) { throw new ProtocolException(T($"PACE-CAM: A_IC nicht entschlüsselbar ({ex.Message}).", $"PACE-CAM: A_IC cannot be decrypted ({ex.Message}).")); }
    }

    /// <summary>
    /// Terminal check of PACE-CAM (ICAO 9303-11 4.4.3.5.2): PK_Map,IC = CA_IC · PK_IC, with PK_IC from a
    /// ChipAuthenticationPublicKeyInfo of EF.CardSecurity on the PACE domain. Returns the matching key or null.
    /// </summary>
    public static ChipAuthenticationPublicKeyInfo? VerifyChipAuthenticationMapping(PaceResult pace, IEnumerable<ChipAuthenticationPublicKeyInfo> keys)
    {
        if (pace.ChipAuthenticationData is not { } caIc || pace.ChipMappingPublicKey is not { } mapping || pace.Info.ParameterId is not { } id) return null;
        var domain = StandardizedDomainParameters.Curve(id);
        var ca = new BigInteger(1, caIc);
        if (ca.SignValue <= 0 || ca.CompareTo(domain.N) >= 0) return null;
        var expected = domain.Curve.DecodePoint(mapping).Normalize();
        foreach (var info in keys)
        {
            ECPoint pk;
            try
            {
                if (ChipPublicKey.From(info).Domain is not EcDomain ec || !ec.Parameters.Curve.Equals(domain.Curve)) continue;
                pk = domain.Curve.DecodePoint(ChipPublicKey.From(info).PublicKey).Normalize();
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException or NotSupportedException) { continue; }
            if (!pk.IsValid()) continue;
            if (pk.Multiply(ca).Normalize().Equals(expected)) return info;
        }
        return null;
    }

    /// <summary>3DES MACs are computed over padded data (ISO/IEC 9797-1 M2); AES-CMAC over the unpadded data.</summary>
    private static byte[] MacInput(CipherAlgorithm cipher, byte[] data) => cipher == CipherAlgorithm.Aes ? data : SymmetricCrypto.Pad(data, 8);

    /// <summary>Public key data object '7F49' {06 OID, 86 point} used as authentication token input (9303-11 4.4.3.4).</summary>
    public static byte[] AuthTokenInput(string oid, byte[] encodedPoint)
    {
        var oidBytes = new DerObjectIdentifier(oid).GetEncoded()[2..];
        return BerTlv.Encode(0x7F49, [.. BerTlv.Encode(0x06, oidBytes), .. BerTlv.Encode(0x86, encodedPoint)]);
    }

    private static void Detail(this Logger log, LogCategory c, string m, ECPoint p, string r) => log.Detail(c, m, p.GetEncoded(false), r);

    private static BigInteger RandomScalar(BigInteger n)
    {
        var random = new SecureRandom();
        BigInteger k;
        do k = new BigInteger(n.BitLength, random); while (k.SignValue == 0 || k.CompareTo(n) >= 0);
        return k;
    }

    private static byte[] FieldBytes(BigInteger value, X9ECParameters domain)
    {
        var size = (domain.Curve.FieldSize + 7) / 8;
        var raw = value.ToByteArrayUnsigned();
        if (raw.Length == size) return raw;
        var result = new byte[size];
        raw.CopyTo(result, size - raw.Length);
        return result;
    }

    private static ECPoint DecodeAndValidate(X9ECParameters domain, byte[] encoded, string name, ECCurve? curve = null)
    {
        ECPoint p;
        try { p = (curve ?? domain.Curve).DecodePoint(encoded).Normalize(); }
        catch (Exception ex) { throw new ProtocolException(T($"PACE: {name} ist kein gültiger Kurvenpunkt: {ex.Message}", $"PACE: {name} is not a valid curve point: {ex.Message}")); }
        if (p.IsInfinity || !p.IsValid()) throw new ProtocolException(T($"PACE: {name} liegt nicht auf der Kurve.", $"PACE: {name} is not on the curve."));
        return p;
    }

    private static List<BerTlv> GeneralAuthenticate(IApduChannel channel, byte[] content, bool chained, string label)
    {
        var data = BerTlv.Encode(0x7C, content);
        var response = channel.Transmit(new CommandApdu(chained ? (byte)0x10 : (byte)0x00, 0x86, 0x00, 0x00, data, 256), label);
        if (!response.Status.IsSuccess)
            throw new ProtocolException(T($"{label} abgelehnt: {response.Status} {response.Status.Description}", $"{label} rejected: {response.Status} {response.Status.Description}"), response.Status);
        var dad = BerTlv.ParseSingle(response.Data);
        if (dad.Tag != 0x7C) throw new ProtocolException(T($"{label}: Antwort ist kein Dynamic Authentication Data Objekt ('7C').", $"{label}: response is not a Dynamic Authentication Data object ('7C')."));
        return [.. dad.Children];
    }

    private static byte[] Expect(List<BerTlv> objects, uint tag, string name) =>
        objects.FirstOrDefault(o => o.Tag == tag)?.Value ?? throw new ProtocolException(T($"PACE: Datenobjekt '{tag:X2}' ({name}) fehlt in der Antwort.", $"PACE: data object '{tag:X2}' ({name}) missing in the response."));
}
