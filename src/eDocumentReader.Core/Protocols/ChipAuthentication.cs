using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace eDocumentReader.Core.Protocols;

/// <summary>Chip Authentication public key taken from a ChipAuthenticationPublicKeyInfo (9303-11 9.2.6).</summary>
public sealed record ChipPublicKey(KeyAgreementDomain Domain, byte[] PublicKey, int? KeyId)
{
    public static ChipPublicKey From(ChipAuthenticationPublicKeyInfo info)
    {
        var spki = Asn1Sequence.GetInstance(info.PublicKey);
        var algId = Asn1Sequence.GetInstance(spki[0]);
        var algOid = DerObjectIdentifier.GetInstance(algId[0]).Id;
        var ec = algOid == Oids.EcPublicKey || info.Oid == Oids.IdPkEcdh;
        var domain = KeyAgreementDomain.FromParameters(algId.Count > 1 ? algId[1] : null, ec);
        var bits = DerBitString.GetInstance(spki[1]).GetOctets();
        // DH: subjectPublicKey contains a DER INTEGER (X9.42 DHPublicKey); ECDH: the encoded point itself.
        var pk = ec ? bits : KeyAgreementDomain.FixedLength(DerInteger.GetInstance(Asn1Object.FromByteArray(bits)).Value, ((DhDomain)domain).Length);
        return new ChipPublicKey(domain, pk, info.KeyId);
    }
}

public sealed record ChipAuthenticationResult(SecureChannel Channel, byte[] TerminalEphemeralPublicKey, byte[] CompressedTerminalKey, string Oid);

/// <summary>Chip Authentication version 1 (ICAO 9303-11 6.2, BSI TR-03110-1 3.4, APDUs TR-03110-3 B.14.1â€“B.14.3).</summary>
public static class ChipAuthentication
{
    private const string Ref = "ICAO 9303-11 6.2";

    /// <summary>
    /// Chooses the CA algorithm for a public key: the ChipAuthenticationInfo with the same key id
    /// (preferring AES over 3DES); without ChipAuthenticationInfo, 3DES is implied (TR-03110-3 A.1.1.2).
    /// </summary>
    public static string SelectOid(ChipAuthenticationPublicKeyInfo pk, IEnumerable<ChipAuthenticationInfo> infos)
    {
        var candidates = infos.Where(i => i.KeyId == pk.KeyId || pk.KeyId == null || i.KeyId == null).OrderByDescending(i => i.Oid, StringComparer.Ordinal).ToList();
        if (candidates.Count > 0) return candidates[0].Oid;
        return (pk.Oid == Oids.IdPkEcdh ? Oids.IdCa + ".2" : Oids.IdCa + ".1") + ".1";
    }

    public static SessionKeyType KeyType(string caOid) => caOid.Split('.')[^1] switch
    {
        "1" => SessionKeyType.DesEde,
        "2" => SessionKeyType.Aes128,
        "3" => SessionKeyType.Aes192,
        "4" => SessionKeyType.Aes256,
        _ => throw new NotSupportedException($"CA-OID {caOid}"),
    };

    /// <summary>
    /// Value of DO'84' (reference of a private key): unsigned integer, minimum number of octets, no leading '00'
    /// (TR-03110-3 D.2.1.1). KeyID 195 → C3, not the ASN.1 INTEGER encoding 00 C3 (rejected by chips with 6A88).
    /// </summary>
    public static byte[] EncodeKeyReference(int keyId) => keyId == 0 ? [0x00] : BigInteger.ValueOf(keyId).ToByteArrayUnsigned();

    public static ChipAuthenticationResult Perform(SecureChannel channel, ChipPublicKey chipKey, string caOid, bool useSetAtFor3Des = false, BigInteger? testPrivateKey = null)
    {
        var log = channel.Logger;
        var keyType = KeyType(caOid);
        log.Info(LogCategory.Protocol, $"Chip Authentication: {Oids.Name(caOid)}{(chipKey.KeyId is { } kid ? $", KeyID {kid}" : "")}", null, Ref);
        log.Detail(LogCategory.Crypto, T("PK_IC (statisch)", "PK_IC (static)"), chipKey.PublicKey, Ref);

        var eph = chipKey.Domain.Generate(testPrivateKey);
        log.Detail(LogCategory.Crypto, T("SK_PCD (ephemer)", "SK_PCD (ephemeral)"), eph.PrivateKey.ToByteArrayUnsigned(), Ref);
        log.Detail(LogCategory.Crypto, T("PK_PCD (ephemer)", "PK_PCD (ephemeral)"), eph.PublicKey, Ref);
        byte[]? keyRef = chipKey.KeyId is { } id ? EncodeKeyReference(id) : null;

        if (keyType == SessionKeyType.DesEde && !useSetAtFor3Des)
        {
            // MSE:Set KAT (TR-03110-3 B.14.3)
            var data = new List<byte>(BerTlv.Encode(0x91, eph.PublicKey));
            if (keyRef != null) data.AddRange(BerTlv.Encode(0x84, keyRef));
            var r = channel.Transmit(new CommandApdu(0x00, 0x22, 0x41, 0xA6, [.. data]), "MSE:Set KAT (Chip Authentication)");
            if (!r.Status.IsSuccess) throw new ProtocolException(T($"Chip Authentication (MSE:Set KAT) abgelehnt: {r.Status} {r.Status.Description}", $"Chip Authentication (MSE:Set KAT) rejected: {r.Status} {r.Status.Description}"), r.Status);
        }
        else
        {
            // MSE:Set AT + GENERAL AUTHENTICATE (TR-03110-3 B.14.1 / B.14.2)
            var oid = new DerObjectIdentifier(caOid).GetEncoded()[2..];
            var data = new List<byte>(BerTlv.Encode(0x80, oid));
            if (keyRef != null) data.AddRange(BerTlv.Encode(0x84, keyRef));
            var mse = channel.Transmit(new CommandApdu(0x00, 0x22, 0x41, 0xA4, [.. data]), "MSE:Set AT (Chip Authentication)");
            if (!mse.Status.IsSuccess) throw new ProtocolException(T($"Chip Authentication (MSE:Set AT) abgelehnt: {mse.Status} {mse.Status.Description}", $"Chip Authentication (MSE:Set AT) rejected: {mse.Status} {mse.Status.Description}"), mse.Status);
            var ga = channel.Transmit(new CommandApdu(0x00, 0x86, 0x00, 0x00, BerTlv.Encode(0x7C, BerTlv.Encode(0x80, eph.PublicKey)), 256), "GENERAL AUTHENTICATE (Chip Authentication)");
            if (!ga.Status.IsSuccess) throw new ProtocolException(T($"Chip Authentication (GENERAL AUTHENTICATE) abgelehnt: {ga.Status} {ga.Status.Description}", $"Chip Authentication (GENERAL AUTHENTICATE) rejected: {ga.Status} {ga.Status.Description}"), ga.Status);
            if (ga.Data.Length > 0 && BerTlv.ParseSingle(ga.Data).Tag != 0x7C)
                log.Warning(LogCategory.Protocol, T("Antwort auf GENERAL AUTHENTICATE ist kein '7C'-Objekt (TR-03110-3 B.14.2).", "Response to GENERAL AUTHENTICATE is not a '7C' object (TR-03110-3 B.14.2)."));
        }

        var k = chipKey.Domain.Agree(eph.PrivateKey, chipKey.PublicKey);
        var ksEnc = Kdf.Derive(k, Kdf.CounterEnc, keyType);
        var ksMac = Kdf.Derive(k, Kdf.CounterMac, keyType);
        log.Detail(LogCategory.Crypto, "K = KA(SK_PCD, PK_IC)", k, Ref);
        log.Detail(LogCategory.Crypto, "KSEnc = KDF(K, 1)", ksEnc, "9303-11 9.7.1");
        log.Detail(LogCategory.Crypto, "KSMAC = KDF(K, 2)", ksMac, "9303-11 9.7.1");
        var comp = chipKey.Domain.Compress(eph.PublicKey);
        log.Detail(LogCategory.Crypto, T("Comp(PK_PCD) für Terminal Authentication", "Comp(PK_PCD) for Terminal Authentication"), comp, "TR-03110-3 A.2.2.3");
        log.Info(LogCategory.Protocol, T("Chip Authentication erfolgreich – Secure Messaging mit neuen Sitzungsschlüsseln neu gestartet (SSC = 0)", "Chip Authentication successful – secure messaging restarted with new session keys (SSC = 0)"), null, "9303-11 6.2.2 / 9.8.2");
        var sm = new SecureChannel(channel.Inner, keyType, ksEnc, ksMac, new byte[SymmetricCrypto.BlockSize(Kdf.Algorithm(keyType))], "Chip Authentication");
        return new ChipAuthenticationResult(sm, eph.PublicKey, comp, caOid);
    }
}

