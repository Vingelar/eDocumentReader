using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Protocols;

public sealed class SecureMessagingException(string message, StatusWord? status = null) : Exception(message)
{
    public StatusWord? Status { get; } = status;
}

/// <summary>
/// Secure messaging according to ICAO 9303-11 clause 9.8 (BSI TR-03110-3 F) with 3DES (9.8.6) or AES (9.8.7).
/// Wraps an underlying channel; all protected/unprotected APDUs and MAC computations are logged.
/// </summary>
public sealed class SecureChannel : IApduChannel
{
    private const string Ref = "ICAO 9303-11 9.8";
    private readonly IApduChannel inner;
    private readonly byte[] ksEnc;
    private readonly byte[] ksMac;
    private readonly byte[] ssc;

    public CipherAlgorithm Algorithm { get; }
    /// <summary>The underlying (plain) channel; used when secure messaging is restarted with new keys.</summary>
    public IApduChannel Inner => inner;
    public Logger Logger => inner.Logger;
    public CardChannel Card => inner.Card;
    public bool IsActive { get; private set; } = true;
    /// <summary>Description of the protocol which established this channel (BAC, PACE, CA).</summary>
    public string EstablishedBy { get; }

    public SecureChannel(IApduChannel inner, SessionKeyType keyType, byte[] ksEnc, byte[] ksMac, byte[] initialSsc, string establishedBy)
    {
        this.inner = inner;
        Algorithm = Kdf.Algorithm(keyType);
        this.ksEnc = ksEnc;
        this.ksMac = ksMac;
        ssc = (byte[])initialSsc.Clone();
        if (ssc.Length != SymmetricCrypto.BlockSize(Algorithm)) throw new ArgumentException(T("SSC-Länge muss der Blockgröße entsprechen (9303-11 9.8.2).", "SSC length must equal the block size (9303-11 9.8.2)."));
        EstablishedBy = establishedBy;
    }

    public byte[] CurrentSsc => (byte[])ssc.Clone();
    private int BlockSize => SymmetricCrypto.BlockSize(Algorithm);

    private void IncrementSsc()
    {
        for (var i = ssc.Length - 1; i >= 0; i--)
            if (++ssc[i] != 0) break;
    }

    private byte[] Iv() => Algorithm == CipherAlgorithm.Aes
        ? SymmetricCrypto.EcbEncryptBlock(CipherAlgorithm.Aes, ksEnc, ssc) // 9303-11 9.8.7.1: IV = E(KSEnc, SSC)
        : new byte[8];                                                      // 9303-11 9.8.6.1: zero IV

    private byte[] ComputeMac(byte[] data)
    {
        var input = SymmetricCrypto.Pad([.. ssc, .. data], BlockSize);
        var mac = SymmetricCrypto.Mac(Algorithm, ksMac, input);
        Logger.Trace(LogCategory.SecureMessaging, T("MAC-Eingabe (SSC || Daten, gepaddet)", "MAC input (SSC || data, padded)"), input, Ref);
        return mac;
    }

    /// <summary>Builds the protected command APDU (9303-11 9.8.4, Figure 5). Increments the SSC.</summary>
    public CommandApdu Protect(CommandApdu plain)
    {
        if ((plain.Cla & 0x80) != 0) throw new SecureMessagingException(T("SM für proprietäre Klassenbytes nicht definiert.", "SM is not defined for proprietary class bytes."));
        // 9303-11 9.8.2: SSC is incremented before each command; the AES IV uses this incremented value.
        IncrementSsc();
        var cla = (byte)(plain.Cla | 0x0C);
        var header = SymmetricCrypto.Pad([cla, plain.Ins, plain.P1, plain.P2], BlockSize);
        var dataObjects = new List<byte>();
        if (plain.Data.Length > 0)
        {
            var encrypted = SymmetricCrypto.CbcEncrypt(Algorithm, ksEnc, Iv(), SymmetricCrypto.Pad(plain.Data, BlockSize));
            // Even INS: DO'87' with padding-content indicator '01'; odd INS: DO'85' without indicator.
            dataObjects.AddRange((plain.Ins & 1) == 0
                ? BerTlv.Encode(0x87, [0x01, .. encrypted])
                : BerTlv.Encode(0x85, encrypted));
        }
        if (plain.Ne > 0)
        {
            byte[] le = plain.IsExtended
                ? plain.Ne == 65536 ? [0x00, 0x00] : [(byte)(plain.Ne >> 8), (byte)plain.Ne]
                : [plain.Ne == 256 ? (byte)0 : (byte)plain.Ne];
            dataObjects.AddRange(BerTlv.Encode(0x97, le));
        }
        var mac = ComputeMac([.. header, .. dataObjects]);
        dataObjects.AddRange(BerTlv.Encode(0x8E, mac));
        Logger.Detail(LogCategory.SecureMessaging, T($"SSC={Hex.Compact(ssc)} MAC(Kommando)", $"SSC={Hex.Compact(ssc)} MAC(command)"), mac, Ref);
        var extended = plain.IsExtended || dataObjects.Count > 255;
        return new CommandApdu(cla, plain.Ins, plain.P1, plain.P2, [.. dataObjects], extended ? 65536 : 256, extended);
    }

    /// <summary>Verifies and decrypts a protected response (9303-11 9.8.4, Figure 6). Increments the SSC.</summary>
    public ResponseApdu Unprotect(ResponseApdu protectedResponse)
    {
        IncrementSsc();
        var objects = BerTlv.ParseAll(protectedResponse.Data);
        var do87 = objects.FirstOrDefault(o => o.Tag is 0x87 or 0x85);
        var do99 = objects.FirstOrDefault(o => o.Tag == 0x99);
        var do8E = objects.FirstOrDefault(o => o.Tag == 0x8E);
        if (do8E == null)
        {
            IsActive = false;
            throw new SecureMessagingException(T($"Antwort ohne SM-Datenobjekt '8E' (SW {protectedResponse.Status} {protectedResponse.Status.Description}) – SM-Sitzung vom Chip beendet (9303-11 9.8.5).", $"Response without SM data object '8E' (SW {protectedResponse.Status} {protectedResponse.Status.Description}) – SM session ended by the chip (9303-11 9.8.5)."), protectedResponse.Status);
        }
        var macInput = new List<byte>();
        foreach (var o in objects.Where(o => o.Tag != 0x8E)) macInput.AddRange(o.Encode());
        var expected = ComputeMac([.. macInput]);
        if (!expected.AsSpan().SequenceEqual(do8E.Value))
        {
            IsActive = false;
            throw new SecureMessagingException(T($"MAC der Antwort ungültig: erhalten {Hex.Compact(do8E.Value)}, berechnet {Hex.Compact(expected)} (SSC {Hex.Compact(ssc)}).", $"Response MAC invalid: received {Hex.Compact(do8E.Value)}, computed {Hex.Compact(expected)} (SSC {Hex.Compact(ssc)})."), protectedResponse.Status);
        }
        Logger.Detail(LogCategory.SecureMessaging, T($"SSC={Hex.Compact(ssc)} MAC(Antwort) korrekt", $"SSC={Hex.Compact(ssc)} MAC(response) correct"), expected, Ref);

        var data = Array.Empty<byte>();
        if (do87 != null)
        {
            var cryptogram = do87.Tag == 0x87 ? do87.Value[1..] : do87.Value;
            if (do87.Tag == 0x87 && do87.Value[0] != 0x01) Logger.Warning(LogCategory.SecureMessaging, T($"DO'87' Padding-Indikator {do87.Value[0]:X2} ≠ 01", $"DO'87' padding indicator {do87.Value[0]:X2} ≠ 01"), null, Ref);
            data = SymmetricCrypto.Unpad(SymmetricCrypto.CbcDecrypt(Algorithm, ksEnc, Iv(), cryptogram));
        }
        StatusWord status;
        if (do99 is { Value.Length: 2 })
        {
            status = new StatusWord(do99.Value[0], do99.Value[1]);
            if (status != protectedResponse.Status)
                Logger.Warning(LogCategory.SecureMessaging, T($"SW in DO'99' ({status}) ≠ SW der Antwort ({protectedResponse.Status})", $"SW in DO'99' ({status}) ≠ SW of the response ({protectedResponse.Status})"), null, Ref);
        }
        else
        {
            status = protectedResponse.Status;
            Logger.Warning(LogCategory.SecureMessaging, T("DO'99' fehlt in der geschützten Antwort", "DO'99' missing in the protected response"), null, Ref);
        }
        return new ResponseApdu(data, status);
    }

    public ResponseApdu Transmit(CommandApdu command, string? label = null)
    {
        if (!IsActive) throw new SecureMessagingException(T("SM-Sitzung ist nicht mehr aktiv.", "SM session is no longer active."));
        var name = label ?? CardChannel.DescribeCommand(command.ToBytes());
        Logger.Write(new LogEntry(DateTimeOffset.Now, LogCategory.SecureMessaging, LogLevel.Info, T($"{name} (ungeschützt)", $"{name} (unprotected)"), command.ToBytes(), ApduDirection.Command));
        var protectedCommand = Protect(command);
        var raw = inner.Transmit(protectedCommand, "SM " + name);
        var plain = Unprotect(raw);
        Logger.Write(new LogEntry(DateTimeOffset.Now, LogCategory.SecureMessaging, plain.Status.IsCompleted ? LogLevel.Info : LogLevel.Warning,
            T($"{plain.Status} {plain.Status.Description} (entschlüsselt)", $"{plain.Status} {plain.Status.Description} (decrypted)"), plain.ToBytes(), ApduDirection.Response));
        return plain;
    }
}
