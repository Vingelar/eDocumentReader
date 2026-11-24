using System.Text;
using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Pki;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace eDocumentReader.Core.Protocols;

public sealed record TerminalAuthenticationResult(bool Success, string Detail, List<string> Steps);

/// <summary>Terminal Authentication version 1 (BSI TR-03110-1 3.5, APDU mapping TR-03110-3 B.3 / B.14.4–B.14.7).</summary>
public static class TerminalAuthentication
{
    private const string Ref = "BSI TR-03110-1 3.5";

    /// <summary>EF.CVCA (SFI '1C' in the eMRTD application): one or two CARs ('42'), padded with '00' (TR-03110-3 A.7.2 / 9303-10).</summary>
    public static List<string> ParseEfCvca(byte[] data)
    {
        var result = new List<string>();
        foreach (var o in BerTlv.ParseAll(data))
            if (o.Tag == 0x42) result.Add(Encoding.Latin1.GetString(o.Value));
        return result;
    }

    /// <summary>Sends one command, or a chain of commands with CLA '10' for all but the last block (ISO/IEC 7816-4 5.3.3).</summary>
    public static ResponseApdu SendChained(IApduChannel channel, byte ins, byte p1, byte p2, byte[] data, int? maxCommandData, string label)
    {
        if (maxCommandData is not { } max || data.Length <= max)
            return channel.Transmit(new CommandApdu(0x00, ins, p1, p2, data), label);
        var blocks = (data.Length + max - 1) / max;
        ResponseApdu? response = null;
        for (var i = 0; i < blocks; i++)
        {
            var last = i == blocks - 1;
            var block = data.AsSpan(i * max, Math.Min(max, data.Length - i * max)).ToArray();
            response = channel.Transmit(new CommandApdu(last ? (byte)0x00 : (byte)0x10, ins, p1, p2, block), $"{label} [Block {i + 1}/{blocks}{(last ? "" : ", verkettet")}]");
            if (!last && !response.Status.IsSuccess) return response;
        }
        return response!;
    }

    /// <summary>
    /// Performs TA v1. <paramref name="idPicc"/>: Comp(PK_PICC,PACE) (dynamic binding), or document number+check digit (BAC / static binding).
    /// <paramref name="compressedTerminalKey"/>: Comp(PK_PCD) of the preceding Chip Authentication.
    /// The chain must start with a certificate whose CAR is known to the chip.
    /// <paramref name="maxCommandData"/>: if set, PSO:Verify Certificate is sent with command chaining
    /// (ISO/IEC 7816-4 5.3.3, CLA bit b5) in blocks of at most this many plain data bytes.
    /// </summary>
    public static TerminalAuthenticationResult Perform(IApduChannel channel, IReadOnlyList<CvCertificate> chain, AsymmetricKeyParameter terminalKey,
        byte[] idPicc, byte[] compressedTerminalKey, int? maxCommandData = null)
    {
        var log = channel.Logger;
        var steps = new List<string>();
        var terminal = chain[^1];
        log.Info(LogCategory.Protocol, $"Terminal Authentication v1 mit {terminal.Chr} ({TaOids.Name(terminal.PublicKey.Oid)}, {terminal.DescribeAuthorization()})", null, Ref);

        // TR-03110-3 B.11.5: data field = certificate body '7F4E' || signature '5F37' (without the outer '7F21').
        // Some chips expect the complete certificate; after 6A80 the complete encoding is tried once (reported as a deviation).
        var wrapped = false;
        foreach (var cert in chain)
        {
            ResponseApdu pso;
            var attempt = 0;
            while (true)
            {
                var dst = channel.Transmit(new CommandApdu(0x00, 0x22, 0x81, 0xB6, BerTlv.Encode(0x83, Encoding.Latin1.GetBytes(cert.Car))), $"MSE:Set DST (CAR {cert.Car})");
                if (!dst.Status.IsSuccess)
                    return Fail($"MSE:Set DST für CAR {cert.Car}: {dst.Status} {dst.Status.Description}");
                byte[] data = wrapped ? cert.Encoded : [.. cert.Body, .. BerTlv.Encode(0x5F37, cert.Signature)];
                pso = SendChained(channel, 0x2A, 0x00, 0xBE, data, maxCommandData,
                    $"PSO:Verify Certificate ({cert.Chr}{(wrapped ? ", mit '7F21'" : "")})");
                if (pso.Status.Value == 0x6A80 && !wrapped && attempt++ == 0)
                {
                    wrapped = true;
                    var finding = "⚠ PSO:Verify Certificate: Chip lehnt '7F4E'||'5F37' (TR-03110-3 B.11.5) mit 6A80 ab und erwartet das vollständige Zertifikat mit '7F21'";
                    steps.Add(finding);
                    log.Warning(LogCategory.Protocol, finding, null, Ref);
                    continue;
                }
                break;
            }
            if (!pso.Status.IsSuccess)
                return Fail($"PSO:Verify Certificate {cert.Chr}: {pso.Status} {pso.Status.Description}");
            steps.Add($"Zertifikat {cert.Chr} vom Chip akzeptiert{(wrapped ? " (mit '7F21')" : "")}");
        }

        var at = channel.Transmit(new CommandApdu(0x00, 0x22, 0x81, 0xA4, BerTlv.Encode(0x83, Encoding.Latin1.GetBytes(terminal.Chr))), "MSE:Set AT (Terminal Authentication)");
        if (!at.Status.IsSuccess) return Fail($"MSE:Set AT: {at.Status} {at.Status.Description}");

        var challenge = channel.Transmit(new CommandApdu(0x00, 0x84, 0x00, 0x00, null, 8), "GET CHALLENGE (r_PICC)");
        if (!challenge.Status.IsSuccess || challenge.Data.Length != 8) return Fail($"GET CHALLENGE: {challenge.Status} {challenge.Status.Description}");

        byte[] toSign = [.. idPicc, .. challenge.Data, .. compressedTerminalKey];
        log.Detail(LogCategory.Crypto, "ID_PICC", idPicc, Ref);
        log.Detail(LogCategory.Crypto, "r_PICC", challenge.Data, Ref);
        log.Detail(LogCategory.Crypto, "Comp(PK_PCD)", compressedTerminalKey, Ref);
        var signer = SignerUtilities.GetSigner(TaOids.SignatureAlgorithm(terminal.PublicKey.Oid));
        signer.Init(true, ParametersWithRandomIfNeeded(terminalKey));
        signer.BlockUpdate(toSign, 0, toSign.Length);
        var sPcd = signer.GenerateSignature();
        log.Detail(LogCategory.Crypto, $"s_PCD = Sign(SK_PCD, ID_PICC || r_PICC || Comp(PK_PCD)) [{TaOids.Name(terminal.PublicKey.Oid)}]", sPcd, Ref);

        var ext = channel.Transmit(new CommandApdu(0x00, 0x82, 0x00, 0x00, sPcd), "EXTERNAL AUTHENTICATE (Terminal Authentication)");
        if (!ext.Status.IsSuccess) return Fail($"EXTERNAL AUTHENTICATE: {ext.Status} {ext.Status.Description}");
        steps.Add("EXTERNAL AUTHENTICATE erfolgreich");
        log.Info(LogCategory.Protocol, $"Terminal Authentication erfolgreich – Rechte: {terminal.DescribeAuthorization()}", null, Ref);
        return new TerminalAuthenticationResult(true, terminal.DescribeAuthorization(), steps);

        TerminalAuthenticationResult Fail(string message)
        {
            log.Error(LogCategory.Protocol, "Terminal Authentication fehlgeschlagen: " + message, null, Ref);
            steps.Add(message);
            return new TerminalAuthenticationResult(false, message, steps);
        }
    }

    /// <summary>ParametersWithRandom only for keys that need randomness (ECDSA); keeps RSA-v1.5 deterministic.</summary>
    private static ICipherParameters ParametersWithRandomIfNeeded(AsymmetricKeyParameter key) => new Org.BouncyCastle.Crypto.Parameters.ParametersWithRandom(key, new SecureRandom());

    public static byte[] StaticIdPicc(string documentNumberWithCheckDigit) => Encoding.ASCII.GetBytes(documentNumberWithCheckDigit);
}
