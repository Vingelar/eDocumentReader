using System.Diagnostics;
using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Transport;

public sealed class ChannelOptions
{
    /// <summary>Handle SW1='61' with GET RESPONSE (ISO/IEC 7816-4 5.1.3). Disable for raw protocol tests.</summary>
    public bool AutoGetResponse { get; set; } = true;
    /// <summary>Re-issue the command with Le=SW2 on SW1='6C' (ISO/IEC 7816-4 5.1.3). Disable for raw protocol tests.</summary>
    public bool AutoCorrectLe { get; set; } = true;
}

/// <summary>
/// APDU-level channel on top of a raw transport: encoding, transmission-level response handling and APDU logging.
/// Secure messaging is layered on top of this channel (see Protocols).
/// </summary>
public sealed class CardChannel(ICardTransport transport, Logger logger, ChannelOptions? options = null) : IApduChannel
{
    public CardChannel Card => this;

    public ICardTransport Transport { get; } = transport;
    public Logger Logger { get; } = logger;
    public ChannelOptions Options { get; } = options ?? new ChannelOptions();

    public ResponseApdu Transmit(CommandApdu command, string? label = null)
    {
        var response = TransmitOnce(command, label);

        if (Options.AutoCorrectLe && response.Status.Sw1 == 0x6C && command.Ne > 0)
        {
            Logger.Detail(LogCategory.Apdu, $"SW 6C{response.Status.Sw2:X2}: Kommando wird mit Le={response.Status.Sw2:X2} wiederholt (ISO/IEC 7816-4 5.1.3)");
            response = TransmitOnce(command.WithNe(response.Status.Sw2 == 0 ? 256 : response.Status.Sw2), label);
        }

        if (Options.AutoGetResponse && response.Status.Sw1 == 0x61)
        {
            var data = new List<byte>(response.Data);
            while (response.Status.Sw1 == 0x61)
            {
                // 7816-4 5.1.3: "GET RESPONSE command ... with the same CLA" (chaining bit cleared: last command of chain).
                var cla = (command.Cla & 0x80) == 0 ? (byte)(command.Cla & ~0x10) : command.Cla;
                var getResponse = new CommandApdu(cla, 0xC0, 0x00, 0x00, null, response.Status.Sw2 == 0 ? 256 : response.Status.Sw2);
                response = TransmitOnce(getResponse, "GET RESPONSE");
                data.AddRange(response.Data);
            }
            response = new ResponseApdu([.. data], response.Status);
        }
        return response;
    }

    /// <summary>Exactly one exchange with the card, no interpretation (needed for negative tests).</summary>
    public ResponseApdu TransmitOnce(CommandApdu command, string? label = null) => TransmitRaw(command.ToBytes(), label);

    public ResponseApdu TransmitRaw(byte[] commandBytes, string? label = null)
    {
        Logger.Write(new LogEntry(DateTimeOffset.Now, LogCategory.Apdu, LogLevel.Info, label ?? DescribeCommand(commandBytes), commandBytes, ApduDirection.Command));
        var sw = Stopwatch.StartNew();
        byte[] raw;
        try
        {
            raw = Transport.Transmit(commandBytes);
        }
        catch (Exception ex)
        {
            Logger.Error(LogCategory.Reader, $"Übertragungsfehler: {ex.Message}");
            throw;
        }
        sw.Stop();
        var response = ResponseApdu.Parse(raw);
        Logger.Write(new LogEntry(DateTimeOffset.Now, LogCategory.Apdu, response.Status.IsCompleted ? LogLevel.Info : LogLevel.Warning,
            $"{response.Status} {response.Status.Description}", raw, ApduDirection.Response, sw.Elapsed));
        return response;
    }

    public static string DescribeCommand(byte[] apdu)
    {
        if (apdu.Length < 4) return "Ungültiges APDU";
        var name = apdu[1] switch
        {
            0xA4 => "SELECT",
            0xB0 => "READ BINARY",
            0xB1 => "READ BINARY (odd INS)",
            0xB2 => "READ RECORD",
            0xC0 => "GET RESPONSE",
            0xCA or 0xCB => "GET DATA",
            0x84 => "GET CHALLENGE",
            0x82 => "EXTERNAL/MUTUAL AUTHENTICATE",
            0x88 => "INTERNAL AUTHENTICATE",
            0x86 or 0x87 => "GENERAL AUTHENTICATE",
            0x22 => "MANAGE SECURITY ENVIRONMENT",
            0x2A => "PERFORM SECURITY OPERATION",
            0x20 => "VERIFY",
            0x24 => "CHANGE REFERENCE DATA",
            0x2C => "RESET RETRY COUNTER",
            0xD6 => "UPDATE BINARY",
            0x44 => "ACTIVATE",
            0x04 => "DEACTIVATE",
            0xE2 => "APPEND RECORD",
            _ => $"INS {apdu[1]:X2}",
        };
        if (apdu[0] == 0xFF) name = "PC/SC " + name;
        else if ((apdu[0] & 0x80) == 0 && (apdu[0] & 0x0C) != 0) name = "SM " + name;
        return name;
    }

    /// <summary>PC/SC Part 3 3.2.2.1.3 GET DATA (UID / ATS historical bytes) for contactless cards.</summary>
    public byte[]? GetContactlessData(bool historicalBytes)
    {
        try
        {
            var r = TransmitOnce(new CommandApdu(0xFF, 0xCA, historicalBytes ? (byte)0x01 : (byte)0x00, 0x00, null, 256),
                historicalBytes ? "PC/SC GET DATA (ATS hist. Bytes)" : "PC/SC GET DATA (UID)");
            return r.Status.IsSuccess ? r.Data : null;
        }
        catch (Exception ex)
        {
            Logger.Warning(LogCategory.Reader, $"PC/SC GET DATA nicht verfügbar: {ex.Message}");
            return null;
        }
    }

    public override string ToString() => $"{Transport.Name} ({Transport.Protocol}, ATR {Hex.Of(Transport.Atr)})";
}
