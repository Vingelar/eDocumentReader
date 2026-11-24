using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;

namespace eDocumentReader.Core.Transport;

/// <summary>Anything that executes command APDUs: a plain card channel or a secure messaging channel on top of it.</summary>
public interface IApduChannel
{
    Logger Logger { get; }
    CardChannel Card { get; }
    ResponseApdu Transmit(CommandApdu command, string? label = null);
}
