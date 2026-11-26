using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1;

namespace eDocumentReader.Tests;

public class CardFilesTests
{
    // EF.ATR/INFO of a production eMRTD (no personal data): card service data, card capabilities, 7F66 with 1520/1520.
    private const string ProductionAtrInfo = "43 01 F8 47 03 F7 41 E0 7F 66 08 02 02 05 F0 02 02 05 F0";

    [Fact]
    public void AtrInfoIsDecoded()
    {
        var info = new AtrInfoFile(Hex.Parse(ProductionAtrInfo));
        Assert.Equal((byte)0xF8, info.CardServiceData);
        Assert.True(info.CommandChaining);
        Assert.True(info.ExtendedLength);
        Assert.True(info.ExtendedLengthInformation);
        Assert.Equal(1520, info.MaxCommandApdu);
        Assert.Equal(1520, info.MaxResponseApdu);
        Assert.True(info.BufferSizesStated);
        Assert.Empty(info.Findings);
        Assert.Contains("1520", info.Describe());
    }

    [Fact]
    public void AtrInfoWithoutExtendedLengthInformationIsFlagged()
    {
        // Byte 3 b6 announces '7F66', which is missing.
        var info = new AtrInfoFile(Hex.Parse("47 03 F7 41 E0"));
        Assert.True(info.CommandChaining);
        Assert.False(info.BufferSizesStated);
        Assert.Single(info.Findings);
    }

    [Fact]
    public void EfDirListsApplications()
    {
        var dir = new EfDirFile(Hex.Parse("61 09 4F 07 A0 00 00 02 47 10 01  61 08 4F 06 A0 00 00 02 48 02  00 00"));
        Assert.Equal(2, dir.Applications.Count);
        Assert.True(dir.Lists(EmrtdReader.EmrtdAid));
        Assert.Empty(dir.Findings);
    }

    [Fact]
    public void EfDirInfoIsParsedFromSecurityInfos()
    {
        var content = Hex.Parse("61 09 4F 07 A0 00 00 02 47 10 01");
        var set = new DerSet(new DerSequence(new DerObjectIdentifier(Oids.IdEfDir), new DerOctetString(content)));
        var info = Assert.IsType<EfDirInfo>(Assert.Single(SecurityInfos.Parse(set.GetEncoded())));
        Assert.Equal(content, info.Content);
    }

    [Fact]
    public void WholeFileIsReadUntilShortAnswer()
    {
        var transport = new ScriptedTransport(
            ("00 B0 81 00 04", "43 01 F8 47 9000"),
            ("00 B0 00 04 04", "03 F7 9000"));
        var data = new FileReader(new CardChannel(transport, Logger.Null)) { MaxChunk = 4 }.ReadWholeBySfi(CardFiles.SfiAtrInfo, CardFiles.AtrInfoName);
        Assert.Equal(Hex.Parse("43 01 F8 47 03 F7"), data);
    }

    [Fact]
    public void MissingFileReports6A82()
    {
        var transport = new ScriptedTransport(("00 B0 9E 00 DF", "6A82"));
        var ex = Assert.Throws<FileReadException>(() => new FileReader(new CardChannel(transport, Logger.Null)).ReadWholeBySfi(CardFiles.SfiDir, CardFiles.DirName));
        Assert.Equal((ushort)0x6A82, ex.Status!.Value.Value);
    }

    [Fact]
    public void WholeFileIsReadAfterSelectByFid()
    {
        var transport = new ScriptedTransport(
            ("00 A4 02 0C 02 2F 01", "9000"),
            ("00 B0 00 00 DF", "43 01 F8 47 03 F7 41 E0 9000"));
        var data = new FileReader(new CardChannel(transport, Logger.Null)).ReadWholeByFid(CardFiles.FidAtrInfo, CardFiles.AtrInfoName);
        Assert.Equal(Hex.Parse("43 01 F8 47 03 F7 41 E0"), data);
    }
}
