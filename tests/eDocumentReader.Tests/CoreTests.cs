using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Tests;

public class ApduTests
{
    [Theory]
    [InlineData("00A4000C", ApduCase.Case1)]
    [InlineData("00B0000000", ApduCase.Case2Short)]
    [InlineData("00A4020C02011E", ApduCase.Case3Short)]
    [InlineData("00A4020402011E00", ApduCase.Case4Short)]
    [InlineData("00B0000000FFFF", ApduCase.Case2Extended)]
    [InlineData("00A40204000002011E", ApduCase.Case3Extended)]
    [InlineData("00A40204000002011E0000", ApduCase.Case4Extended)]
    public void ParseAndEncodeRoundTrip(string hex, ApduCase expected)
    {
        var bytes = Hex.Parse(hex);
        var apdu = CommandApdu.Parse(bytes);
        Assert.Equal(expected, apdu.Case);
        Assert.Equal(bytes, apdu.ToBytes());
    }

    [Fact]
    public void LeZeroMeansMaximum()
    {
        Assert.Equal(256, CommandApdu.Parse(Hex.Parse("00B0000000")).Ne);
        Assert.Equal(65536, CommandApdu.Parse(Hex.Parse("00B0000000000000")[..7]).Ne);
    }

    [Fact]
    public void LargeNeSwitchesToExtended()
    {
        var apdu = new CommandApdu(0x00, 0xB0, 0x00, 0x00, null, 1000);
        Assert.Equal(Hex.Parse("00B00000 0003E8"), apdu.ToBytes());
    }

    [Fact]
    public void StatusWordCategories()
    {
        Assert.Equal(StatusCategory.NormalProcessing, new StatusWord(0x90, 0x00).Category);
        Assert.True(new StatusWord(0x63, 0xC2).NonVolatileMemoryChanged);
        Assert.Equal(StatusCategory.CheckingError, new StatusWord(0x69, 0x88).Category);
        Assert.Equal("SM-Datenobjekte fehlerhaft", new StatusWord(0x69, 0x88).Description);
    }
}

public class TlvTests
{
    [Fact]
    public void ParsesNestedAndLongForm()
    {
        // EF.COM-like structure: 60 { 5F01 "0107", 5F36 "040000", 5C 61 75 }
        var data = Hex.Parse("60 14 5F01 04 30313037 5F36 06 303430303030 5C 02 6175");
        var tlv = BerTlv.ParseSingle(data);
        Assert.Equal(0x60u, tlv.Tag);
        Assert.True(tlv.IsConstructed);
        Assert.Equal(TagClass.Application, tlv.Class);
        Assert.Equal(3, tlv.Children.Count);
        Assert.Equal(0x5F01u, tlv.Children[0].Tag);
        Assert.Equal(Hex.Parse("6175"), tlv.Find(0x5C)!.Value);
        Assert.Equal(data, tlv.Encode());
    }

    [Fact]
    public void ReportsNonMinimalLength()
    {
        var tlv = BerTlv.ParseSingle(Hex.Parse("04 81 02 AABB"));
        Assert.Contains(tlv.Findings, f => f.Contains("DER"));
    }

    [Fact]
    public void RejectsIndefiniteLengthAndPaddingInTemplate()
    {
        Assert.Throws<TlvException>(() => BerTlv.ParseSingle(Hex.Parse("30 80 0000")));
        Assert.Throws<TlvException>(() => BerTlv.ParseSingle(Hex.Parse("30 03 00 0100")));
        Assert.Equal(2, BerTlv.ParseAll(Hex.Parse("00 0101AA 00 0101BB 00")).Count);
    }

    [Theory]
    [InlineData(0, "00")]
    [InlineData(127, "7F")]
    [InlineData(128, "8180")]
    [InlineData(256, "820100")]
    [InlineData(70000, "83011170")]
    public void EncodesMinimalLength(int length, string expected) => Assert.Equal(Hex.Parse(expected), BerTlv.EncodeLength(length));
}

public class AtrTests
{
    [Fact]
    public void ContactlessPcscAtrIsRecognised()
    {
        // PC/SC Part 3 Table 3-5 structure, 14443-4 type A without historical bytes: 3B 80 80 01 01
        var atr = new AtrInfo(Hex.Parse("3B 80 80 01 01"));
        Assert.True(atr.IsPcscContactless);
        Assert.Equal(true, atr.TckValid);
        Assert.Equal([0, 1], atr.Protocols);
    }

    [Fact]
    public void ContactAtrWithT1AndCardCapabilities()
    {
        // TS T0 TA1 TD1(T=1) TD2? -> build: 3B D8 18 81 31 FE ... use a known-structured example:
        // 3B 88 80 01 + hist "80 73 C8 21 C0" ... simplified: category 80, card capabilities 73 with 3rd byte C0
        var hist = Hex.Parse("80 73 00 00 C0");
        var body = new List<byte> { 0x3B, (byte)(0x80 | hist.Length), 0x81, 0x31 };
        // TD1 = 81 -> T=1, Y2 = 8 -> TD2 = 31 -> T=1, Y3=3 -> TA3,TB3
        body.AddRange([0xFE, 0x45]); // TA3 IFSC=254, TB3 BWI=4 CWI=5
        body.AddRange(hist);
        byte tck = 0;
        for (var i = 1; i < body.Count; i++) tck ^= body[i];
        body.Add(tck);
        var atr = new AtrInfo([.. body]);
        Assert.Empty(atr.Findings);
        Assert.Equal(true, atr.ExtendedLengthSupported);
        Assert.Equal(true, atr.CommandChainingSupported);
        Assert.Contains(atr.InterfaceBytes, b => b.Name == "TA3" && b.Meaning == "IFSC = 254");
    }

    [Fact]
    public void InvalidTckIsReported()
    {
        var atr = new AtrInfo(Hex.Parse("3B 80 80 01 00"));
        Assert.Equal(false, atr.TckValid);
    }
}
