using System.Text;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Tlv;

namespace eDocumentReader.Tests;

public class IdlTests
{
    private static byte[] Lp(string s) { var b = Encoding.UTF8.GetBytes(s); return [(byte)b.Length, .. b]; }
    private static byte[] Bcd(string digits) => Convert.FromHexString(digits);

    // Synthetic test person, Annex C layout.
    private static byte[] Dg1() => BerTlv.EncodeConstructed(0x61,
        BerTlv.Encode(0x5F1F, [.. Lp("MUSTER"), .. Lp("ERIKA"), .. Bcd("19800102"), .. Bcd("20200301"), .. Bcd("20350228"),
            .. Encoding.ASCII.GetBytes("ZZZ"), .. Lp("TEST AUTHORITY"), .. Lp("ZZ0000001")]),
        BerTlv.EncodeConstructed(0x7F63,
            BerTlv.Encode(0x02, [0x02]),
            BerTlv.Encode(0x87, [.. "B"u8, 0x3B, .. Bcd("20200301"), 0x3B, .. Bcd("20350228"), 0x3B, 0x3B]),
            BerTlv.Encode(0x87, [.. "AM"u8, 0x3B, 0x3B, 0x3B, 0x3B])));

    [Fact]
    public void Dg1_AnnexCLayout_IsDecoded()
    {
        var r = Idl.Parse(new Dictionary<int, byte[]> { [1] = Dg1() });
        Assert.Equal("MUSTER", r.Fields.Single(f => f.Name == "Familienname").Value);
        Assert.Equal("02.01.1980", r.Fields.Single(f => f.Name == "Geburtsdatum").Value);
        Assert.Equal("ZZ0000001", r.Fields.Single(f => f.Name == "Führerscheinnummer").Value);
        Assert.Equal(2, r.Categories.Count);
        Assert.Equal("B", r.Categories[0].Category);
        Assert.Equal("20350228", r.Categories[0].ExpiryDate);
        Assert.Empty(r.Categories[0].Findings);
        Assert.All(r.Fields, f => Assert.Empty(f.Findings));
    }

    [Fact]
    public void Dg4_PortraitWithCaptureTime_IsExtracted()
    {
        byte[] jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0];
        var dg4 = BerTlv.EncodeConstructed(0x65, BerTlv.Encode(0x02, [1]),
            BerTlv.EncodeConstructed(0xA2, BerTlv.Encode(0x88, Bcd("20261105000000")), BerTlv.Encode(0x89, [3]), BerTlv.Encode(0x5F40, jpeg)));
        var img = Assert.Single(Idl.Parse(new Dictionary<int, byte[]> { [4] = dg4 }).Images);
        Assert.Equal("JPEG", img.Format);
        Assert.Equal("05.11.2026 00:00:00", img.Captured);
        Assert.Equal("03", img.ImageType);
    }

    [Fact]
    public void PlaceholderText_IsShownWithFinding()
    {
        var dg1 = BerTlv.EncodeConstructed(0x61, BerTlv.Encode(0x53, Encoding.ASCII.GetBytes("PLACEHOLDER")));
        var f = Idl.Parse(new Dictionary<int, byte[]> { [1] = dg1 }).Fields.Single(x => x.TagHex == "53");
        Assert.Equal("PLACEHOLDER", f.Value);
        Assert.NotEmpty(f.Findings);
    }

    [Fact]
    public void Category_IssueAfterExpiry_IsReported() =>
        Assert.NotEmpty(Idl.ParseCategory([.. "C"u8, 0x3B, .. Bcd("20300101"), 0x3B, .. Bcd("20200101"), 0x3B, 0x3B]).Findings);

    [Fact]
    public void Demographics_NotAnnexC_FallsBackToRawContent()
    {
        var dg1 = BerTlv.EncodeConstructed(0x61, BerTlv.Encode(0x5F1F, Encoding.ASCII.GetBytes("FREE TEXT ONLY")));
        var f = Idl.Parse(new Dictionary<int, byte[]> { [1] = dg1 }).Fields.Single(x => x.TagHex == "5F1F");
        Assert.Contains("Anhang C", f.Findings.Single());
    }
}
