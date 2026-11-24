using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Tests;

public class DocumentTests
{
    [Theory]
    [InlineData(195, "C3")]  // the KeyID of the German passport that was rejected with 6A88 as '00 C3'
    [InlineData(1, "01")]
    [InlineData(127, "7F")]
    [InlineData(256, "0100")]
    [InlineData(0, "00")]
    public void ChipAuthentication_KeyReference_IsMinimalUnsigned(int keyId, string expected) =>
        Assert.Equal(expected, Hex.Compact(ChipAuthentication.EncodeKeyReference(keyId)));

    [Fact]
    public void Dg1_SpecimenMrz_IsSplitIntoLinesAndDecoded()
    {
        // ICAO 9303-4 specimen (TD3)
        const string mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" + "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        var dg1 = BerTlv.EncodeConstructed(0x61, BerTlv.Encode(0x5F1F, System.Text.Encoding.ASCII.GetBytes(mrz)));
        var parsed = Lds.ParseDg1(dg1)!;
        Assert.Equal(MrzFormat.TD3, parsed.Format);
        Assert.Equal("ERIKSSON", parsed.PrimaryIdentifier);
        Assert.Equal("ANNA MARIA", parsed.SecondaryIdentifier);
        Assert.Equal("L898902C3", parsed.DocumentNumber);
        Assert.All(parsed.Fields, f => Assert.NotEqual(false, f.Valid));
    }

    [Fact]
    public void Dg1_WrongMrzLength_IsRejected()
    {
        var dg1 = BerTlv.EncodeConstructed(0x61, BerTlv.Encode(0x5F1F, new byte[80]));
        Assert.Throws<FormatException>(() => Lds.ParseDg1(dg1));
    }

    [Fact]
    public void Dg2_FacialRecord_ImageDataIsLocatedFromHeaderFields()
    {
        byte[] image = [0xFF, 0xD8, 0xFF, 0xE0, 0x11, 0x22, 0xFF, 0xD9];
        var record = FacialRecord(image, featurePoints: 2, imageDataType: 0x00, width: 413, height: 531);
        var dg2 = BerTlv.EncodeConstructed(0x75, BerTlv.EncodeConstructed(0x7F61, BerTlv.Encode(0x02, [0x01]),
            BerTlv.EncodeConstructed(0x7F60, BerTlv.EncodeConstructed(0xA1, BerTlv.Encode(0x80, [0x01, 0x01])), BerTlv.Encode(0x5F2E, record))));

        var face = Assert.Single(FaceImageParser.ParseDg2(dg2));
        Assert.Equal(FaceImageDataType.Jpeg, face.DataType);
        Assert.Equal(413, face.Width);
        Assert.Equal(531, face.Height);
        Assert.Equal(image, face.ImageData);
        Assert.Empty(face.Findings);
    }

    [Fact]
    public void Dg2_RecordLengthMismatch_IsReportedAsFinding()
    {
        var record = FacialRecord([1, 2, 3], featurePoints: 0, imageDataType: 0x01, width: 1, height: 1);
        record[11]++; // record length field ≠ actual length
        var face = FaceImageParser.ParseFacialRecord(1, record);
        Assert.Equal(FaceImageDataType.Jpeg2000, face.DataType);
        Assert.Contains(face.Findings, f => f.Contains("Record Length"));
    }

    [Fact]
    public void FileReader_ReportsProgressPerReadBinary()
    {
        // EF.COM-like file of 12 bytes: first READ BINARY (SFI, Le=8) returns the head, the second the rest.
        var transport = new ScriptedTransport(
            ("00 B0 9E 00 08", "60 0A 5F 01 04 30 31 30 9000"),
            ("00 B0 00 08 04", "38 5C 01 75 9000"));
        var progress = new List<(int Done, int Total)>();
        var reader = new FileReader(new CardChannel(transport, Logger.Null)) { Progress = (_, done, total) => progress.Add((done, total)) };

        var data = reader.ReadBySfi(0x1E, "EF.COM");

        Assert.Equal(12, data.Length);
        Assert.Equal([(8, 12), (12, 12)], progress);
    }

    /// <summary>ISO/IEC 19794-5:2005 record: header (14), facial information (20), feature points (8 each), image information (12), image data.</summary>
    private static byte[] FacialRecord(byte[] image, int featurePoints, byte imageDataType, int width, int height)
    {
        var facialBlock = 20 + 8 * featurePoints + 12 + image.Length;
        var total = 14 + facialBlock;
        var r = new List<byte>();
        r.AddRange("FAC\0010\0"u8.ToArray());
        r.AddRange(BigEndian((uint)total, 4));
        r.AddRange(BigEndian(1, 2));
        r.AddRange(BigEndian((uint)facialBlock, 4));
        r.AddRange(BigEndian((uint)featurePoints, 2));
        r.AddRange(new byte[14]); // gender … pose angle uncertainty
        for (var i = 0; i < featurePoints; i++) r.AddRange(new byte[8]);
        r.Add(0x01);
        r.Add(imageDataType);
        r.AddRange(BigEndian((uint)width, 2));
        r.AddRange(BigEndian((uint)height, 2));
        r.AddRange(new byte[6]); // colour space, source type, device type, quality
        r.AddRange(image);
        return [.. r];
    }

    private static byte[] BigEndian(uint v, int bytes) => Enumerable.Range(0, bytes).Select(i => (byte)(v >> (8 * (bytes - 1 - i)))).ToArray();
}
