using System.Security.Cryptography;
using System.Text.Json;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Tlv;

namespace eDocumentReader.Tests;

public class DocumentSetTests
{
    private static EmrtdReadResult IdlResult()
    {
        var r = new EmrtdReadResult { AccessControl = "PACE (id-PACE-ECDH-GM-AES-CBC-CMAC-128, CAN)" };
        var com = BerTlv.EncodeConstructed(0x60, BerTlv.Encode(0x5F01, [1, 1]), BerTlv.Encode(0x5C, [0x61, 0x6B]));
        var dg1 = BerTlv.EncodeConstructed(0x61, BerTlv.Encode(0x53, "TEST"u8.ToArray()));
        r.Files.Add(new EmrtdFile("EF.COM", Lds.SfiCom, 0, com));
        r.Files.Add(new EmrtdFile("EF.DG1", 1, 1, [.. dg1, 0x00, 0x00]));   // 2 bytes padding after the TLV
        r.Files.Add(new EmrtdFile("EF.CVCA", 0x1C, 0, [0x42, 1, 0x41, 0x00, 0x00]));   // CAR + padding, exported as read
        r.Files.Add(new EmrtdFile(CardFiles.DirName, 0x1E, 0, [0x61, 0x03, 0x4F, 0x01, 0x01, 0x61, 0x03, 0x4F, 0x01, 0x02], 0x2F00));
        r.Files.Add(new EmrtdFile(CardFiles.AtrInfoName, 0x01, 0, [0x43, 0x01, 0xB8, 0x47, 0x03, 0x86, 0x01, 0xE0], 0x2F01));
        r.DataGroups[1] = r.Files[1].Data;
        r.DataGroupsListed.AddRange([1, 2]);
        r.Steps.Add(ReadStep.ReadFailed("EF.DG2", "EF.DG2: 6982 Sicherheitszustand nicht erfüllt"));
        r.Steps.Add(new ReadStep("Chip Authentication", StepOutcome.Success, ""));
        return r;
    }

    [Fact]
    public void Idl_SetFolderAndProjectJson_FollowTheExchangeFormat()
    {
        var export = DocumentSet.FromEmrtd(IdlResult(), isIdl: true, can: "123456");
        var root = Path.Combine(Path.GetTempPath(), "edoc_set_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            var dir = DocumentSet.Write(export, root);
            Assert.StartsWith("IDL_unbekannt_", Path.GetFileName(dir));
            var bytes = File.ReadAllBytes(Path.Combine(dir, "project.json"));
            Assert.False(bytes is [0xEF, 0xBB, 0xBF, ..]);                    // UTF-8 without BOM
            using var json = JsonDocument.Parse(bytes);
            var p = json.RootElement;
            Assert.Equal(1, p.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("reader", p.GetProperty("source").GetString());
            Assert.Equal("IDL", p.GetProperty("documentType").GetString());
            Assert.Equal("PACE", p.GetProperty("authentication").GetString());
            Assert.Equal("123456", p.GetProperty("can").GetString());
            Assert.Equal("PACE-CAN", p.GetProperty("origin").GetProperty("accessProtocol").GetString());
            Assert.Equal("OK", p.GetProperty("origin").GetProperty("chipAuthentication").GetString());
            Assert.Equal("6982 Sicherheitszustand nicht erfüllt", p.GetProperty("origin").GetProperty("notRead").GetProperty("DG2").GetString());
            Assert.False(p.TryGetProperty("paChain", out _));

            var files = p.GetProperty("files").EnumerateArray().ToList();
            Assert.Equal(["EF.COM", "DG1", "EF.CVCA", "EF.DIR", "EF.ATR/INFO"], files.Select(f => f.GetProperty("name").GetString()));
            // Sequences of data objects are exported byte-exact, '/' is not used in the file name.
            var atr = files[4];
            Assert.Equal("ef/EF.ATR_INFO.bin", atr.GetProperty("path").GetString());
            Assert.Equal("2F01", atr.GetProperty("fileId").GetString());
            Assert.Equal(JsonValueKind.Null, atr.GetProperty("dataGroup").ValueKind);
            Assert.Equal(8, File.ReadAllBytes(Path.Combine(dir, "ef", "EF.ATR_INFO.bin")).Length);
            Assert.Equal(10, File.ReadAllBytes(Path.Combine(dir, "ef", "EF.DIR.bin")).Length);
            Assert.Equal(5, File.ReadAllBytes(Path.Combine(dir, "ef", "EF.CVCA.bin")).Length);
            Assert.Equal("001C", files[2].GetProperty("fileId").GetString());
            Assert.Equal(JsonValueKind.Null, files[0].GetProperty("dataGroup").ValueKind);   // present, null
            var dg1 = files[1];
            Assert.Equal(1, dg1.GetProperty("dataGroup").GetInt32());
            Assert.Equal("0001", dg1.GetProperty("fileId").GetString());
            Assert.Equal("ef/DG1.bin", dg1.GetProperty("path").GetString());
            var content = File.ReadAllBytes(Path.Combine(dir, "ef", "DG1.bin"));
            Assert.Equal(0x61, content[0]);
            Assert.Equal(content.Length, dg1.GetProperty("length").GetInt32());   // padding removed
            Assert.Equal(Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(), dg1.GetProperty("sha256").GetString());
            Assert.Contains(p.GetProperty("origin").GetProperty("notes").EnumerateArray(), n => n.GetString()!.Contains("Padding"));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData("EF.DG14", 14, "DG14.bin")]
    [InlineData("EF.SOD", 0, "EF.SOD.bin")]
    [InlineData("EF.CardAccess", 0, "EF.CardAccess.bin")]
    [InlineData("EF.ATR/INFO", 0, "EF.ATR_INFO.bin")]
    [InlineData("EF.DIR", 0, "EF.DIR.bin")]
    [InlineData("EF.CVCA", 0, "EF.CVCA.bin")]
    public void SingleFileNames(string name, int dg, string expected) =>
        Assert.Equal(expected, DocumentSet.SingleFileName(new EmrtdFile(name, 0, dg, [])));

    [Theory]
    [InlineData(SetDocumentType.Icao, "DG2", 2, "0102")]
    [InlineData(SetDocumentType.Icao, "EF.COM", null, "011E")]
    [InlineData(SetDocumentType.Idl, "DG4", 4, "0004")]
    [InlineData(SetDocumentType.Idl, "EF.SOD", null, "001D")]
    [InlineData(SetDocumentType.Idl, "EF.CardAccess", null, "011C")]
    [InlineData(SetDocumentType.Icao, "EF.CVCA", null, "011C")]
    [InlineData(SetDocumentType.Icao, "EF.DIR", null, "2F00")]
    [InlineData(SetDocumentType.Icao, "EF.ATR/INFO", null, "2F01")]
    public void FileIds_FollowTheStandardTables(SetDocumentType type, string name, int? dg, string fid) =>
        Assert.Equal(fid, DocumentSet.FileId(type, name, dg, null));

    [Fact]
    public void Trim_KeepsExactTlv() =>
        Assert.Null(DocumentSet.TrimToTlv("DG1", [0x61, 0x03, 0x53, 0x01, 0x41], null, 1).Note);
}
