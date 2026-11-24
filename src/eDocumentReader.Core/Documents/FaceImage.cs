using System.Buffers.Binary;
using eDocumentReader.Core.Tlv;

namespace eDocumentReader.Core.Documents;

public enum FaceImageDataType { Jpeg = 0, Jpeg2000 = 1, Unknown = 0xFF }

public sealed record FaceImage(int Index, FaceImageDataType DataType, int Width, int Height, byte ColourSpace, byte SourceType, byte[] ImageData, List<string> Findings)
{
    public string Describe() =>
        T($"Bild {Index}: {(DataType switch { FaceImageDataType.Jpeg => "JPEG", FaceImageDataType.Jpeg2000 => "JPEG 2000", _ => "unbekannt" })}, ", $"Image {Index}: {(DataType switch { FaceImageDataType.Jpeg => "JPEG", FaceImageDataType.Jpeg2000 => "JPEG 2000", _ => "unknown" })}, ") +
        T($"{Width}×{Height}, Farbraum {ColourSpace}, Quelle {SourceType}, {ImageData.Length} Bytes", $"{Width}×{Height}, colour space {ColourSpace}, source {SourceType}, {ImageData.Length} bytes");
}

/// <summary>
/// Face images from DG2: '75' → '7F61' (Biometric Information Group Template) → '7F60' (BIT) → 'A1' (BHT) + '5F2E' (BDB)
/// (ICAO 9303-10 4.7.2, ISO/IEC 7816-11). The BDB holds an ISO/IEC 19794-5:2005 facial record.
/// The 19794-5 text is not part of docs/standards; the field layout is the published 2005 record format.
/// </summary>
public static class FaceImageParser
{
    private const string Ref = "ICAO 9303-10 4.7.2 / ISO/IEC 19794-5:2005";

    public static List<FaceImage> ParseDg2(byte[] dg2)
    {
        var result = new List<FaceImage>();
        var root = BerTlv.ParseSingle(dg2);
        var group = root.Find(0x7F61) ?? throw new FormatException(T("DG2: Biometric Information Group Template '7F61' fehlt.", "DG2: Biometric Information Group Template '7F61' missing."));
        var index = 0;
        foreach (var bit in group.FindAll(0x7F60))
        {
            index++;
            var bdb = bit.Find(0x5F2E);
            if (bdb == null)
            {
                result.Add(new FaceImage(index, FaceImageDataType.Unknown, 0, 0, 0, 0, [],
                    [bit.Find(0x7F2E) != null ? T("BDB '7F2E' (ISO/IEC 39794-5) wird noch nicht unterstützt.", "BDB '7F2E' (ISO/IEC 39794-5) is not supported yet.") : T("Biometric Data Block '5F2E' fehlt.", "Biometric Data Block '5F2E' missing.")]));
                continue;
            }
            result.Add(ParseFacialRecord(index, bdb.Value));
        }
        var count = group.Find(0x02)?.Value;
        if (count is { Length: 1 } && count[0] != index && result.Count > 0)
            result[0].Findings.Add(T($"Anzahl Instanzen '02' = {count[0]}, gefunden {index} ({Ref}).", $"Number of instances '02' = {count[0]}, found {index} ({Ref})."));
        return result;
    }

    public static FaceImage ParseFacialRecord(int index, byte[] r)
    {
        var findings = new List<string>();
        // Facial Record Header (14 bytes): 'FAC\0', version '010\0', record length (4), number of facial images (2)
        if (r.Length < 46 || r[0] != 'F' || r[1] != 'A' || r[2] != 'C' || r[3] != 0)
            return new FaceImage(index, FaceImageDataType.Unknown, 0, 0, 0, 0, [], [T("Kein ISO/IEC-19794-5-Datensatz (Format-ID 'FAC\\0' fehlt).", "Not an ISO/IEC 19794-5 record (format ID 'FAC\\0' missing).")]);
        var version = System.Text.Encoding.ASCII.GetString(r, 4, 3);
        if (version != "010") findings.Add(T($"Version '{version}' statt '010' (ISO/IEC 19794-5:2005).", $"Version '{version}' instead of '010' (ISO/IEC 19794-5:2005)."));
        var recordLength = BinaryPrimitives.ReadUInt32BigEndian(r.AsSpan(8));
        if (recordLength != r.Length) findings.Add(T($"Record Length {recordLength} ≠ BDB-Länge {r.Length}.", $"Record length {recordLength} ≠ BDB length {r.Length}."));
        var faces = BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(12));
        if (faces != 1) findings.Add(T($"{faces} Gesichtsbilder in einem Datensatz – nur das erste wird angezeigt.", $"{faces} facial images in one record – only the first is shown."));

        // Facial Information (20 bytes) starting at offset 14
        var p = 14;
        var blockLength = (int)BinaryPrimitives.ReadUInt32BigEndian(r.AsSpan(p));
        var featurePoints = BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(p + 4));
        p += 20 + 8 * featurePoints;
        if (p + 12 > r.Length) return new FaceImage(index, FaceImageDataType.Unknown, 0, 0, 0, 0, [], [.. findings, T("Datensatz zu kurz für Image Information.", "Record too short for the image information.")]);

        // Image Information (12 bytes): face image type, image data type, width, height, colour space, source type, device type, quality
        var dataType = r[p + 1] switch { 0 => FaceImageDataType.Jpeg, 1 => FaceImageDataType.Jpeg2000, _ => FaceImageDataType.Unknown };
        if (dataType == FaceImageDataType.Unknown) findings.Add(T($"Image Data Type {r[p + 1]:X2} unbekannt.", $"Image data type {r[p + 1]:X2} unknown."));
        var width = BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(p + 2));
        var height = BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(p + 4));
        var colour = r[p + 6];
        var source = r[p + 7];
        p += 12;

        var imageLength = blockLength - 20 - 8 * featurePoints - 12;
        if (imageLength <= 0 || p + imageLength > r.Length)
        {
            findings.Add(T($"Facial Record Data Length {blockLength} passt nicht zur Datenlänge – Bilddaten bis Datensatzende verwendet.", $"Facial record data length {blockLength} does not match the data length – image data up to the end of the record used."));
            imageLength = r.Length - p;
        }
        return new FaceImage(index, dataType, width, height, colour, source, r[p..(p + imageLength)], findings);
    }
}
