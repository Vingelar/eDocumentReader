using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CoreJ2K;
using eDocumentReader.Core.Documents;

namespace eDocumentReader.App.Imaging;

/// <summary>Turns the image data of an ISO/IEC 19794-5 facial record into a WPF bitmap (JPEG via WIC, JPEG 2000 via CoreJ2K).</summary>
public static class FaceImageDecoder
{
    public static BitmapSource Decode(FaceImage face) => face.DataType switch
    {
        FaceImageDataType.Jpeg => DecodeJpeg(face.ImageData),
        FaceImageDataType.Jpeg2000 => DecodeJpeg2000(face.ImageData),
        _ => throw new NotSupportedException("Unbekanntes Bildformat."),
    };

    /// <summary>Raw image data with format detection (JPEG / JPEG 2000), e.g. IDL DG4 '5F40' or DG5 '5F43'.</summary>
    public static BitmapSource DecodeAny(byte[] data) => Idl.ImageFormat(data) switch
    {
        "JPEG" => DecodeJpeg(data),
        "unbekannt" => throw new NotSupportedException("Unbekanntes Bildformat."),
        _ => DecodeJpeg2000(data),
    };

    private static BitmapSource DecodeJpeg(byte[] data)
    {
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = new MemoryStream(data);
        image.EndInit();
        image.Freeze();
        return image;
    }

    private static BitmapSource DecodeJpeg2000(byte[] data)
    {
        using var image = J2kImage.FromBytes(data, (CoreJ2K.j2k.util.ParameterList)null!);
        int w = image.Width, h = image.Height, n = image.NumberOfComponents;
        // Samples deeper than 8 bit are scaled down for display; the raw codestream stays untouched.
        var channels = Enumerable.Range(0, Math.Min(n, 3)).Select(c => (Data: image.GetComponent(c), Shift: Math.Max(0, image.GetBitDepth(c) - 8))).ToArray();
        BitmapSource bitmap;
        if (channels.Length >= 3)
        {
            var pixels = new byte[w * h * 3];
            for (var i = 0; i < w * h; i++)
                for (var c = 0; c < 3; c++)
                    pixels[i * 3 + c] = Clamp(channels[c].Data[i] >> channels[c].Shift);
            bitmap = BitmapSource.Create(w, h, 96, 96, PixelFormats.Rgb24, null, pixels, w * 3);
        }
        else
        {
            var pixels = new byte[w * h];
            for (var i = 0; i < w * h; i++) pixels[i] = Clamp(channels[0].Data[i] >> channels[0].Shift);
            bitmap = BitmapSource.Create(w, h, 96, 96, PixelFormats.Gray8, null, pixels, w);
        }
        bitmap.Freeze();
        return bitmap;
    }

    private static byte Clamp(int v) => (byte)Math.Clamp(v, 0, 255);
}
