using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace eDocumentReader.Core.Crypto;

public enum CipherAlgorithm { DesEde, Aes }

/// <summary>Block cipher primitives used by ICAO 9303-11 / BSI TR-03110 (9303-11 clause 9.8.6 / 9.8.7).</summary>
public static class SymmetricCrypto
{
    public static int BlockSize(CipherAlgorithm algorithm) => algorithm == CipherAlgorithm.Aes ? 16 : 8;

    /// <summary>ISO/IEC 9797-1 padding method 2: '80' followed by '00' up to a multiple of the block size.</summary>
    public static byte[] Pad(ReadOnlySpan<byte> data, int blockSize)
    {
        var length = (data.Length / blockSize + 1) * blockSize;
        var result = new byte[length];
        data.CopyTo(result);
        result[data.Length] = 0x80;
        return result;
    }

    /// <summary>Removes ISO/IEC 9797-1 padding method 2; throws if the padding is malformed.</summary>
    public static byte[] Unpad(ReadOnlySpan<byte> data)
    {
        var i = data.Length - 1;
        while (i >= 0 && data[i] == 0x00) i--;
        if (i < 0 || data[i] != 0x80) throw new System.Security.Cryptography.CryptographicException("UngÃ¼ltiges Padding (ISO/IEC 9797-1 Methode 2).");
        return data[..i].ToArray();
    }

    private static IBlockCipher Engine(CipherAlgorithm algorithm) => algorithm == CipherAlgorithm.Aes ? new AesEngine() : new DesEdeEngine();

    public static byte[] CbcEncrypt(CipherAlgorithm algorithm, byte[] key, byte[] iv, byte[] data) => Cbc(algorithm, key, iv, data, true);
    public static byte[] CbcDecrypt(CipherAlgorithm algorithm, byte[] key, byte[] iv, byte[] data) => Cbc(algorithm, key, iv, data, false);

    private static byte[] Cbc(CipherAlgorithm algorithm, byte[] key, byte[] iv, byte[] data, bool encrypt)
    {
        var bs = BlockSize(algorithm);
        if (data.Length % bs != 0) throw new System.Security.Cryptography.CryptographicException($"DatenlÃ¤nge {data.Length} ist kein Vielfaches der BlockgrÃ¶ÃŸe {bs}.");
        var cipher = new CbcBlockCipher(Engine(algorithm));
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        var output = new byte[data.Length];
        for (var off = 0; off < data.Length; off += bs) cipher.ProcessBlock(data, off, output, off);
        return output;
    }

    public static byte[] EcbEncryptBlock(CipherAlgorithm algorithm, byte[] key, byte[] block)
    {
        var engine = Engine(algorithm);
        engine.Init(true, new KeyParameter(key));
        var output = new byte[block.Length];
        engine.ProcessBlock(block, 0, output, 0);
        return output;
    }

    /// <summary>ISO/IEC 9797-1 MAC algorithm 3 (Retail MAC) with DES, zero IV; input must already be padded.</summary>
    public static byte[] RetailMac(byte[] key, byte[] paddedData)
    {
        var mac = new ISO9797Alg3Mac(new DesEngine());
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(paddedData, 0, paddedData.Length);
        var output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    /// <summary>AES-CMAC (NIST SP 800-38B) truncated to 8 bytes.</summary>
    public static byte[] Cmac8(byte[] key, byte[] data)
    {
        var mac = new CMac(new AesEngine(), 64);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var output = new byte[8];
        mac.DoFinal(output, 0);
        return output;
    }

    /// <summary>MAC as used for SM / BAC / PACE tokens. 3DES: Retail MAC over padded data. AES: CMAC over data as given.</summary>
    public static byte[] Mac(CipherAlgorithm algorithm, byte[] key, byte[] data) =>
        algorithm == CipherAlgorithm.Aes ? Cmac8(key, data) : RetailMac(key, data);

    /// <summary>Sets odd parity in each DES key byte (9303-11 9.7.1 / Appendix D.1 step 4).</summary>
    public static byte[] AdjustParity(byte[] key)
    {
        var result = (byte[])key.Clone();
        for (var i = 0; i < result.Length; i++)
        {
            var b = result[i] & 0xFE;
            var ones = System.Numerics.BitOperations.PopCount((uint)b);
            result[i] = (byte)(b | (ones % 2 == 0 ? 1 : 0));
        }
        return result;
    }
}

