using System.Security.Cryptography;

namespace eDocumentReader.Core.Crypto;

public enum SessionKeyType { DesEde, Aes128, Aes192, Aes256 }

/// <summary>Key derivation function according to ICAO 9303-11 clause 9.7.1 (identical to BSI TR-03110-3 A.2.3).</summary>
public static class Kdf
{
    public const uint CounterEnc = 1;
    public const uint CounterMac = 2;
    public const uint CounterPassword = 3;

    public static CipherAlgorithm Algorithm(SessionKeyType type) => type == SessionKeyType.DesEde ? CipherAlgorithm.DesEde : CipherAlgorithm.Aes;

    /// <summary>KDF(K, c) = H(K || c) with c as 32-bit big-endian counter; truncation/hash as per key type.</summary>
    public static byte[] Derive(ReadOnlySpan<byte> sharedSecret, uint counter, SessionKeyType type)
    {
        var input = new byte[sharedSecret.Length + 4];
        sharedSecret.CopyTo(input);
        input[^4] = (byte)(counter >> 24);
        input[^3] = (byte)(counter >> 16);
        input[^2] = (byte)(counter >> 8);
        input[^1] = (byte)counter;
        return type switch
        {
            // 3DES: SHA-1, two 8-byte keys Ka || Kb with adjusted parity (two-key 3DES).
            SessionKeyType.DesEde => SymmetricCrypto.AdjustParity(SHA1.HashData(input)[..16]),
            SessionKeyType.Aes128 => SHA1.HashData(input)[..16],
            SessionKeyType.Aes192 => SHA256.HashData(input)[..24],
            SessionKeyType.Aes256 => SHA256.HashData(input),
            _ => throw new ArgumentOutOfRangeException(nameof(type)),
        };
    }
}
