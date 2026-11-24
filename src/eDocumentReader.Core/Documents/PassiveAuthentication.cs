using eDocumentReader.Core.Pki;
using Org.BouncyCastle.X509;

namespace eDocumentReader.Core.Documents;

public sealed record PassiveAuthenticationResult(
    SecurityObject Sod,
    List<HashCheck> Hashes,
    bool SignatureValid,
    string SignatureDetail,
    X509Certificate? Signer,
    PkiStore.ChainResult? Chain)
{
    /// <summary>True only if every read data group matches, the SOD signature is valid and the DS chains to a trusted CSCA.</summary>
    public bool Valid => SignatureValid && Chain?.Valid == true && Hashes.All(h => h.Match != false);
}

/// <summary>Passive Authentication (ICAO 9303-11 5.1): SOD signature, DS → CSCA chain, data group hashes.</summary>
public static class PassiveAuthentication
{
    public static PassiveAuthenticationResult Verify(byte[] efSod, IReadOnlyDictionary<int, byte[]> dataGroups, PkiStore? pki)
    {
        var sod = new SecurityObject(efSod);
        var hashes = sod.Hashes.Select(h => sod.CheckDataGroup(h.DataGroup, dataGroups.GetValueOrDefault(h.DataGroup))).ToList();
        var (valid, signer, detail) = sod.VerifySignature();
        var chain = signer != null && pki != null ? pki.ValidateDocumentSigner(signer) : null;
        return new PassiveAuthenticationResult(sod, hashes, valid, detail, signer, chain);
    }
}
