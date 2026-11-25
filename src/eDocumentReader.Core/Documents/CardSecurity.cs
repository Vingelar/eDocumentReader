using eDocumentReader.Core.Pki;
using eDocumentReader.Core.Protocols;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;

namespace eDocumentReader.Core.Documents;

/// <summary>
/// EF.CardSecurity (ICAO 9303-11 9.2.11, MF 011D, SFI 1D; TR-03110-3 A.1.2.5): CMS SignedData with eContentType
/// id-SecurityObject over SecurityInfos, signed by the Document Signer. Required for PACE-CAM.
/// </summary>
public sealed class CardSecurity
{
    public const string SecurityObjectOid = "0.4.0.127.0.7.3.2.1";
    public CmsSignedData SignedData { get; }
    public List<SecurityInfo> Infos { get; }
    public List<X509Certificate> Certificates { get; } = [];
    public List<string> Findings { get; } = [];

    public CardSecurity(byte[] data)
    {
        SignedData = new CmsSignedData(data);
        if (SignedData.SignedContentType.Id != SecurityObjectOid)
            Findings.Add($"eContentType {SignedData.SignedContentType.Id} ≠ id-SecurityObject {SecurityObjectOid} (TR-03110-3 A.1.2.5).");
        var sd = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(SignedData.ContentInfo.Content);
        Infos = SecurityInfos.Parse(Asn1OctetString.GetInstance(sd.EncapContentInfo.Content).GetOctets());
        foreach (var c in SignedData.GetCertificates().EnumerateMatches(null)) Certificates.Add(c);
    }

    public sealed record Check(bool SignatureValid, string SignatureDetail, X509Certificate? Signer, PkiStore.ChainResult? Chain)
    {
        /// <summary>Signature valid and the DS chains to a trusted CSCA (Passive Authentication of EF.CardSecurity).</summary>
        public bool Valid => SignatureValid && Chain?.Valid == true;
    }

    /// <summary>Signature with the embedded DS certificate and the DS → CSCA chain from the PKI store (ICAO 9303-11 5.1).</summary>
    public Check Verify(PkiStore? pki)
    {
        var (valid, signer, detail) = SecurityObject.VerifySigner(SignedData, Certificates);
        if (Findings.Count > 0) return new Check(false, string.Join(" ", Findings), signer, null);
        return new Check(valid, detail, signer, signer != null && pki != null ? pki.ValidateDocumentSigner(signer) : null);
    }
}
