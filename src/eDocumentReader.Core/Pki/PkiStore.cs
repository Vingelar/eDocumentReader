using System.Security.Cryptography;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace eDocumentReader.Core.Pki;

public enum PkiItemKind { Csca, DocumentSigner, MasterList, Crl, Cvc, TerminalKey, Unknown }

public sealed record ImportResult(string File, PkiItemKind Kind, string Description, int Count = 1);

/// <summary>A terminal (Inspection System) certificate with matching private key.</summary>
public sealed record TerminalCredential(CvCertificate Certificate, AsymmetricKeyParameter PrivateKey);

/// <summary>
/// Folder-based PKI store: X.509 CSCA/DS certificates, CSCA Master Lists (ICAO 9303-12 9), CRLs,
/// CV certificates (TR-03110-3 C) and terminal private keys (PKCS#8).
/// Layout: &lt;root&gt;\csca, \ds, \crl, \masterlist, \cvc, \keys
/// </summary>
public sealed class PkiStore
{
    private static readonly X509CertificateParser CertParser = new();
    public string Root { get; }
    public List<X509Certificate> Cscas { get; } = [];
    public List<X509Certificate> DocumentSigners { get; } = [];
    public List<X509Crl> Crls { get; } = [];
    public List<CvCertificate> CvCertificates { get; } = [];
    public List<(string File, AsymmetricKeyParameter Key)> PrivateKeys { get; } = [];
    public List<string> Errors { get; } = [];

    public static string DefaultRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "eDocumentReader", "pki");

    public PkiStore(string? root = null)
    {
        Root = root ?? DefaultRoot;
        foreach (var d in new[] { "csca", "ds", "crl", "masterlist", "cvc", "keys" }) Directory.CreateDirectory(Path.Combine(Root, d));
        Reload();
    }

    public void Reload()
    {
        Cscas.Clear(); DocumentSigners.Clear(); Crls.Clear(); CvCertificates.Clear(); PrivateKeys.Clear(); Errors.Clear();
        foreach (var f in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
        {
            try { Load(f, File.ReadAllBytes(f), persist: false); }
            catch (Exception ex) { Errors.Add($"{Path.GetFileName(f)}: {ex.Message}"); }
        }
    }

    /// <summary>Imports a file into the store (copied into the matching sub folder).</summary>
    public List<ImportResult> Import(string file) => Load(file, File.ReadAllBytes(file), persist: true);

    private List<ImportResult> Load(string file, byte[] data, bool persist)
    {
        var results = new List<ImportResult>();
        data = DecodePem(data, out var pemType);
        var kind = Detect(data, pemType);
        switch (kind)
        {
            case PkiItemKind.Cvc:
            {
                var cvc = new CvCertificate(data);
                if (!CvCertificates.Any(c => c.Encoded.AsSpan().SequenceEqual(data))) CvCertificates.Add(cvc);
                if (persist) Save("cvc", SafeName(cvc.Chr) + ".cvcert", data);
                results.Add(new ImportResult(file, kind, cvc.Describe()));
                break;
            }
            case PkiItemKind.TerminalKey:
            {
                var key = PrivateKeyFactory.CreateKey(data);
                PrivateKeys.Add((file, key));
                var name = FindCertificateForKey(key)?.Chr;
                if (persist) Save("keys", SafeName(name ?? Path.GetFileNameWithoutExtension(file)) + ".pkcs8", data);
                results.Add(new ImportResult(file, kind, T($"Privater Schlüssel ({key.GetType().Name}){(name != null ? $" passend zu CVC {name}" : " – kein passendes CV-Zertifikat geladen")}", $"Private key ({key.GetType().Name}){(name != null ? $" matching CVC {name}" : " – no matching CV certificate loaded")}")));
                break;
            }
            case PkiItemKind.MasterList:
            {
                var certs = ParseMasterList(data, out var signer);
                var verification = VerifyMasterList(data, certs);
                foreach (var c in certs) AddCsca(c);
                if (persist) Save("masterlist", Path.GetFileName(file), data);
                results.Add(new ImportResult(file, kind, T($"CSCA Master List{(signer != null ? $" von {signer.SubjectDN}" : "")}: {certs.Count} Zertifikate; {verification}", $"CSCA Master List{(signer != null ? $" from {signer.SubjectDN}" : "")}: {certs.Count} certificates; {verification}"), certs.Count));
                break;
            }
            case PkiItemKind.Crl:
            {
                var crl = new X509CrlParser().ReadCrl(data);
                Crls.Add(crl);
                if (persist) Save("crl", Path.GetFileName(file), data);
                results.Add(new ImportResult(file, kind, T($"CRL von {crl.IssuerDN}, nächste Aktualisierung {crl.NextUpdate:yyyy-MM-dd}", $"CRL from {crl.IssuerDN}, next update {crl.NextUpdate:yyyy-MM-dd}")));
                break;
            }
            case PkiItemKind.Csca or PkiItemKind.DocumentSigner:
            {
                var cert = CertParser.ReadCertificate(data);
                var isCa = IsCa(cert);
                if (isCa) AddCsca(cert); else if (!DocumentSigners.Any(c => c.Equals(cert))) DocumentSigners.Add(cert);
                if (persist) Save(isCa ? "csca" : "ds", Path.GetFileNameWithoutExtension(file) + ".cer", cert.GetEncoded());
                results.Add(new ImportResult(file, isCa ? PkiItemKind.Csca : PkiItemKind.DocumentSigner, cert.SubjectDN.ToString()));
                break;
            }
            default:
                throw new NotSupportedException(T("Dateityp nicht erkannt (erwartet X.509, CRL, Master List, CVC oder PKCS#8).", "File type not recognized (expected X.509, CRL, Master List, CVC or PKCS#8)."));
        }
        return results;
    }

    private void AddCsca(X509Certificate cert)
    {
        if (!Cscas.Any(c => c.Equals(cert))) Cscas.Add(cert);
    }

    private void Save(string folder, string name, byte[] data)
    {
        var target = Path.Combine(Root, folder, name);
        File.WriteAllBytes(target, data);
    }

    private static string SafeName(string s) => string.Concat(s.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

    private static byte[] DecodePem(byte[] data, out string? type)
    {
        type = null;
        var text = System.Text.Encoding.ASCII.GetString(data);
        if (!text.Contains("-----BEGIN ", StringComparison.Ordinal)) return data;
        using var reader = new StringReader(text);
        var pem = new Org.BouncyCastle.Utilities.IO.Pem.PemReader(reader).ReadPemObject();
        type = pem.Type;
        return pem.Content;
    }

    public static PkiItemKind Detect(byte[] data, string? pemType = null)
    {
        if (data.Length > 2 && data[0] == 0x7F && data[1] == 0x21) return PkiItemKind.Cvc;
        if (pemType is "PRIVATE KEY" or "EC PRIVATE KEY" or "RSA PRIVATE KEY") return PkiItemKind.TerminalKey;
        if (pemType == "X509 CRL") return PkiItemKind.Crl;
        Asn1Sequence seq;
        try { seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(data)); }
        catch { return PkiItemKind.Unknown; }
        if (seq.Count >= 2 && seq[0] is DerObjectIdentifier oid && oid.Id == "1.2.840.113549.1.7.2") return PkiItemKind.MasterList;
        if (seq.Count == 3 && seq[0] is DerInteger && seq[1] is Asn1Sequence && seq[2] is Asn1OctetString) return PkiItemKind.TerminalKey;
        if (seq.Count == 3 && seq[0] is Asn1Sequence tbs)
        {
            // TBSCertificate starts with [0] version; TBSCertList with optional INTEGER version and AlgorithmIdentifier.
            if (tbs[0] is Asn1TaggedObject) return PkiItemKind.Csca;
            return PkiItemKind.Crl;
        }
        return PkiItemKind.Unknown;
    }

    private static bool IsCa(X509Certificate c) => c.GetBasicConstraints() >= 0 || c.SubjectDN.Equivalent(c.IssuerDN);

    /// <summary>CSCA Master List: CMS SignedData, eContentType id-icao-cscaMasterList (2.23.136.1.1.2), ICAO 9303-12 9.</summary>
    public static List<X509Certificate> ParseMasterList(byte[] data, out X509Certificate? signer)
    {
        var cms = new CmsSignedData(data);
        if (cms.SignedContentType.Id != "2.23.136.1.1.2") throw new FormatException(T($"eContentType {cms.SignedContentType.Id} ist keine CSCA Master List.", $"eContentType {cms.SignedContentType.Id} is not a CSCA Master List."));
        var sd = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(cms.ContentInfo.Content);
        var content = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(Asn1OctetString.GetInstance(sd.EncapContentInfo.Content).GetOctets()));
        var list = new List<X509Certificate>();
        foreach (var e in Asn1Set.GetInstance(content[1])) list.Add(new X509Certificate(X509CertificateStructure.GetInstance(e)));
        var si = cms.GetSignerInfos().GetSigners().FirstOrDefault();
        signer = si == null ? null : cms.GetCertificates().EnumerateMatches(null).FirstOrDefault(c => si.SignerID.Match(c));
        return list;
    }

    /// <summary>
    /// Verifies the Master List CMS signature with the Master List Signer certificate and that certificate against a CSCA
    /// of the same country (contained in the list or already trusted) – ICAO 9303-12 9.
    /// </summary>
    public string VerifyMasterList(byte[] data, IReadOnlyList<X509Certificate> listCertificates)
    {
        var cms = new CmsSignedData(data);
        var si = cms.GetSignerInfos().GetSigners().FirstOrDefault();
        if (si == null) return T("keine SignerInfo", "no SignerInfo");
        var signer = cms.GetCertificates().EnumerateMatches(null).FirstOrDefault(c => si.SignerID.Match(c));
        if (signer == null) return T("Master List Signer-Zertifikat fehlt – Signatur nicht prüfbar", "Master List signer certificate missing – signature cannot be verified");
        if (!si.Verify(signer)) return T("CMS-Signatur UNGÜLTIG", "CMS signature INVALID");
        var issuer = listCertificates.Concat(Cscas).FirstOrDefault(c => c.SubjectDN.Equivalent(signer.IssuerDN) && Verifies(signer, c));
        return issuer == null
            ? T("CMS-Signatur gültig, Signer-Zertifikat aber keiner CSCA zuordenbar", "CMS signature valid, but the signer certificate matches no CSCA")
            : T($"CMS-Signatur gültig, Signer-Zertifikat von CSCA „{issuer.SubjectDN}“ (Serial {issuer.SerialNumber:X}) ausgestellt{(signer.IsValid(DateTime.UtcNow) ? "" : ", Signer-Zertifikat ABGELAUFEN")}", $"CMS signature valid, signer certificate issued by CSCA \"{issuer.SubjectDN}\" (serial {issuer.SerialNumber:X}){(signer.IsValid(DateTime.UtcNow) ? "" : ", signer certificate EXPIRED")}");

        static bool Verifies(X509Certificate cert, X509Certificate issuer)
        {
            try { cert.Verify(issuer.GetPublicKey()); return true; } catch { return false; }
        }
    }

    // ---------------- Passive Authentication chain ----------------

    public sealed record ChainResult(bool Valid, X509Certificate? Csca, List<string> Steps);

    /// <summary>Validates a Document Signer certificate against the stored CSCAs (ICAO 9303-12 / 9303-11 5.1, RFC 5280 subset).</summary>
    public ChainResult ValidateDocumentSigner(X509Certificate ds, DateTime? at = null, Logger? log = null)
    {
        var steps = new List<string>();
        var time = at ?? DateTime.UtcNow;
        var akiExt = ds.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        byte[]? aki = akiExt == null ? null : AuthorityKeyIdentifier.GetInstance(Asn1Object.FromByteArray(akiExt.GetOctets())).KeyIdentifier?.GetOctets();
        var candidates = Cscas.Where(c => c.SubjectDN.Equivalent(ds.IssuerDN)).ToList();
        if (aki != null)
        {
            var byKey = candidates.Where(c => SubjectKeyId(c) is { } ski && ski.AsSpan().SequenceEqual(aki)).ToList();
            if (byKey.Count > 0) candidates = byKey;
        }
        if (candidates.Count == 0)
        {
            steps.Add(T($"Kein CSCA-Zertifikat für Aussteller „{ds.IssuerDN}“{(aki != null ? $" (AKI {Hex.Compact(aki)})" : "")} im PKI-Speicher.", $"No CSCA certificate for issuer \"{ds.IssuerDN}\"{(aki != null ? $" (AKI {Hex.Compact(aki)})" : "")} in the PKI store."));
            return new ChainResult(false, null, steps);
        }
        foreach (var csca in candidates)
        {
            try
            {
                ds.Verify(csca.GetPublicKey());
            }
            catch (Exception ex)
            {
                steps.Add(T($"Signaturprüfung mit CSCA „{csca.SubjectDN}“ (Serial {csca.SerialNumber:X}) fehlgeschlagen: {ex.Message}", $"Signature check with CSCA \"{csca.SubjectDN}\" (serial {csca.SerialNumber:X}) failed: {ex.Message}"));
                continue;
            }
            steps.Add(T($"DS-Signatur mit CSCA „{csca.SubjectDN}“ (Serial {csca.SerialNumber:X}) gültig.", $"DS signature with CSCA \"{csca.SubjectDN}\" (serial {csca.SerialNumber:X}) valid."));
            var valid = true;
            if (!csca.IsValid(time)) { steps.Add(T($"CSCA zum Prüfzeitpunkt nicht gültig ({csca.NotBefore:yyyy-MM-dd} – {csca.NotAfter:yyyy-MM-dd}).", $"CSCA not valid at the time of verification ({csca.NotBefore:yyyy-MM-dd} – {csca.NotAfter:yyyy-MM-dd}).")); valid = false; }
            if (!ds.IsValid(time)) { steps.Add(T($"DS-Zertifikat zum Prüfzeitpunkt nicht gültig ({ds.NotBefore:yyyy-MM-dd} – {ds.NotAfter:yyyy-MM-dd}).", $"DS certificate not valid at the time of verification ({ds.NotBefore:yyyy-MM-dd} – {ds.NotAfter:yyyy-MM-dd}).")); valid = false; }
            foreach (var crl in Crls.Where(c => c.IssuerDN.Equivalent(csca.SubjectDN)))
            {
                // ICAO 9303-12: the CRL is issued by the CSCA (same DN) – typically signed with its current key,
                // which may differ from the key that signed the DS certificate.
                var crlSigner = Cscas.Where(c => c.SubjectDN.Equivalent(crl.IssuerDN)).FirstOrDefault(c =>
                {
                    try { crl.Verify(c.GetPublicKey()); return true; } catch { return false; }
                });
                if (crlSigner == null) { steps.Add(T($"CRL von {crl.IssuerDN} vom {crl.ThisUpdate:yyyy-MM-dd}: Signatur mit keinem CSCA-Schlüssel verifizierbar – ignoriert.", $"CRL from {crl.IssuerDN} of {crl.ThisUpdate:yyyy-MM-dd}: signature verifiable with no CSCA key – ignored.")); continue; }
                steps.Add(T($"CRL vom {crl.ThisUpdate:yyyy-MM-dd} (signiert von CSCA Serial {crlSigner.SerialNumber:X}) gültig{(crl.NextUpdate is { } nu && nu < time ? ", aber ABGELAUFEN" : "")}.", $"CRL of {crl.ThisUpdate:yyyy-MM-dd} (signed by CSCA serial {crlSigner.SerialNumber:X}) valid{(crl.NextUpdate is { } nu2 && nu2 < time ? ", but EXPIRED" : "")}."));
                if (crl.IsRevoked(ds)) { steps.Add(T("DS-Zertifikat ist laut CRL GESPERRT.", "DS certificate is REVOKED according to the CRL.")); valid = false; }
                else steps.Add(T("DS-Zertifikat ist nicht gesperrt.", "DS certificate is not revoked."));
            }
            if (!Crls.Any(c => c.IssuerDN.Equivalent(csca.SubjectDN))) steps.Add(T("Keine CRL der CSCA im PKI-Speicher – Sperrstatus unbekannt.", "No CRL of the CSCA in the PKI store – revocation status unknown."));
            return new ChainResult(valid, csca, steps);
        }
        return new ChainResult(false, null, steps);
    }

    private static byte[]? SubjectKeyId(X509Certificate c)
    {
        var ext = c.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
        return ext == null ? null : SubjectKeyIdentifier.GetInstance(Asn1Object.FromByteArray(ext.GetOctets())).GetKeyIdentifier();
    }

    // ---------------- Terminal Authentication chain ----------------

    public CvCertificate? FindCertificateForKey(AsymmetricKeyParameter privateKey)
    {
        foreach (var cvc in CvCertificates)
        {
            if (privateKey is ECPrivateKeyParameters ec && cvc.PublicKey.IsEc && cvc.PublicKey.Elements.TryGetValue(0x86, out var point))
            {
                var q = ec.Parameters.G.Multiply(ec.D).Normalize().GetEncoded(false);
                if (q.AsSpan().SequenceEqual(point)) return cvc;
            }
            if (privateKey is RsaPrivateCrtKeyParameters rsa && cvc.PublicKey.IsRsa && cvc.PublicKey.Elements.TryGetValue(0x81, out var n)
                && new Org.BouncyCastle.Math.BigInteger(1, n).Equals(rsa.Modulus)) return cvc;
        }
        return null;
    }

    /// <summary>
    /// Candidate trust points for a chip without EF.CVCA (IDL, ISO/IEC 18013-3): CHRs of self-signed CVCA certificates
    /// and the CARs of certificates whose issuer is not in the store, newest first.
    /// </summary>
    public List<string> CandidateTrustPoints() =>
        CvCertificates.Where(c => c.IsSelfSigned).OrderByDescending(c => c.ExpirationDate).Select(c => c.Chr)
            .Concat(CvCertificates.Where(c => !c.IsSelfSigned && CvCertificates.All(i => i.Chr != c.Car)).Select(c => c.Car))
            .Distinct().ToList();

    public List<TerminalCredential> TerminalCredentials() =>
        PrivateKeys.Select(k => (k.Key, Cert: FindCertificateForKey(k.Key))).Where(x => x.Cert != null && x.Cert.Role == CvRole.InspectionSystemOrTerminal)
            .Select(x => new TerminalCredential(x.Cert!, x.Key)).ToList();

    /// <summary>
    /// Builds a certificate chain to be sent to the chip: starting below the trust point referenced by
    /// <paramref name="chipCar"/> (EF.CVCA), optionally via CVCA link certificates, to a DV and a terminal certificate with key.
    /// </summary>
    public (List<CvCertificate> Chain, TerminalCredential Terminal)? BuildTerminalChain(string chipCar, string? terminalOid = TaOids.IdIs, DateOnly? today = null)
    {
        var date = today ?? DateOnly.FromDateTime(DateTime.UtcNow);
        foreach (var terminal in TerminalCredentials().Where(t => terminalOid == null || t.Certificate.ChatOid == terminalOid)
                     .OrderByDescending(t => t.Certificate.ExpirationDate))
        {
            var chain = new List<CvCertificate> { terminal.Certificate };
            var current = terminal.Certificate;
            var guard = 0;
            while (current.Car != chipCar && guard++ < 8)
            {
                var issuer = CvCertificates.Where(c => c.Chr == current.Car && !c.IsSelfSigned).OrderByDescending(c => c.ExpirationDate).FirstOrDefault();
                if (issuer == null) break;
                chain.Insert(0, issuer);
                current = issuer;
            }
            if (current.Car == chipCar) return (chain, terminal);
        }
        return null;
    }

    /// <summary>Domain parameters for EC keys in a chain are inherited from the CVCA certificate (TR-03110-3 D.3.3).</summary>
    public ECDomainParameters? FindDomainParameters(CvCertificate cert)
    {
        var current = cert;
        for (var i = 0; i < 8 && current != null; i++)
        {
            if (current.PublicKey.EcDomain() is { } d) return d;
            current = CvCertificates.FirstOrDefault(c => c.Chr == current.Car && c != current);
        }
        return null;
    }

    /// <summary>Checks the CV certificate chain signatures offline (CVCA → … → terminal).</summary>
    public List<string> VerifyCvChain(CvCertificate cert)
    {
        var report = new List<string>();
        var current = cert;
        // TR-03110-3 D.3.3: the CVCA certificate SHALL contain the domain parameters. Some test chains omit them;
        // then the curve of the matching EC terminal key is assumed (one domain per chain) and the deviation is reported.
        ECDomainParameters? fallback = null;
        if (FindDomainParameters(cert) == null && cert.PublicKey.IsEc)
        {
            fallback = PrivateKeys.Select(k => k.Key).OfType<ECPrivateKeyParameters>().Select(k => k.Parameters)
                .FirstOrDefault(d => { try { d.Curve.DecodePoint(cert.PublicKey.Elements[0x86]); return true; } catch { return false; } });
            report.Add(fallback != null
                ? T("⚠ CVCA ohne EC-Domain-Parameter (TR-03110-3 D.3.3) – Kurve des privaten Terminalschlüssels angenommen", "⚠ CVCA without EC domain parameters (TR-03110-3 D.3.3) – curve of the private terminal key assumed")
                : T("⚠ CVCA ohne EC-Domain-Parameter (TR-03110-3 D.3.3) und kein passender EC-Terminalschlüssel", "⚠ CVCA without EC domain parameters (TR-03110-3 D.3.3) and no matching EC terminal key"));
        }
        for (var i = 0; i < 8; i++)
        {
            var issuer = current.IsSelfSigned ? current : CvCertificates.FirstOrDefault(c => c.Chr == current.Car);
            if (issuer == null) { report.Add(T($"{current.Chr}: Aussteller {current.Car} nicht im Speicher.", $"{current.Chr}: issuer {current.Car} not in the store.")); break; }
            var domain = FindDomainParameters(issuer) ?? fallback;
            bool ok;
            try { ok = current.VerifySignature(issuer.PublicKey, domain); }
            catch (Exception ex) { report.Add(T($"{current.Chr}: Signaturprüfung nicht möglich: {ex.Message}", $"{current.Chr}: signature check not possible: {ex.Message}")); break; }
            report.Add(T($"{current.Chr}: Signatur durch {issuer.Chr} {(ok ? "gültig" : "UNGÜLTIG")}", $"{current.Chr}: signature by {issuer.Chr} {(ok ? "valid" : "INVALID")}"));
            if (current.IsSelfSigned) break;
            current = issuer;
        }
        return report;
    }
}
