using System.Text;
using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace eDocumentReader.Core.Documents;

public sealed record EvrcField(string Path, string TagHex, string Name, string Value, List<string> Findings);

public sealed record EvrcSignatureCheck(string Part, bool? Valid, string Detail, X509Certificate? Certificate);

public sealed class EvrcReadResult
{
    public List<EmrtdFile> Files { get; } = [];
    public List<ReadStep> Steps { get; } = [];
    public List<EvrcField> Fields { get; } = [];
    public List<EvrcSignatureCheck> Signatures { get; } = [];
    /// <summary>Deviations of the card from the directive / ISO/IEC 7816-4 found while reading.</summary>
    public List<string> Findings { get; } = [];
    public byte[]? File(string name) => Files.FirstOrDefault(f => f.Name == name)?.Data;
}

/// <summary>
/// Electronic vehicle registration certificate, Commission Directive 2003/127/EC amending 1999/37/EC, Annex II Chapter III.
/// Application DF.Registration, files per Table 1 (III.10), data objects per Tables 2/3 (III.11), reading per III.12.
/// </summary>
public static class Evrc
{
    public const string Ref = "RL 2003/127/EG Anhang III";

    /// <summary>De-facto AID 'A0 00 00 04 56' + "EVR-01" (the directive leaves the AID to a laboratory selected by the Commission, III.12 A).</summary>
    public static readonly byte[] Aid = Hex.Parse("A000000456455652 2D3031");

    /// <summary>III.10 Table 1: (name, FID). Letter C files are Member State specific and not listed.</summary>
    public static readonly (string Name, ushort Fid)[] Files =
    [
        ("EF.Registration_A", 0xD001),
        ("EF.Signature_A", 0xE001),
        ("EF.C.IA_A.DS", 0xC001),
        ("EF.Registration_B", 0xD011),
        ("EF.Signature_B", 0xE011),
        ("EF.C.IA_B.DS", 0xC011),
    ];

    /// <summary>Tag meanings of III.11 Tables 2 and 3 (context: template '71' = Part 1 mandatory, '72' = Chapter II.6 optional).</summary>
    public static string? TagName(uint tag) => tag switch
    {
        0x78 => "Compatible tag allocation authority",
        0x4F => "Application Identifier",
        0x71 => "Pflichtdaten Teil I (II.4/II.5)",
        0x72 => "Optionale Daten Teil I (II.6)",
        0x80 => "Version der Tag-Definition",
        0x9F33 => "Ausstellender Mitgliedstaat",
        0x9F34 => "Andere (nationale) Dokumentbezeichnung",
        0x9F35 => "Zuständige Behörde",
        0x9F36 => "Ausstellende Behörde",
        0x9F37 => "Zeichensatz",
        0x9F38 => "Dokumentnummer",
        0x81 => "(A) Amtliches Kennzeichen",
        0x82 => "(B) Datum der Erstzulassung",
        0xA1 => "(C) Personendaten",
        0xA2 => "(C.1) Inhaber der Zulassungsbescheinigung",
        0x83 => "Name bzw. Firmenname",
        0x84 => "Vornamen oder Initialen",
        0x85 => "Anschrift",
        0x86 => "(C.4) Eigentümer-Status",
        0xA3 => "(D) Fahrzeug",
        0x87 => "(D.1) Marke",
        0x88 => "(D.2) Typ",
        0x89 => "(D.3) Handelsbezeichnung",
        0x8A => "(E) Fahrzeug-Identifizierungsnummer",
        0xA4 => "(F) Masse",
        0x8B => "(F.1) Technisch zulässige Gesamtmasse",
        0x8C => "(G) Leermasse mit Aufbau",
        0x8D => "(H) Gültigkeitsdauer",
        0x8E => "(I) Datum der Zulassung",
        0x8F => "(K) Typgenehmigungsnummer",
        0xA5 => "(P) Motor",
        0x90 => "(P.1) Hubraum",
        0x91 => "(P.2) Nennleistung",
        0x92 => "(P.3) Kraftstoffart",
        0x93 => "(Q) Leistungsgewicht",
        0xA6 => "(S) Sitzplätze",
        0x94 => "(S.1) Sitzplätze",
        0x95 => "(S.2) Stehplätze",
        0xA7 => "(C.2) Eigentümer",
        0xA8 => "(C.2) Zweiter Eigentümer",
        0xA9 => "(C.3) Verfügungsberechtigte Person",
        0x96 => "(F.2) Zulässige Gesamtmasse im Betrieb",
        0x97 => "(F.3) Zulässige Gesamtmasse der Fahrzeugkombination",
        0x98 => "(J) Fahrzeugklasse",
        0x99 => "(L) Anzahl Achsen",
        0x9A => "(M) Radstand",
        0xAD => "(N) Achslastverteilung",
        0x9F1F => "(N.1) Achse 1",
        0x9F20 => "(N.2) Achse 2",
        0x9F21 => "(N.3) Achse 3",
        0x9F22 => "(N.4) Achse 4",
        0x9F23 => "(N.5) Achse 5",
        0xAE => "(O) Anhängelast",
        0x9B => "(O.1) gebremst",
        0x9C => "(O.2) ungebremst",
        0x9D => "(P.4) Nenndrehzahl",
        0x9E => "(P.5) Motorkennnummer",
        0x9F24 => "(R) Farbe",
        0x9F25 => "(T) Höchstgeschwindigkeit",
        0xAF => "(U) Geräuschpegel",
        0x9F26 or 0xDF26 => "(U.1) Standgeräusch",
        0x9F27 or 0xDF27 => "(U.2) Drehzahl",
        0x9F28 or 0xDF28 => "(U.3) Fahrgeräusch",
        0xB0 => "(V) Abgaswerte",
        0x9F29 => "(V.1) CO",
        0x9F2A => "(V.2) HC",
        0x9F2B => "(V.3) NOx",
        0x9F2C => "(V.4) HC+NOx",
        0x9F2D => "(V.5) Partikel (Diesel)",
        0x9F2E => "(V.6) Absorptionskoeffizient (Diesel)",
        0x9F2F => "(V.7) CO2",
        0x9F30 => "(V.8) Kombinierter Kraftstoffverbrauch",
        0x9F31 => "(V.9) Umweltklasse",
        0x9F32 => "(W) Tankinhalt",
        _ => null,
    };

    private static readonly HashSet<uint> DateTags = [0x82, 0x8E];

    /// <summary>The character set object '9F37' of EF.Registration_A (Table 2); Table 3 (Letter B) has no own '9F37'.</summary>
    public static byte[]? CharsetValue(byte[] registrationA)
    {
        try { return BerTlv.ParseAll(registrationA).Select(o => o.FindRecursive(0x9F37)).FirstOrDefault(t => t != null)?.Value; }
        catch (TlvException) { return null; }
    }

    /// <summary>Decodes EF.Registration_A/B into display fields; value encoding per III.11 and '9F37' of Letter A.</summary>
    public static List<EvrcField> ParseRegistration(byte[] data, string file, byte[]? charset)
    {
        var fields = new List<EvrcField>();
        List<BerTlv> objects;
        try { objects = BerTlv.ParseAll(data); }
        catch (TlvException ex)
        {
            fields.Add(new EvrcField(file, "", "TLV-Fehler", ex.Message, [ex.Message]));
            return fields;
        }
        var encoding = Charset(charset, out _);
        foreach (var o in objects) Walk(o, file, encoding, fields);
        return fields;
    }

    /// <summary>'9F37': '00' Latin-1, '01' ISO/IEC 8859-5, '02' ISO/IEC 8859-7 (Table 2). ASCII digits "00"… are accepted with a finding.</summary>
    public static Encoding Charset(byte[]? value, out string? finding)
    {
        finding = null;
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var code = value switch
        {
            [var b] when b <= 2 => b,
            [(byte)'0', var d] when d is >= (byte)'0' and <= (byte)'2' => (byte)(d - '0'),
            _ => (byte)0xFF,
        };
        if (value == null) finding = "Zeichensatz '9F37' fehlt – Latin-1 angenommen (III.11 Tabelle 2).";
        else if (code == 0xFF) finding = $"Zeichensatz '9F37' = {Hex.Of(value)} nicht definiert (nur '00'/'01'/'02') – Latin-1 angenommen.";
        else if (value.Length == 2) finding = $"Zeichensatz '9F37' ist als ASCII-Text \"{Encoding.ASCII.GetString(value)}\" kodiert statt als Byte '{code:X2}' (III.11 Tabelle 2) – als Code {code:X2} interpretiert.";
        return code switch
        {
            1 => Encoding.GetEncoding("iso-8859-5"),
            2 => Encoding.GetEncoding("iso-8859-7"),
            _ => Encoding.Latin1,
        };
    }

    private static void Walk(BerTlv tlv, string path, Encoding encoding, List<EvrcField> fields)
    {
        var name = TagName(tlv.Tag) ?? $"Tag {tlv.TagHex} (nicht in Tabelle 2/3)";
        var findings = tlv.Findings.ToList();
        if (TagName(tlv.Tag) == null) findings.Add($"Tag {tlv.TagHex} ist in {Ref} Tabelle 2/3 nicht definiert (ggf. nationale Daten).");
        if (tlv.Tag is 0xDF26 or 0xDF27 or 0xDF28) findings.Add($"Tag {tlv.TagHex}: Tabelle 3 nennt im Text 'DF26'–'DF28', in der Tag-Spalte aber '9F26'–'9F28'.");
        if (tlv.IsConstructed)
        {
            fields.Add(new EvrcField(path, tlv.TagHex, name, "", findings));
            foreach (var c in tlv.Children) Walk(c, path + "/" + tlv.TagHex, encoding, fields);
            return;
        }
        string value;
        switch (tlv.Tag)
        {
            case 0x4F:
                value = Hex.Of(tlv.Value);
                break;
            case 0x9F37:
                var cs = Charset(tlv.Value, out var csFinding);
                value = $"{Hex.Of(tlv.Value)} → {cs.WebName}";
                if (csFinding != null) findings.Add(csFinding);
                break;
            case 0x86 when tlv.Value is [<= 2]:
                value = tlv.Value[0] switch { 0 => "00 – ist Eigentümer", 1 => "01 – ist nicht Eigentümer", _ => "02 – nicht als Eigentümer ausgewiesen" };
                break;
            case 0x86:
                value = encoding.GetString(tlv.Value);
                findings.Add("'86' enthält Text statt eines der Codes '00'/'01'/'02' (III.11 Tabelle 2).");
                break;
            default:
                value = encoding.GetString(tlv.Value);
                break;
        }
        if (tlv.Tag == 0x4F && tlv.Value.All(b => Uri.IsHexDigit((char)b)) && tlv.Value.Length % 2 == 0)
            findings.Add($"AID '4F' ist als ASCII-Text \"{Encoding.ASCII.GetString(tlv.Value)}\" kodiert statt binär (ISO/IEC 7816-4 8.2.1.2: AID = Bytefolge).");
        if (DateTags.Contains(tlv.Tag) && !IsYyyyMmDd(value)) findings.Add($"Datum '{value}' nicht im Format JJJJMMTT (III.11).");
        if (DateTags.Contains(tlv.Tag) && IsYyyyMmDd(value)) value = $"{value} ({value[6..8]}.{value[4..6]}.{value[..4]})";
        fields.Add(new EvrcField(path, tlv.TagHex, name, value, findings));
    }

    private static bool IsYyyyMmDd(string s) => s.Length == 8 && s.All(char.IsAsciiDigit) && DateOnly.TryParseExact(s, "yyyyMMdd", out _);

    /// <summary>
    /// Verifies EF.Signature_x over the complete content of EF.Registration_x with the key from EF.C.IA_x.DS (III.2 D, III.12 C).
    /// The directive does not fix the signature scheme; RSA signatures are opened with the public key to identify
    /// PKCS#1 v1.5 and the hash from the DigestInfo, otherwise RSA-PSS and ECDSA (plain/DER) are tried with common hashes.
    /// </summary>
    public static EvrcSignatureCheck VerifySignature(string part, byte[]? data, byte[]? signature, byte[]? certificateDer)
    {
        if (data == null) return new EvrcSignatureCheck(part, null, "Registrierungsdaten nicht gelesen", null);
        if (signature == null) return new EvrcSignatureCheck(part, null, "Signaturdatei nicht gelesen", null);
        if (certificateDer == null) return new EvrcSignatureCheck(part, null, "Zertifikat nicht gelesen", null);
        X509Certificate cert;
        try { cert = new X509CertificateParser().ReadCertificate(certificateDer) ?? throw new FormatException("leer"); }
        catch (Exception ex) { return new EvrcSignatureCheck(part, false, $"Zertifikat kein gültiges X.509v3 (ISO/IEC 9594-8): {ex.Message}", null); }

        var key = cert.GetPublicKey();
        string[] hashes = ["SHA-256", "SHA-1", "SHA-384", "SHA-512", "SHA-224"];
        if (key is RsaKeyParameters rsa)
        {
            var k = (rsa.Modulus.BitLength + 7) / 8;
            var s = new BigInteger(1, signature);
            if (signature.Length == k && s.CompareTo(rsa.Modulus) < 0)
            {
                var em = s.ModPow(rsa.Exponent, rsa.Modulus).ToByteArrayUnsigned();
                em = [.. new byte[k - em.Length], .. em];
                if (em[0] == 0x00 && em[1] == 0x01)
                {
                    var sep = Array.IndexOf(em, (byte)0x00, 2);
                    if (sep > 9 && em[2..sep].All(b => b == 0xFF))
                    {
                        try
                        {
                            var di = DigestInfo.GetInstance(em[(sep + 1)..]);
                            var oid = di.DigestAlgorithm.Algorithm.Id;
                            var actual = DigestUtilities.CalculateDigest(oid, data);
                            var ok = actual.AsSpan().SequenceEqual(di.Digest.GetOctets());
                            return new EvrcSignatureCheck(part, ok, $"RSA-{rsa.Modulus.BitLength} PKCS#1 v1.5, {Oids.Name(oid)}: {(ok ? "Signatur gültig" : "Hash stimmt NICHT")}", cert);
                        }
                        catch (Exception ex) { return new EvrcSignatureCheck(part, false, $"PKCS#1-v1.5-Block ohne gültige DigestInfo: {ex.Message}", cert); }
                    }
                }
            }
            foreach (var h in hashes)
                if (TryVerify($"{h.Replace("-", "")}withRSAandMGF1", cert, data, signature))
                    return new EvrcSignatureCheck(part, true, $"RSA-{rsa.Modulus.BitLength} PSS, {h}: Signatur gültig", cert);
            return new EvrcSignatureCheck(part, false, $"RSA-{rsa.Modulus.BitLength}: Signatur passt zu keinem geprüften Verfahren (PKCS#1 v1.5, PSS mit SHA-1/2)", cert);
        }
        if (key is ECPublicKeyParameters)
        {
            foreach (var h in hashes)
                foreach (var (scheme, label) in new[] { ("PLAIN-ECDSA", "ECDSA plain r‖s"), ("ECDSA", "ECDSA DER") })
                    if (TryVerify($"{h.Replace("-", "")}with{scheme}", cert, data, signature))
                        return new EvrcSignatureCheck(part, true, $"{label}, {h}: Signatur gültig", cert);
            return new EvrcSignatureCheck(part, false, "ECDSA: Signatur passt zu keiner geprüften Hash-/Kodierungsvariante", cert);
        }
        return new EvrcSignatureCheck(part, false, $"Schlüsseltyp {key.GetType().Name} nicht unterstützt", cert);
    }

    private static bool TryVerify(string algorithm, X509Certificate cert, byte[] data, byte[] signature)
    {
        try
        {
            var signer = SignerUtilities.GetSigner(algorithm);
            signer.Init(false, cert.GetPublicKey());
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
        catch { return false; }
    }

    /// <summary>File size from the FCP template: '62' → '80' (data bytes) or '81' (total), ISO/IEC 7816-4 5.3.3 Table 12.</summary>
    public static int? FileSize(byte[] fcp)
    {
        try
        {
            var t = BerTlv.ParseSingle(fcp);
            if (t.Tag != 0x62) return null;
            var size = t.Find(0x80) ?? t.Find(0x81);
            return size == null ? null : (int)size.Value.Aggregate(0u, (a, b) => (a << 8) | b);
        }
        catch (TlvException) { return null; }
    }
}

/// <summary>Reading procedure of 2003/127/EC Annex III.12: SELECT DF by name, SELECT EF (P1='02', P2='04'), READ BINARY.</summary>
public sealed class EvrcReader(CardChannel channel)
{
    public Action<ReadProgress>? Progress { get; set; }

    public EvrcReadResult Read(CancellationToken ct = default)
    {
        var log = channel.Logger;
        var result = new EvrcReadResult();
        Progress?.Invoke(new ReadProgress("SELECT DF.Registration"));
        var sel = channel.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, Evrc.Aid), "SELECT DF.Registration (eVRC)");
        if (!sel.Status.IsSuccess) throw new ProtocolException($"eVRC-Anwendung nicht vorhanden: {sel.Status} {sel.Status.Description}", sel.Status);
        result.Steps.Add(new ReadStep("Anwendung", StepOutcome.Success, $"DF.Registration ({Hex.Of(Evrc.Aid)})"));

        foreach (var (name, fid) in Evrc.Files)
        {
            ct.ThrowIfCancellationRequested();
            Progress?.Invoke(new ReadProgress("Lesen", name));
            // III.12 B: P1 = '02', P2 = '04' (return FCP template), data = FID.
            var r = channel.Transmit(new CommandApdu(0x00, 0xA4, 0x02, 0x04, [(byte)(fid >> 8), (byte)fid], 256), $"SELECT {name} ({fid:X4})");
            if (!r.Status.IsSuccess)
            {
                var optional = name.EndsWith("_B") || name.Contains("_B.");
                result.Steps.Add(new ReadStep($"Lesen {name}", optional && r.Status.Value == 0x6A82 ? StepOutcome.NotSupported : StepOutcome.Failed,
                    $"SELECT {r.Status} {r.Status.Description}{(optional ? " (Teil B ist optional, III.11 Tabelle 3)" : "")}"));
                continue;
            }
            var size = Evrc.FileSize(r.Data);
            if (size == null)
            {
                log.Warning(LogCategory.Protocol, $"{name}: FCP ohne Dateigröße ('80'/'81') – Länge wird aus dem TLV-Kopf bestimmt (III.12 B)", r.Data, Evrc.Ref);
            }
            try
            {
                var reader = new FileReader(channel) { MaxChunk = 0xFF, Cancellation = ct, Progress = (n, done, total) => Progress?.Invoke(new ReadProgress("Lesen", n, done, total)) };
                var data = size is { } s ? reader.ReadSelected(s, name) : ReadByTlvHead(reader, name);
                result.Files.Add(new EmrtdFile(name, 0, 0, data, fid));
                if (size is { } announced && data.Length < announced)
                {
                    var c5 = ProprietaryLength(r.Data);
                    var finding = $"{name}: FCP '80' meldet {announced} Datenbytes, die Datei endet aber nach {data.Length} Bytes (6282). " +
                        $"ISO/IEC 7816-4 Tabelle 12: '80' = Anzahl der Datenbytes.{(c5 == data.Length ? $" Das proprietäre Tag 'C5' enthält die tatsächliche Länge {c5}." : "")}";
                    result.Findings.Add(finding);
                    log.Warning(LogCategory.Protocol, finding, null, Evrc.Ref);
                }
            }
            catch (FileReadException ex)
            {
                result.Steps.Add(new ReadStep($"Lesen {name}", StepOutcome.Failed, ex.Message));
            }
        }

        var regA = result.File("EF.Registration_A");
        var charset = regA != null ? Evrc.CharsetValue(regA) : null;
        if (regA != null && charset == null) result.Findings.Add("EF.Registration_A: Zeichensatz '9F37' fehlt (III.11 Tabelle 2) – Latin-1 angenommen.");
        foreach (var part in new[] { "A", "B" })
        {
            var reg = result.File($"EF.Registration_{part}");
            if (reg != null) result.Fields.AddRange(Evrc.ParseRegistration(reg, $"EF.Registration_{part}", charset));
        }
        result.Findings.AddRange(result.Fields.SelectMany(f => f.Findings.Select(x => $"{f.Path}/{f.TagHex}: {x}")).Distinct());
        foreach (var part in new[] { "A", "B" })
        {
            var reg = result.File($"EF.Registration_{part}");
            if (reg == null && part == "B") continue;
            var check = Evrc.VerifySignature(part, reg, result.File($"EF.Signature_{part}"), result.File($"EF.C.IA_{part}.DS"));
            result.Signatures.Add(check);
            result.Steps.Add(new ReadStep($"Signatur Teil {part}", check.Valid switch { true => StepOutcome.Success, false => StepOutcome.Failed, null => StepOutcome.Skipped }, check.Detail));
            log.Info(LogCategory.Crypto, $"eVRC Signatur Teil {part}: {check.Detail}", null, "RL 2003/127/EG III.2 D / III.12 C");
        }
        Progress?.Invoke(new ReadProgress("Fertig"));
        return result;
    }

    private static int? ProprietaryLength(byte[] fcp)
    {
        try { return BerTlv.ParseSingle(fcp).Find(0xC5)?.Value.Aggregate(0, (a, b) => (a << 8) | b); }
        catch (TlvException) { return null; }
    }

    private static byte[] ReadByTlvHead(FileReader reader, string name)
    {
        var head = reader.ReadSelected(4, name);
        var total = FileReader.TotalTlvLength(head);
        return reader.ReadSelected(total, name);
    }
}
