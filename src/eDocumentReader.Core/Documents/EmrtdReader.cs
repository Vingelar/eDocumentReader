using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Pki;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Documents;

/// <summary>Access key for BAC/PACE: MRZ information (document number, date of birth, date of expiry with check digits) or CAN.</summary>
public abstract record AccessKey
{
    public sealed record MrzKey(string MrzInformation) : AccessKey;
    public sealed record CanKey(string Can) : AccessKey;
}

public sealed class EmrtdReadOptions
{
    public required AccessKey Key { get; init; }
    /// <summary>Use PACE if EF.CardAccess offers it (ICAO 9303-11 4.2: PACE SHALL be preferred).</summary>
    public bool PreferPace { get; init; } = true;
    public bool ChipAuthentication { get; init; } = true;
    public bool TerminalAuthentication { get; init; } = true;
    public bool ActiveAuthentication { get; init; } = true;
    /// <summary>Application to select: eMRTD (ICAO 9303-10) or IDL (ISO/IEC 18013-3 8.1, same LDS mechanisms).</summary>
    public byte[] Aid { get; init; } = EmrtdReader.EmrtdAid;
    public string ApplicationName { get; init; } = "eMRTD";
    /// <summary>
    /// Command chaining (ISO/IEC 7816-4 5.3.3) for long TA commands, block size <see cref="ChainingBlockSize"/>.
    /// null = automatic: on for the IDL (the tested ISO 18013-3 applet rejects longer SM commands with 6988), off otherwise.
    /// </summary>
    public bool? CommandChaining { get; init; }
    public int ChainingBlockSize { get; init; } = 192;
    public int? MaxCommandData => (CommandChaining ?? IsIdl) ? ChainingBlockSize : null;
    public bool IsIdl => Aid.AsSpan().SequenceEqual(EmrtdReader.IdlAid);
}

public enum StepOutcome { Success, Failed, Skipped, NotSupported, Warning }

public sealed record ReadStep(string Name, StepOutcome Outcome, string Detail);

public sealed record ReadProgress(string Stage, string? File = null, int Done = 0, int Total = 0);

public sealed record EmrtdFile(string Name, byte Sfi, int DataGroup, byte[] Data, ushort? Fid = null);

public sealed class EmrtdReadResult
{
    public List<EmrtdFile> Files { get; } = [];
    public List<ReadStep> Steps { get; } = [];
    public Dictionary<int, byte[]> DataGroups { get; } = [];
    public List<int> DataGroupsListed { get; } = [];
    public PassiveAuthenticationResult? PassiveAuthentication { get; set; }
    public string? AccessControl { get; set; }

    public byte[]? File(string name) => Files.FirstOrDefault(f => f.Name == name)?.Data;
}

/// <summary>eMRTD inspection procedure (ICAO 9303-11 Appendix J / BSI TR-03110-1 Appendix B / TR-03135).</summary>
public sealed class EmrtdReader(CardChannel channel, PkiStore pki)
{
    public static readonly byte[] EmrtdAid = Hex.Parse("A0000002471001");
    /// <summary>ISO/IEC 18013-3 8.1: AID of the IDL application.</summary>
    public static readonly byte[] IdlAid = Hex.Parse("A0000002480200");

    public Action<ReadProgress>? Progress { get; set; }

    public enum DocumentApplication { Emrtd, Idl }

    /// <summary>
    /// Unprotected SELECT of the IDL application (allowed before BAP/PACE, ISO/IEC 18013-3 8.1); otherwise eMRTD is assumed.
    /// The eMRTD application is deliberately not selected here: afterwards SFI 1C would address EF.CVCA instead of
    /// EF.CardAccess in the MF. A failed SELECT leaves the current selection unchanged (ISO/IEC 7816-4 11.2.2).
    /// </summary>
    public static DocumentApplication DetectApplication(IApduChannel c)
    {
        var sw = c.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, IdlAid), "SELECT IDL (Erkennung der Anwendung)").Status;
        // 6987/6988: SM session of an earlier connection still open; the chip ends it on this error (9303-11 9.8.5) – repeat once.
        if (sw.Value is 0x6987 or 0x6988) sw = c.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, IdlAid), "SELECT IDL (Erkennung, Wiederholung)").Status;
        return sw.IsSuccess ? DocumentApplication.Idl : DocumentApplication.Emrtd;
    }

    public EmrtdReadResult Read(EmrtdReadOptions options, CancellationToken ct = default)
    {
        var log = channel.Logger;
        var result = new EmrtdReadResult();

        // 1. EF.CardAccess in the MF (9303-11 4.2, 9303-10 3.11.3)
        Report("EF.CardAccess");
        List<PaceInfo> paceInfos = [];
        try
        {
            byte[] cardAccess;
            try { cardAccess = new FileReader(channel) { Cancellation = ct }.ReadBySfi(Lds.SfiCardAccess, "EF.CardAccess"); }
            catch (FileReadException ex) when (ex.Status?.Value is 0x6987 or 0x6988)
            {
                // SM session of an earlier connection still open (RF field not switched off); the chip ends it on this error (9303-11 9.8.5).
                log.Info(LogCategory.Protocol, "Chip war noch in einer SM-Sitzung – EF.CardAccess wird erneut gelesen.");
                cardAccess = new FileReader(channel) { Cancellation = ct }.ReadBySfi(Lds.SfiCardAccess, "EF.CardAccess");
            }
            result.Files.Add(new EmrtdFile("EF.CardAccess", Lds.SfiCardAccess, 0, cardAccess));
            paceInfos = SecurityInfos.Parse(cardAccess).OfType<PaceInfo>().ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Info(LogCategory.Protocol, $"EF.CardAccess nicht verfügbar ({ex.Message})");
        }

        // 2. Access control: PACE (preferred) or BAC
        ct.ThrowIfCancellationRequested();
        SecureChannel sm;
        PaceResult? pace = null;
        string? paceFailure = null;
        if (paceInfos.Count > 0 && (options.PreferPace || options.Key is AccessKey.CanKey))
        {
            Report("PACE");
            var password = options.Key switch
            {
                AccessKey.MrzKey m => PacePassword.FromMrz(m.MrzInformation),
                AccessKey.CanKey c => PacePassword.FromCan(c.Can),
                _ => throw new ArgumentOutOfRangeException(nameof(options)),
            };
            try
            {
                pace = Pace.Perform(channel, paceInfos[0], password, includeParameterId: paceInfos.Count > 1);
            }
            catch (ProtocolException ex) when (options.Key is AccessKey.MrzKey)
            {
                // ICAO 9303-11 4.2: if PACE fails, the terminal MAY fall back to BAC (BAP for the IDL, ISO/IEC 18013-3 8.2.3).
                paceFailure = ex.Message;
                log.Warning(LogCategory.Protocol, $"PACE mit MRZ fehlgeschlagen ({ex.Message}) – Rückfall auf {(options.IsIdl ? "BAP" : "BAC")}");
            }
        }
        if (pace != null)
        {
            sm = pace.Channel;
            result.AccessControl = $"PACE ({Oids.Name(paceInfos[0].Oid)}, {(options.Key is AccessKey.CanKey ? "CAN" : "MRZ")})";
            Select(sm, options);
        }
        else
        {
            if (options.Key is not AccessKey.MrzKey mrz)
                throw new ProtocolException("CAN ist nur mit PACE verwendbar, der Chip bietet in EF.CardAccess kein PACE an (ICAO 9303-11 4.4).");
            if (paceFailure != null) result.Steps.Add(new ReadStep("PACE (MRZ)", StepOutcome.Warning, $"{paceFailure} – Rückfall auf {(options.IsIdl ? "BAP" : "BAC")}"));
            Report(options.IsIdl ? "BAP" : "BAC");
            Select(channel, options);
            sm = Bac.Perform(channel, mrz.MrzInformation);
            result.AccessControl = options.IsIdl ? "BAP Konfiguration 1 (ISO/IEC 18013-3 8.2.3)" : "BAC";
        }
        result.Steps.Add(new ReadStep("Zugriffskontrolle", StepOutcome.Success, result.AccessControl));

        // 3. EF.COM, EF.SOD and the data groups readable after BAC/PACE (all except EAC-protected DG3/DG4)
        var com = ReadFile(sm, Lds.SfiCom, "EF.COM", 0, result, ct) ?? throw new ProtocolException("EF.COM nicht lesbar.");
        var tagList = BerTlv.ParseSingle(com).Find(0x5C)?.Value ?? [];
        if (!options.IsIdl) result.DataGroupsListed.AddRange(tagList.Select(Lds.DataGroupNumber).Where(d => d > 0));
        var sod = ReadFile(sm, Lds.SfiSod, "EF.SOD", 0, result, ct);
        if (options.IsIdl)
        {
            // ISO/IEC 18013-3 uses its own tag list in EF.COM; the SFI of EF.DGn is n (Table 12), so every DG is probed.
            for (var dg = 1; dg <= 14; dg++)
                ReadFile(sm, (byte)dg, $"EF.DG{dg}", dg, result, ct, absentIsNormal: true);
        }
        else
            foreach (var dg in result.DataGroupsListed.Where(d => !Lds.IsEacProtected(d)))
                ReadFile(sm, Lds.DataGroupSfi(dg), $"EF.DG{dg}", dg, result, ct);

        // 4. Chip Authentication (DG14), then Terminal Authentication (EF.CVCA + chain from the PKI store)
        if (!options.ChipAuthentication) result.Steps.Add(new ReadStep("Chip Authentication", StepOutcome.Skipped, "abgewählt"));
        else if (!result.DataGroups.TryGetValue(14, out var dg14)) result.Steps.Add(new ReadStep("Chip Authentication", StepOutcome.NotSupported, "kein DG14"));
        else
        {
            Report("Chip Authentication");
            var ca = RunChipAuthentication(ref sm, dg14, result);
            // IDL (ISO/IEC 18013-3 8.2.4, EAP): data groups refused with 6982 are protected by CA + TA and are read again afterwards.
            var protectedDgs = options.IsIdl
                ? result.Steps.Where(s => s.Outcome == StepOutcome.Failed && s.Name.StartsWith("Lesen EF.DG") && s.Detail.Contains("6982"))
                    .Select(s => int.Parse(s.Name["Lesen EF.DG".Length..])).ToList()
                : result.DataGroupsListed.Where(Lds.IsEacProtected).ToList();
            if (ca != null && protectedDgs.Count > 0)
            {
                if (options.TerminalAuthentication)
                {
                    Report("Terminal Authentication");
                    result.Steps.Add(RunTerminalAuthentication(sm, pace, options, ca, protectedDgs, result, ct));
                }
                else result.Steps.Add(new ReadStep("Terminal Authentication", StepOutcome.Skipped, "abgewählt"));
            }
        }

        // 5. Active Authentication (DG15)
        if (!options.ActiveAuthentication) result.Steps.Add(new ReadStep("Active Authentication", StepOutcome.Skipped, "abgewählt"));
        // The AA public key is in DG15 (ICAO 9303-11 6.1) or, for the IDL, in DG13 (ISO/IEC 18013-3 Table 12).
        else if (!result.DataGroups.TryGetValue(options.IsIdl ? 13 : 15, out var dg15)) result.Steps.Add(new ReadStep("Active Authentication", StepOutcome.NotSupported, options.IsIdl ? "kein DG13" : "kein DG15"));
        else
        {
            Report("Active Authentication");
            try
            {
                var key = ActiveAuthentication.PublicKeyFromDg15(dg15);
                var aaInfo = result.DataGroups.TryGetValue(14, out var d14) ? SecurityInfos.Parse(BerTlv.ParseSingle(d14).Value).OfType<ActiveAuthenticationInfo>().FirstOrDefault() : null;
                var aa = ActiveAuthentication.Perform(sm, key, aaInfo?.SignatureAlgorithm);
                result.Steps.Add(new ReadStep("Active Authentication", aa.Valid ? StepOutcome.Success : StepOutcome.Failed, aa.Detail));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                result.Steps.Add(new ReadStep("Active Authentication", StepOutcome.Failed, ex.Message));
            }
        }

        // 6. Passive Authentication (offline, 9303-11 5.1)
        if (sod != null)
        {
            Report("Passive Authentication");
            try
            {
                var pa = PassiveAuthentication.Verify(sod, result.DataGroups, pki);
                result.PassiveAuthentication = pa;
                var mismatches = pa.Hashes.Where(h => h.Match == false).Select(h => $"DG{h.DataGroup}").ToList();
                var detail = mismatches.Count > 0 ? $"Hash falsch: {string.Join(", ", mismatches)}"
                    : !pa.SignatureValid ? pa.SignatureDetail
                    : pa.Chain?.Valid != true ? "DS-Zertifikat nicht bis zu einer vertrauenswürdigen CSCA prüfbar"
                    : "Hashes, SOD-Signatur und Kette DS → CSCA gültig";
                result.Steps.Add(new ReadStep("Passive Authentication", pa.Valid ? StepOutcome.Success : StepOutcome.Failed, detail));
            }
            catch (Exception ex)
            {
                result.Steps.Add(new ReadStep("Passive Authentication", StepOutcome.Failed, ex.Message));
            }
        }
        Report("Fertig");
        return result;
    }

    private void Report(string stage, string? file = null, int done = 0, int total = 0) => Progress?.Invoke(new ReadProgress(stage, file, done, total));

    private static void Select(IApduChannel c, EmrtdReadOptions options)
    {
        var sel = c.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, options.Aid), $"SELECT {options.ApplicationName}-Anwendung");
        if (!sel.Status.IsSuccess) throw new ProtocolException($"SELECT {options.ApplicationName}-Anwendung: {sel.Status} {sel.Status.Description}", sel.Status);
    }

    private byte[]? ReadFile(IApduChannel c, byte sfi, string name, int dg, EmrtdReadResult result, CancellationToken ct, bool absentIsNormal = false)
    {
        ct.ThrowIfCancellationRequested();
        Report("Lesen", name);
        try
        {
            var data = new FileReader(c) { Cancellation = ct, Progress = (n, done, total) => Report("Lesen", n, done, total) }.ReadBySfi(sfi, name);
            result.Files.Add(new EmrtdFile(name, sfi, dg, data));
            if (dg > 0) result.DataGroups[dg] = data;
            return data;
        }
        catch (FileReadException ex) when (absentIsNormal && ex.Status?.Value == 0x6A82)
        {
            return null;
        }
        catch (FileReadException ex) when (absentIsNormal && ex.Status?.Value == 0x6986)
        {
            // ISO/IEC 7816-4 7.2.2/5.6: a missing short EF is reported with 6A82; 6986 ("no current EF") is a deviation.
            result.Steps.Add(new ReadStep($"Normkonformität {name}", StepOutcome.Warning, "READ BINARY mit SFI einer nicht vorhandenen Datei: 6986 statt 6A82 (ISO/IEC 7816-4)"));
            return null;
        }
        catch (FileReadException ex)
        {
            channel.Logger.Warning(LogCategory.Protocol, $"{name}: {ex.Message}");
            result.Steps.Add(new ReadStep($"Lesen {name}", StepOutcome.Failed, ex.Message));
            return null;
        }
    }

    private ChipAuthenticationResult? RunChipAuthentication(ref SecureChannel sm,byte[] dg14, EmrtdReadResult result)
    {
        var infos = SecurityInfos.Parse(BerTlv.ParseSingle(dg14).Value);
        var keys = infos.OfType<ChipAuthenticationPublicKeyInfo>().ToList();
        var caInfos = infos.OfType<ChipAuthenticationInfo>().ToList();
        // Prefer the strongest algorithm (AES-256 > … > 3DES).
        var choice = keys.Select(k => (Key: k, Oid: ChipAuthentication.SelectOid(k, caInfos.Where(c => c.KeyId == k.KeyId || c.KeyId == null))))
            .OrderByDescending(x => x.Oid, StringComparer.Ordinal).FirstOrDefault();
        if (choice.Key == null)
        {
            result.Steps.Add(new ReadStep("Chip Authentication", StepOutcome.NotSupported, "kein ChipAuthenticationPublicKeyInfo in DG14"));
            return null;
        }
        try
        {
            var ca = ChipAuthentication.Perform(sm, ChipPublicKey.From(choice.Key), choice.Oid);
            sm = ca.Channel;
            // Proof that the new session keys work: read the EF.COM head again.
            var check = sm.Transmit(new CommandApdu(0x00, 0xB0, (byte)(0x80 | Lds.SfiCom), 0x00, null, 4), "READ BINARY EF.COM (Kontrolle nach CA)");
            var detail = $"{Oids.Name(choice.Oid)}, KeyID {choice.Key.KeyId?.ToString() ?? "-"}";
            result.Steps.Add(check.Status.IsSuccess
                ? new ReadStep("Chip Authentication", StepOutcome.Success, detail)
                : new ReadStep("Chip Authentication", StepOutcome.Failed, $"{detail}: Lesen nach Schlüsselwechsel {check.Status}"));
            return check.Status.IsSuccess ? ca : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result.Steps.Add(new ReadStep("Chip Authentication", StepOutcome.Failed, ex.Message));
            return null;
        }
    }

    private ReadStep RunTerminalAuthentication(IApduChannel sm, PaceResult? pace, EmrtdReadOptions options, ChipAuthenticationResult ca, List<int> protectedDgs, EmrtdReadResult result, CancellationToken ct)
    {
        var key = options.Key;
        const string name = "Terminal Authentication";
        var log = channel.Logger;
        List<string> cars;
        var carSource = "EF.CVCA";
        try
        {
            var cvca = new FileReader(sm).ReadSmallBySfi(Lds.SfiCvca, "EF.CVCA");
            result.Files.Add(new EmrtdFile("EF.CVCA", Lds.SfiCvca, 0, cvca));
            cars = TerminalAuthentication.ParseEfCvca(cvca);
            log.Info(LogCategory.Protocol, $"EF.CVCA: Vertrauensanker des Chips {string.Join(", ", cars)}");
        }
        catch (FileReadException ex) when (options.IsIdl && ex.Status?.Value == 0x6A82)
        {
            // The IDL application has no EF.CVCA (ISO/IEC 18013-3 Table 12): the chip's trust point is not readable,
            // so every CVCA of the PKI store is offered; the chip rejects an unknown CAR in MSE:Set DST.
            cars = pki.CandidateTrustPoints();
            carSource = "PKI-Speicher (IDL ohne EF.CVCA)";
            log.Info(LogCategory.Protocol, $"Kein EF.CVCA in der IDL-Anwendung – Vertrauensanker aus dem PKI-Speicher: {(cars.Count == 0 ? "keine" : string.Join(", ", cars))}");
            if (cars.Count == 0) return new ReadStep(name, StepOutcome.Skipped, "IDL ohne EF.CVCA und kein CVCA-Zertifikat im PKI-Speicher – bitte IDL-Terminalkette importieren (Tab „PKI“)");
        }
        catch (Exception ex) { return new ReadStep(name, StepOutcome.Failed, $"EF.CVCA nicht lesbar ({ex.Message})"); }

        var rejected = new List<string>();
        foreach (var car in cars)
        {
            // eMRTD: Inspection System role (id-IS); the IDL uses its own terminal roles, any CHAT OID is accepted.
            var built = pki.BuildTerminalChain(car, options.IsIdl ? null : TaOids.IdIs);
            if (built == null) continue;
            var (chain, terminal) = built.Value;
            // Dynamic binding after PACE (TR-03110-1 3.5); after BAC: document number + check digit.
            byte[] idPicc;
            if (pace != null) idPicc = pace.CompressedChipEphemeralKey;
            else if (key is AccessKey.MrzKey m) idPicc = TerminalAuthentication.StaticIdPicc(m.MrzInformation[..10]);
            else return new ReadStep(name, StepOutcome.Failed, "ID_PICC nicht bestimmbar.");
            TerminalAuthenticationResult ta;
            try { ta = TerminalAuthentication.Perform(sm, chain, terminal.PrivateKey, idPicc, ca.CompressedTerminalKey, options.MaxCommandData); }
            catch (Exception ex) when (ex is SecureMessagingException or ProtocolException)
            {
                return new ReadStep(name, StepOutcome.Failed, $"Kette über CAR {car}: {ex.Message}");
            }
            foreach (var finding in ta.Steps.Where(x => x.StartsWith('⚠')))
                result.Steps.Add(new ReadStep("Normkonformität TA", StepOutcome.Warning, finding.TrimStart('⚠', ' ')));
            if (!ta.Success)
            {
                // IDL: trust point unknown, so a rejected chain (normally MSE:Set DST 6A88) is followed by the next candidate.
                if (options.IsIdl && sm is SecureChannel { IsActive: true })
                {
                    rejected.Add($"{car}: {ta.Detail}");
                    log.Info(LogCategory.Protocol, $"Kette über CAR {car} abgelehnt ({ta.Detail}) – nächster Kandidat");
                    continue;
                }
                return new ReadStep(name, StepOutcome.Failed, ta.Detail);
            }
            foreach (var dg in protectedDgs)
            {
                var stale = result.Steps.FirstOrDefault(s => s.Name == $"Lesen EF.DG{dg}" && s.Outcome == StepOutcome.Failed);
                if (stale != null) result.Steps.Remove(stale);
                // Authorization bits of the IDL terminal certificate differ from the eMRTD role (18013-3 Annex); the chip decides.
                if (!options.IsIdl && !terminal.Certificate.AllowsDataGroup(dg)) { log.Info(LogCategory.Protocol, $"DG{dg}: Terminalzertifikat berechtigt nicht zum Lesen"); continue; }
                if (ReadFile(sm, Lds.DataGroupSfi(dg), $"EF.DG{dg}", dg, result, ct) is { } read)
                    result.Steps.Add(new ReadStep($"Lesen EF.DG{dg}", StepOutcome.Success, $"{read.Length} Byte, nach Terminal Authentication"));
            }
            return new ReadStep(name, StepOutcome.Success, $"{terminal.Certificate.Chr} über CAR {car} ({terminal.Certificate.DescribeAuthorization()}; Anker aus {carSource})");
        }
        if (rejected.Count > 0) return new ReadStep(name, StepOutcome.Failed, $"alle Ketten vom Chip abgelehnt: {string.Join("; ", rejected)}");
        return new ReadStep(name, StepOutcome.Skipped, $"keine passende Terminal-Zertifikatskette (mit privatem Schlüssel) im PKI-Speicher für CAR {string.Join(" / ", cars)} – {string.Join(", ", protectedDgs.Select(d => $"DG{d}"))} nicht gelesen");
    }
}
