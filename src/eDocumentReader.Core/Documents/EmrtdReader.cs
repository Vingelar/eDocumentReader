using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Crypto;
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
    public sealed record MrzKey(string MrzInformation) : AccessKey
    {
        /// <summary>
        /// The value is the IDL input string (ISO/IEC 18013-3 8.3.2.5, 8.5.4: Kdoc for BAP) and not ICAO MRZ information;
        /// PACE then uses f(π) = input string (Amd.1 C.2.2) instead of SHA-1(MRZ information).
        /// </summary>
        public bool IsIdlInputString { get; init; }
    }
    public sealed record CanKey(string Can) : AccessKey;
}

public sealed class EmrtdReadOptions
{
    public required AccessKey Key { get; init; }
    /// <summary>Use PACE if EF.CardAccess offers it (ICAO 9303-11 4.2: PACE SHALL be preferred).</summary>
    public bool PreferPace { get; init; } = true;
    /// <summary>
    /// Use PACE-CAM if EF.CardAccess offers it (ICAO 9303-11 4.4.3.3.3): the chip authenticates within PACE, the
    /// terminal checks it with EF.CardSecurity, and Chip Authentication with DG14 is not needed.
    /// </summary>
    public bool PreferChipAuthenticationMapping { get; init; } = true;
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

    /// <summary>
    /// Applications to try in this order (automatic detection). The SELECT by AID happens where the standards put it:
    /// after PACE under secure messaging, or before BAC/BAP (ICAO 9303-11 4.2, ISO/IEC 18013-3 8.7.4). If BAC/BAP fails
    /// with one application, the next one is tried with the same key. null: only <see cref="Aid"/>.
    /// </summary>
    public IReadOnlyList<EmrtdReader.DocumentApplication>? Candidates { get; init; }

    /// <summary>The same options for one application.</summary>
    public EmrtdReadOptions For(EmrtdReader.DocumentApplication application) => new()
    {
        Key = Key,
        PreferPace = PreferPace,
        PreferChipAuthenticationMapping = PreferChipAuthenticationMapping,
        ChipAuthentication = ChipAuthentication,
        TerminalAuthentication = TerminalAuthentication,
        ActiveAuthentication = ActiveAuthentication,
        Aid = application == EmrtdReader.DocumentApplication.Idl ? EmrtdReader.IdlAid : EmrtdReader.EmrtdAid,
        ApplicationName = application == EmrtdReader.DocumentApplication.Idl ? "IDL" : "eMRTD",
        CommandChaining = CommandChaining,
        ChainingBlockSize = ChainingBlockSize,
        Candidates = Candidates,
    };
}

public enum StepOutcome { Success, Failed, Skipped, NotSupported, Warning }

public sealed record ReadStep(string Name, StepOutcome Outcome, string Detail)
{
    /// <summary>Language-independent identity for program logic (e.g. "read:EF.DG3"); the name is display text.</summary>
    public string? Key { get; init; }
    public string Id => Key ?? Name;

    public static ReadStep ReadFailed(string file, string detail) => new(T("Lesen ", "Read ") + file, StepOutcome.Failed, detail) { Key = "read:" + file };
}

public sealed record ReadProgress(string Stage, string? File = null, int Done = 0, int Total = 0);

public enum StepState { Pending, Running, Done, Removed }

/// <summary>
/// Live view of the inspection for a UI: steps are planned (Pending), started (Running, with byte counts for files),
/// finished (Done) or dropped again (Removed, e.g. an IDL data group that does not exist). Provisional results exist
/// only in the live view (e.g. a file read without error) and may be replaced by a later step with the same Id.
/// </summary>
/// <param name="Before">For a planned step: insert it before the planned step with this Id (if there is one).</param>
public sealed record StepEvent(string Id, string Name, StepState State, ReadStep? Step = null, string? Detail = null, int Done = 0, int Total = 0, bool Provisional = false, string? Before = null);

/// <summary>The access control (PACE, BAC or BAP) failed; another application may still accept the key.</summary>
public sealed class AccessControlException(string message, StatusWord? status, Exception inner) : Exception(message, inner)
{
    public StatusWord? Status { get; } = status;
}

public sealed record EmrtdFile(string Name, byte Sfi, int DataGroup, byte[] Data, ushort? Fid = null);

/// <summary>One PACEInfo of EF.CardAccess for the user's choice; <see cref="Supported"/>: this reader can run it.</summary>
public sealed record PaceOption(PaceInfo Info, bool Supported, string Description);

/// <summary>
/// EF.CardAccess offers several PACE variants (ICAO 9303-11 9.2.1): the options in card order, the automatic choice,
/// and whether BAC/BAP is possible instead (MRZ key, not CAN).
/// </summary>
public sealed record PaceChoiceRequest(IReadOnlyList<PaceOption> Options, PaceInfo Preselected, string? Fallback);

public sealed class EmrtdReadResult
{
    public List<EmrtdFile> Files { get; } = [];
    public List<ReadStep> Steps { get; } = [];
    public Dictionary<int, byte[]> DataGroups { get; } = [];
    public List<int> DataGroupsListed { get; } = [];
    public PassiveAuthenticationResult? PassiveAuthentication { get; set; }
    /// <summary>The application that was selected and read.</summary>
    public EmrtdReader.DocumentApplication Application { get; set; }
    public bool IsIdl => Application == EmrtdReader.DocumentApplication.Idl;
    public string? AccessControl { get; set; }
    /// <summary>EF.ATR/INFO of the MF, if present (ICAO 9303-10 3.11.1).</summary>
    public AtrInfoFile? AtrInfo { get; set; }
    /// <summary>EF.DIR of the MF, if present (ICAO 9303-10 3.11.2).</summary>
    public EfDirFile? Dir { get; set; }

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
    public static DocumentApplication DetectApplication(IApduChannel c) => Detect(c).Application;

    /// <summary>As <see cref="DetectApplication"/>, with the status word of the SELECT for display.</summary>
    public static (DocumentApplication Application, StatusWord Status) Detect(IApduChannel c)
    {
        var sw = c.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, IdlAid), T("SELECT IDL (Erkennung der Anwendung)", "SELECT IDL (application detection)")).Status;
        // 6987/6988: SM session of an earlier connection still open; the chip ends it on this error (9303-11 9.8.5) – repeat once.
        if (sw.Value is 0x6987 or 0x6988) sw = c.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, IdlAid), T("SELECT IDL (Erkennung, Wiederholung)", "SELECT IDL (detection, retry)")).Status;
        return (sw.IsSuccess ? DocumentApplication.Idl : DocumentApplication.Emrtd, sw);
    }

    public EmrtdReadResult Read(EmrtdReadOptions options, CancellationToken ct = default)
    {
        var log = channel.Logger;
        var result = new EmrtdReadResult();
        var accessName = T("Zugriffskontrolle", "Access control");
        Plan(FileId("EF.CardAccess"), ReadName("EF.CardAccess"));
        Plan(FileId(CardFiles.DirName), ReadName(CardFiles.DirName));
        Plan(FileId(CardFiles.AtrInfoName), ReadName(CardFiles.AtrInfoName));
        Plan("access", accessName);
        Plan(FileId("EF.COM"), ReadName("EF.COM"));
        Plan(FileId("EF.SOD"), ReadName("EF.SOD"));
        Plan("Chip Authentication", "Chip Authentication");
        Plan("Active Authentication", "Active Authentication");
        Plan("Passive Authentication", "Passive Authentication");

        IReadOnlyList<DocumentApplication> candidates = options.Candidates is { Count: > 0 } list ? list : [options.IsIdl ? DocumentApplication.Idl : DocumentApplication.Emrtd];
        options = options.For(candidates[0]);
        result.Application = candidates[0];

        // 1. EF.CardAccess in the MF, read first and without any SELECT (9303-11 4.2 step 1, 9303-10 3.11.3,
        //    ISO/IEC 18013-3 8.7.3): after reset the MF is the current DF (ISO/IEC 7816-4 7.1). SELECT MF is
        //    not used (9303-10 3.6.1.1: not recommended). No EF.CardAccess means: no PACE.
        Report("EF.CardAccess");
        Start(FileId("EF.CardAccess"), ReadName("EF.CardAccess"));
        List<PaceInfo> paceInfos = [];
        try
        {
            byte[] cardAccess;
            try { cardAccess = new FileReader(channel) { Cancellation = ct, Progress = FileProgress }.ReadBySfi(Lds.SfiCardAccess, "EF.CardAccess"); }
            catch (FileReadException ex) when (ex.Status?.Value is 0x6987 or 0x6988)
            {
                // SM session of an earlier connection still open (RF field not switched off); the chip ends it on this error (9303-11 9.8.5).
                log.Info(LogCategory.Protocol, T("Chip war noch in einer SM-Sitzung – EF.CardAccess wird erneut gelesen.", "Chip was still in an SM session – reading EF.CardAccess again."));
                cardAccess = new FileReader(channel) { Cancellation = ct, Progress = FileProgress }.ReadBySfi(Lds.SfiCardAccess, "EF.CardAccess");
            }
            result.Files.Add(new EmrtdFile("EF.CardAccess", Lds.SfiCardAccess, 0, cardAccess));
            paceInfos = SecurityInfos.Parse(cardAccess).OfType<PaceInfo>().ToList();
            ReadDone("EF.CardAccess", cardAccess.Length);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Info(LogCategory.Protocol, T($"EF.CardAccess nicht verfügbar ({ex.Message})", $"EF.CardAccess not available ({ex.Message})"));
            Provisional(new ReadStep(ReadName("EF.CardAccess"), StepOutcome.NotSupported, T($"nicht verfügbar ({ex.Message})", $"not available ({ex.Message})")) { Key = FileId("EF.CardAccess") });
        }

        // 1a. EF.DIR and EF.ATR/INFO in the MF, still before any SELECT (9303-10 3.11.1/3.11.2, ISO/IEC 7816-4 8.2.1.1).
        //     Both are optional for LDS1; EF.DIR is step 2 of 9303-11 4.2. '6A82' is the normal answer of a chip without them.
        atrInfo = null;
        var dirData = ReadMfFile(CardFiles.SfiDir, CardFiles.FidDir, CardFiles.DirName, result, ct);
        if (dirData != null)
        {
            try
            {
                result.Dir = new EfDirFile(dirData);
                foreach (var f in result.Dir.Findings) AddStep(result, new ReadStep(T($"Normkonformität {CardFiles.DirName}", $"Conformance {CardFiles.DirName}"), StepOutcome.Warning, f));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                AddStep(result, new ReadStep(T($"Normkonformität {CardFiles.DirName}", $"Conformance {CardFiles.DirName}"), StepOutcome.Warning, T($"nicht dekodierbar: {ex.Message}", $"cannot be decoded: {ex.Message}")));
            }
        }
        var atrData = ReadMfFile(CardFiles.SfiAtrInfo, CardFiles.FidAtrInfo, CardFiles.AtrInfoName, result, ct);
        if (atrData != null)
        {
            try
            {
                atrInfo = result.AtrInfo = new AtrInfoFile(atrData);
                var buffers = atrInfo.MaxCommandApdu is { } mc ? T($", Puffer {mc}/{atrInfo.MaxResponseApdu} Byte", $", buffers {mc}/{atrInfo.MaxResponseApdu} bytes") : "";
                log.Info(LogCategory.Protocol, T($"{CardFiles.AtrInfoName}: Command chaining {(atrInfo.CommandChaining ? "ja" : "nein")}, Extended Lc/Le {(atrInfo.ExtendedLength ? "ja" : "nein")}{buffers}", $"{CardFiles.AtrInfoName}: command chaining {(atrInfo.CommandChaining ? "yes" : "no")}, extended Lc/Le {(atrInfo.ExtendedLength ? "yes" : "no")}{buffers}"), null, "ICAO 9303-11 9.3.1");
                foreach (var f in atrInfo.Findings) AddStep(result, new ReadStep(T($"Normkonformität {CardFiles.AtrInfoName}", $"Conformance {CardFiles.AtrInfoName}"), StepOutcome.Warning, f));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                AddStep(result, new ReadStep(T($"Normkonformität {CardFiles.AtrInfoName}", $"Conformance {CardFiles.AtrInfoName}"), StepOutcome.Warning, T($"nicht dekodierbar: {ex.Message}", $"cannot be decoded: {ex.Message}")));
            }
        }
        // Automatic detection: only the applications that EF.DIR lists are tried. The order in EF.DIR has no meaning
        // (9303-10 3.11.2: templates in any order), so the configured preference stays.
        if (result.Dir is { Applications.Count: > 0 } dir && candidates.Count > 1)
        {
            var listed = candidates.Where(c => dir.Lists(options.For(c).Aid)).ToList();
            if (listed.Count > 0 && listed.Count < candidates.Count)
            {
                var names = string.Join(", ", listed.Select(c => options.For(c).ApplicationName));
                log.Info(LogCategory.Protocol, T($"EF.DIR listet nur {names} – andere Anwendungen werden nicht versucht", $"EF.DIR lists only {names} – other applications are not tried"));
                candidates = listed;
                options = options.For(candidates[0]);
                result.Application = candidates[0];
            }
        }

        // 2. Access control: PACE (preferred) or BAC
        ct.ThrowIfCancellationRequested();
        SecureChannel sm;
        PaceResult? pace = null;
        PaceInfo? chosen = null;
        var camVerified = false;
        string? paceFailure = null;
        var usePace = paceInfos.Count > 0 && (options.PreferPace || options.Key is AccessKey.CanKey);
        // PACE runs in the MF before the SELECT of the application; BAC/BAP after it (9303-11 4.2/4.3).
        Plan("select", candidates.Count > 1 ? T("SELECT Anwendung", "SELECT application") : SelectName(options), before: usePace ? FileId("EF.COM") : "access");
        try
        {
        if (usePace)
        {
            Report("PACE");
            Start("access", accessName, "PACE");
            var password = options.Key switch
            {
                // IDL: the key is the printed input string; PACE uses it unhashed (ISO/IEC 18013-3 8.7, Amd.1 C.2.1).
                AccessKey.MrzKey m => m.IsIdlInputString || options.IsIdl ? PacePassword.FromIdlInputString(m.MrzInformation) : PacePassword.FromMrz(m.MrzInformation),
                AccessKey.CanKey c => PacePassword.FromCan(c.Can),
                _ => throw new ArgumentOutOfRangeException(nameof(options)),
            };
            // Supported: ECDH with GM, or with CAM (AES) on standardized domain parameters.
            var supported = paceInfos.Where(p => p.Algorithm.KeyAgreement == KeyAgreement.Ecdh && p.ParameterId is { } id && StandardizedDomainParameters.IsEc(id)
                && (p.Algorithm.Mapping == PaceMapping.Generic || (p.Algorithm.Mapping == PaceMapping.ChipAuthentication && p.Algorithm.KeyType != Crypto.SessionKeyType.DesEde))).ToList();
            var cam = options.PreferChipAuthenticationMapping ? supported.FirstOrDefault(p => p.Algorithm.Mapping == PaceMapping.ChipAuthentication) : null;
            chosen = cam ?? supported.FirstOrDefault(p => p.Algorithm.Mapping == PaceMapping.Generic) ?? paceInfos[0];
            var userChoice = false;
            if (paceInfos.Count > 1 && ChoosePace != null)
            {
                // Several variants in EF.CardAccess (9303-11 9.2.1): the user picks one, or BAC/BAP with the MRZ.
                var fallback = options.Key is AccessKey.MrzKey ? (options.IsIdl ? "BAP" : "BAC") : null;
                var offered = paceInfos.Select(p => new PaceOption(p, supported.Contains(p), DescribePace(p))).ToList();
                var picked = ChoosePace(new PaceChoiceRequest(offered, chosen, fallback));
                userChoice = true;
                if (picked == null && fallback == null) throw new OperationCanceledException();
                log.Info(LogCategory.Protocol, picked == null
                    ? T($"PACE-Auswahl: Benutzer wählt {fallback} statt PACE", $"PACE choice: the user chooses {fallback} instead of PACE")
                    : T($"PACE-Auswahl: Benutzer wählt {DescribePace(picked)}", $"PACE choice: the user chooses {DescribePace(picked)}"), null, "ICAO 9303-11 9.2.1");
                if (picked == null) AddStep(result, new ReadStep("PACE", StepOutcome.Skipped, T($"vom Benutzer abgewählt – {fallback}", $"deselected by the user – {fallback}")));
                chosen = picked;
            }
            try
            {
                if (chosen != null) try { pace = Pace.Perform(channel, chosen, password, includeParameterId: paceInfos.Count > 1); }
                catch (ProtocolException ex) when (chosen.Algorithm.Mapping == PaceMapping.ChipAuthentication && !userChoice && supported.FirstOrDefault(p => p.Algorithm.Mapping == PaceMapping.Generic) is { } gm)
                {
                    // A failed PACE-CAM run is repeated with generic mapping before any fallback to BAC (9303-11 4.2).
                    log.Warning(LogCategory.Protocol, T($"PACE-CAM fehlgeschlagen ({ex.Message}) – Wiederholung mit PACE-GM", $"PACE-CAM failed ({ex.Message}) – repeating with PACE-GM"));
                    AddStep(result, new ReadStep("PACE-CAM", StepOutcome.Warning, T($"{ex.Message} – Wiederholung mit PACE-GM", $"{ex.Message} – repeated with PACE-GM")));
                    chosen = gm;
                    pace = Pace.Perform(channel, chosen, password, includeParameterId: paceInfos.Count > 1);
                }
            }
            catch (ProtocolException ex) when (options.Key is AccessKey.MrzKey)
            {
                // ICAO 9303-11 4.2: if PACE fails, the terminal MAY fall back to BAC (BAP for the IDL, ISO/IEC 18013-3 8.2.3).
                paceFailure = ex.Message;
                log.Warning(LogCategory.Protocol, T($"PACE mit MRZ fehlgeschlagen ({ex.Message}) – Rückfall auf {(options.IsIdl ? "BAP" : "BAC")}", $"PACE with MRZ failed ({ex.Message}) – falling back to {(options.IsIdl ? "BAP" : "BAC")}"));
            }
        }
        if (pace != null)
        {
            sm = pace.Channel;
            result.AccessControl = $"PACE ({Oids.Name(chosen!.Oid)}, {(options.Key is AccessKey.CanKey ? "CAN" : "MRZ")})";
            if (pace.ChipAuthenticationMapping)
            {
                // EF.CardSecurity is in the MF (SFI 1D, as EF.SOD in the application): read it before SELECT.
                Report("EF.CardSecurity");
                var step = VerifyChipAuthenticationMapping(pace, ReadFile(sm, Lds.SfiCardSecurity, "EF.CardSecurity", 0, result, ct));
                camVerified = step.Outcome is StepOutcome.Success or StepOutcome.Warning;
                AddStep(result, step);
            }
            // EF.DIR read: its authenticity MUST be verified with EFDIRInfo in EF.CardSecurity (9303-11 4.2 step 2, 9.2.10),
            // in the MF before the SELECT of the application.
            if (dirData != null) AddStep(result, VerifyEfDir(sm, dirData, result, ct));
            // PACE is application independent; the application is selected under secure messaging afterwards
            // (9303-11 4.2, ISO/IEC 18013-3 8.7.4 d).
            options = SelectApplication(sm, candidates, options, result);
        }
        else
        {
            if (options.Key is not AccessKey.MrzKey mrz)
                throw new ProtocolException(T("CAN ist nur mit PACE verwendbar, der Chip bietet in EF.CardAccess kein PACE an (ICAO 9303-11 4.4).", "CAN works with PACE only; the chip offers no PACE in EF.CardAccess (ICAO 9303-11 4.4)."));
            if (paceFailure != null) AddStep(result, new ReadStep("PACE (MRZ)", StepOutcome.Warning, T($"{paceFailure} – Rückfall auf {(options.IsIdl ? "BAP" : "BAC")}", $"{paceFailure} – fallback to {(options.IsIdl ? "BAP" : "BAC")}")));
            // BAC/BAP run in the application, which is selected first (9303-11 4.2 step 4, ISO/IEC 18013-3 8.5.4).
            for (var i = 0; ; i++)
            {
                var candidate = options.For(candidates[i]);
                var last = i == candidates.Count - 1;
                if (!TrySelect(channel, candidate, result, last)) continue;
                var protocol = candidate.IsIdl ? "BAP" : "BAC";
                Report(protocol);
                Start("access", accessName, protocol);
                try
                {
                    sm = Bac.Perform(channel, mrz.MrzInformation);
                    options = candidate;
                    break;
                }
                catch (Exception ex) when (!last && ex is ProtocolException or SecureMessagingException)
                {
                    var next = options.For(candidates[i + 1]).ApplicationName;
                    log.Warning(LogCategory.Protocol, T($"{protocol} mit der {candidate.ApplicationName}-Anwendung fehlgeschlagen ({ex.Message}) – Versuch mit der {next}-Anwendung und demselben Schlüssel", $"{protocol} with the {candidate.ApplicationName} application failed ({ex.Message}) – trying the {next} application with the same key"));
                    AddStep(result, new ReadStep($"{protocol} ({candidate.ApplicationName})", StepOutcome.Warning, T($"{ex.Message} – Versuch mit {next}", $"{ex.Message} – trying {next}")));
                }
            }
            result.AccessControl = options.IsIdl ? T("BAP Konfiguration 1 (ISO/IEC 18013-3 8.2.3)", "BAP configuration 1 (ISO/IEC 18013-3 8.2.3)") : "BAC";
            if (dirData != null)
                AddStep(result, new ReadStep(T("Echtheit EF.DIR", "Authenticity of EF.DIR"), StepOutcome.Warning, T("ohne PACE nicht prüfbar: EFDIRInfo steht in EF.CardSecurity im MF (ICAO 9303-11 4.2, 9.2.10)", "cannot be verified without PACE: EFDIRInfo is in EF.CardSecurity in the MF (ICAO 9303-11 4.2, 9.2.10)")));
        }
        }
        catch (Exception ex) when (ex is ProtocolException or SecureMessagingException)
        {
            var status = ex switch { ProtocolException p => p.Status, SecureMessagingException s => s.Status, _ => null };
            AddStep(result, new ReadStep(accessName, StepOutcome.Failed, ex.Message + (status is { } sw ? $" ({sw})" : "")) { Key = "access" });
            throw new AccessControlException(ex.Message, status, ex);
        }
        AddStep(result, new ReadStep(accessName, StepOutcome.Success, result.AccessControl) { Key = "access" });

        // 3. EF.COM, EF.SOD and the data groups readable after BAC/PACE (all except EAC-protected DG3/DG4)
        var com = ReadFile(sm, Lds.SfiCom, "EF.COM", 0, result, ct) ?? throw new ProtocolException(T("EF.COM nicht lesbar.", "EF.COM not readable."));
        var tagList = BerTlv.ParseSingle(com).Find(0x5C)?.Value ?? [];
        // EF.COM tag list: eMRTD tags (ICAO 9303-10) or the IDL tags of ISO/IEC 18013-2 Table C.2.
        result.DataGroupsListed.AddRange(tagList.Select(t => options.IsIdl ? Idl.DataGroupNumber(t) : Lds.DataGroupNumber(t)).Where(d => d > 0).Distinct());
        // ISO/IEC 18013-3 uses its own tag list in EF.COM; the SFI of EF.DGn is n (Table 12), so every DG is probed.
        var dataGroups = options.IsIdl ? Enumerable.Range(1, 14).ToList() : result.DataGroupsListed.Where(d => !Lds.IsEacProtected(d)).ToList();
        foreach (var dg in dataGroups) Plan(FileId($"EF.DG{dg}"), ReadName($"EF.DG{dg}"), before: camVerified ? "Active Authentication" : "Chip Authentication");
        var sod = ReadFile(sm, Lds.SfiSod, "EF.SOD", 0, result, ct);
        foreach (var dg in dataGroups)
            ReadFile(sm, options.IsIdl ? (byte)dg : Lds.DataGroupSfi(dg), $"EF.DG{dg}", dg, result, ct, absentIsNormal: options.IsIdl);

        // 4. Chip Authentication (DG14) unless PACE-CAM authenticated the chip, then Terminal Authentication (EF.CVCA +
        //    chain from the PKI store). After PACE-CAM, TA uses Comp(PK_DH,IFD) of PACE (ICAO 9303-11 7.1).
        byte[]? terminalKey = null;
        if (camVerified)
        {
            terminalKey = pace!.CompressedTerminalEphemeralKey;
            log.Info(LogCategory.Protocol, T("Chip Authentication mit DG14 entfällt: der Chip hat sich mit PACE-CAM authentisiert (ICAO 9303-11 4.4.3.3.3).", "Chip Authentication with DG14 not needed: the chip authenticated with PACE-CAM (ICAO 9303-11 4.4.3.3.3)."));
        }
        else if (!options.ChipAuthentication) AddStep(result, new ReadStep("Chip Authentication", StepOutcome.Skipped, T("abgewählt", "deselected")));
        else if (!result.DataGroups.TryGetValue(14, out var dg14)) AddStep(result, new ReadStep("Chip Authentication", StepOutcome.NotSupported, T("kein DG14", "no DG14")));
        else
        {
            Report("Chip Authentication");
            Start("Chip Authentication", "Chip Authentication");
            terminalKey = RunChipAuthentication(ref sm, dg14, result)?.CompressedTerminalKey;
        }
        if (terminalKey != null)
        {
            // IDL (ISO/IEC 18013-3 8.2.4, EAP): data groups refused with 6982 are protected by CA + TA and are read again afterwards.
            var protectedDgs = options.IsIdl
                ? result.Steps.Where(s => s.Outcome == StepOutcome.Failed && s.Id.StartsWith("read:EF.DG") && s.Detail.Contains("6982"))
                    .Select(s => int.Parse(s.Id["read:EF.DG".Length..])).ToList()
                : result.DataGroupsListed.Where(Lds.IsEacProtected).ToList();
            if (protectedDgs.Count > 0)
            {
                if (options.TerminalAuthentication)
                {
                    Report("Terminal Authentication");
                    Start("Terminal Authentication", "Terminal Authentication");
                    AddStep(result, RunTerminalAuthentication(sm, pace, options, terminalKey, protectedDgs, result, ct));
                }
                else AddStep(result, new ReadStep("Terminal Authentication", StepOutcome.Skipped, T("abgewählt", "deselected")));
            }
        }

        // 5. Active Authentication (DG15)
        if (!options.ActiveAuthentication) AddStep(result, new ReadStep("Active Authentication", StepOutcome.Skipped, T("abgewählt", "deselected")));
        // The AA public key is in DG15 (ICAO 9303-11 6.1) or, for the IDL, in DG13 (ISO/IEC 18013-3 Table 12).
        else if (!result.DataGroups.TryGetValue(options.IsIdl ? 13 : 15, out var dg15)) AddStep(result, new ReadStep("Active Authentication", StepOutcome.NotSupported, options.IsIdl ? T("kein DG13", "no DG13") : T("kein DG15", "no DG15")));
        else
        {
            Report("Active Authentication");
            Start("Active Authentication", "Active Authentication");
            try
            {
                var key = ActiveAuthentication.PublicKeyFromDg15(dg15);
                var aaInfo = result.DataGroups.TryGetValue(14, out var d14) ? SecurityInfos.Parse(BerTlv.ParseSingle(d14).Value).OfType<ActiveAuthenticationInfo>().FirstOrDefault() : null;
                var aa = ActiveAuthentication.Perform(sm, key, aaInfo?.SignatureAlgorithm);
                AddStep(result, new ReadStep("Active Authentication", aa.Valid ? StepOutcome.Success : StepOutcome.Failed, aa.Detail));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                AddStep(result, new ReadStep("Active Authentication", StepOutcome.Failed, ex.Message));
            }
        }

        // 6. Passive Authentication (offline, 9303-11 5.1)
        if (sod != null)
        {
            Report("Passive Authentication");
            Start("Passive Authentication", "Passive Authentication");
            try
            {
                var pa = PassiveAuthentication.Verify(sod, result.DataGroups, pki);
                result.PassiveAuthentication = pa;
                var mismatches = pa.Hashes.Where(h => h.Match == false).Select(h => $"DG{h.DataGroup}").ToList();
                var detail = mismatches.Count > 0 ? T($"Hash falsch: {string.Join(", ", mismatches)}", $"Hash mismatch: {string.Join(", ", mismatches)}")
                    : !pa.SignatureValid ? pa.SignatureDetail
                    : pa.Chain?.Valid != true ? T("DS-Zertifikat nicht bis zu einer vertrauenswürdigen CSCA prüfbar", "DS certificate cannot be verified up to a trusted CSCA")
                    : T("Hashes, SOD-Signatur und Kette DS → CSCA gültig", "Hashes, SOD signature and chain DS → CSCA valid");
                AddStep(result, new ReadStep("Passive Authentication", pa.Valid ? StepOutcome.Success : StepOutcome.Failed, detail));
            }
            catch (Exception ex)
            {
                AddStep(result, new ReadStep("Passive Authentication", StepOutcome.Failed, ex.Message));
            }
        }
        Report(T("Fertig", "Done"));
        return result;
    }

    private void Report(string stage, string? file = null, int done = 0, int total = 0) => Progress?.Invoke(new ReadProgress(stage, file, done, total));

    /// <summary>
    /// Several PACEInfos in EF.CardAccess: the user chooses the variant. Called on the reading thread; returns the chosen
    /// PACEInfo, or null for BAC/BAP instead of PACE; throws <see cref="OperationCanceledException"/> to cancel.
    /// Not set: automatic choice (CAM before GM, as <see cref="EmrtdReadOptions.PreferChipAuthenticationMapping"/>).
    /// </summary>
    public Func<PaceChoiceRequest, PaceInfo?>? ChoosePace { get; set; }

    /// <summary>Text for one PACEInfo: OID name, mapping, key agreement, cipher and domain parameters (9303-11 Table 2/3, 12).</summary>
    public static string DescribePace(PaceInfo p)
    {
        var a = p.Algorithm;
        var mapping = a.Mapping switch
        {
            PaceMapping.Generic => "Generic Mapping",
            PaceMapping.Integrated => "Integrated Mapping",
            _ => "Chip Authentication Mapping",
        };
        var cipher = a.KeyType switch
        {
            Crypto.SessionKeyType.DesEde => "3DES",
            Crypto.SessionKeyType.Aes128 => "AES-128",
            Crypto.SessionKeyType.Aes192 => "AES-192",
            _ => "AES-256",
        };
        var domain = p.ParameterId is { } id
            ? (id <= 31 ? $"{id} ({StandardizedDomainParameters.Name(id)})" : T($"{id} (explizit)", $"{id} (explicit)"))
            : T("explizit (PACEDomainParameterInfo)", "explicit (PACEDomainParameterInfo)");
        return T($"{Oids.Name(p.Oid)} – {mapping}, {(a.KeyAgreement == KeyAgreement.Ecdh ? "ECDH" : "DH")}, {cipher}, Domain-Parameter {domain}",
                 $"{Oids.Name(p.Oid)} – {mapping}, {(a.KeyAgreement == KeyAgreement.Ecdh ? "ECDH" : "DH")}, {cipher}, domain parameters {domain}");
    }

    /// <summary>Live step view (see <see cref="StepEvent"/>); called on the reading thread.</summary>
    public Action<StepEvent>? StepChanged { get; set; }

    private static string FileId(string file) => "read:" + file;
    private static string ReadName(string file) => T("Lesen ", "Read ") + file;
    private void Plan(string id, string name, string? before = null) => StepChanged?.Invoke(new StepEvent(id, name, StepState.Pending, Before: before));
    private void Start(string id, string name, string? detail = null) => StepChanged?.Invoke(new StepEvent(id, name, StepState.Running, Detail: detail));
    private void Provisional(ReadStep step)
    {
        StepChanged?.Invoke(new StepEvent(step.Id, step.Name, StepState.Done, step, Provisional: true));
        Separator(step);
    }

    /// <summary>Separator line in the log after every step of the result list.</summary>
    private void Separator(ReadStep step)
    {
        if (StepChanged != null) channel.Logger.Info(LogCategory.Application, SeparatorText(step));
    }

    public static string SeparatorText(ReadStep step)
    {
        var symbol = step.Outcome switch { StepOutcome.Success => "✔", StepOutcome.Failed => "✘", StepOutcome.Skipped => "–", StepOutcome.Warning => "⚠", _ => "○" };
        return $"──────────────── {symbol} {step.Name}: {step.Detail} ────────────────";
    }
    private void Drop(string id) => StepChanged?.Invoke(new StepEvent(id, id, StepState.Removed));
    private void ReadDone(string file, int length) => Provisional(new ReadStep(ReadName(file), StepOutcome.Success, T($"{length} Byte", $"{length} bytes")) { Key = FileId(file) });

    private void FileProgress(string file, int done, int total)
    {
        Report(T("Lesen", "Reading"), file, done, total);
        StepChanged?.Invoke(new StepEvent(FileId(file), ReadName(file), StepState.Running, Done: done, Total: total));
    }

    private void AddStep(EmrtdReadResult result, ReadStep step)
    {
        result.Steps.Add(step);
        StepChanged?.Invoke(new StepEvent(step.Id, step.Name, StepState.Done, step));
        Separator(step);
    }

    private void RemoveStep(EmrtdReadResult result, ReadStep step)
    {
        result.Steps.Remove(step);
        Drop(step.Id);
    }

    private static string SelectName(EmrtdReadOptions options) => T($"SELECT {options.ApplicationName}-Anwendung", $"SELECT {options.ApplicationName} application");

    /// <summary>SELECT of the first candidate application that exists (under SM after PACE).</summary>
    private EmrtdReadOptions SelectApplication(IApduChannel c, IReadOnlyList<DocumentApplication> candidates, EmrtdReadOptions options, EmrtdReadResult result)
    {
        for (var i = 0; ; i++)
        {
            var candidate = options.For(candidates[i]);
            if (TrySelect(c, candidate, result, last: i == candidates.Count - 1)) return candidate;
        }
    }

    /// <summary>
    /// SELECT by AID (9303-10 3.6.1.2, ISO/IEC 18013-2 C.7.5.1). A missing application is skipped while another
    /// candidate remains; the last one throws.
    /// </summary>
    private bool TrySelect(IApduChannel c, EmrtdReadOptions options, EmrtdReadResult result, bool last)
    {
        var name = SelectName(options);
        Start("select", name);
        var sel = c.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, options.Aid), name);
        var detail = $"AID {Hex.Of(options.Aid)}: {sel.Status} {sel.Status.Description}";
        if (sel.Status.IsSuccess)
        {
            AddStep(result, new ReadStep(name, StepOutcome.Success, detail) { Key = "select" });
            result.Application = options.IsIdl ? DocumentApplication.Idl : DocumentApplication.Emrtd;
            return true;
        }
        if (!last)
        {
            AddStep(result, new ReadStep(name, StepOutcome.Skipped, T($"{detail} – Anwendung nicht vorhanden", $"{detail} – application not present")) { Key = "select" });
            return false;
        }
        AddStep(result, new ReadStep(name, StepOutcome.Failed, detail) { Key = "select" });
        throw new ProtocolException($"{name}: {sel.Status} {sel.Status.Description}", sel.Status);
    }

    private AtrInfoFile? atrInfo;

    /// <summary>
    /// Block size for PSO:Verify Certificate (TA). An explicit option wins; otherwise EF.ATR/INFO decides: extended
    /// length beyond MSE:Set KAT / GENERAL AUTHENTICATE only with stated buffer sizes (9303-11 9.3.1.2), command chaining
    /// only if the chip indicates it (9.3.2). Without EF.ATR/INFO the former rule stays (chaining for the IDL).
    /// </summary>
    private int? MaxCommandData(EmrtdReadOptions options)
    {
        if (options.CommandChaining.HasValue || atrInfo == null) return options.MaxCommandData;
        // Headroom for the APDU header, extended Lc/Le, DO'87' with padding, DO'97' and DO'8E'.
        const int smOverhead = 64;
        if (atrInfo.BufferSizesStated)
            return atrInfo.CommandChaining ? Math.Max(options.ChainingBlockSize, atrInfo.MaxCommandApdu!.Value - smOverhead) : null;
        if (atrInfo.CommandChaining) return options.ChainingBlockSize;
        channel.Logger.Warning(LogCategory.Protocol, T("EF.ATR/INFO zeigt weder Command chaining noch Puffergrößen für Extended Length an – PSO:Verify Certificate wird ungeteilt gesendet", "EF.ATR/INFO indicates neither command chaining nor buffer sizes for extended length – PSO:Verify Certificate is sent in one piece"), null, "ICAO 9303-11 9.3.1.2, 9.3.2");
        return null;
    }

    /// <summary>
    /// EF.ATR/INFO or EF.DIR in the MF, unprotected: by SFI (9303-10 Tables 28/30), and if the chip answers '6A82',
    /// by SELECT FID + READ BINARY (9303-10 3.11.1; production chips often assign no SFI to these files).
    /// '6A82' both ways means: not present (optional).
    /// </summary>
    private byte[]? ReadMfFile(byte sfi, ushort fid, string name, EmrtdReadResult result, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Report(T("Lesen", "Reading"), name);
        Start(FileId(name), ReadName(name));
        var reader = new FileReader(channel) { Cancellation = ct, Progress = FileProgress };
        try
        {
            byte[] data;
            try { data = reader.ReadWholeBySfi(sfi, name); }
            catch (FileReadException ex) when (ex.Status?.Value is 0x6A82 or 0x6981 or 0x6986 or 0x6A81)
            {
                channel.Logger.Info(LogCategory.Protocol, T($"{name}: SFI {sfi:X2} → {ex.Status} – Versuch mit SELECT FID {fid:X4}", $"{name}: SFI {sfi:X2} → {ex.Status} – trying SELECT FID {fid:X4}"), null, "ICAO 9303-10 3.11");
                data = reader.ReadWholeByFid(fid, name);
                // The file exists, but not under the SFI that 9303-10 assigns (Table 28 / 30) – a deviation of the chip.
                AddStep(result, new ReadStep(T($"Normkonformität {name}", $"Conformance {name}"), StepOutcome.Warning,
                    T($"nur per SELECT FID {fid:X4} lesbar, nicht per SFI {sfi:X2} ({ex.Status}); ICAO 9303-10 sieht SFI {sfi:X2} vor", $"readable by SELECT FID {fid:X4} only, not by SFI {sfi:X2} ({ex.Status}); ICAO 9303-10 assigns SFI {sfi:X2}")));
            }
            result.Files.Add(new EmrtdFile(name, sfi, 0, data, fid));
            ReadDone(name, data.Length);
            return data;
        }
        catch (FileReadException ex) when (ex.Status?.Value == 0x6A82)
        {
            channel.Logger.Info(LogCategory.Protocol, T($"{name}: optional, nicht vorhanden (6A82 per SFI und per FID)", $"{name}: optional, not present (6A82 by SFI and by FID)"), null, "ICAO 9303-10 3.11");
            Provisional(new ReadStep(ReadName(name), StepOutcome.NotSupported, T("optional, nicht vorhanden (6A82)", "optional, not present (6A82)")) { Key = FileId(name) });
            return null;
        }
        catch (FileReadException ex)
        {
            channel.Logger.Warning(LogCategory.Protocol, $"{name}: {ex.Message}");
            Provisional(new ReadStep(ReadName(name), StepOutcome.Warning, ex.Message) { Key = FileId(name) });
            return null;
        }
    }

    /// <summary>EF.DIR = EFDIRInfo of EF.CardSecurity, and EF.CardSecurity signed by a DS of a trusted CSCA (9303-11 9.2.10).</summary>
    private ReadStep VerifyEfDir(IApduChannel sm, byte[] dir, EmrtdReadResult result, CancellationToken ct)
    {
        var name = T("Echtheit EF.DIR", "Authenticity of EF.DIR");
        var data = result.File("EF.CardSecurity") ?? ReadFile(sm, Lds.SfiCardSecurity, "EF.CardSecurity", 0, result, ct);
        if (data == null)
            return new ReadStep(name, StepOutcome.Warning, T("nicht prüfbar: EF.CardSecurity nicht lesbar (ICAO 9303-11 4.2)", "cannot be verified: EF.CardSecurity not readable (ICAO 9303-11 4.2)"));
        try
        {
            var cardSecurity = new CardSecurity(data);
            var info = cardSecurity.Infos.OfType<EfDirInfo>().FirstOrDefault();
            if (info == null)
                return new ReadStep(name, StepOutcome.Failed, T("EF.CardSecurity enthält kein EFDIRInfo (ICAO 9303-11 9.2.11, 9303-10 3.11.2)", "EF.CardSecurity contains no EFDIRInfo (ICAO 9303-11 9.2.11, 9303-10 3.11.2)"));
            if (!info.Content.AsSpan().SequenceEqual(dir))
                return new ReadStep(name, StepOutcome.Failed, T($"EF.DIR ({dir.Length} Byte) ≠ EFDIRInfo ({info.Content.Length} Byte) – EF.DIR nicht authentisch", $"EF.DIR ({dir.Length} bytes) ≠ EFDIRInfo ({info.Content.Length} bytes) – EF.DIR not authentic"));
            var check = cardSecurity.Verify(pki);
            if (!check.SignatureValid)
                return new ReadStep(name, StepOutcome.Failed, T($"EF.DIR = EFDIRInfo, aber EF.CardSecurity: {check.SignatureDetail}", $"EF.DIR = EFDIRInfo, but EF.CardSecurity: {check.SignatureDetail}"));
            return check.Valid
                ? new ReadStep(name, StepOutcome.Success, T("EF.DIR = EFDIRInfo, EF.CardSecurity signiert, Kette DS → CSCA gültig", "EF.DIR = EFDIRInfo, EF.CardSecurity signed, chain DS → CSCA valid"))
                : new ReadStep(name, StepOutcome.Warning, T("EF.DIR = EFDIRInfo, EF.CardSecurity signiert; DS nicht bis zu einer vertrauenswürdigen CSCA prüfbar", "EF.DIR = EFDIRInfo, EF.CardSecurity signed; DS cannot be verified up to a trusted CSCA"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ReadStep(name, StepOutcome.Failed, T($"EF.CardSecurity ungültig ({ex.Message})", $"EF.CardSecurity invalid ({ex.Message})"));
        }
    }

    private byte[]? ReadFile(IApduChannel c, byte sfi, string name, int dg, EmrtdReadResult result, CancellationToken ct, bool absentIsNormal = false)
    {
        ct.ThrowIfCancellationRequested();
        Report(T("Lesen", "Reading"), name);
        Start(FileId(name), ReadName(name));
        try
        {
            var data = new FileReader(c) { Cancellation = ct, Progress = FileProgress }.ReadBySfi(sfi, name);
            result.Files.Add(new EmrtdFile(name, sfi, dg, data));
            if (dg > 0) result.DataGroups[dg] = data;
            ReadDone(name, data.Length);
            return data;
        }
        catch (FileReadException ex) when (absentIsNormal && ex.Status?.Value == 0x6A82)
        {
            Drop(FileId(name));
            return null;
        }
        catch (FileReadException ex) when (absentIsNormal && ex.Status?.Value == 0x6986)
        {
            // ISO/IEC 7816-4 7.2.2/5.6: a missing short EF is reported with 6A82; 6986 ("no current EF") is a deviation.
            Drop(FileId(name));
            AddStep(result, new ReadStep(T($"Normkonformität {name}", $"Conformance {name}"), StepOutcome.Warning, T("READ BINARY mit SFI einer nicht vorhandenen Datei: 6986 statt 6A82 (ISO/IEC 7816-4)", "READ BINARY with the SFI of a missing file: 6986 instead of 6A82 (ISO/IEC 7816-4)")));
            return null;
        }
        catch (FileReadException ex)
        {
            channel.Logger.Warning(LogCategory.Protocol, $"{name}: {ex.Message}");
            AddStep(result, ReadStep.ReadFailed(name, ex.Message));
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
            AddStep(result, new ReadStep("Chip Authentication", StepOutcome.NotSupported, T("kein ChipAuthenticationPublicKeyInfo in DG14", "no ChipAuthenticationPublicKeyInfo in DG14")));
            return null;
        }
        try
        {
            var ca = ChipAuthentication.Perform(sm, ChipPublicKey.From(choice.Key), choice.Oid);
            sm = ca.Channel;
            // Proof that the new session keys work: read the EF.COM head again.
            var check = sm.Transmit(new CommandApdu(0x00, 0xB0, (byte)(0x80 | Lds.SfiCom), 0x00, null, 4), T("READ BINARY EF.COM (Kontrolle nach CA)", "READ BINARY EF.COM (check after CA)"));
            var detail = $"{Oids.Name(choice.Oid)}, KeyID {choice.Key.KeyId?.ToString() ?? "-"}";
            AddStep(result, check.Status.IsSuccess
                ? new ReadStep("Chip Authentication", StepOutcome.Success, detail)
                : new ReadStep("Chip Authentication", StepOutcome.Failed, T($"{detail}: Lesen nach Schlüsselwechsel {check.Status}", $"{detail}: read after key change {check.Status}")));
            return check.Status.IsSuccess ? ca : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AddStep(result, new ReadStep("Chip Authentication", StepOutcome.Failed, ex.Message));
            return null;
        }
    }

    /// <summary>
    /// PACE-CAM check (ICAO 9303-11 4.4.3.5.2): Passive Authentication of EF.CardSecurity, then PK_Map,IC = CA_IC · PK_IC
    /// with its ChipAuthenticationPublicKeyInfo. Reported as the "Chip Authentication" step.
    /// </summary>
    private ReadStep VerifyChipAuthenticationMapping(PaceResult pace, byte[]? data)
    {
        const string name = "Chip Authentication";
        if (data == null) return new ReadStep(name, StepOutcome.Failed, T("PACE-CAM: EF.CardSecurity nicht lesbar (9303-11 9.2.11: Pflicht bei CAM)", "PACE-CAM: EF.CardSecurity not readable (9303-11 9.2.11: required with CAM)"));
        try
        {
            var cardSecurity = new CardSecurity(data);
            var check = cardSecurity.Verify(pki);
            if (!check.SignatureValid) return new ReadStep(name, StepOutcome.Failed, T($"PACE-CAM: EF.CardSecurity {check.SignatureDetail}", $"PACE-CAM: EF.CardSecurity {check.SignatureDetail}"));
            var key = Pace.VerifyChipAuthenticationMapping(pace, cardSecurity.Infos.OfType<ChipAuthenticationPublicKeyInfo>());
            if (key == null) return new ReadStep(name, StepOutcome.Failed, T("PACE-CAM: PK_Map,IC ≠ CA_IC · PK_IC für jeden Schlüssel in EF.CardSecurity – Chip nicht authentisch", "PACE-CAM: PK_Map,IC ≠ CA_IC · PK_IC for every key in EF.CardSecurity – chip not authentic"));
            var detail = $"PACE-CAM ({Oids.Name(pace.Info.Oid)}){(key.KeyId is { } k ? $", KeyID {k}" : "")}";
            return check.Valid
                ? new ReadStep(name, StepOutcome.Success, T($"{detail}: CA_IC · PK_IC = PK_Map,IC, EF.CardSecurity signiert, Kette DS → CSCA gültig", $"{detail}: CA_IC · PK_IC = PK_Map,IC, EF.CardSecurity signed, chain DS → CSCA valid"))
                : new ReadStep(name, StepOutcome.Warning, T($"{detail}: CA_IC · PK_IC = PK_Map,IC; DS von EF.CardSecurity nicht bis zu einer vertrauenswürdigen CSCA prüfbar", $"{detail}: CA_IC · PK_IC = PK_Map,IC; DS of EF.CardSecurity cannot be verified up to a trusted CSCA"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ReadStep(name, StepOutcome.Failed, T($"PACE-CAM: EF.CardSecurity ungültig ({ex.Message})", $"PACE-CAM: EF.CardSecurity invalid ({ex.Message})"));
        }
    }

    private ReadStep RunTerminalAuthentication(IApduChannel sm, PaceResult? pace, EmrtdReadOptions options, byte[] terminalKey, List<int> protectedDgs, EmrtdReadResult result, CancellationToken ct)
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
            log.Info(LogCategory.Protocol, T($"EF.CVCA: Vertrauensanker des Chips {string.Join(", ", cars)}", $"EF.CVCA: trust points of the chip {string.Join(", ", cars)}"));
        }
        catch (FileReadException ex) when (options.IsIdl && ex.Status?.Value == 0x6A82)
        {
            // The IDL application has no EF.CVCA (ISO/IEC 18013-3 Table 12): the chip's trust point is not readable,
            // so every CVCA of the PKI store is offered; the chip rejects an unknown CAR in MSE:Set DST.
            cars = pki.CandidateTrustPoints();
            carSource = T("PKI-Speicher (IDL ohne EF.CVCA)", "PKI store (IDL without EF.CVCA)");
            log.Info(LogCategory.Protocol, T($"Kein EF.CVCA in der IDL-Anwendung – Vertrauensanker aus dem PKI-Speicher: {(cars.Count == 0 ? "keine" : string.Join(", ", cars))}", $"No EF.CVCA in the IDL application – trust points from the PKI store: {(cars.Count == 0 ? "none" : string.Join(", ", cars))}"));
            if (cars.Count == 0) return new ReadStep(name, StepOutcome.Skipped, T("IDL ohne EF.CVCA und kein CVCA-Zertifikat im PKI-Speicher – bitte IDL-Terminalkette importieren (Tab „PKI“)", "IDL without EF.CVCA and no CVCA certificate in the PKI store – please import the IDL terminal chain (tab 'PKI')"));
        }
        catch (Exception ex) { return new ReadStep(name, StepOutcome.Failed, T($"EF.CVCA nicht lesbar ({ex.Message})", $"EF.CVCA not readable ({ex.Message})")); }

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
            else return new ReadStep(name, StepOutcome.Failed, T("ID_PICC nicht bestimmbar.", "ID_PICC cannot be determined."));
            TerminalAuthenticationResult ta;
            try { ta = TerminalAuthentication.Perform(sm, chain, terminal.PrivateKey, idPicc, terminalKey, MaxCommandData(options)); }
            catch (Exception ex) when (ex is SecureMessagingException or ProtocolException)
            {
                return new ReadStep(name, StepOutcome.Failed, T($"Kette über CAR {car}: {ex.Message}", $"Chain via CAR {car}: {ex.Message}"));
            }
            foreach (var finding in ta.Steps.Where(x => x.StartsWith('⚠')))
                AddStep(result, new ReadStep(T("Normkonformität TA", "Conformance TA"), StepOutcome.Warning, finding.TrimStart('⚠', ' ')));
            if (!ta.Success)
            {
                // IDL: trust point unknown, so a rejected chain (normally MSE:Set DST 6A88) is followed by the next candidate.
                if (options.IsIdl && sm is SecureChannel { IsActive: true })
                {
                    rejected.Add($"{car}: {ta.Detail}");
                    log.Info(LogCategory.Protocol, T($"Kette über CAR {car} abgelehnt ({ta.Detail}) – nächster Kandidat", $"Chain via CAR {car} rejected ({ta.Detail}) – next candidate"));
                    continue;
                }
                return new ReadStep(name, StepOutcome.Failed, ta.Detail);
            }
            foreach (var dg in protectedDgs)
            {
                var stale = result.Steps.FirstOrDefault(s => s.Id == $"read:EF.DG{dg}" && s.Outcome == StepOutcome.Failed);
                if (stale != null) RemoveStep(result, stale);
                // Authorization bits of the IDL terminal certificate differ from the eMRTD role (18013-3 Annex); the chip decides.
                if (!options.IsIdl && !terminal.Certificate.AllowsDataGroup(dg)) { log.Info(LogCategory.Protocol, T($"DG{dg}: Terminalzertifikat berechtigt nicht zum Lesen", $"DG{dg}: terminal certificate does not authorize reading")); continue; }
                if (ReadFile(sm, Lds.DataGroupSfi(dg), $"EF.DG{dg}", dg, result, ct) is { } read)
                    AddStep(result, new ReadStep(T($"Lesen EF.DG{dg}", $"Read EF.DG{dg}"), StepOutcome.Success, T($"{read.Length} Byte, nach Terminal Authentication", $"{read.Length} bytes, after Terminal Authentication")) { Key = $"read:EF.DG{dg}" });
            }
            return new ReadStep(name, StepOutcome.Success, T($"{terminal.Certificate.Chr} über CAR {car} ({terminal.Certificate.DescribeAuthorization()}; Anker aus {carSource})", $"{terminal.Certificate.Chr} via CAR {car} ({terminal.Certificate.DescribeAuthorization()}; trust point from {carSource})"));
        }
        if (rejected.Count > 0) return new ReadStep(name, StepOutcome.Failed, T($"alle Ketten vom Chip abgelehnt: {string.Join("; ", rejected)}", $"all chains rejected by the chip: {string.Join("; ", rejected)}"));
        return new ReadStep(name, StepOutcome.Skipped, T($"keine passende Terminal-Zertifikatskette (mit privatem Schlüssel) im PKI-Speicher für CAR {string.Join(" / ", cars)} – {string.Join(", ", protectedDgs.Select(d => $"DG{d}"))} nicht gelesen", $"no matching terminal certificate chain (with private key) in the PKI store for CAR {string.Join(" / ", cars)} – {string.Join(", ", protectedDgs.Select(d => $"DG{d}"))} not read"));
    }
}
