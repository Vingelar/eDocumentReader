namespace eDocumentReader.Core.Documents;

/// <summary>
/// Single-line machine-readable zone of an ISO/IEC 18013 driving licence (30 characters, document code 'D').
/// The check digit (ICAO 9303-3 4.9, weights 7-3-1) covers characters 1–29. The BAP key seed is derived from
/// characters 2–29, i.e. without the document code and the check digit (ISO/IEC 18013-3 8.2.3); this was
/// confirmed against a personalised IDL test card.
/// </summary>
public sealed record IdlMrz(string Line)
{
    public const int Length = 30;

    /// <summary>Character 2: BAP configuration ('1' = BAP configuration 1, ISO/IEC 18013-3 8.2.3).</summary>
    public char Configuration => Line[1];

    public char CheckDigit => Line[^1];

    public bool CheckDigitValid => Mrz.ComputeCheckDigit(Line[..29]) == CheckDigit;

    /// <summary>Input for Kseed = SHA-1(…)[0..15], the same derivation as BAC (ICAO 9303-11 9.7.2).</summary>
    public string BapKeySeedInformation => Line[1..29];

    public static bool LooksLikeIdlMrz(string text)
    {
        var t = Normalize(text);
        return t.Length == Length && t[0] == 'D' && t.All(c => char.IsAsciiLetterUpper(c) || char.IsAsciiDigit(c) || c == '<');
    }

    public static IdlMrz Parse(string text)
    {
        var t = Normalize(text);
        if (!LooksLikeIdlMrz(t)) throw new FormatException(T("IDL-MRZ: 30 Zeichen A–Z, 0–9, '<', beginnend mit 'D' erwartet (ISO/IEC 18013).", "IDL MRZ: 30 characters A–Z, 0–9, '<', starting with 'D' expected (ISO/IEC 18013)."));
        return new IdlMrz(t);
    }

    private static string Normalize(string text) => text.Trim().Replace(" ", "").ToUpperInvariant();
}
