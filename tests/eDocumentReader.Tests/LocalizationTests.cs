using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Localization;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Tests;

/// <summary>The language is process-wide, so these tests must not run in parallel with the German text assertions.</summary>
[CollectionDefinition(nameof(LanguageCollection), DisableParallelization = true)]
public sealed class LanguageCollection;

[Collection(nameof(LanguageCollection))]
public sealed class LocalizationTests
{
    private static T InEnglish<T>(Func<T> f)
    {
        Loc.Language = UiLanguage.English;
        try { return f(); }
        finally { Loc.Language = UiLanguage.German; }
    }

    [Fact]
    public void Texts_FollowTheLanguage()
    {
        Assert.Equal("Sicherheitszustand nicht erfüllt", StatusWord.Parse(0x6982).Description);
        Assert.Equal("Security status not satisfied", InEnglish(() => StatusWord.Parse(0x6982).Description));
        Assert.Equal("Read EF.DG3", InEnglish(() => ReadStep.ReadFailed("EF.DG3", "x").Name));
    }

    [Fact]
    public void ProgramLogic_UsesLanguageIndependentKeys()
    {
        // IDL DG1 demographics (ISO/IEC 18013-2 Annex C): family name "MUSTER", licence number "ZZ1".
        var demographics = Hex.Parse("064D5553544552 0445524B41 19800102 20200101 20300101 5A5A5A 02414B 035A5A31");
        var dg1 = Hex.Parse("61" + (demographics.Length + 3).ToString("X2") + "5F1F" + demographics.Length.ToString("X2") + Hex.Compact(demographics));
        var idl = InEnglish(() => Idl.Parse(new Dictionary<int, byte[]> { [1] = dg1 }));
        Assert.Equal("Family name", idl.Fields.Single(f => f.Key == "familyName").Name);
        Assert.Equal("ZZ1", idl.Fields.Single(f => f.Key == "licenceNumber").Value);

        var mrz = InEnglish(() => Mrz.Parse("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10"));
        Assert.Equal("Composite check digit", mrz.Fields.Single(f => f.Key == "composite").Name);
        Assert.All(mrz.Fields, f => Assert.True(f.Valid != false, f.Key));

        // The step key drives the "notRead" reason of the exchange format in both languages.
        var step = InEnglish(() => ReadStep.ReadFailed("EF.DG2", "EF.DG2: 6982"));
        Assert.Equal("read:EF.DG2", step.Id);
    }
}
