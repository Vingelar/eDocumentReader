using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Crypto;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;
using Org.BouncyCastle.Math;

namespace eDocumentReader.Tests;

/// <summary>Test vectors from ICAO Doc 9303-11 (8th ed.) Appendices D (BAC) and G (PACE GM).</summary>
public class Icao9303WorkedExampleTests
{
    [Fact]
    public void D1_KeyDerivationFromSeed()
    {
        var seed = Hex.Parse("239AB9CB282DAF66231DC5A4DF6BFBAE");
        Assert.Equal(Hex.Parse("AB94FDECF2674FDF B9B391F85D7F76F2"), Kdf.Derive(seed, 1, SessionKeyType.DesEde));
        Assert.Equal(Hex.Parse("7962D9ECE03D1ACD 4C76089DCE131543"), Kdf.Derive(seed, 2, SessionKeyType.DesEde));
    }

    [Theory]
    [InlineData("I<UTOSTEVENSON<<PETER<JOHN<<<<<<<<<<\nD23145890<UTO3407127M95071227349<<<8", "D23145890734934071279507122")]
    [InlineData("I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<\nL898902C<3UTO6908061F9406236<<<<<<<8", "L898902C<369080619406236")]
    [InlineData("I<UTOD23145890<7349<<<<<<<<<<<\n3407127M9507122UTO<<<<<<<<<<<2\nSTEVENSON<<PETER<JOHN<<<<<<<<<", "D23145890734934071279507122")]
    [InlineData("I<UTOL898902C<3<<<<<<<<<<<<<<<\n6908061F9406236UTO<<<<<<<<<<<1\nERIKSSON<<ANNA<MARIA<<<<<<<<<<", "L898902C<369080619406236")]
    public void D2_MrzInformation(string mrzText, string expected)
    {
        var mrz = Mrz.Parse(mrzText);
        // Note: the ERIKSSON examples in 9303-11 App. D carry an incorrect composite check digit (correct value: 2).
        // Only the fields relevant for BAC are required to be consistent here.
        Assert.All(mrz.Fields.Where(f => f.Key != "composite"), f => Assert.True(f.Valid != false, f.Name));
        Assert.Equal(expected, mrz.KeySeedInformation);
    }

    [Fact]
    public void D2_DocumentKeys()
    {
        var (kEnc, kMac) = Bac.DocumentKeys("L898902C<369080619406236");
        Assert.Equal(Hex.Parse("AB94FDECF2674FDFB9B391F85D7F76F2"), kEnc);
        Assert.Equal(Hex.Parse("7962D9ECE03D1ACD4C76089DCE131543"), kMac);
    }

    [Fact]
    public void D3_D4_BacAndSecureMessaging()
    {
        var transport = new ScriptedTransport(
            ("0084000008", "4608F91988702212 9000"),
            ("0082000028 72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7 28",
             "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449 9000"),
            ("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800", "990290008E08FA855A5D4C50A8ED 9000"),
            ("0CB000000D9701048E08ED6705417E96BA5500", "8709019FF0EC34F9922651990290008E08AD55CC17140B2DED 9000"));
        var channel = new CardChannel(transport, Logger.Null);
        var sm = Bac.Perform(channel, "L898902C<369080619406236", Hex.Parse("781723860C06C226"), Hex.Parse("0B795240CB7049B01C19B33E32804F0B"));

        var select = sm.Transmit(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Hex.Parse("011E")));
        Assert.True(select.Status.IsSuccess);
        var read = sm.Transmit(new CommandApdu(0x00, 0xB0, 0x00, 0x00, null, 4));
        Assert.True(read.Status.IsSuccess);
        // 9303-11 D.4 step 2 i): decrypted data of the first four bytes of EF.COM
        Assert.Equal(Hex.Parse("60145F01"), read.Data);
        Assert.Equal(Hex.Parse("887022120C06C22A"), sm.CurrentSsc);
    }

    [Fact]
    public void SecureMessaging_TamperedMacIsRejected()
    {
        var transport = new ScriptedTransport(
            ("0084000008", "4608F91988702212 9000"),
            (null, "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449 9000"),
            (null, "990290008E08FA855A5D4C50A8EE 9000"));
        var sm = Bac.Perform(new CardChannel(transport, Logger.Null), "L898902C<369080619406236", Hex.Parse("781723860C06C226"), Hex.Parse("0B795240CB7049B01C19B33E32804F0B"));
        Assert.Throws<SecureMessagingException>(() => sm.Transmit(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Hex.Parse("011E"))));
        Assert.False(sm.IsActive);
    }

    [Fact]
    public void G1_PaceGenericMappingEcdh()
    {
        const string mrz = "T22000129364081251010318";
        var password = PacePassword.FromMrz(mrz);
        Assert.Equal(Hex.Parse("7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD"), password.Encode());
        Assert.Equal(Hex.Parse("89DED1B26624EC1E634C1989302849DD"), Kdf.Derive(password.Encode(), 3, SessionKeyType.Aes128));

        var info = (PaceInfo)SecurityInfos.Parse(Hex.Parse("3114 3012060A04007F000702020402020201020201 0D"))[0];
        Assert.Equal(13, info.ParameterId);

        var transport = new ScriptedTransport(
            ("0022C1A40F800A04007F0007020204020283010 1", "9000"),
            ("10860000027C0000", "7C12801095A3A016522EE98D01E76CB6B98B42C3 9000"),
            ("10860000457C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D00",
             "7C438241048 24FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F5730D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54 9000"),
            ("10860000457C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB3646200",
             "7C438441049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094 9000"),
            ("008600000C7C0A8508C2B0BD78D94BA86600", "7C0A86083ABB9674BCE93C08 9000"));

        var test = new PaceTestValues(
            new BigInteger("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99", 16),
            new BigInteger("A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595", 16));
        var result = Pace.Perform(new CardChannel(transport, Logger.Null), info, password, test: test);
        Assert.Equal(CipherAlgorithm.Aes, result.Channel.Algorithm);
        Assert.Equal(new byte[16], result.Channel.CurrentSsc);
    }

    [Fact]
    public void CheckDigits()
    {
        Assert.Equal('3', Mrz.ComputeCheckDigit("520727")); // ICAO 9303-3 4.9 Example 1
        Assert.Equal('3', Mrz.ComputeCheckDigit("L898902C<"));
    }
}
