# eDocumentReader

*[English version below](#english)*

Testsoftware zum Lesen und Prüfen elektronischer Dokumente über PC/SC-Leser (Windows, .NET 10, WPF).
Oberfläche und Meldungen auf Deutsch oder Englisch (Menü *Einstellungen → Sprache*).

## Funktionen

- **Reisepass / ID-Karte (eMRTD, ICAO Doc 9303):** BAC, PACE (MRZ oder CAN), Chip Authentication, Terminal Authentication,
  Active Authentication und Passive Authentication mit CSCA-Kette und CRL; Anzeige von MRZ und Gesichtsbild.
- **Führerschein (IDL, ISO/IEC 18013-2/-3):** BAP und PACE, EAP mit Terminal Authentication, aufbereitete Anzeige der Datengruppen.
- **Zulassungsbescheinigung (eVRC, Richtlinie 2003/127/EG):** Lesen und Signaturprüfung.
- **Analyse:** Dateibaum mit BER-TLV-Struktur und Normbefunden, Sicherheitsbericht, ATR-Auswertung, APDU-Konsole, Kommunikationslog.
- **PKI-Speicher:** Import von CSCA/DS, Master Lists, CRLs, CV-Zertifikaten und Terminalschlüsseln.
- **Export:** einzelne EF-Dateien oder ein vollständiger Datensatz (`project.json` + `ef/*.bin`).

## Bauen und starten

```powershell
dotnet build eDocumentReader.slnx
dotnet test eDocumentReader.slnx
dotnet run --project src/eDocumentReader.App
```

## Testsoftware

eDocumentReader ist eine Testsoftware zum Lesen und Prüfen elektronischer Dokumente über PC/SC-Leser. Sie dient Entwicklung,
Test und Analyse und ist kein zertifiziertes Prüf- oder Kontrollsystem.

Die Software wurde nach den relevanten Standards geschrieben, insbesondere ICAO Doc 9303 (Teile 3, 10, 11), BSI TR-03110 und
TR-03111, ISO/IEC 7816-3/-4, ISO/IEC 14443, ISO/IEC 18013-2/-3, ISO/IEC 19794-5, PC/SC und Richtlinie 2003/127/EG.
Abweichungen von den Standards und Fehler in der Auswertung sind dennoch möglich.

## Gewährleistungs- und Haftungsausschluss

Die Software wird ohne jegliche Gewährleistung bereitgestellt, weder ausdrücklich noch stillschweigend, einschließlich der
Gewährleistung der Marktgängigkeit, der Eignung für einen bestimmten Zweck und der Fehlerfreiheit. Die Nutzung erfolgt auf
eigenes Risiko. **Schäden an Karten, Chips oder Lesegeräten** – etwa durch blockierte Zugangsdaten, verbrauchte
Fehlbedienungszähler, unterbrochene Kommunikation oder unerwartetes Verhalten des Chips – **können nicht ausgeschlossen werden.**
Eine Haftung für Schäden jeder Art ist ausgeschlossen, soweit das Gesetz dies zulässt.

## Künstliche Intelligenz

Die Software wurde mit Hilfe künstlicher Intelligenz (Claude von Anthropic) geschrieben.

## Lizenz

[MIT-Lizenz](LICENSE) – freie Nutzung, Änderung und Weitergabe, auch kommerziell, solange der Copyright- und Lizenzhinweis
erhalten bleibt. Verwendete Bibliotheken: BouncyCastle (MIT), CommunityToolkit.Mvvm (MIT), CoreJ2K (BSD-3-Clause).
Die Normdokumente selbst sind nicht Teil des Repositorys; enthalten sind nur die öffentlichen Testdaten, die die Unit-Tests
verwenden (BSI TR-03110 Worked Example, BSI TR-03105-5 Referenzdatensatz).

---

<a id="english"></a>
# eDocumentReader (English)

Test software for reading and checking electronic documents with PC/SC readers (Windows, .NET 10, WPF).
User interface and messages in German or English (menu *Settings → Language*).

## Features

- **Passport / ID card (eMRTD, ICAO Doc 9303):** BAC, PACE (MRZ or CAN), Chip Authentication, Terminal Authentication,
  Active Authentication and Passive Authentication with CSCA chain and CRL; display of MRZ and facial image.
- **Driving licence (IDL, ISO/IEC 18013-2/-3):** BAP and PACE, EAP with Terminal Authentication, prepared display of the data groups.
- **Vehicle registration certificate (eVRC, Directive 2003/127/EC):** reading and signature verification.
- **Analysis:** file tree with BER-TLV structure and conformance findings, security report, ATR analysis, APDU console, communication log.
- **PKI store:** import of CSCA/DS, Master Lists, CRLs, CV certificates and terminal keys.
- **Export:** single EF files or a complete data set (`project.json` + `ef/*.bin`).

## Build and run

```powershell
dotnet build eDocumentReader.slnx
dotnet test eDocumentReader.slnx
dotnet run --project src/eDocumentReader.App
```

## Test software

eDocumentReader is test software for reading and checking electronic documents with PC/SC readers. It is meant for
development, testing and analysis and is not a certified inspection system.

The software was written according to the relevant standards, in particular ICAO Doc 9303 (Parts 3, 10, 11), BSI TR-03110
and TR-03111, ISO/IEC 7816-3/-4, ISO/IEC 14443, ISO/IEC 18013-2/-3, ISO/IEC 19794-5, PC/SC and Directive 2003/127/EC.
Deviations from the standards and errors in the evaluation are nevertheless possible.

## Disclaimer of warranty and liability

The software is provided without any warranty, express or implied, including the warranties of merchantability, fitness for
a particular purpose and freedom from errors. Use it at your own risk. **Damage to cards, chips or readers** – for example
through blocked access credentials, exhausted retry counters, interrupted communication or unexpected chip behaviour –
**cannot be ruled out.** Liability for damage of any kind is excluded to the extent permitted by law.

## Artificial intelligence

The software was written with the help of artificial intelligence (Claude by Anthropic).

## Licence

[MIT License](LICENSE) – free use, modification and distribution, also commercially, as long as the copyright and licence
notice is kept. Libraries used: BouncyCastle (MIT), CommunityToolkit.Mvvm (MIT), CoreJ2K (BSD-3-Clause).
The standards documents themselves are not part of the repository; only the public test data used by the unit tests is
included (BSI TR-03110 Worked Example, BSI TR-03105-5 reference data set).
