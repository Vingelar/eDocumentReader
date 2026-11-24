# eDocumentReader – Projektplan

Ziel: Windows-GUI-Anwendung (C#/.NET 10, WPF), die über PC/SC-Leser (kontaktbehaftet ISO/IEC 7816-3, kontaktlos ISO/IEC 14443-4)
eMRTD/eID (ICAO 9303), IDL/eDL (ISO/IEC 18013) und eVRC (EU-Richtlinie 2003/127/EG) ausliest, prüft und mit konfigurierbaren
Positiv-/Negativtests testet. Funktionaler Maßstab für das Auslesen: Golden Reader Tool (GRT) Platinum Edition 3.10.

---

## 0. Bestandsaufnahme (bereits erfolgt)

| Thema | Vorhanden | Fehlt / muss beschafft werden |
|---|---|---|
| ICAO 9303 | Teil 10 (LDS), Teil 11 (Security) | Teil 3 (Allgemeines, Prüfziffern, Zeichensatz), Teil 4/5/6 (MRZ TD3/TD1/TD2), Teil 12 (PKI, Master List, CRL, DS/CSCA-Profile) – frei bei icao.int |
| EAC | – | BSI TR-03110 Teile 1–4 (PACE, CA v1/v2/v3, TA v1/v2, RI, CVC, CHAT, eID-Anwendung), TR-03111 (ECC), TR-03105 Teil 5.1/5.2 (Konformitätstests eMRTD/eID), TR-03135 (Logformat), TR-03116-2 |
| Testspezifikation ICAO | – | ICAO Technical Report „RF and Protocol Testing Part 3“ (LDS/Protokoll-Tests, Grundlage für Negativtests), ggf. Part 4/5 (PACE/EAC) |
| ISO 18013 | Teil 2 (+AMD1), Teil 3 (+AMD1, AMD2), Teil 4 (Testmethoden) | – |
| ISO 7816 | Teil 3 (2006), Teil 4 (2005) | Teil 4:2020 (optional), Teil 8 (Sicherheitsoperationen, z. B. PSO Verify Certificate), Teil 11 (Biometrie) |
| ISO 14443 | Teil 2, 3, 4 inkl. Amendments | – |
| Biometrie | – | ISO/IEC 19794-4/-5 (Finger/Gesicht, 2005/2011), ISO/IEC 39794 (LDS 1.8+/2), WSQ (FBI/NIST), JPEG 2000 |
| eVRC | – | Richtlinie 1999/37/EG + 2003/127/EG (Datenstruktur, Tags, AID, Signatur) |
| eDL EU | – | Richtlinie 2006/126/EG, VO (EU) 383/2012 (Chip-Anforderungen EU-Führerschein, BAP/EAC-Profil) |
| PC/SC | – | PC/SC Part 3 (ATR kontaktlos, Pseudo-APDU FF CA), Part 10 AMD1 (PACE im Leser via SCardControl) |

Entwicklungsumgebung: .NET SDK 10.0.401 vorhanden. Vorlage aus eigenem Bestand: `H:\VS_projects\EmvLab` (WPF, net10.0-windows,
eigene winscard-P/Invoke-Schicht `PcscTransport.cs`).

GRT (erste REA-Analyse): 32-Bit MFC-Anwendung, Module `ePassportReader.dll` (PC/SC: SCardConnect/Transmit/Control/GetStatusChange →
Hotplug + PACE-fähige Leser über Part 10), `ePassportAPI.dll`, `ePassportCrypto.dll` (OpenSSL 1.0.2a), `ePassportISPKI.dll` +
`ispkiFileDatabase.dll` (Zertifikatsdatenbank), `ispkiTCCReader.dll` (Terminal Control Center), `Iso19794Lib.dll`, `cximage` (Bilder).

## 1. Referenzimplementierungen (nur zur Verifikation, kein Code-Copy wegen Lizenzen)

- **JMRTD** (Java, LGPL): eMRTD-Gesamtstack (BAC, PACE GM/IM/CAM, CA, TA, AA, LDS, CVC) – Hauptreferenz.
- **OpenPACE** (C, GPL): PACE/CA/TA/RI nach TR-03110, gute Testvektoren.
- **AndyQ NFCPassportReader** (Swift), **pypassport/emrtd** (Python): kompakte BAC/SM/PACE-Logik.
- **jnbis / NIST NBIS**: WSQ-Decoder (Portierung nach C# nötig oder fertige .NET-Bibliothek prüfen).
- **ISO 18013-3-Implementierungen** (selten öffentlich) → Normtext + Annex-Beispiele maßgeblich.
- Testvektoren: ICAO 9303-11 Anhang (BAC-/PACE-Worked-Examples), TR-03110/TR-03105 Beispiele, ISO 18013-3 Anhänge (BAP).

## 2. Analyse GRT (REA + Doku)

1. Benutzerhandbuch (EN/DE PDF) und CHM auswerten → Funktionsumfang, Dialoge, Einstellungen, Ansichten.
2. Satelliten-DLL `PlatinumReaderToolDEU.dll` (Ressourcen: Dialoge, Menüs, Strings) → vollständige Liste der Optionen
   (z. B. „File exists mode COM/SOD/always“, EF.COM optional, CA/AA/TA abschaltbar, BAP-Profile, IDL-AID wählbar, Logdetails).
3. Exporte/Imports von `ePassportAPI.dll`, `ePassportISPKI.dll` → Modulgrenzen, Ablaufreihenfolge (Protokoll-State-Machine).
4. `report.xslt` / XML-Exportformat → Struktur für eigenen Report-Export.
5. Wenn ein Leser + Testdokument verfügbar: GRT-Log-Mitschnitt als Referenz-APDU-Trace (Abgleich mit eigener Implementierung).
Ergebnis: Feature-Matrix „GRT ↔ eDocumentReader“ (`docs/GRT-FeatureMatrix.md`).

## 3. Architektur (Solution `eDocumentReader.sln`)

```
src/
  eDocumentReader.Core        Basis: Hex/TLV (BER), ASN.1 (via BouncyCastle), APDU-Modell (kurz/erweitert, Chaining), StatusWords (7816-4)
  eDocumentReader.Transport   PC/SC (winscard P/Invoke), Hotplug (SCardGetStatusChange), ATR/ATS-Parser (7816-3, PC/SC Part 3),
                              UID/ATS via FF CA, Erkennung kontaktlos/kontaktbehaftet, Extended-Length-Erkennung,
                              Part-10-Features (FEATURE_EXECUTE_PACE), Transport-Decorator für Logging/Replay/Simulation
  eDocumentReader.Crypto      3DES/AES, Retail-MAC/CMAC, KDF (9303-11), ECDH/DH (Brainpool, NIST, explizite Parameter),
                              RSA/ECDSA/DSA/RSA-PSS, Hashes; BouncyCastle.Cryptography als Basis
  eDocumentReader.Protocols   Secure Messaging (3DES/AES, SSC-Handling), BAC, PACE (GM/IM/CAM, MRZ/CAN/PIN/PUK), CA v1/v2/v3,
                              TA v1/v2 (CVC-Kette, MSE:Set DST/AT, PSO:Verify Certificate, External Auth), AA, RI, PA,
                              BAP (ISO 18013-3), EAC für IDL; jede Stufe liefert ein ProtocolResult + Berechnungsschritte
  eDocumentReader.Documents   Dokumentprofile mit AIDs und Leseabläufen:
                              - eMRTD (A0000002471001), eID (TR-03110 eID-App), EF.CardAccess/CardSecurity/ATR-Info/DIR
                              - IDL ISO (18013-2/-3) + eDL EU (AID wählbar wie im GRT)
                              - eVRC (AID A0 00 00 04 56 45 56 52 2D 30 31, EF.Registration A/B/C, EF.SOD)
                              Parser: EF.COM, EF.SOD, DG1–DG16 (eMRTD), eID-DGs 1–22, IDL-DGs 1–14, eVRC-Daten
  eDocumentReader.Biometrics  CBEFF/19794-4/-5, 39794, JPEG, JPEG2000, WSQ → Bitmap
  eDocumentReader.Pki         Zertifikatsspeicher (CSCA, DS, Master Lists, Defect Lists, CRLs, CVCA/DV/IS + privater Terminal-Schlüssel),
                              Import/Export (DER, PEM, CMS-ML, PKCS#8/PKCS#12), Kettenprüfung X.509 + CVC, Gültigkeit/Zeitpunkte,
                              Import extern erzeugter Terminal-Testketten (CVCA/DV/IS + privater Schlüssel)
  eDocumentReader.Logging     Strukturierte Ereignisse (APDU raw, APDU entschlüsselt, Berechnungsschritte, Timing, Ergebnisse),
                              Detailstufen + Kategorien, Export Text/HTML/XML/JSON, TR-03135-Format (Import/Export)
  eDocumentReader.Testing     Testengine: Testkatalog (JSON), Testfall = Vorbedingungen + Schrittfolge + erwartete SW/Daten,
                              Positiv/Negativ, Kategorien, Auswahl/Profile, Ergebnisreport (Pass/Fail/Inconclusive/Skipped)
  eDocumentReader.App         WPF-GUI (MVVM, CommunityToolkit.Mvvm)
tests/
  eDocumentReader.Tests       xUnit: Normvektoren (9303-11 Anhang D/G, TR-03110), Parser-Tests, Replay-Traces
  eDocumentReader.Simulator   Virtuelle Karte (eMRTD/IDL/eVRC) für Tests ohne Hardware inkl. Fehlerinjektion
docs/                         Feature-Matrix, Normreferenzen pro Testfall, Benutzerhandbuch
```

Leitprinzipien: Jede Protokollentscheidung im Code mit Normverweis (Dokument + Abschnitt); strikt standardkonforme APDUs
(Le-Behandlung, Extended Length nur wenn per ATR/EF.ATR/INFO angekündigt, Chaining nach 7816-4); toleranter Leser aber
„strenger Prüfer“: Abweichungen werden nicht stillschweigend akzeptiert, sondern als Befund protokolliert.

## 4. GUI (orientiert am GRT)

- **Hauptfenster**: Leserauswahl + Hotplug-Status, Dokumenttyp (Auto/eMRTD/eID/IDL/eDL/eVRC), Zugangsdaten
  (MRZ manuell/MRZ-Zeile, CAN, PIN/PUK, IDL-MRZ/BAP-Schlüssel), Start/Abbruch, Fortschritt.
- **Ansichten (Tabs)**: Übersicht/Ampel (Sicherheitsbewertung PA/AA/CA/TA), Personendaten + MRZ (Prüfziffern geprüft),
  Gesichtsbild(er), Fingerabdrücke, Iris, Unterschrift, Zusatzdaten (DG11/12/13 …), IDL-Kategorien, eVRC-Fahrzeugdaten,
  Dateiansicht (Hex + TLV-Baum je EF), Sicherheitsansicht (SOD, DS/CSCA, CVC-Ketten, Hashvergleich je DG), Log, Testergebnisse.
- **Einstellungen**: Protokolle einzeln an/aus (BAC, PACE, CA, TA, AA, PA, RI), PACE-/CA-Algorithmus-Auswahl, Dateimodus
  (EF.COM / EF.SOD / alle versuchen), Blockgröße/Extended Length, Timeouts, Logdetailstufen, Exportpfade, Sprache DE/EN.
- **PKI-Manager**: Baumansicht der Zertifikate, Import/Export, aktivieren/deaktivieren, Terminal-Zertifikat + Schlüssel, Prüfung.
- **Testmanager**: Katalog mit Filter (Dokumenttyp, Protokoll, positiv/negativ, Norm), Auswahl/Profile speichern, Ausführung,
  Ergebnisse mit erwarteter/tatsächlicher Antwort, Export als Report.
- **Export**: „Capture to disk“ (alle EFs roh + Bilder + Zertifikate + Log + XML/HTML-Report).

## 5. Testkonzept (Funktion „Testen“)

- Testfall-Struktur: ID, Titel, Normreferenz (z. B. „TR-03105-5.1 ISO7816_B_xx“, „ISO 18013-4 Abs. x“), Dokumenttypen,
  Vorbedingung (Zustand: kein SM / nach BAC / nach PACE / nach EAC), Schritte (APDU-Vorlagen oder Protokollaktionen),
  Erwartung (SW, Datenmuster, SM-Zustand danach), Schweregrad.
- **Positivtests**: vollständiges Auslesen, korrekte Kodierung aller EFs, PA (Hash/Signatur/Kette), AA/CA/TA erfolgreich,
  SM-Konformität (SSC, Padding, DO87/97/99/8E), MRZ-/Datenkonsistenz DG1 ↔ MRZ, LDS-Version, SecurityInfos.
- **Negativtests** (mit erwarteten Fehlerantworten nach Norm): falscher BAC-/PACE-Schlüssel (6300/63Cx), Zugriff ohne SM
  (6982), falscher MAC (6988), SM-Fehler → Sitzungsabbruch, falsches SSC, Lesen hinter Dateiende (6B00/6282), unbekannte
  Datei (6A82), falsche P1/P2/Lc/Le (6A86/6700/6Cxx), unzulässige INS (6D00)/CLA (6E00), Zugriff auf EAC-geschützte DGs
  ohne TA (6982), TA mit abgelaufenem/falschem Zertifikat, falsche Reihenfolge der Kommandos (6985), PIN-Retry-Zähler
  (nur mit expliziter Bestätigung – kann Karte sperren!).
- Auswahl durch den Nutzer: Umfang (Schnelltest / Standard / vollständig), Kategorien, Einzeltests, „destruktive“
  Tests separat freizuschalten.
- Testkatalog als JSON-Dateien im Programm, erweiterbar ohne Neukompilierung.

## 6. Umsetzungsphasen

| Phase | Inhalt | Ergebnis |
|---|---|---|
| 1 | Dokumentbeschaffung (fehlende Normen), GRT-Analyse (Handbuch, Ressourcen, REA), Feature-Matrix | `docs/` |
| 2 | Solution-Gerüst, Core (TLV, APDU, SW), Transport (PC/SC, Hotplug, ATR/ATS), Logging-Grundgerüst, minimale GUI mit Leserliste + APDU-Konsole | lauffähiges Grundprogramm |
| 3 | Crypto + Secure Messaging + BAC, Lesen EF.COM/SOD/DG1/DG2, MRZ-Eingabe, Unit-Tests mit 9303-11-Vektoren | erstes Auslesen ePass |
| 4 | PACE (GM, IM, CAM; DH/ECDH; 3DES/AES-128/192/256), EF.CardAccess, CAN/PIN/PUK, PC/SC Part 10 PACE | PACE-Dokumente lesbar |
| 5 | LDS-Parser aller DGs, Biometrie-Dekoder (JPEG/J2K/WSQ), Datenansichten | aufbereitete Anzeige |
| 6 | PKI-Manager, PA (SOD/CMS, DS/CSCA, Master List, CRL), AA, CA v1/v2/v3, TA v1/v2 mit CVC, RI, eID-Anwendung | volle eMRTD/eID-Sicherheit |
| 7 | IDL/eDL: ISO 18013-2 Datenstrukturen, BAP (18013-3), EAC-Profil IDL, AA für IDL; eVRC: Datenstruktur + SOD-Prüfung | weitere Dokumenttypen |
| 8 | Testengine + Testkatalog (Positiv/Negativ) nach TR-03105 / ICAO Testspezifikation / ISO 18013-4, Testmanager-GUI | Testfunktion |
| 9 | Simulator + Replay, Reports/Export (HTML/XML/TR-03135), Einstellungen persistieren, DE/EN, Feinschliff | Release-Kandidat |
| 10 | Abgleich mit GRT an echten Dokumenten/Testkarten (Logs vergleichen), Bugfixing, Dokumentation | Abnahme |

## 7. Technische Entscheidungen (Vorschlag)

- .NET 10, WPF, MVVM (CommunityToolkit.Mvvm), x64.
- Krypto/ASN.1/CMS/X.509: `BouncyCastle.Cryptography` (MIT). CVC: eigene Implementierung nach TR-03110-3.
- JPEG2000: `CoreJ2K` o. ä. (Lizenz prüfen); WSQ: eigene C#-Portierung nach NBIS (Public Domain).
- Eigene winscard-P/Invoke-Schicht (Muster aus EmvLab) statt Fremdbibliothek → volle Kontrolle über SCardControl/Part 10.
- Persistenz: JSON-Einstellungen, PKI-Store als Ordnerstruktur + Index (SQLite optional).

## 8. Risiken / Hinweise

- Ohne Terminalzertifikate (IS-Zertifikat + Schlüssel einer gültigen CVCA-Kette) sind TA-geschützte Daten (DG3/DG4) echter
  Dokumente nicht lesbar → Test-PKI + Testdokumente (z. B. BSI-/Hersteller-Testpässe) nötig.
- Negativtests können Dokumente beschädigen/sperren (PIN-/CAN-Fehlversuche, PACE-Suspend) → Warnung + explizite Freigabe.
- ISO 14443 Schicht 2/3 (REQA, Antikollision, Timing) ist über PC/SC nicht direkt steuerbar; nur ATR/ATS/UID-Auswertung
  und ggf. leserspezifische Escape-Kommandos.
- GRT-Analyse dient nur der Funktionsermittlung (Interoperabilität); keine Übernahme von Code oder Ressourcen.

## 9. Umsetzungsstand

Hinweis Architektur: Die in Abschnitt 3 genannten Module werden zunächst als Namespaces in `eDocumentReader.Core`
umgesetzt (weniger Assemblies, gleiche Schichtung); eine Aufteilung in eigene Projekte ist jederzeit möglich.

- **Phase 1 (teilweise erledigt)**: Fehlende Unterlagen geladen nach `docs/standards/` (ICAO 9303 Teile 3/4/5/6/12,
  BSI TR-03110 Teile 1–4 + EAC Worked Example (CVCs, Schlüssel, Logs), TR-03111, TR-03116-2, TR-03135 (+XML),
  TR-03105 Teile 3.1–3.4, 5.1–5.3 (+XML-Testfälle, Referenzdatensatz mit EF.COM/SOD/DGs + Schlüsseln),
  ICAO TR RF & Protocol Testing Teil 3 (V3.00) und 4, EU 1999/37, 2003/127 (eVRC), 2006/126, 383/2012 (eDL),
  PC/SC Part 3 und Part 10). Volltexte aller Normen (inkl. lokaler ISO-Dokumente) durchsuchbar in `docs/standards-text/`
  (Erzeugung: `python docs/tools/pdf2txt.py`).
  Nicht frei verfügbar: ISO/IEC 19794-4/-5, 39794, PC/SC Part 10 AMD1 (PACE) – ggf. vom Auftraggeber bereitstellen.
  Offen: GRT-Analyse (Feature-Matrix).
- **Phase 2 (erledigt)**: Solution `eDocumentReader.slnx` (Core, App/WPF, Tests/xUnit).
  Core: Hex, BER-TLV (7816-4 5.2.2 mit Befundmeldungen), Command/Response-APDU (alle 7 Fälle), Statuswörter (7816-4 Tab. 5/6),
  PC/SC-Transport (winscard), Hotplug-Monitor, ATR-Analyse (7816-3 Kap. 8, 7816-4 8.1.1, PC/SC Part 3 kontaktlos),
  PC/SC GET DATA (UID/ATS), Part-10-Features (inkl. dwMaxAPDUDataSize, EXECUTE_PACE), CardChannel mit 61xx/6Cxx-Behandlung
  (abschaltbar für Negativtests), Logging mit Kategorien/Detailstufen.
  GUI: Leserliste mit Kartenstatus, Verbinden/Trennen/Reset, Karteninfo, APDU-Konsole, Log mit Detaileinstellung + Export.

- **Phase 3 (erledigt, Konsole)**: MRZ (TD1/2/3), KDF, BAC, SM 3DES/AES, PACE ECDH-GM, SecurityInfos, FileReader
  (SFI, B1 für Offsets > 32767). Byte-genau gegen ICAO 9303-11 App. D und G getestet (31 Unit-Tests).
  Realtest deutscher Reisepass (kontaktlos): PACE ECDH-GM AES-128 brainpoolP256r1 → EF.COM, EF.SOD, DG1, DG2 (JP2), DG14 gelesen.
  Vorgezogen aus Phase 6: SOD-Auswertung, DG-Hashvergleich, CMS-Signaturprüfung mit DS-Zertifikat (ohne CSCA-Kette).
  Normbefund: ICAO 9303-11 App. D, Beispiel-MRZ „ERIKSSON“ mit falscher Gesamtprüfziffer.
  Werkzeug: `tools/eDocumentReader.Probe` (survey / read / analyze); Rohdaten nur im Temp-Verzeichnis (personenbezogen).

- **Phase 6 (Kern erledigt, vorgezogen)**:
  - Chip Authentication v1 (DH/ECDH, MSE:Set KAT für 3DES bzw. MSE:Set AT + GA für AES), SM-Neustart mit SSC=0.
  - Active Authentication (RSA ISO/IEC 9796-2 Schema 1 inkl. Trailer-Option 2 und min(σ, n−σ); ECDSA plain).
  - CV-Zertifikate (TR-03110-3 C/D), Kettenprüfung inkl. Domain-Parameter-Vererbung, Terminal-Schlüssel (PKCS#8).
  - Terminal Authentication v1 (EF.CVCA, MSE:Set DST, PSO:Verify Certificate, MSE:Set AT, GET CHALLENGE,
    EXTERNAL AUTHENTICATE; dynamische Bindung bei PACE, statische bei BAC).
  - PKI-Speicher `%APPDATA%\eDocumentReader\pki` (CSCA, DS, CRL, Master List mit Signaturprüfung, CVC, Schlüssel).
  - Passive Authentication komplett: Hashes, CMS-Signatur, DS→CSCA (DN + AKI/SKI), Gültigkeit, CRL (Signatur mit
    beliebigem CSCA-Schlüssel gleichen DNs).
  - Deutsche Master List (BSI, 609 CSCA) + CSCA-CRL importiert; deutscher Pass: Kette DS→CSCA gültig, nicht gesperrt.
  - Tests: EAC-Worked-Example-Ketten (ECDH/DH), AA mit TR-03105-Referenzschlüssel, CA-KA mit Referenz-DG14, RFC-5114-Gruppen.
  - Live-Test CA am deutschen Pass (2026-11-23): OK mit id-CA-ECDH-AES-CBC-CMAC-128, KeyID 195; Lesen nach SM-Neustart OK.
    Dabei behoben: Schlüsselreferenz 0x84 wurde als ASN.1-INTEGER mit führendem 0x00 kodiert (00 C3) → Chip antwortete 6A88.
    Jetzt unsigned, minimale Länge nach TR-03110-3 D.2.1.1 (C3). EF.CVCA des Passes: CAR DECVCAEPASS00105.
  - Offen: TA mit Test-Terminalzertifikaten + passendem Testdokument, PACE-DH/IM/CAM, CA v2/TA v2 (eID).

- **Phase 5 (GUI-Lesen, erledigt 2026-11-23)**:
  - Leseablauf als Dienst `Core/Documents/EmrtdReader` (EF.CardAccess → PACE/BAC → EF.COM/SOD/DGs → CA → TA → AA → PA),
    mit Fortschritt je READ BINARY, Abbruch, Schrittprotokoll (Erfolg/Fehler/übersprungen/nicht unterstützt) und CAN.
    Konsolen-Tool und GUI nutzen denselben Ablauf.
  - `Lds` (DG-Nummern/SFIs, Tag-Namen, DG1-MRZ), `FaceImageParser` (DG2: 7F61/7F60/A1/5F2E, ISO/IEC 19794-5:2005-Record),
    `PassiveAuthentication` (Ergebnisobjekt).
  - GUI-Tabs: „Dokument“ (MRZ einfügen oder Felder, CAN, Protokollauswahl, Fortschritt, Ergebnis, MRZ-Tabelle mit
    Prüfziffern, Gesichtsbild), „Dateien“ (EF-/TLV-Baum mit Befunden, Hex-Ansicht, Rohdaten speichern), „Sicherheit“ (Bericht).
  - JPEG 2000 über CoreJ2K (BSD-3-Clause, NuGet); JPEG über WIC.
  - eVRC (Phase 7, Teil 1, erledigt 2026-11-23): `Core/Documents/Evrc` + `EvrcReader` nach RL 2003/127/EG Anhang III.10–III.12
    (SELECT DF by name, SELECT EF P1=02/P2=04 mit FCP, READ BINARY; D001/E001/C001, D011/E011/C011), Tag-Tabellen 2/3,
    Zeichensatz '9F37' aus Teil A, Signaturprüfung (Verfahren nicht normiert → RSA PKCS#1 v1.5 per DigestInfo, PSS,
    ECDSA plain/DER mit SHA-1/2). GUI: Knopf „Zulassungsbescheinigung (eVRC) lesen“, Tab „Fahrzeugdaten“, Bericht.
    Realtest österreichische eVRC (kontaktbehaftet, T=1): beide Signaturen gültig (ECDSA DER, SHA-256, brainpoolP224r1).
    Befunde der Karte: FCP '80' = reservierte statt tatsächlicher Größe (tatsächliche Länge im proprietären 'C5', Dateiende
    per 6282); AID in '4F' als ASCII-Text; '9F37' als ASCII "00"; '86' als Freitext statt Code.
    Ausstellerzertifikat (C=AT, „Zertifizierungsdienst“) ohne Vertrauensanker nicht prüfbar (Sache der Mitgliedstaaten).
  - Noch nicht umgesetzt: DG3 (WSQ), DG7, DG11/12 aufbereitet, ISO/IEC 39794-5 ('7F2E'), lange Dokumentnummern bei
    manueller Eingabe (nur über eingefügte MRZ).

## 10. Entscheidungen des Auftraggebers

1. eIDL = ISO-konformer IDL nach ISO/IEC 18013; eDL = EU-Führerschein (Richtlinie 2006/126/EG, VO (EU) 383/2012).
2. Hardware: Standard-USB-PC/SC-Leser (kontaktbehaftet + kontaktlos). Terminal-Testzertifikatsketten (CVCA/DV/IS + Schlüssel)
   werden von externer Software erzeugt → PKI-Manager muss diese importieren können (CVC DER, Schlüssel PKCS#8/DER/PEM);
   ein eigener Test-PKI-Generator entfällt.
3. GUI: WPF.
4. ISO/IEC 18013-5 (mDL) und LDS2: nicht im Umfang (evtl. später; Architektur offen halten).
5. TCC-Anbindung: nicht im Umfang.

## IDL (ISO/IEC 18013-3) – Live-Test 23.11.2026

Testkarte (JavaCard, Applet-Instanz `A0 00 00 02 48 02 00`, personalisiert mit Simulator-PKI „CSCA eIDL test“, C=ZZ):

- Anwendungserkennung: `EmrtdReader.DetectApplication` (ungeschütztes SELECT IDL), GUI-Auswahl „Automatisch / Pass-ID / Führerschein“.
- PACE nur mit CAN (MSE:Set AT mit MRZ-Passwort → `6A80`), Rückfall auf BAP funktioniert.
- BAP-Konfiguration 1: Kseed = SHA-1(MRZ-Zeichen 2–29)[0..15]; Prüfziffer (7-3-1) über Zeichen 1–29 (`IdlMrz`).
- Ohne Authentisierung lesbar: EF.CardAccess. Nach BAP/PACE: EF.COM, EF.SOD, DG13 (AA-Schlüssel), DG14.
- DG1/DG2/DG4/DG5: `6982` auch nach CA → EAP (CA + TA) nötig; kein EF.CVCA in der IDL-Anwendung, keine IDL-Terminalzertifikate im PKI-Speicher. **Offen:** IDL-Terminalkette importieren, Vertrauensanker für TA ohne EF.CVCA (DG14 / Konfiguration) klären.
- CA nach PACE ✔ (ECDH AES-128, KeyID 1); CA nach BAP ✘ `6988` – Ursache (Karte oder 3DES-SM-Übergang) offen.
- AA über DG13 ✔ (ECDSA brainpoolP256r1, ecdsa-plain-SHA256 nach TR-03111, OIDs ergänzt).
- Abweichung: fehlende DGs liefern `6986` statt `6A82` (als Warnung gemeldet).
- Die Darstellung der IDL-Datengruppen (ISO/IEC 18013-2 Anhang C) fehlt noch, ebenso die eigene Gesichtsbild-DG; bisher nur Dateibaum.
- Leser lässt bei Reset das RF-Feld an → offene SM-Sitzung der Karte; Reader wiederholt EF.CardAccess/SELECT nach `6987`/`6988`.
- TA für IDL (umgesetzt, am Chip noch ungetestet): ohne EF.CVCA werden alle CVCA-Anker des PKI-Speichers (`PkiStore.CandidateTrustPoints`) nacheinander angeboten, abgelehnte Ketten → nächster Kandidat; jede Terminal-Rolle (CHAT-OID) wird akzeptiert; anschließend werden die mit `6982` abgewiesenen DGs erneut gelesen. ID_PICC bei BAP für die IDL noch ungeklärt (derzeit Dokumentnummer-Ansatz aus 9303).
- GUI-Tab „PKI“: Import (Mehrfachauswahl, Typ wird erkannt), Übersicht mit Kettenprüfung der Terminal-Credentials, Ordner öffnen.
- **TA am Chip erfolgreich (23.11.2026):** Kette `golden-lab-pki` (CVCA `DETESTC00001`, Vertrauenspunkt per DF01 personalisiert). Danach DG1/DG2/DG4/DG5 gelesen, PA vollständig gültig (6 DG-Hashes, SOD, DS → CSCA „CSCA eIDL test“).
  - Applet nimmt SM-Kommandos > ca. 192 Byte Klartext nicht an (`6988`, SM-Abbruch) → Command Chaining (ISO/IEC 7816-4 5.3.3), Option `EmrtdReadOptions.CommandChaining` (automatisch für IDL), Blockgröße 192 wie Referenz-Host `diagnostics/eac/eac_peer.py`.
  - Abweichung: PSO:Verify Certificate erwartet das vollständige Zertifikat mit `7F21` statt `7F4E`‖`5F37` (TR-03110-3 B.11.5); Reader fällt nach `6A80` darauf zurück und meldet „Normkonformität TA“.
  - Abweichung der Testkette: CVCA-Zertifikat ohne EC-Domain-Parameter (TR-03110-3 D.3.3); Offline-Kettenprüfung nimmt die Kurve des Terminalschlüssels an.
- **IDL-Anzeige (23.11.2026):** `Idl.Parse` (Core) + Tab „Führerscheindaten“, DG1-Übersicht im Dokument-Tab, DG4-Lichtbild (JPEG/JPEG 2000), DG5-Unterschrift. Format nach ISO/IEC 18013-2 Anhang C, wie es das freie isodl-Projekt umsetzt (5F1F mit Längenpräfixen/BCD-Daten, 7F63/87 „;“-getrennt, DG2 5F35/5F64…, DG4 A2{88,89,5F40}, DG5 89/5F43). **Offen:** gegen ISO/IEC 18013-2:2020 (+Amd 1:2023) prüfen, sobald der Normtext vorliegt. Die Testkarte enthält Platzhalter (Tag 53), DG4 ein echtes JPEG.
- Applet-Normabweichungen mit Codestellen: `docs/IDL-Applet-Normkonformitaet.md`.
- **Applet-Normkorrekturen 1–4 am Chip bestätigt (23.11.2026):** neue Firmware/Instanz, TA ohne Command Chaining erfolgreich, keine Normwarnungen mehr (Details in `docs/IDL-Applet-Normkonformitaet.md`). Konsolen-Option `read … --nochain|--chain`.
- **Export (24.11.2026):** Tab „Dateien“: „Datensatz (Set) speichern…“ (Ordner mit `project.json` + `ef/*.bin` nach `H:\JOB\ICAO\ICAO_perso\docs\SET-FORMAT.md`, Schema 1, `source: reader`, ICAO/IDL/EVRC, TLV-Kürzung mit SOD-Prüfung, `origin.notRead`, CSCA als `reader/CSCA.der`) und „Datei speichern…“ (einzelnes EF als `DG<n>.bin`/`EF.xxx.bin`). Core: `DocumentSet`. Konsole: Umgebungsvariable `EDOC_SET_DIR` bei `read`/`evrc`. eVRC-Set von der Karte geprüft; IDL/ICAO-Set nur per Unit-Test.
