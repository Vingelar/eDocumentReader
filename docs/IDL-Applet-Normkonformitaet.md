# eIDL-Applet: Änderungen für normkonformes Verhalten

Stand: 23.11.2026. Grundlage: Live-Test mit eDocumentReader gegen die personalisierte IDL-Testkarte
(AID `A0 00 00 02 48 02 00`, Profil `diagnostics/files/profile-personalize-existing.jcsh`, CAN-PACE, CA, TA mit
`golden-lab-pki`) und Abgleich mit dem Quellcode unter `H:\JOB\SIM\eIDL_18013\src\eidl`.

Einordnung:

- **Belegt** heißt: Das Verhalten wurde am Chip beobachtet und die Codestelle gefunden.
- **Zu prüfen** heißt: Das Verhalten wurde beobachtet, die normative Anforderung muss aber noch am Normtext bestätigt werden, bevor das Applet geändert wird.

Abschnittsangaben ohne „(geprüft)“ bitte vor der Umsetzung im jeweiligen Normtext nachschlagen.

## Umsetzungsstand (23.11.2026)

Punkte 1–4 sind im Quellcode umgesetzt, aber **nicht committet und noch nicht auf der Karte getestet**:
Firmware/Maske und CAP wurden nicht neu gebaut, und es wurde nichts geladen.

| Punkt | Änderung | Geprüft |
|---|---|---|
| 1 | **OS** `SIM_IDL`: `src/lib/pace/pace_sm.c/.h` und `src/vm/jcapi/native_crypt.c` – Kommando-Klartext bis 223 Byte (vorher 192 bzw. 208), Kapazität 232; Chaining-Freigabe als eigener Parameter statt über `limit==208`. **Applet**: `AesBapSession` bis 223 Byte, `BapSession` (3DES) bis 207 Byte. | Host-Tests `diagnostics/sm/test_sm_core.py` (466), `test_sm_eac_core.py` (32), `eac/test_sm_extension.py` (40) grün |
| 2 | `AppletTA.certificate`: akzeptiert `7F4E`‖`5F37`, ein vorangestelltes `7F21` weiterhin | javac + JC-Converter 3.0.4 ohne Fehler |
| 3 | `EidlApplet.process`: nach dem Senden der geschützten Antwort wird das SW aus DO'99' auch als SW1-SW2 gesetzt; die Sitzung bleibt dabei erhalten (eigener `catch (ISOException)` mit Merker) | javac + Converter |
| 4 | `FileStore.read`: nicht personalisierter Slot → `6A82`; `6986` nur ohne aktuelles EF | javac + Converter |

Nicht umgesetzt aus Punkt 1: `6700` statt `6988` für überlange Kommandos (würde das Sitzungsdesign des OS ändern) und
Extended Length. Responses bleiben bei 192 bzw. 208 Byte.

Testanpassungen: Die Host-Tests prüfen jetzt 209 und 223 Byte als gültig und 224 als zu lang. Die Kartentests
`sm/test_sm.py` und `eac/test_eac.py` verwenden 224 statt 193/209 als „zu lang“. In `test_sm_extension.py` war der
Vergleich `bytes(ctx)==bytes(736)` veraltet (der Kontext hat 488 Byte); jetzt `bytes(len(ctx))`.

**Kartentest 23.11.2026** (neu gebaute Firmware/Maske, frische Instanz, DF10 `04 01010101`, eDocumentReader-Konsole,
PACE mit CAN, **ohne** Command Chaining):

| Punkt | Ergebnis am Chip |
|---|---|
| 1 | PSO:Verify Certificate für DV und Terminal (je 221 Byte Klartext) in einem SM-Kommando angenommen, kein `6988` |
| 2 | TA erfolgreich mit `7F4E`‖`5F37`, keine Warnung „Normkonformität TA“ mehr |
| 3 | Äußeres SW = SW in DO'99' (z. B. `6982`, `6A82`), keine Abweichungsmeldung mehr |
| 4 | Nicht personalisiertes DG3 → `6A82`, keine `6986`-Warnungen mehr |

PACE, CA, TA, AA und PA sind alle erfolgreich; DG1, DG2, DG4 und DG5 werden nach TA gelesen.
Derselbe Lauf **mit** Command Chaining (Rückwärtskompatibilität) ist ebenfalls erfolgreich, ebenso der Lauf in der
GUI (Standard für IDL: Chaining an) – alle Schritte grün, keine Normwarnungen.

---

## 1. Secure Messaging: Kommandos mit mehr als 192 Byte Klartext werden abgelehnt (belegt)

**Beobachtung:** PSO:Verify Certificate mit 221 Byte Klartext (SM-APDU mit Lc = 238) wird mit `6988` beantwortet,
und die SM-Sitzung wird beendet. Mit Command Chaining in Blöcken ≤ 192 Byte wird der Befehl angenommen.

**Code:**

- `AesBapSession.java`, ca. Zeile 420: `if (plain > 192) fail(SW_INCORRECT_SM_DATA_OBJECTS);`
- `BapSession.java`, ca. Zeile 525: dieselbe Grenze für 3DES.

**Problem:** `6988` bedeutet „SM-Datenobjekte fehlerhaft“. Die Daten sind aber korrekt, nur zu lang für den internen
Puffer. Ein Lesegerät, das nicht verkettet, verliert dadurch die ganze SM-Sitzung. Das sind praktisch alle Lesegeräte,
denn ein CV-Zertifikat hat meist mehr als 192 Byte.

**Änderung:**

1. Kurze APDUs mit vollem Lc (bis 255 Byte Klartext minus Padding) innerhalb von SM unterstützen. Das CV-Zertifikat
   (DV/Terminal, ca. 220–240 Byte) muss in **einem** SM-Kommando ankommen dürfen. Dazu einen Puffer ≥ 256 Byte
   verwenden (APDU-Puffer oder transienter Puffer); siehe ISO/IEC 7816-4 5.1 und ICAO 9303-11 9.8.
2. Wenn eine Grenze technisch unvermeidlich ist: eine überlange Länge mit `6700` (Wrong length) melden, nicht mit
   `6988`. Laut ICAO 9303-11 9.8.5 darf die SM-Sitzung nur bei echten SM-Fehlern beendet werden.
3. Command Chaining (CLA-Bit b5) weiter unterstützen. Das ist korrekt und bleibt als Alternative erhalten.
4. Optional: Extended Length anbieten (TR-03110-3 empfiehlt Extended Length für EAC) und im EF.ATR/INFO bzw. im ATR anzeigen.

---

## 2. PSO:Verify Certificate erwartet das vollständige Zertifikat mit `7F21` (belegt)

**Beobachtung:** Das Datenfeld `7F4E` (Body) ‖ `5F37` (Signatur) wird mit `6A80` abgelehnt. Das vollständige
Zertifikat `7F21 { 7F4E … 5F37 … }` wird angenommen.

**Code:** `AppletTA.java`, `certificate(...)`, ca. Zeile 178:
`short outer = take(cert, end, (short)0x7f21);` – das äußere Tag ist Pflicht.

**Norm:** Nach BSI TR-03110-3 (Teil B, Kommando PSO:Verify Certificate) besteht das Datenfeld aus
Certificate Body `7F4E` und Signature `5F37`, **ohne** das umschließende `7F21`. Genau so senden es auch
Golden Reader Tool und eDocumentReader.

**Änderung:** Das Datenfeld als `7F4E … 5F37 …` parsen. Für Abwärtskompatibilität mit dem bisherigen Test-Host
(`diagnostics/eac/eac_peer.py`, sendet `7F21`) kann zusätzlich ein vorangestelltes `7F21` akzeptiert werden:

```java
short pos = off;
if (Util.getShort(cert, off) == (short)0x7F21) {      // tolerant: vollständiges Zertifikat
    pos = contentOffset(cert, off);                    // hinter Tag und Länge von 7F21
}
short body = take(cert, end, (short)0x7f4e);           // Pflicht
short sig  = take(cert, end, (short)0x5f37);           // Pflicht, direkt danach
```

Den Test-Host danach auf `7F4E‖5F37` umstellen, damit die Tests das normgerechte Format abdecken.

---

## 3. Status Word in DO'99' weicht vom SW der Antwort ab (belegt)

**Beobachtung:** Protected Responses mit einem Fehler, z. B. READ BINARY auf ein TA-geschütztes DG, liefern
`DO'99' = 6982`, aber das äußere SW1-SW2 ist `9000`.

**Code:** `BapSession.java` (ca. Zeile 546 ff., „Output is DO87? || DO99 || DO8E“) und
`EidlApplet.java` (`sendBytesLong` mit festem `SW_NO_ERROR`, ca. Zeilen 375/405).

**Norm:** Nach ICAO 9303-11 9.8 (Protected Response) ist der Statuscode in DO'99' der Statuscode der Verarbeitung,
und das unverschlüsselte SW1-SW2 der Antwort-APDU muss damit übereinstimmen. Bei SM-Fehlern (`6987`/`6988`) wird
ohne SM geantwortet.

**Änderung:** Nach `sendBytesLong` das Verarbeitungs-SW als Antwortstatus setzen (`ISOException.throwIt(sw)` nach
dem Senden der Daten bzw. `setOutgoingLength` + Status), statt immer `9000` zu liefern.

---

## 4. Nicht vorhandene Datei per SFI: `6986` statt `6A82` (belegt)

**Beobachtung:** READ BINARY mit SFI für DG3, DG6, DG7 und DG11 (nicht personalisiert) liefert `6986`
(„Command not allowed, no current EF“). Für DG8, DG9, DG10 und DG12 kommt korrekt `6A82`.

**Code:** `FileStore.java`, ca. Zeilen 160 und 338: `if (i < 0 || lengths[i] == 0) ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);`.
Die Slots dieser DGs existieren im Profil, haben aber die Länge 0.

**Norm:** ISO/IEC 7816-4 (READ BINARY mit SFI, Statusbytes): Eine nicht vorhandene Datei wird mit
`6A82` (File or application not found) gemeldet.

**Änderung:** `lengths[i] == 0` (nicht personalisiert) wie „nicht vorhanden“ behandeln und `6A82` melden.
`6986` nur verwenden, wenn READ BINARY ohne SFI und ohne aktuelles EF aufgerufen wird.

---

## 5. EF.CVCA nicht per SFI lesbar (belegt, Norm zu prüfen)

**Beobachtung:** READ BINARY mit SFI `1C` innerhalb der IDL-Anwendung liefert nach PACE/CA `6A82`. Vor dem Aufbau
von SM wird über dieselbe SFI EF.CardAccess gelesen.

**Code:** `EidlApplet.java`, `CARD_ACCESS_SFI = 28` (ca. Zeile 1281) – SFI 1C ist fest EF.CardAccess zugeordnet.
EF.CVCA wird nur bei SELECT über FID `011C` synthetisiert (ca. Zeile 1476 ff.).

**Norm:** Wenn das Applet EAC nach TR-03110 / ICAO 9303-11 umsetzt, liegt EF.CVCA in der Anwendung (FID `011C`,
SFI `1C`) und muss dort lesbar sein, damit das Lesegerät den Vertrauensanker (CAR) bestimmen kann. Ob
ISO/IEC 18013-3 (EAP) EF.CVCA verbindlich vorschreibt, bitte in 18013-3 nachschlagen.

**Änderung:** Innerhalb der ausgewählten IDL-Anwendung SFI `1C` auf EF.CVCA abbilden, sobald SM aktiv ist bzw. die
Anwendung ausgewählt ist. EF.CardAccess bleibt über MF/SFI `1C` ohne SM erreichbar. Ohne EF.CVCA müssen Lesegeräte
alle bekannten CVCAs durchprobieren; eDocumentReader macht das inzwischen, andere Lesegeräte in der Regel nicht.

---

## 6. PACE nur mit CAN, nicht mit MRZ (zu prüfen)

**Beobachtung:** MSE:Set AT (PACE) mit Passwortreferenz `01` (MRZ) → `6A80`. Mit `02` (CAN) funktioniert PACE.

**Norm:** Laut ICAO 9303-11 4.4 muss ein Chip, der PACE anbietet, PACE mit dem aus der MRZ abgeleiteten Passwort
unterstützen. Für die IDL ist zu klären, welche Passwörter ISO/IEC 18013-3 für PACE verlangt.

**Änderung (falls bestätigt):** Passwortreferenz `01` unterstützen, mit π = SHA-1(BAP-Eingabe), analog zu BAC/BAP.
Dabei dieselbe MRZ-Eingabe wie bei BAP verwenden (Zeichen 2–29, siehe Punkt 8).

---

## 7. Chip Authentication nach BAP schlägt fehl (zu prüfen)

**Beobachtung:** Nach BAP (3DES-SM) beendet MSE:Set AT (CA) bzw. General Authenticate die Sitzung mit `6988`.
Nach PACE (AES-SM) funktioniert CA.

**Norm:** ISO/IEC 18013-3 EAP sieht CA nach BAP vor. Der Wechsel von 3DES-SM (BAP) auf die CA-Sitzungsschlüssel
muss funktionieren.

**Änderung:** Den Pfad BAP → CA im Applet testen (Wechsel der SM-Instanz von `BapSession` auf die CA-Schlüssel).
Laut README zur Golden-Lab-PKI ist das „noch nicht nachgewiesen“. Ein Fehler auf der Lesegerät-Seite ist noch
nicht ausgeschlossen. Bitte mit dem Python-Referenz-Host gegenprüfen.

---

## 8. BAP-Schlüsseleingabe (zu prüfen)

Der Chip akzeptiert BAP mit Kseed = SHA-1(MRZ-Zeichen 2–29)[0..15], also ohne Dokumentcode `D` und ohne Prüfziffer.
Bitte gegen ISO/IEC 18013-3 (BAP-Konfiguration 1) bestätigen. Weicht die Norm ab, müssen Applet und Lesegerät
angepasst werden.

---

## Test-PKI (keine Applet-Änderung, aber für Normkonformität der Testumgebung)

- **CVCA ohne EC-Domain-Parameter:** `CVCA-TEST-ONLY.cvc` enthält im Public Key nur `06` (OID) und `86` (Punkt).
  BSI TR-03110-3 (Anhang D, Public Key Data Objects) verlangt im CVCA-Zertifikat die vollständigen Domain-Parameter
  `81`–`87`, die DV und Terminal erben. Bitte im Generator `diagnostics/eac/export_golden_lab_pki.py` bzw.
  `prepare_eac.py` ergänzen.
- **Terminal-Rolle:** Die CHAT-OID ist `id-IS` (ePassport Inspection System, `0.4.0.127.0.7.3.1.2.1`). Prüfen, ob
  ISO/IEC 18013-3 für IDL-Terminals eine eigene Rolle bzw. eigene Rechtebits vorsieht.

---

## Bereits normkonform (zur Abgrenzung)

- Antwort `6987` auf ein ungeschütztes Kommando während aktiver SM und anschließendes Beenden der Sitzung
  (ICAO 9303-11 9.8.5).
- Command Chaining für PSO:Verify Certificate.
- PACE ECDH-GM AES-128 brainpoolP256r1, CA ECDH AES-128, AA ECDSA mit ecdsa-plain-SHA256 (TR-03111) über DG13.
- EF.SOD und Hashes aller DGs, DS → CSCA.

## Empfohlene Reihenfolge

1, 2, 3, 4 (kleine, klar belegte Änderungen) → 5 → Klärung 6–8 am Normtext → Test-PKI.
Nach jeder Änderung mit eDocumentReader und GRT gegentesten. eDocumentReader meldet die Punkte 2 und 4 heute als
„Normkonformität …“-Warnung; nach der Korrektur sollten diese Warnungen verschwinden.
