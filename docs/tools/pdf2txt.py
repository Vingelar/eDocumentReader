"""Extracts text from all referenced standards into docs/standards-text (one .txt per PDF, with page markers)."""
import pathlib
import sys

import pymupdf

SOURCES = [
    r"H:\NextCloud\Technik\Standards\ICAO9303",
    r"H:\NextCloud\Technik\Standards\ISO18013 - IDL\clean",
    r"H:\NextCloud\Technik\Smartcard",
    r"H:\NextCloud\Technik\Standards\ISOIEC_14443 Prox cards",
    str(pathlib.Path(__file__).resolve().parents[1] / "standards"),
]
target = pathlib.Path(__file__).resolve().parents[1] / "standards-text"
target.mkdir(exist_ok=True)

for source in SOURCES:
    for pdf in pathlib.Path(source).rglob("*"):
        if pdf.suffix.lower() != ".pdf":
            continue
        out = target / (pdf.stem + ".txt")
        if out.exists() and out.stat().st_mtime >= pdf.stat().st_mtime:
            continue
        try:
            with pymupdf.open(pdf) as doc, open(out, "w", encoding="utf-8") as f:
                for number, page in enumerate(doc, 1):
                    f.write(f"\n=== PAGE {number} ===\n")
                    f.write(page.get_text())
            print("OK  ", pdf.name)
        except Exception as e:  # noqa: BLE001
            print("FAIL", pdf.name, e, file=sys.stderr)
