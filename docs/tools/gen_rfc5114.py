"""Generates src/eDocumentReader.Core/Crypto/Rfc5114.cs from docs/standards/RFC5114.txt."""
import pathlib
import re

root = pathlib.Path(__file__).resolve().parents[2]
text = (root / "docs/standards/RFC5114.txt").read_text(encoding="utf-8-sig").replace("\r\n", "\n").replace("\f", "")
# remove page breaks (footer/header lines)
text = re.sub(r"\n\s*\n+Lepinski & Kent[^\n]*\n\s*\nRFC 5114[^\n]*\n", "\n", text)

sections = ["2.1.  1024-bit MODP", "2.2.  2048-bit MODP", "2.3.  2048-bit MODP"]


def grab(section: str, name: str) -> str:
    start = text.index(section)
    end = text.index("\n2.", start + 10)
    body = text[start:end] + "\n\n"
    match = re.search(r"\n\s+" + name + r" =\s+([0-9A-F \n]+?)\n[ \t]*\n", body)
    if match is None:
        raise SystemExit(f"not found: {section} {name}\n{body[:600]!r}")
    return re.sub(r"[^0-9A-F]", "", match.group(1))


lines = [
    "// Generated from RFC 5114 (docs/standards/RFC5114.txt) by docs/tools/gen_rfc5114.py - do not edit.",
    "namespace eDocumentReader.Core.Crypto;",
    "",
    "internal static class Rfc5114",
    "{",
]
for index, section in enumerate(sections):
    for name in "pgq":
        lines.append(f'    public const string G{index}{name.upper()} = "{grab(section, name)}";')
lines.append("}")
(root / "src/eDocumentReader.Core/Crypto/Rfc5114.cs").write_text("\n".join(lines) + "\n", encoding="utf-8")
for line in lines:
    print(line[:100])
