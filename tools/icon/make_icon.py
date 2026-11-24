"""Draws the application icon: the ICAO chip symbol for electronic machine readable travel documents
(rectangle, horizontal line, circle in the middle) on a passport-blue tile, with an "R" badge for "reader".

Usage: python tools/icon/make_icon.py  ->  src/eDocumentReader.App/Assets/eDocumentReader.ico (+ .png preview)
Requires Pillow. Each icon size is rendered at 8x and scaled down, so small sizes stay sharp.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "src" / "eDocumentReader.App" / "Assets"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]

BLUE = (22, 58, 110, 255)       # passport cover
WHITE = (255, 255, 255, 255)
GOLD = (232, 176, 38, 255)      # badge
INK = (22, 40, 70, 255)


def font(px: int) -> ImageFont.FreeTypeFont:
    for name in ("segoeuib.ttf", "arialbd.ttf"):
        try:
            return ImageFont.truetype(name, px)
        except OSError:
            pass
    return ImageFont.load_default(px)


def render(size: int) -> Image.Image:
    s = size * 8
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    u = s / 32  # design grid: 32 x 32

    # Tile
    d.rounded_rectangle([0.5 * u, 0.5 * u, 31.5 * u, 31.5 * u], radius=5 * u, fill=BLUE)

    # ICAO chip symbol: rectangle, horizontal line, circle in the middle (thicker strokes at small sizes)
    w = (2.4 if size <= 24 else 1.9) * u
    left, top, right, bottom = 3.5 * u, 4.5 * u, 24.5 * u, 19 * u
    d.rounded_rectangle([left, top, right, bottom], radius=1.2 * u, outline=WHITE, width=round(w))
    cy = (top + bottom) / 2
    cx = (left + right) / 2
    d.line([left, cy, right, cy], fill=WHITE, width=round(w))
    r = 4.2 * u
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=BLUE, outline=WHITE, width=round(w))

    # "R" badge for reader
    br = 7.9 * u
    bx, by = 31.5 * u - br - 0.3 * u, 31.5 * u - br - 0.3 * u
    d.ellipse([bx - br, by - br, bx + br, by + br], fill=GOLD, outline=BLUE, width=round(1.2 * u))
    f = font(round(11.8 * u))
    box = d.textbbox((0, 0), "R", font=f)
    tw, th = box[2] - box[0], box[3] - box[1]
    d.text((bx - tw / 2 - box[0], by - th / 2 - box[1]), "R", font=f, fill=INK)

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    images = [render(n) for n in SIZES]
    big = images[-1]
    big.save(OUT / "eDocumentReader.ico", format="ICO", sizes=[(n, n) for n in SIZES], append_images=images[:-1])
    big.save(OUT / "eDocumentReader.png")
    print("written:", OUT / "eDocumentReader.ico")


if __name__ == "__main__":
    main()
