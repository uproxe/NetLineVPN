#!/usr/bin/env python3
"""Делает все картинки значков из SVG в branding/.

Нужны rsvg-convert (librsvg2-bin) и Pillow. Результат уже лежит в репозитории,
запускать заново нужно только после изменения SVG:  python3 tools/make_icons.py
"""
import io
import os
import subprocess
import sys

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BR = os.path.join(ROOT, "branding")
DESK = os.path.join(ROOT, "desktop", "icons")
RES = os.path.join(ROOT, "android", "app", "src", "main", "res")


def render(svg, size):
    png = subprocess.run(
        ["rsvg-convert", "-w", str(size), "-h", str(size), os.path.join(BR, svg)],
        check=True, capture_output=True).stdout
    return Image.open(io.BytesIO(png)).convert("RGBA")


def save(img, *path):
    out = os.path.join(*path)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    img.save(out, optimize=True)
    print("  ", os.path.relpath(out, ROOT))


def icon(size):
    # до 48 px — толстый вариант, иначе линия теряется
    return render("icon-small.svg" if size <= 48 else "icon.svg", size)


def main():
    print("Компьютер")
    save(icon(32), DESK, "32x32.png")
    save(icon(64), DESK, "64x64.png")
    save(icon(128), DESK, "128x128.png")
    save(icon(256), DESK, "128x128@2x.png")
    save(icon(512), DESK, "icon.png")
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    imgs = [icon(s) for s in sizes]
    ico = os.path.join(DESK, "icon.ico")
    imgs[-1].save(ico, sizes=[(s, s) for s in sizes], append_images=imgs[:-1])
    print("  ", os.path.relpath(ico, ROOT))
    icns = os.path.join(DESK, "icon.icns")
    render("icon-mac.svg", 1024).save(icns)
    print("  ", os.path.relpath(icns, ROOT))
    for name in ("tray-on", "tray-off"):
        save(render(name + ".svg", 64), DESK, name + ".png")
        save(render(name + "-template.svg", 44), DESK, name + "-template.png")

    print("Android")
    dens = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}
    for d, k in dens.items():
        legacy = int(48 * k)
        save(icon(legacy), RES, "mipmap-" + d, "ic_launcher.png")
        # круглый значок: тот же рисунок на круге
        sq = render("icon.svg", legacy)
        mask = Image.new("L", (legacy, legacy), 0)
        from PIL import ImageDraw
        ImageDraw.Draw(mask).ellipse((0, 0, legacy - 1, legacy - 1), fill=255)
        rnd = Image.new("RGBA", (legacy, legacy), (0, 0, 0, 0))
        bg = Image.new("RGBA", (legacy, legacy), (0x0B, 0x12, 0x20, 255))
        rnd.paste(bg, (0, 0), mask)
        rnd.alpha_composite(Image.composite(sq, Image.new("RGBA", sq.size, (0, 0, 0, 0)), mask))
        save(rnd, RES, "mipmap-" + d, "ic_launcher_round.png")
        save(render("android-foreground.svg", int(108 * k)), RES, "mipmap-" + d, "ic_launcher_foreground.png")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        sys.exit("Нужна программа rsvg-convert (пакет librsvg2-bin)")
