#!/usr/bin/env python3
"""Иконка Развилки: дорога, расходящаяся на две полосы (VPN — янтарь, напрямую — синий)."""
import sys
from PIL import Image, ImageDraw
S = 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle([40, 40, S - 40, S - 40], radius=200, fill=(0x26, 0x2b, 0x33, 255))
w = 92
def poly(points, col):
    d.line(points, fill=col, width=w, joint="curve")
    for x, y in (points[0], points[-1]):
        d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=col)
d.line([(512, 880), (512, 560)], fill=(0xe8, 0xe6, 0xe1, 255), width=w)
d.ellipse([512 - w/2, 880 - w/2, 512 + w/2, 880 + w/2], fill=(0xe8, 0xe6, 0xe1, 255))
poly([(512, 560), (384, 370), (250, 170)], (0xf2, 0xb3, 0x3d, 255))
poly([(512, 560), (640, 370), (774, 170)], (0x6f, 0xa8, 0xdc, 255))
d.ellipse([512 - w/2, 560 - w/2, 512 + w/2, 560 + w/2], fill=(0xe8, 0xe6, 0xe1, 255))
out = sys.argv[1]
img.save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
img.resize((256, 256), Image.LANCZOS).save(out.replace(".ico", ".png"))
