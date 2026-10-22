#!/usr/bin/env python3
"""Generate the launcher icon PNGs without any third-party imaging library.

Draws a flat red rounded square with a white broken-chain glyph. Hand-rolled
rasteriser, which is plenty for a handful of small icons.

Usage: python3 tools/make_icon.py
"""

import pathlib
import struct
import zlib

RES = pathlib.Path(__file__).resolve().parent.parent / "app" / "src" / "main" / "res"
SIZES = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}

BG = (198, 40, 40)
FG = (255, 255, 255)


def write_png(path: pathlib.Path, width: int, height: int, pixels: bytes) -> None:
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    raw = b"".join(b"\x00" + pixels[y * width * 4:(y + 1) * width * 4] for y in range(height))
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def inside_rounded_square(x: float, y: float, size: int, radius: float) -> bool:
    cx = min(max(x, radius), size - radius)
    cy = min(max(y, radius), size - radius)
    dx, dy = x - cx, y - cy
    return dx * dx + dy * dy <= radius * radius


def inside_capsule(u: float, v: float, start: float, end: float, radius: float) -> bool:
    clamped = min(max(u, start), end)
    du, dv = u - clamped, v
    return du * du + dv * dv <= radius * radius


def inside_glyph(x: float, y: float, size: int) -> bool:
    """Two chain links, rotated 45 degrees, with a gap between them."""
    centre = size / 2
    dx = (x - centre) / 2 ** 0.5
    dy = (y - centre) / 2 ** 0.5
    u, v = dx + dy, dy - dx
    half_width = size * 0.062
    link_length = size * 0.155
    gap = size * 0.16
    left = inside_capsule(u, v, -gap / 2 - link_length, -gap / 2, half_width)
    right = inside_capsule(u, v, gap / 2, gap / 2 + link_length, half_width)
    return left or right


def render(size: int) -> bytes:
    pixels = bytearray(size * size * 4)
    radius = size * 0.22
    for y in range(size):
        for x in range(size):
            idx = (y * size + x) * 4
            if not inside_rounded_square(x + 0.5, y + 0.5, size, radius):
                continue
            colour = FG if inside_glyph(x + 0.5, y + 0.5, size) else BG
            pixels[idx:idx + 4] = bytes((*colour, 255))
    return bytes(pixels)


def main() -> None:
    for bucket, size in SIZES.items():
        out = RES / f"mipmap-{bucket}" / "ic_launcher.png"
        out.parent.mkdir(parents=True, exist_ok=True)
        write_png(out, size, size, render(size))
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
