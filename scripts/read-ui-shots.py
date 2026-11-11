#!/usr/bin/env python3
"""Достаёт снимки интерфейса из аннотаций запуска GitHub Actions и сохраняет их в PNG.

Сборочная машина ничего не выгружает, поэтому проверки интерфейса (tests/UltimateWindows.WindowsTests)
записывают запрошенные снимки текстом, а scripts/ci.ps1 передаёт этот текст аннотациями «uwshot имя i/n».
Какие снимки передавать, перечислено в tests/UltimateWindows.WindowsTests/ui-snapshots.txt.

Запуск (нужны программа gh и модуль brotli: pip install brotli):

    python scripts/read-ui-shots.py <владелец/репозиторий> <номер запуска> [каталог для PNG]

Формат снимка: «UWS1», ширина и высота (по 2 байта), число цветов, палитра RGB,
затем индексы пикселей, сжатые Brotli. Текст — по 15 бит на знак, перед ним длина в байтах и «:».
"""
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import brotli


def gh_json(path):
    out = subprocess.run(["gh", "api", "--paginate", path], check=True, capture_output=True).stdout.decode("utf-8")
    # --paginate склеивает страницы подряд: «[...][...]»
    items, decoder, pos = [], json.JSONDecoder(), 0
    while pos < len(out):
        while pos < len(out) and out[pos].isspace():
            pos += 1
        if pos >= len(out):
            break
        value, pos = decoder.raw_decode(out, pos)
        items.extend(value if isinstance(value, list) else [value])
    return items


def decode_text(text):
    length, _, payload = text.partition(":")
    out, buffer, bits = bytearray(), 0, 0
    for ch in payload:
        code = ord(ch)
        if 0x3400 <= code <= 0x4DBF:
            value = code - 0x3400
        elif 0x4E00 <= code <= 0x9FFF:
            value = code - 0x4E00 + 6592
        elif 0xAC00 <= code <= 0xC03F:
            value = code - 0xAC00 + 27584
        else:
            continue
        buffer = (buffer << 15) | value
        bits += 15
        while bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
        buffer &= (1 << bits) - 1
    return bytes(out[: int(length)])


def to_png(data):
    if data[:4] != b"UWS1":
        raise ValueError("это не снимок интерфейса")
    width, height, colors = struct.unpack_from("<HHB", data, 4)
    palette = data[9 : 9 + colors * 3]
    pixels = brotli.decompress(data[9 + colors * 3 :])
    if len(pixels) != width * height:
        raise ValueError(f"размер снимка не сходится: {len(pixels)} вместо {width * height}")

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    rows = b"".join(b"\x00" + pixels[y * width : (y + 1) * width] for y in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 3, 0, 0, 0))
        + chunk(b"PLTE", palette)
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    repo, run_id = sys.argv[1], sys.argv[2]
    out_dir = Path(sys.argv[3] if len(sys.argv) > 3 else "ui-shots")
    out_dir.mkdir(parents=True, exist_ok=True)

    parts = {}
    for job in gh_json(f"repos/{repo}/actions/runs/{run_id}/jobs"):
        for entry in job.get("jobs", [job]):
            for note in gh_json(f"repos/{repo}/check-runs/{entry['id']}/annotations"):
                title = (note.get("title") or "").split()
                if len(title) == 3 and title[0] == "uwshot":
                    index, total = (int(x) for x in title[2].split("/"))
                    parts.setdefault(title[1], {})[index] = (total, note.get("message") or "")

    if not parts:
        print("В аннотациях запуска снимков нет.")
        return 1

    for name, chunks in sorted(parts.items()):
        total = next(iter(chunks.values()))[0]
        if len(chunks) != total:
            print(f"{name}: получено {len(chunks)} частей из {total} — пропущен")
            continue
        try:
            png = to_png(decode_text("".join(chunks[i][1] for i in range(1, total + 1))))
        except Exception as error:  # noqa: BLE001 — показываем причину и идём к следующему снимку
            print(f"{name}: {error}")
            continue
        path = out_dir / f"{name}.png"
        path.write_bytes(png)
        print(f"{name}: {path} ({len(png) // 1024} КБ)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
