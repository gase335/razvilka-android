#!/usr/bin/env python3
"""Сборка geoip.dat для Razvilka из CSV DB-IP «IP to Country Lite» (CC BY 4.0).

Формат (все числа big-endian):
  b"RZGEO1\\0\\0"
  u16 count_codes, затем count_codes * 2 байта ISO-кодов (индекс 0 = "--": нет данных)
  u32 n4, затем n4 записей: u32 start, u16 code_index   (диапазон до следующего start)
  u32 n6, затем n6 записей: 16 байт start, u16 code_index
Файл целиком сжат zlib (после 8-байтного заголовка).

Использование: build_geoip.py dbip-country-ipv4.csv dbip-country-ipv6.csv geoip.dat
"""
import ipaddress, struct, sys, zlib

def load(path, v6):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            a, b, cc = line.split(",")[:3]
            s = int(ipaddress.ip_address(a)); e = int(ipaddress.ip_address(b))
            rows.append((s, e, cc.upper()))
    rows.sort()
    out = []  # (start, cc) с явными дырами "--"
    nxt = 0
    for s, e, cc in rows:
        if s > nxt:
            out.append((nxt, "--"))
        if out and out[-1][1] == cc:
            pass
        else:
            out.append((s, cc))
        nxt = e + 1
    top = (1 << (128 if v6 else 32))
    if nxt < top:
        out.append((nxt, "--"))
    # убрать подряд идущие одинаковые коды
    merged = []
    for s, cc in out:
        if merged and merged[-1][1] == cc:
            continue
        merged.append((s, cc))
    return merged

def main():
    v4 = load(sys.argv[1], False)
    v6 = load(sys.argv[2], True)
    codes = ["--"] + sorted({cc for _, cc in v4 + v6} - {"--"})
    idx = {c: i for i, c in enumerate(codes)}
    body = bytearray()
    body += struct.pack(">H", len(codes))
    for c in codes:
        body += c.encode("ascii")[:2].ljust(2, b"-")
    body += struct.pack(">I", len(v4))
    for s, cc in v4:
        body += struct.pack(">IH", s, idx[cc])
    body += struct.pack(">I", len(v6))
    for s, cc in v6:
        body += s.to_bytes(16, "big") + struct.pack(">H", idx[cc])
    with open(sys.argv[3], "wb") as f:
        f.write(b"RZGEO1\0\0")
        f.write(zlib.compress(bytes(body), 9))
    print(f"codes={len(codes)} v4={len(v4)} v6={len(v6)} raw={len(body)}")

if __name__ == "__main__":
    main()
