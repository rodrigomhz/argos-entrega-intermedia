import mmap
import struct
import zipfile
from datetime import datetime
from pathlib import Path

CARPETA = Path.home() / "argos-datos" / "listas"
MALWAREBAZAAR = "malwarebazaar-sha256.zip"
CIRCL = "circl-hashlookup-full.bloom"

MASCARA_64 = 0xFFFFFFFFFFFFFFFF
# Constantes del filtro de Bloom de DCSO (github.com/DCSO/flor: filter.py y fnv.py)
OFFSET_FNV = 14695981039346656037
PRIMO_FNV = 1099511628211
M1 = 18446744073709551557
G = 18446744073709550147


def fnv1_64(dato):
    h = OFFSET_FNV
    for byte in dato:
        h = (h * PRIMO_FNV) & MASCARA_64
        h ^= byte
    return h


def en_malwarebazaar(sha256):
    """(esta, fecha de la lista), o None si falta el fichero de la lista."""
    ruta = CARPETA / MALWAREBAZAAR
    if not ruta.is_file():
        return None
    buscada = sha256.encode()
    fecha = "?"
    # ponytail: recorre ~1,15 millones de líneas en cada consulta (~3,5 s si no está); si molesta, ordenar la lista y buscar a saltos
    with zipfile.ZipFile(ruta) as z, z.open("full_sha256.txt") as f:
        for linea in f:
            if linea.startswith(b"# Last updated:"):
                fecha = linea.split()[3].decode()  # "# Last updated: 2026-10-06 13:39:18 UTC #"
            elif linea.strip() == buscada:
                return True, fecha
    return False, fecha


def en_circl(sha1):
    """(esta, fecha de descarga), o None si falta el fichero de la lista. El filtro se equivoca 1 de cada 10.000 veces."""
    ruta = CARPETA / CIRCL
    if not ruta.is_file():
        return None
    fecha = datetime.fromtimestamp(ruta.stat().st_mtime).date().isoformat()
    valor = sha1.upper().encode()  # CIRCL consulta la SHA-1 en hexadecimal mayúsculas
    with ruta.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as filtro:
        flags, _n, _p, k, m, _N = struct.unpack("<QQdQQQ", filtro[:48])
        if flags & 0xFF != 1:
            raise ValueError(f"versión de filtro no soportada: {flags & 0xFF}")
        hn = fnv1_64(valor) % M1
        for _ in range(k):
            hn = ((hn * G) & MASCARA_64) % M1
            pos = hn % m
            if not filtro[48 + pos // 8] & (1 << (pos % 8)):
                return False, fecha
    return True, fecha
