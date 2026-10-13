# Se lanza con: python tests/test_estatico.py (usa notepad.exe del propio Windows)
from pathlib import Path

from argos.estatico import analizar_pe, verificar_firma

datos = analizar_pe(Path(r"C:\Windows\System32\notepad.exe").read_bytes())
assert datos["arquitectura"] == "x64 (64 bits)"
nombres = [s["nombre"] for s in datos["secciones"]]
assert ".text" in nombres and ".rsrc" in nombres
assert all(0 <= s["entropia"] <= 8 for s in datos["secciones"])
assert "GDI32.dll" in datos["importaciones"]
assert sum(len(f) for f in datos["importaciones"].values()) > 100

# Lo que no es un ejecutable de Windows no rompe nada: da None
assert analizar_pe(b"esto no es un ejecutable") is None

# Firma: notepad.exe está firmado por Microsoft (en un catálogo de Windows); el lanzador argos.exe no lleva firma
import sys

firma = verificar_firma(r"C:\Windows\System32\notepad.exe")
assert firma["estado"] == "válida" and "Microsoft" in firma["firmante"]
assert verificar_firma(Path(sys.executable).with_name("argos.exe"))["estado"] == "sin firma"

print("OK")
