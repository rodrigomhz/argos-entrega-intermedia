# Se lanza con: python tests/test_estatico.py (usa notepad.exe del propio Windows)
from pathlib import Path

from argos.estatico import analizar_pe, suplantacion, verificar_firma

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

# Suplantación: un notepad de verdad no da indicios; su firma va en catálogo, así que no hay zona incrustada que revisar
assert suplantacion(datos, firma) == []
assert datos["zona_firma"] is None

# ...pero si los datos de versión dicen ser de Microsoft y firma otro, avisa (y el firmante tampoco es conocido)
datos_mentirosos = {**datos, "version": {"empresa": "Microsoft Corporation", "nombre_original": "NOTEPAD.EXE"}}
avisos = suplantacion(datos_mentirosos, {"estado": "válida", "tipo": "incrustada en el fichero", "firmante": "CN=Evil Lda, O=Evil Lda"})
assert any("suplantación" in a and "Evil Lda" in a for a in avisos), avisos
assert any("poco conocido" in a for a in avisos), avisos

# Sin firma y diciendo ser de Microsoft: también avisa
assert any("no está firmado" in a for a in suplantacion(datos_mentirosos, {"estado": "sin firma", "tipo": "", "firmante": ""}))

# Zona de firma de verdad: python.exe lleva firma incrustada y está limpio; con bytes pegados al final, Argos los cuenta
import shutil
import tempfile

base = Path(sys.base_prefix) / "python.exe"
assert base.is_file(), f"no encuentro el python base: {base}"
assert suplantacion(analizar_pe(base.read_bytes()), verificar_firma(base)) == []
with tempfile.TemporaryDirectory() as tmp:
    copia = Path(tmp) / "python-copia.exe"
    shutil.copyfile(base, copia)
    with open(copia, "ab") as f:
        f.write(b"x" * 512)
    pe_copia = analizar_pe(copia.read_bytes())
    assert pe_copia["zona_firma"]["tras"] == 512
    assert any("después de la firma" in a for a in suplantacion(pe_copia, verificar_firma(copia)))

print("OK")
