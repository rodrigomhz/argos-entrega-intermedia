# Se lanza con: python tests/test_listas.py (necesita las dos listas descargadas)
import zipfile
from pathlib import Path

from argos import listas

# FNV-1 de 64 bits: vectores de la batería de pruebas oficial de FNV
assert listas.fnv1_64(b"") == 0xCBF29CE484222325
assert listas.fnv1_64(b"a") == 0xAF63BD4C8601B7BE
assert listas.fnv1_64(b"foobar") == 0x340D8765A4DDA9C2

# MalwareBazaar: una SHA-256 sacada de la propia lista está; una inventada no
with zipfile.ZipFile(listas.CARPETA / listas.MALWAREBAZAAR) as z, z.open("full_sha256.txt") as f:
    de_la_lista = next(linea for linea in f if not linea.startswith(b"#")).decode().strip()
assert listas.en_malwarebazaar(de_la_lista)[0] is True
assert listas.en_malwarebazaar("0" * 64)[0] is False

# CIRCL: dos SHA-1 que la API de hashlookup.circl.lu dio como conocidas (D3DCompiler_41.dll y Microsoft.DirectX.dll)
assert listas.en_circl("3c918aee68fa2465e56b93cb7cfe884e2e166c96")[0] is True
assert listas.en_circl("c4c7e034773a240909332814f499730575a1cd71")[0] is True
# ...y una cadena aleatoria que la API dio como desconocida
assert listas.en_circl("69e69496ea64fde60110dab6b07a8dc7efc666d7")[0] is False

# Lista ausente: no es un error, da None
listas.CARPETA = Path("carpeta-que-no-existe")
assert listas.en_malwarebazaar("0" * 64) is None
assert listas.en_circl("0" * 40) is None

print("OK")
