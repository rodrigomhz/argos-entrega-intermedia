# Se lanza con: python tests/test_yara.py (necesita las reglas descargadas con «argos actualiza» y usa notepad.exe del propio Windows)
from pathlib import Path

import yara_x

from argos import estatico

# Sin reglas descargadas: no es un error, da None
reglas_reales = estatico.REGLAS
estatico.REGLAS = Path("carpeta-que-no-existe")
assert estatico.yara(b"cualquier cosa") is None
estatico.REGLAS = reglas_reales
estatico.cargar_reglas.cache_clear()  # cargar_reglas recuerda su resultado (None, en este caso)

# Una regla escrita aquí, con bytes inofensivos: coincide con unos bytes y no con otros
de_prueba = yara_x.compile('rule prueba_argos { meta: description = "regla de prueba" strings: $a = "argos-inofensivo" condition: $a }')
cargar_reglas = estatico.cargar_reglas
estatico.cargar_reglas = lambda: de_prueba
assert estatico.yara(b"hola argos-inofensivo adios") == [("prueba_argos", "regla de prueba")]
assert estatico.yara(b"hola argos adios") == []
estatico.cargar_reglas = cargar_reglas

# Las reglas de verdad (las que baja «argos actualiza») compilan y notepad.exe no da coincidencias
assert estatico.cargar_reglas() is not None, "faltan las reglas: ejecuta «argos actualiza»"
assert estatico.yara(Path(r"C:\Windows\System32\notepad.exe").read_bytes()) == []

print("OK")
