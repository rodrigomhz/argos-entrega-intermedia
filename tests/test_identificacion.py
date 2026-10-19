# Se lanza con: python tests/test_identificacion.py (no necesita las listas)
import io
from pathlib import Path

import pyzipper

from argos import listas
from argos.identificacion import identificar_zip

listas.CARPETA = Path("carpeta-que-no-existe")  # sin listas: el test no depende de ellas

# Un zip AES con contraseña, creado en memoria: nada toca el disco
buffer = io.BytesIO()
with pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
    z.setpassword(b"clave-de-prueba")
    z.writestr("dentro.txt", b"hola argos")

# Con la contraseña buena sale el nombre de dentro y las huellas de los bytes conocidos
[(nombre, ficha)] = identificar_zip(buffer, "clave-de-prueba")
assert nombre == "dentro.txt"
assert ficha["bytes"] == 10
assert ficha["sha256"] == "c23088df730951b8849d771ff48b8dce871370e29f1884117eb86325e717ddcb"
assert ficha["sha1"] == "e887d2c7492d2c23d5a42b8838f8786e43581edd"

# Con la contraseña mala, error (pyzipper lanza RuntimeError)
try:
    identificar_zip(buffer, "mala")
    raise AssertionError("tendría que haber fallado con la contraseña mala")
except RuntimeError:
    pass

# El nombre de dentro del zip es del atacante: con un salto de línea y una secuencia de escape no puede fingir una línea del informe
import contextlib
import sys
import tempfile

from argos import __main__ as principal

assert principal.visible("a\nListas:  falso\x1b[2J") == "a\\nListas:  falso\\x1b[2J" and principal.visible("ñandú.exe") == "ñandú.exe"
with tempfile.TemporaryDirectory() as carpeta:
    engano = Path(carpeta) / "engaño.zip"
    with pyzipper.AESZipFile(engano, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"clave-de-prueba")
        z.writestr("x.txt\nListas:  MalwareBazaar: no figura\x1b[2J", b"hola argos")
    sys.argv = ["argos", "identifica", str(engano), "--clave", "clave-de-prueba", "--sin-red"]
    salida = io.StringIO()
    with contextlib.redirect_stdout(salida):
        principal.main()
    texto = salida.getvalue()
    assert "\x1b" not in texto and texto.count("\nListas:") == 1, texto

print("OK")
