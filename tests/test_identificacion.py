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

print("OK")
