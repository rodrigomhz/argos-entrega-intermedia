import hashlib
from pathlib import Path

import pyzipper
from magika import Magika

from argos import listas


def _bloques(f):
    while bloque := f.read(1024 * 1024):
        yield bloque


def _huellas(bloques):
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    # Un solo recorrido para las dos huellas
    for bloque in bloques:
        sha256.update(bloque)
        sha1.update(bloque)
    return sha256.hexdigest(), sha1.hexdigest()


def _ficha(huella256, huella1, tamano, tipo, nombre):
    """Lo igual para un fichero del disco y para unos bytes: tipo, aviso de extensión y listas."""
    extension = Path(nombre).suffix.lower().lstrip(".")
    return {
        "sha256": huella256,
        "sha1": huella1,
        "bytes": tamano,
        "tipo": f"{tipo.description} ({tipo.group})",
        "extension_engana": bool(tipo.extensions) and extension not in tipo.extensions,
        "extensiones_esperadas": tipo.extensions,
        "malwarebazaar": listas.en_malwarebazaar(huella256),
        "circl": listas.en_circl(huella1),
    }


def identificar(ruta):
    ruta = Path(ruta)
    with ruta.open("rb") as f:
        huella256, huella1 = _huellas(_bloques(f))
    tipo = Magika().identify_path(ruta).output
    return _ficha(huella256, huella1, ruta.stat().st_size, tipo, ruta.name)


def identificar_zip(ruta_zip, clave):
    """[(nombre dentro del zip, ficha)] de cada fichero del zip. Todo en memoria: nada se escribe al disco."""
    magika = Magika()
    fichas = []
    with pyzipper.AESZipFile(ruta_zip) as z:
        z.setpassword(clave.encode())
        for info in z.infolist():
            if info.is_dir():
                continue
            # ponytail: cada fichero entero en memoria (falla si no cabe en la RAM, p. ej. una bomba zip); mejorar: z.open() en bloques y un tope de tamaño
            datos = z.read(info)
            huella256, huella1 = _huellas([datos])
            tipo = magika.identify_bytes(datos).output
            fichas.append((info.filename, _ficha(huella256, huella1, len(datos), tipo, info.filename)))
    return fichas
