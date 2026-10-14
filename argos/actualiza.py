import json
import os
import shutil
import urllib.request
from datetime import datetime
from email.utils import parsedate_to_datetime

from argos import listas
from argos.estatico import REGLAS, REGLAS_ZIP

# La última versión publicada de YARA Forge (paquete "core"), por la API de GitHub y sin cuenta
API_YARA_FORGE = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
URL_MALWAREBAZAAR = "https://bazaar.abuse.ch/export/txt/sha256/full/"
URL_CIRCL = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
ESPERA = 30  # segundos sin recibir nada antes de rendirse (no es el tiempo total de la descarga)


def mb(tamano):
    return f"{tamano / 1e6:.1f} MB".replace(".", ",")


def momento(segundos):
    return datetime.fromtimestamp(segundos).strftime("%Y-%m-%d %H:%M")


def abrir(url, metodo="GET"):
    return urllib.request.urlopen(urllib.request.Request(url, method=metodo), timeout=ESPERA)


def descargar(url, destino, esperado):
    """Baja url a un fichero temporal junto a destino y solo lo renombra si llegó con los bytes anunciados."""
    destino.parent.mkdir(parents=True, exist_ok=True)
    temporal = destino.with_name(destino.name + ".parte")
    try:
        with abrir(url) as r, temporal.open("wb") as f:
            # ponytail: sin barra de progreso; el filtro de CIRCL (1 GB) tarda minutos sin decir nada. Mejorar: copiar en bloques e ir imprimiendo los MB
            shutil.copyfileobj(r, f)
        recibidos = temporal.stat().st_size
        if recibidos != esperado:  # si la conexión se corta, Python no avisa: el fichero solo queda más corto
            raise OSError(f"la descarga llegó incompleta ({mb(recibidos)} de {mb(esperado)})")
        os.replace(temporal, destino)
    finally:
        temporal.unlink(missing_ok=True)  # tras el replace ya no existe; si algo falló, no deja el temporal


def reglas():
    with abrir(API_YARA_FORGE) as r:
        ultima = json.load(r)
    version = ultima["tag_name"]
    paquete = next(a for a in ultima["assets"] if a["name"] == REGLAS_ZIP)
    destino, marca = REGLAS / REGLAS_ZIP, REGLAS / "version.txt"
    if destino.is_file() and marca.is_file() and marca.read_text() == version:
        print(f"Reglas YARA (YARA Forge, paquete core): al día, versión {version}")
        return
    print(f"Reglas YARA (YARA Forge, paquete core): descargando la versión {version} ({mb(paquete['size'])})...")
    descargar(paquete["browser_download_url"], destino, paquete["size"])
    marca.write_text(version)  # la última: si algo falla antes, la próxima vez vuelve a descargar
    print("Reglas YARA: hecho")


def lista(nombre, fichero, url):
    """Pone al día una lista comparando lo que anuncia el servidor (tamaño y fecha) con el fichero que hay en el disco."""
    destino = listas.CARPETA / fichero
    with abrir(url, "HEAD") as r:  # solo las cabeceras: no baja el fichero
        tamano = int(r.headers["Content-Length"])
        modificado = parsedate_to_datetime(r.headers["Last-Modified"]).timestamp()
    if not destino.is_file():
        motivo = "no hay copia"
    elif destino.stat().st_size != tamano:
        motivo = f"el servidor anuncia otro tamaño: {mb(tamano)}, y tu copia {mb(destino.stat().st_size)}"
    # ponytail: compara la fecha del servidor con la del fichero en este equipo; si el servidor la cambia mientras se descarga, no se nota. Mejorar: guardar la fecha del servidor junto a la copia
    elif destino.stat().st_mtime < modificado:
        motivo = f"el servidor la cambió el {momento(modificado)} y tu copia es del {momento(destino.stat().st_mtime)}"
    else:
        print(f"{nombre}: al día (mismo tamaño, {mb(tamano)}; el servidor la cambió el {momento(modificado)} y tu copia es posterior)")
        return
    print(f"{nombre}: descargando {mb(tamano)} ({motivo})...")
    descargar(url, destino, tamano)
    print(f"{nombre}: hecho")


def actualizar(sin_circl):
    reglas()
    lista("MalwareBazaar", listas.MALWAREBAZAAR, URL_MALWAREBAZAAR)
    if sin_circl:
        print("CIRCL: omitido (--sin-circl)")
    else:
        lista("CIRCL", listas.CIRCL, URL_CIRCL)
