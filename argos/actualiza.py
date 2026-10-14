import json
import os
import shutil
import sys
import time
import urllib.request
from collections import namedtuple
from datetime import datetime
from email.utils import parsedate_to_datetime
from http.client import HTTPException

from argos import listas
from argos.estatico import REGLAS, REGLAS_ZIP

# La última versión publicada de YARA Forge (paquete "core"), por la API de GitHub y sin cuenta
API_YARA_FORGE = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
URL_MALWAREBAZAAR = "https://bazaar.abuse.ch/export/txt/sha256/full/"
URL_CIRCL = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
ESPERA = 30  # segundos sin recibir nada antes de rendirse (no es el tiempo total de la descarga)
# ponytail: ESPERA_AVISO también es por operación, no total (3 peticiones: con un servidor lento podrían sumar más). Mejorar: un plazo total con un hilo
ESPERA_AVISO = 5  # lo mismo para el aviso de antes de analizar: no debe hacer esperar al análisis
CADA = 24 * 3600  # segundos entre dos comprobaciones del aviso
VERSION_REGLAS = REGLAS / "version.txt"
ULTIMA_COMPROBACION = REGLAS.parent / "ultima-comprobacion"  # en argos-datos, junto a reglas y listas; solo importa su fecha

# Un dato desactualizado o ausente: lo que hace falta para avisar (nombre, motivo, tamaño) y para descargarlo (url, destino)
# version solo la llevan las reglas: es lo que se anota en VERSION_REGLAS al terminar
Pendiente = namedtuple("Pendiente", "nombre motivo tamano url destino version", defaults=[None])


def mb(tamano):
    return f"{tamano / 1e6:.1f} MB".replace(".", ",")


def momento(segundos):
    return datetime.fromtimestamp(segundos).strftime("%Y-%m-%d %H:%M")


def abrir(url, metodo="GET", espera=ESPERA):
    return urllib.request.urlopen(urllib.request.Request(url, method=metodo), timeout=espera)


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


def pendiente_reglas(espera):
    """Pendiente con las reglas YARA si faltan o hay otra versión en GitHub; None si están al día."""
    with abrir(API_YARA_FORGE, espera=espera) as r:
        ultima = json.load(r)
    version = ultima["tag_name"]
    paquete = next(a for a in ultima["assets"] if a["name"] == REGLAS_ZIP)
    destino = REGLAS / REGLAS_ZIP
    if not (destino.is_file() and VERSION_REGLAS.is_file()):
        motivo = "no hay copia"
    elif VERSION_REGLAS.read_text() != version:
        motivo = f"tu copia es la {VERSION_REGLAS.read_text()}"
    else:
        return None
    return Pendiente(f"reglas YARA {version}", motivo, paquete["size"], paquete["browser_download_url"], destino, version)


def pendiente_lista(nombre, fichero, url, espera):
    """Pendiente con una lista si falta o el servidor tiene una versión más nueva que el fichero del disco; None si está al día."""
    destino = listas.CARPETA / fichero
    with abrir(url, "HEAD", espera) as r:  # solo las cabeceras: no baja el fichero
        tamano = int(r.headers["Content-Length"])
        modificado = parsedate_to_datetime(r.headers["Last-Modified"]).timestamp()
    # Solo cuenta la fecha, no el tamaño: el servidor de MalwareBazaar reparte a la vez una copia nueva y otra
    # algo más vieja, de tamaños distintos, y comparar tamaños haría que siempre pareciese desactualizada
    if not destino.is_file():
        motivo = "no hay copia"
    # ponytail: compara la fecha del servidor con la del fichero en este equipo; si el servidor la cambia mientras se descarga, no se nota. Mejorar: guardar la fecha del servidor junto a la copia
    elif destino.stat().st_mtime < modificado:
        motivo = f"el servidor la cambió el {momento(modificado)} y tu copia es del {momento(destino.stat().st_mtime)}"
    else:
        return None
    return Pendiente(nombre, motivo, tamano, url, destino)


def comprobar(sin_circl, espera=ESPERA):
    """Lista de Pendiente: lo que falta o está desactualizado. No descarga nada."""
    pendientes = [
        pendiente_reglas(espera),
        pendiente_lista("MalwareBazaar", listas.MALWAREBAZAAR, URL_MALWAREBAZAAR, espera),
    ]
    if not sin_circl:
        pendientes.append(pendiente_lista("CIRCL", listas.CIRCL, URL_CIRCL, espera))
    return [p for p in pendientes if p]


def actualizar(sin_circl=False, pendientes=None):
    """Descarga lo pendiente; si el aviso ya lo comprobó, se lo pasa en pendientes y no se vuelve a comprobar."""
    if sin_circl:
        print("CIRCL: omitido (--sin-circl)")
    if pendientes is None:
        pendientes = comprobar(sin_circl)
    for p in pendientes:
        print(f"{p.nombre}: descargando {mb(p.tamano)} ({p.motivo})...")
        descargar(p.url, p.destino, p.tamano)
        if p.version:
            VERSION_REGLAS.write_text(p.version)  # la última: si algo falla antes, la próxima vez vuelve a descargar
        print(f"{p.nombre}: hecho")
    if not pendientes:
        print("Todo al día.")


def avisar():
    """Antes de analizar: dice si hay datos nuevos y, en una terminal, ofrece actualizarlos."""
    if ULTIMA_COMPROBACION.is_file() and time.time() - ULTIMA_COMPROBACION.stat().st_mtime < CADA:
        return
    try:
        pendientes = comprobar(sin_circl=False, espera=ESPERA_AVISO)
    except Exception:  # sin red, servidor caído, respuesta rara...: el aviso nunca debe romper el análisis
        pendientes = []
    ULTIMA_COMPROBACION.parent.mkdir(parents=True, exist_ok=True)
    ULTIMA_COMPROBACION.touch()  # también si falló: hasta dentro de 24 h no se vuelve a intentar
    if not pendientes:
        return
    print("Hay datos nuevos: " + ", ".join(f"{p.nombre} ({mb(p.tamano)})" for p in pendientes) + ".")
    if sys.stdin.isatty() and sys.stdout.isatty() and input("¿Actualizar ahora? [s/N] ").strip().lower() == "s":
        try:
            actualizar(pendientes=pendientes)
        except (OSError, HTTPException) as error:  # la descarga sí la pidió el usuario: si falla, se lo dice y sigue con el análisis
            print(f"error: no se pudo actualizar: {error}")
    else:
        print("Para actualizar cuando quieras: argos actualiza")
