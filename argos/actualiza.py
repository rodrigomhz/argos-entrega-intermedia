import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import namedtuple
from datetime import datetime
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from pathlib import Path

import capa.version

from argos import ember, herramientas, listas
from argos.estatico import REGLAS, REGLAS_ZIP

# La última versión publicada de YARA Forge (paquete "core"), por la API de GitHub y sin cuenta
API_YARA_FORGE = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
# Detect It Easy (horsicq, MIT), también de su repositorio oficial
API_DIE = "https://api.github.com/repos/horsicq/DIE-engine/releases/latest"
# El nombre del zip de Windows cambia con la versión: die_win64_portable_3.21_x64.zip
ZIP_DIE = r"die_win64_portable_[\d.]+_x64\.zip"
# capa (Mandiant, Apache-2.0) llega con Argos por pip (flare-capa), pero el paquete no trae sus reglas ni sus firmas FLIRT: se bajan de los repositorios
# oficiales y SIEMPRE del tag de la librería instalada, porque unas reglas más nuevas pueden usar funciones que esta librería no entiende. {} = el tag, p. ej. v9.4.0
URL_REGLAS_CAPA = "https://codeload.github.com/mandiant/capa-rules/zip/refs/tags/{}"
API_FIRMAS_CAPA = "https://api.github.com/repos/mandiant/capa/contents/sigs?ref={}"
# Desde octubre de 2026 el export viejo (bazaar.abuse.ch/export/txt/...) da 410. El nuevo lleva la Auth-Key de abuse.ch EN LA RUTA ({} = la clave, ya escapada):
# es el volcado completo en CSV (un zip con full.csv, ~226 MB) y se regenera cada hora
URL_MALWAREBAZAAR = "https://mb-api.abuse.ch/v2/files/exports/{}/full.csv.zip"
URL_CIRCL = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
ESPERA = 30  # segundos sin recibir nada antes de rendirse (no es el tiempo total de la descarga)
# ponytail: ESPERA_AVISO también es por operación, no total (4 peticiones: con un servidor lento podrían sumar más). Mejorar: un plazo total con un hilo
ESPERA_AVISO = 5  # lo mismo para el aviso de antes de analizar: no debe hacer esperar al análisis
CADA = 24 * 3600  # segundos entre dos comprobaciones del aviso
VERSION_REGLAS = REGLAS / "version.txt"
ULTIMA_COMPROBACION = REGLAS.parent / "ultima-comprobacion"  # en argos-datos, junto a reglas y listas; solo importa su fecha

# Un dato desactualizado o ausente: lo que hace falta para avisar (nombre, motivo, tamaño) y para descargarlo (url, destino)
# version solo la llevan las reglas y las herramientas: es lo que se anota al terminar
# instalador: lo llevan las herramientas, que son una carpeta entera y la deja esa función (instalar, instalar_capa)
# tamano None: la descarga no lo anuncia (el zip de reglas de capa viene de codeload, que lo manda por partes y sin Content-Length)
# huella: la SHA-256 que tiene que tener lo descargado (el modelo EMBER2024): descargar() la comprueba antes de dejarlo en su sitio
Pendiente = namedtuple("Pendiente", "nombre motivo tamano url destino version instalador huella", defaults=[None, None, None])


def mb(tamano):
    return "tamaño sin anunciar" if tamano is None else f"{tamano / 1e6:.1f} MB".replace(".", ",")


def momento(segundos):
    return datetime.fromtimestamp(segundos).strftime("%Y-%m-%d %H:%M")


def abrir(url, metodo="GET", espera=ESPERA, cabeceras=None, datos=None):
    return urllib.request.urlopen(urllib.request.Request(url, data=datos, headers=cabeceras or {}, method=metodo), timeout=espera)


def sha256(ruta):
    with ruta.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def descargar(url, destino, esperado, huella=None, progreso=None):
    """Baja url a un fichero temporal junto a destino y solo lo renombra si llegó con los bytes anunciados (esperado None: no los anuncia y no se comprueban)
    y, si se da huella, con esa SHA-256: lo que no coincide no llega a su sitio y la copia que hubiera antes sigue intacta.
    progreso(recibidos, esperado), si se da, se llama cada MB: la ventana enseña la descarga sin esperar al final."""
    destino.parent.mkdir(parents=True, exist_ok=True)
    temporal = destino.with_name(destino.name + ".parte")
    try:
        with abrir(url) as r, temporal.open("wb") as f:
            recibidos = 0
            while bloque := r.read(1024 * 1024):
                f.write(bloque)
                recibidos += len(bloque)
                if progreso:
                    progreso(recibidos, esperado)
        recibidos = temporal.stat().st_size
        if esperado is not None and recibidos != esperado:  # si la conexión se corta, Python no avisa: el fichero solo queda más corto
            raise OSError(f"la descarga llegó incompleta ({mb(recibidos)} de {mb(esperado)})")
        if huella is not None and (obtenida := sha256(temporal)) != huella:
            raise OSError(f"la descarga no coincide con la huella publicada (SHA-256 {obtenida}, y debía ser {huella})")
        os.replace(temporal, destino)
    finally:
        temporal.unlink(missing_ok=True)  # tras el replace ya no existe; si algo falló, no deja el temporal


def ultima_release(api, patron, espera):
    """(versión, fichero) de la última release de un repositorio de GitHub; el fichero es el primero cuyo nombre encaja con patron."""
    with abrir(api, espera=espera) as r:
        ultima = json.load(r)
    version = ultima["tag_name"]
    fichero = next((a for a in ultima["assets"] if re.fullmatch(patron, a["name"])), None)
    if fichero is None:
        raise OSError(f"la release {version} de {api} no trae ningún fichero que encaje con {patron}")
    return version, fichero


def pendiente_reglas(espera):
    """Pendiente con las reglas YARA si faltan o hay otra versión en GitHub; None si están al día."""
    version, paquete = ultima_release(API_YARA_FORGE, re.escape(REGLAS_ZIP), espera)
    destino = REGLAS / REGLAS_ZIP
    if not (destino.is_file() and VERSION_REGLAS.is_file()):
        motivo = "no hay copia"
    elif VERSION_REGLAS.read_text() != version:
        motivo = f"tu copia es la {VERSION_REGLAS.read_text()}"
    else:
        return None
    return Pendiente(f"reglas YARA {version}", motivo, paquete["size"], paquete["browser_download_url"], destino, version)


def pendiente_herramienta(herramienta, nombre, api, patron, espera):
    """Pendiente con una herramienta descargada (DIE) si falta o hay otra versión en GitHub; None si está al día."""
    version, paquete = ultima_release(api, patron, espera)
    carpeta = herramientas.CARPETA / herramienta
    anotada = carpeta / "version.txt"  # la versión instalada: se escribe dentro de su carpeta al terminar de descomprimir
    if herramientas.ruta(herramienta) is None or not anotada.is_file():
        motivo = "no hay copia"
    elif anotada.read_text() != version:
        motivo = f"tu copia es la {anotada.read_text()}"
    else:
        return None
    return Pendiente(f"{nombre} {version}", motivo, paquete["size"], paquete["browser_download_url"], carpeta, version, instalar)


def pendiente_capa():
    """Pendiente con las reglas y firmas de capa si faltan o no son de la versión de la librería instalada; None si están al día. No usa la red."""
    # La versión sale de la librería y no de la API de GitHub: ahorra peticiones (el límite sin cuenta es de 60 por hora) y es la que tienen que casar
    version = "v" + capa.version.__version__
    carpeta = herramientas.CARPETA / "capa"
    anotada = carpeta / "version.txt"  # la versión de las reglas y firmas instaladas: se escribe dentro de su carpeta al terminar
    if herramientas.datos_capa() is None or not anotada.is_file():
        motivo = "no hay copia"
    elif anotada.read_text() != version:
        motivo = f"tu copia es la {anotada.read_text()}"
    else:
        return None
    return Pendiente(f"reglas y firmas de capa {version}", motivo, None, URL_REGLAS_CAPA.format(version), carpeta, version, instalar_capa)


def pendiente_modelo():
    """Pendiente con el modelo EMBER2024 si falta o su SHA-256 no es la publicada; None si está al día. No usa la red."""
    # La URL está fijada a una revisión de HuggingFace y no hay «versión más nueva» que preguntar: lo único que se comprueba es la copia del disco
    destino = ember.CARPETA / ember.MODELO
    if not destino.is_file():
        motivo = "no hay copia"
    elif sha256(destino) != ember.SHA256:
        motivo = "tu copia no coincide con la huella publicada"
    else:
        return None
    return Pendiente("modelo EMBER2024", motivo, ember.TAMANO, ember.URL, destino, huella=ember.SHA256)


def pendiente_lista(nombre, fichero, url, espera, instalador=None):
    """Pendiente con una lista si falta o el servidor tiene una versión más nueva que el fichero del disco; None si está al día."""
    destino = listas.CARPETA / fichero
    with abrir(url, "HEAD", espera) as r:  # solo las cabeceras: no baja el fichero
        longitud = r.headers.get("Content-Length")  # el volcado de MalwareBazaar no la anuncia
        tamano = int(longitud) if longitud else None
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
    return Pendiente(nombre, motivo, tamano, url, destino, instalador=instalador)


def clave_abusech():
    """La Auth-Key de abuse.ch (la misma del modo conectado) o "" si no está puesta."""
    return (os.environ.get("ARGOS_ABUSECH_KEY") or "").strip()


def comprobar(sin_circl, espera=ESPERA):
    """Lista de Pendiente: lo que falta o está desactualizado. No descarga nada."""
    pendientes = [pendiente_reglas(espera)]
    if clave := clave_abusech():  # sin clave no se pregunta a MalwareBazaar: actualizar() lo dice
        # quote(safe=""): un carácter raro de la clave no cambia la ruta ni mete caracteres de control (http.client pondría la URL entera, clave incluida, en su error)
        url = URL_MALWAREBAZAAR.format(urllib.parse.quote(clave, safe=""))
        # ponytail: el volcado se regenera cada hora, así que una copia de más de una hora ya sale como desactualizada y se vuelven a bajar 226 MB. Mejorar: dar por buena una copia de menos de 24 h
        try:
            pendientes.append(pendiente_lista("MalwareBazaar", listas.MALWAREBAZAAR, url, espera, instalar_malwarebazaar))
        except urllib.error.HTTPError as error:
            if error.code not in (401, 403):
                raise
            # sin url ni clave en el texto, y sin encadenar el error (que lleva la url)
            raise OSError(f"MalwareBazaar no acepta la clave de ARGOS_ABUSECH_KEY (HTTP {error.code}): revísala en https://auth.abuse.ch/") from None
    if not sin_circl:
        pendientes.append(pendiente_lista("CIRCL", listas.CIRCL, URL_CIRCL, espera))
    # Las herramientas, al final: si una falla (p. ej. Defender bloquea la descarga), lo demás ya está al día
    pendientes.append(pendiente_herramienta("die", "Detect It Easy", API_DIE, ZIP_DIE, espera))
    pendientes.append(pendiente_capa())
    pendientes.append(pendiente_modelo())
    return [p for p in pendientes if p]


def descomprimir(ruta_zip, carpeta):
    """Descomprime un zip en carpeta; si alguna ruta de dentro se saliese de ella, no extrae nada."""
    try:
        z = zipfile.ZipFile(ruta_zip)
    except zipfile.BadZipFile as error:  # no es un OSError, y sin esto «argos actualiza» acabaría con una traza
        # Un zip cortado no tiene directorio central (está al final): es lo que da la integridad cuando la descarga no anuncia su tamaño
        raise OSError(f"el zip descargado está cortado o corrupto: {error}") from error
    except OSError as error:  # Windows Defender lo borra o lo bloquea al terminar de escribirlo si lo detecta como amenaza
        raise OSError(f"no se pudo abrir el zip recién descargado (¿lo ha bloqueado Windows Defender? Argos no cambia sus ajustes): {error}") from error
    with z:
        base = carpeta.resolve()
        for nombre in z.namelist():  # el nombre lo escribe quien hizo el zip: "../x" o "C:/x" escaparían de la carpeta
            if not (base / nombre).resolve().is_relative_to(base):
                raise OSError(f"el zip trae una ruta que se sale de su carpeta: {nombre}")
        z.extractall(carpeta)


def instalar(p, progreso=None):
    """Baja el zip de una herramienta y lo descomprime en su carpeta; si algo falla, no deja la carpeta a medias."""
    zip_descargado = p.destino.with_name(p.destino.name + ".zip")
    nueva = p.destino.with_name(p.destino.name + ".parte")
    try:
        descargar(p.url, zip_descargado, p.tamano, progreso=progreso)
        shutil.rmtree(nueva, ignore_errors=True)  # restos de un intento anterior
        descomprimir(zip_descargado, nueva)
        (nueva / "version.txt").write_text(p.version)
        shutil.rmtree(p.destino, ignore_errors=True)  # la versión vieja
        os.replace(nueva, p.destino)
    finally:
        zip_descargado.unlink(missing_ok=True)
        shutil.rmtree(nueva, ignore_errors=True)  # tras el replace ya no existe; si algo falló, no deja el temporal


def firmas_capa(version):
    """[(nombre, bytes, url)] de las firmas FLIRT (.sig) que capa trae en su repositorio, al tag de la librería. Una petición a la API."""
    with abrir(API_FIRMAS_CAPA.format(version)) as r:
        contenido = json.load(r)
    firmas = [(f["name"], f["size"], f["download_url"]) for f in contenido if f["name"].endswith(".sig")]  # la carpeta trae también un README
    if not firmas:  # sin firmas capa sale con código 1
        raise OSError(f"el repositorio de capa no trae firmas (.sig) en la versión {version}")
    return firmas


def instalar_capa(p, progreso=None):
    """Baja el zip de reglas y las firmas de capa a una carpeta nueva y solo al final la cambia por la buena; si algo falla, no deja nada a medias."""
    # Los nombres de esta instalación son los mismos que dejaba la vía antigua (capa.zip, capa.zip.parte, capa.parte, la carpeta capa con capa.exe):
    # un resto suyo se pisa o se borra aquí, y nada fuera de herramientas\capa* se toca
    zip_descargado = p.destino.with_name(p.destino.name + ".zip")
    nueva = p.destino.with_name(p.destino.name + ".parte")
    try:
        shutil.rmtree(nueva, ignore_errors=True)  # restos de un intento anterior
        descargar(p.url, zip_descargado, p.tamano, progreso=progreso)
        descomprimir(zip_descargado, nueva / "reglas")  # trae una carpeta raíz (capa-rules-9.4.0/ con codeload; el zipball de la API la llama mandiant-capa-rules-<sha>/): capa busca los .yml por dentro
        for nombre, tamano, url in firmas_capa(p.version):
            descargar(url, nueva / "sigs" / Path(nombre).name, tamano)  # .name: el nombre viene de una API, que no escape de sigs
        (nueva / "version.txt").write_text(p.version)
        shutil.rmtree(p.destino, ignore_errors=True)  # la versión vieja
        os.replace(nueva, p.destino)
    finally:
        zip_descargado.unlink(missing_ok=True)
        shutil.rmtree(nueva, ignore_errors=True)  # tras el replace ya no existe; si algo falló, no deja el temporal


def instalar_malwarebazaar(p, progreso=None):
    """Baja el volcado CSV de MalwareBazaar y lo deja en el formato local de siempre (listas.en_malwarebazaar): un zip con full_sha256.txt, una SHA-256 por línea
    más las líneas # (traen la fecha). Solo al final sustituye a la copia que hubiera; si algo falla, esa copia sigue intacta."""
    descargado = p.destino.with_name(p.destino.name + ".csv.zip")
    nuevo = p.destino.with_name(p.destino.name + ".nuevo")
    try:
        descargar(p.url, descargado, p.tamano, progreso=progreso)
        try:
            with (zipfile.ZipFile(descargado) as origen, origen.open("full.csv") as csv,
                  zipfile.ZipFile(nuevo, "w", zipfile.ZIP_DEFLATED) as salida, salida.open("full_sha256.txt", "w") as huellas):
                columnas, filas = False, 0
                for linea in csv:  # en streaming: el CSV descomprimido ocupa cientos de MB
                    if linea.startswith(b"#"):
                        columnas = columnas or linea.startswith(b'# "first_seen_utc","sha256_hash"')
                        huellas.write(linea)
                    elif linea.strip():
                        # Mejor fallar que guardar una lista que nunca encuentra nada: sin la línea de columnas no se sabe cuál es cada columna
                        if not columnas:
                            raise OSError("el volcado de MalwareBazaar cambió de formato (una fila antes de la línea de columnas): Argos no sabe leerlo")
                        # La huella es la 2.ª columna; el split corta antes del nombre de fichero (más a la derecha), que puede traer comillas
                        partes = linea.split(b'"', 4)
                        if len(partes) < 4 or len(partes[3]) != 64:
                            raise OSError("el volcado de MalwareBazaar cambió de formato (una fila sin la SHA-256 donde debía): Argos no sabe leerlo")
                        huellas.write(partes[3] + b"\n")
                        filas += 1
            if not filas:  # una lista vacía sustituiría a una buena
                raise OSError("el volcado de MalwareBazaar no trae ninguna fila")
        except (zipfile.BadZipFile, KeyError, EOFError, zlib.error) as error:
            # Un zip cortado no tiene directorio central (está al final) y uno corrupto falla el CRC al leerlo: es lo que da la integridad, porque la descarga no anuncia su tamaño
            raise OSError(f"el volcado de MalwareBazaar está cortado, corrupto o sin full.csv: {error}") from error
        os.replace(nuevo, p.destino)
    finally:
        descargado.unlink(missing_ok=True)
        nuevo.unlink(missing_ok=True)  # tras el replace ya no existe; si algo falló, no deja el temporal


def actualizar(sin_circl=False, pendientes=None, evento=None):
    """Descarga lo pendiente; si el aviso ya lo comprobó, se lo pasa en pendientes y no se vuelve a comprobar.

    Con evento(dict), la ventana recibe las fases (comprobando, descargando, progreso, hecho, al_dia) y aquí no se imprime nada;
    sin evento, imprime igual que siempre la terminal.
    """
    if sin_circl and evento:
        evento({"estado": "mensaje", "texto": "CIRCL: omitido (sin CIRCL)"})
    elif sin_circl:
        print("CIRCL: omitido (--sin-circl)")
    if not clave_abusech():  # comprobar() no pregunta a MalwareBazaar sin clave
        omitida = ("MalwareBazaar: omitido (falta la clave gratuita de abuse.ch: consíguela en https://auth.abuse.ch/ "
                   "y ponla con setx ARGOS_ABUSECH_KEY tu-clave, en una terminal nueva)")
        if evento:
            evento({"estado": "mensaje", "texto": omitida})
        else:
            print(omitida)
    if pendientes is None:
        if evento:
            evento({"estado": "comprobando"})
        pendientes = comprobar(sin_circl)
    if not pendientes:
        if evento:
            evento({"estado": "al_dia"})
        else:
            print("Todo al día.")
        return
    total = len(pendientes)
    for indice, p in enumerate(pendientes):
        if evento:
            evento({"estado": "descargando", "nombre": p.nombre, "motivo": p.motivo, "tamano": p.tamano, "indice": indice, "total": total})
        else:
            print(f"{p.nombre}: descargando {mb(p.tamano)} ({p.motivo})...")

        def progreso(recibidos, tamano, indice=indice, p=p):
            if evento:
                evento({"estado": "progreso", "nombre": p.nombre, "recibidos": recibidos, "tamano": tamano, "indice": indice, "total": total})

        if p.instalador:
            p.instalador(p, progreso)
        else:
            descargar(p.url, p.destino, p.tamano, p.huella, progreso)
            if p.version:
                VERSION_REGLAS.write_text(p.version)  # la última: si algo falla antes, la próxima vez vuelve a descargar
        if evento:
            evento({"estado": "hecho", "nombre": p.nombre, "indice": indice, "total": total})
        else:
            print(f"{p.nombre}: hecho")


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
