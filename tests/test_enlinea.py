# Se lanza con: python tests/test_enlinea.py (no usa la red: la función que abre las URLs es una falsa que devuelve los códigos y cuerpos de cada caso)
import contextlib
import hashlib
import http.client
import io
import json
import os
import socket
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import pyzipper

from argos import __main__ as principal
from argos import __version__, actualiza, analisis, enlinea, identificacion

CLAVE_MB, CLAVE_VT = "clave-secreta-mb-1234", "clave-secreta-vt-5678"
HUELLA = "ab" * 32
for variable in ("ARGOS_ABUSECH_KEY", "ARGOS_VT_KEY"):  # lo que haya en tu entorno no cuenta: cada caso pone lo suyo
    os.environ.pop(variable, None)

peticiones = []  # (url, método, cabeceras, datos) de cada petición que «sale»
respuestas = {}  # "hashlookup" | "mb-api" | "virustotal" → (código, cuerpo) o una excepción que lanzar


class SeLlamo(BaseException):
    """BaseException a propósito: consultar() se traga las Exception, y esto tiene que reventar el test si alguien pide algo."""


class Respuesta:
    def __init__(self, codigo, cuerpo):
        self.status, self.cuerpo = codigo, cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.cuerpo


def abrir_falso(url, metodo="GET", espera=None, cabeceras=None, datos=None):
    peticiones.append((url, metodo, cabeceras, datos))
    respuesta = respuestas[next(s for s in ("hashlookup", "mb-api", "virustotal") if s in url)]
    if isinstance(respuesta, BaseException):
        raise respuesta
    codigo, cuerpo = respuesta
    if not isinstance(cuerpo, bytes):
        cuerpo = (cuerpo if isinstance(cuerpo, str) else json.dumps(cuerpo)).encode()
    if codigo >= 400:  # como urllib: los 4xx y 5xx son una excepción que lleva el cuerpo
        raise urllib.error.HTTPError(url, codigo, "x", {}, io.BytesIO(cuerpo))
    return Respuesta(codigo, cuerpo)


def abrir_prohibido(*args, **kwargs):
    raise SeLlamo(f"no debía pedirse nada: {args}")


enlinea.abrir = abrir_falso
SERVICIOS = ["CIRCL", "MalwareBazaar", "VirusTotal"]
NO_FIGURA = {"circl": (404, {"message": "Non existing SHA-256"}), "mb": (200, {"query_status": "hash_not_found"}), "vt": (404, {"error": {"code": "NotFoundError"}})}


def consultar(claves=(CLAVE_MB, CLAVE_VT), **respuesta):
    """consultar(HUELLA) con las claves puestas (None: sin poner) y lo que contesta cada servicio (por defecto, «no figura»)."""
    for variable, clave in zip(("ARGOS_ABUSECH_KEY", "ARGOS_VT_KEY"), claves):
        if clave is None:
            os.environ.pop(variable, None)
        else:
            os.environ[variable] = clave
    caso = NO_FIGURA | respuesta
    respuestas.update({"hashlookup": caso["circl"], "mb-api": caso["mb"], "virustotal": caso["vt"]})
    peticiones.clear()
    resultado = enlinea.consultar(HUELLA)
    assert list(resultado) == SERVICIOS  # siempre los tres, en este orden
    for r in resultado.values():
        assert set(r) == {"estado", "detalle"} and isinstance(r["detalle"], str)
        assert CLAVE_MB not in r["detalle"] + r["estado"] and CLAVE_VT not in r["detalle"] + r["estado"]  # la clave no sale en ningún texto
    return resultado


def estado(servicio, **respuesta):
    return consultar(**respuesta)[servicio]


# 1. La forma de las peticiones: HTTPS, solo la huella, el User-Agent de Argos y la clave en la cabecera de cada servicio (y CIRCL sin ninguna)
consultar()
assert [(u, m) for u, m, _, _ in peticiones] == [
    (f"https://hashlookup.circl.lu/lookup/sha256/{HUELLA}", "GET"),
    ("https://mb-api.abuse.ch/api/v1/", "POST"),
    (f"https://www.virustotal.com/api/v3/files/{HUELLA}", "GET"),
], peticiones
circl_c, mb_c, vt_c = (c for _, _, c, _ in peticiones)
assert circl_c == {"User-Agent": f"argos/{__version__}"}
assert mb_c == {"User-Agent": f"argos/{__version__}", "Auth-Key": CLAVE_MB}
assert vt_c == {"User-Agent": f"argos/{__version__}", "x-apikey": CLAVE_VT}
assert [d for _, _, _, d in peticiones] == [None, f"query=get_info&hash={HUELLA}".encode(), None]  # el formulario de MalwareBazaar: solo la consulta y la huella

# 2. CIRCL: no figura, conocido (con o sin nombre y producto), marcado como malicioso, límite y errores
assert estado("CIRCL") == {"estado": "no figura", "detalle": "no figura"}
r = estado("CIRCL", circl=(200, {"FileName": "bloc.exe", "ProductCode": {"ProductName": "Windows 11"}, "SHA-256": HUELLA}))
assert r == {"estado": "conocido", "detalle": "software conocido (bloc.exe, producto: Windows 11); no garantiza que sea seguro"}, r
r = estado("CIRCL", circl=(200, {"SHA-256": HUELLA}))
assert r == {"estado": "conocido", "detalle": "software conocido; no garantiza que sea seguro"}, r
r = estado("CIRCL", circl=(200, {"FileName": "muestra.bin", "ProductCode": {"ProductName": "Distro"}, "KnownMalicious": "ejemplo.org"}))
assert r["estado"] == "malware" and r["detalle"].startswith("MARCADO COMO MALICIOSO por ejemplo.org;") and "muestra.bin" in r["detalle"], r
r = estado("CIRCL", circl=(200, {"KnownMalicious": "ejemplo.org", "SHA-256": HUELLA}))  # solo la marca, sin nada de software: no inventa que sea software conocido
assert r == {"estado": "malware", "detalle": "MARCADO COMO MALICIOSO por ejemplo.org"}, r
r = estado("CIRCL", circl=(200, {"FileName": "\x1b[31mrojo\x07.exe"}))  # un nombre con secuencias de escape no llega a la terminal
assert "\x1b" not in r["detalle"] and "\x07" not in r["detalle"] and "rojo" in r["detalle"], r
assert estado("CIRCL", circl=(429, {}))["estado"] == "límite"
r = estado("CIRCL", circl=(500, "<html>caído</html>"))
assert r == {"estado": "error", "detalle": "respuesta inesperada (HTTP 500)"}, r
assert estado("CIRCL", circl=(400, {"message": "SHA-256 value incorrect"}))["detalle"] == "respuesta inesperada (HTTP 400)"

# 3. MalwareBazaar: malware conocido, no figura, otro estado, y lo que sea que no encaje
ok = {"query_status": "ok", "data": [{"signature": "RevengeRAT", "first_seen": "2020-03-01 05:57:01", "file_type": "exe", "tags": ["revengerat", "rat"]}]}
r = estado("MalwareBazaar", mb=(200, ok))
assert r == {"estado": "malware", "detalle": "MALWARE CONOCIDO (familia RevengeRAT, vista por primera vez el 2020-03-01 05:57:01, tipo exe, etiquetas: revengerat, rat)"}, r
sin_familia = {"query_status": "ok", "data": [{"signature": None, "first_seen": "2020-03-01 05:57:01", "file_type": "exe", "tags": None}]}
r = estado("MalwareBazaar", mb=(200, sin_familia))
assert r["estado"] == "malware" and r["detalle"] == "MALWARE CONOCIDO (vista por primera vez el 2020-03-01 05:57:01, tipo exe)", r
assert estado("MalwareBazaar") == {"estado": "no figura", "detalle": "no figura"}
r = estado("MalwareBazaar", mb=(200, {"query_status": "illegal_hash"}))
assert r == {"estado": "error", "detalle": "respondió illegal_hash"}, r
for raro in ({"query_status": "ok"}, {"query_status": "ok", "data": []}, {"query_status": "ok", "data": "x"}, {"nada": 1}, []):
    r = estado("MalwareBazaar", mb=(200, raro))
    assert r["estado"] == "error", (raro, r)
r = estado("MalwareBazaar", mb=(401, {"error": "Unauthorized"}))  # la clave puesta no vale (sin clave ni se pregunta)
assert r == {"estado": "error", "detalle": "acceso denegado (HTTP 401; ¿clave incorrecta?)"}, r
assert estado("MalwareBazaar", mb=(429, {}))["estado"] == "límite"

# 4. VirusTotal: «N de M motores» (M sin timeouts, fallos ni tipos no soportados), la etiqueta sugerida, limpio, sin analizar, no figura, límite y errores
def respuesta_vt(malicious, suspicious, undetected, harmless, etiqueta=None, **otros):
    atributos = {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "undetected": undetected, "harmless": harmless, **otros}}
    if etiqueta:
        atributos["popular_threat_classification"] = {"suggested_threat_label": etiqueta, "popular_threat_name": [{"value": "emotet", "count": 9}]}
    return 200, {"data": {"attributes": atributos}}


r = estado("VirusTotal", vt=respuesta_vt(3, 1, 60, 6, "trojan.emotet", timeout=2, **{"type-unsupported": 5}))
assert r == {"estado": "malware", "detalle": "3 de 70 motores lo detectan (1 más lo ven sospechoso, etiqueta sugerida: trojan.emotet)"}, r
r = estado("VirusTotal", vt=respuesta_vt(1, 0, 60, 9))
assert r == {"estado": "malware", "detalle": "1 de 70 motores lo detectan"}, r
r = estado("VirusTotal", vt=respuesta_vt(0, 0, 60, 10))
assert r == {"estado": "conocido", "detalle": "0 de 70 motores lo detectan; no garantiza que sea seguro"}, r
r = estado("VirusTotal", vt=respuesta_vt(0, 0, 0, 0, timeout=4))
assert r["estado"] == "conocido" and "sin análisis" in r["detalle"], r
assert estado("VirusTotal") == {"estado": "no figura", "detalle": "no figura"}
r = estado("VirusTotal", vt=(429, {"error": {"code": "QuotaExceededError"}}))
assert r["estado"] == "límite" and "4 consultas por minuto" in r["detalle"] and "500 al día" in r["detalle"], r
assert estado("VirusTotal", vt=(401, {"error": {"code": "WrongCredentialsError"}}))["detalle"] == "acceso denegado (HTTP 401; ¿clave incorrecta?)"
for raro in ({"data": {}}, {"data": {"attributes": {}}}, {"data": []}, {"nada": 1}, []):
    r = estado("VirusTotal", vt=(200, raro))
    assert r["estado"] == "error", (raro, r)

# 5. Sin red, DNS, tiempo agotado, corte a medias, JSON roto: «error» con un motivo corto, en cada servicio, sin excepción ni traza
fallos = [
    ("no se resuelve el nombre del servidor (¿sin red?)", urllib.error.URLError(socket.gaierror(11001, "getaddrinfo failed"))),
    ("sin respuesta en 10 s", urllib.error.URLError(TimeoutError("timed out"))),
    ("sin respuesta en 10 s", TimeoutError("timed out")),  # el de leer el cuerpo: no viene envuelto en URLError
    ("sin conexión (ConnectionResetError)", ConnectionResetError(10054, "reset")),
    ("sin conexión (IncompleteRead)", http.client.IncompleteRead(b"par")),
    ("sin conexión (URLError)", urllib.error.URLError("unknown url type")),  # URLError con un texto y no una excepción en .reason
    ("respuesta con formato inesperado", RuntimeError("cualquier otra cosa")),
]
for esperado, fallo in fallos:
    for servicio, clave in (("CIRCL", "circl"), ("MalwareBazaar", "mb"), ("VirusTotal", "vt")):
        r = estado(servicio, **{clave: fallo})
        assert r == {"estado": "error", "detalle": esperado}, (servicio, r)
for cuerpo in ("esto no es JSON", b"\xff\xfe\x00", "", "null", "[1, 2]"):  # un 200 cuyo cuerpo no vale
    for servicio, clave in (("CIRCL", "circl"), ("MalwareBazaar", "mb"), ("VirusTotal", "vt")):
        r = estado(servicio, **{clave: (200, cuerpo)})
        assert r == {"estado": "error", "detalle": "respuesta inesperada (HTTP 200)"}, (servicio, cuerpo, r)
# Un fallo de un servicio no tapa a los demás
resultado = consultar(circl=urllib.error.URLError("sin red"), vt=respuesta_vt(2, 0, 60, 8))
assert [r["estado"] for r in resultado.values()] == ["error", "no figura", "malware"]

# 6. Sin clave no se hace la petición de ese servicio: dice cómo conseguirla y cómo ponerla; una clave vacía o en blanco también es «sin clave»
resultado = consultar(claves=(None, CLAVE_VT))
assert [url for url, *_ in peticiones if "mb-api" in url] == [] and len(peticiones) == 2
r = resultado["MalwareBazaar"]
assert r["estado"] == "sin clave" and "https://auth.abuse.ch/" in r["detalle"] and "setx ARGOS_ABUSECH_KEY" in r["detalle"] and "terminal nueva" in r["detalle"], r
resultado = consultar(claves=(CLAVE_MB, None))
assert [url for url, *_ in peticiones if "virustotal" in url] == [] and len(peticiones) == 2
r = resultado["VirusTotal"]
assert r["estado"] == "sin clave" and "https://www.virustotal.com/" in r["detalle"] and "perfil" in r["detalle"] and "setx ARGOS_VT_KEY" in r["detalle"], r
resultado = consultar(claves=("", "   "))
assert [url for url, *_ in peticiones] == [f"https://hashlookup.circl.lu/lookup/sha256/{HUELLA}"]  # solo CIRCL, que no pide clave
assert [r["estado"] for r in resultado.values()] == ["no figura", "sin clave", "sin clave"]

# 7. La clave no sale en ningún texto (consultar() ya lo comprueba en cada caso de arriba): ni con un servidor que la repita, ni con un error que la lleve dentro
eco = {"query_status": f"rara {CLAVE_MB}"}
r = estado("MalwareBazaar", mb=(200, eco))
assert r["estado"] == "error" and "***" in r["detalle"], r
r = estado("MalwareBazaar", mb=ValueError(f"Invalid header value b'{CLAVE_MB}\\n'"))  # lo que lanza http.client con una clave mal copiada
assert r == {"estado": "error", "detalle": "respuesta con formato inesperado"}, r
r = estado("VirusTotal", vt=urllib.error.URLError(f"fallo con {CLAVE_VT}"))
assert r == {"estado": "error", "detalle": "sin conexión (URLError)"}, r

# 8. actualiza.abrir (la que usa en producción) pasa bien las cabeceras y el formulario, y sigue igual para los demás: GET sin cuerpo ni cabeceras
pedidas = []
urlopen_real = urllib.request.urlopen
urllib.request.urlopen = lambda req, timeout=None: pedidas.append((req, timeout))
try:
    actualiza.abrir("https://ejemplo.test/a", "POST", 7, {"Auth-Key": "k"}, b"x=1")
    actualiza.abrir("https://ejemplo.test/b")
finally:
    urllib.request.urlopen = urlopen_real
(post, espera_post), (get, espera_get) = pedidas
assert (post.get_method(), post.data, post.get_header("Auth-key"), espera_post) == ("POST", b"x=1", "k", 7)
assert (get.get_method(), get.data, get.header_items(), espera_get) == ("GET", None, [], actualiza.ESPERA)

# 9. En el informe de «identifica»: con --sin-red no sale ninguna petición; sin él, sección propia tras «Listas:» con la misma sangría, también por cada miembro de un zip
def ficha(nombre):
    return {"sha256": hashlib.sha256(nombre.encode()).hexdigest(), "sha1": "0" * 40, "bytes": 3, "tipo": "texto", "extension_engana": False,
            "extensiones_esperadas": [], "malwarebazaar": None, "circl": None}


tmp = Path(tempfile.mkdtemp(prefix="argos-test-enlinea-"))
with pyzipper.AESZipFile(tmp / "m.zip", "w", encryption=pyzipper.WZ_AES) as z:
    z.setpassword(b"infected")
    z.writestr("uno.txt", b"1")
    z.writestr("dos.txt", b"2")
principal.avisar = lambda: None  # el aviso de datos nuevos es otro asunto (test_aviso)
identificacion.identificar = lambda ruta: ficha("suelto")
identificacion.identificar_datos = lambda datos, nombre, magika: ficha(nombre)
analisis.Magika = lambda: None  # no hace falta el modelo de Magika: la ficha es falsa


def lanzar(*opciones):
    sys.argv = ["argos", "identifica", *opciones]
    salida = io.StringIO()
    with contextlib.redirect_stdout(salida):
        principal.main()
    return salida.getvalue()


try:
    enlinea.abrir = abrir_prohibido
    for opciones, miembros in (((__file__, "--sin-red"), 1), ((str(tmp / "m.zip"), "--clave", "infected", "--sin-red"), 2)):
        salida = lanzar(*opciones)
        assert salida.count("En línea: omitido (--sin-red)") == miembros, salida
        assert "En línea (" not in salida and "Listas:  MalwareBazaar" in salida
    enlinea.abrir = abrir_falso

    os.environ.pop("ARGOS_ABUSECH_KEY", None)
    os.environ.pop("ARGOS_VT_KEY", None)
    respuestas["hashlookup"] = NO_FIGURA["circl"]
    peticiones.clear()
    salida = lanzar(__file__)
    esperado = (
        "En línea (solo sale la huella, nunca el fichero):\n"
        "         CIRCL: no figura\n"
        "         MalwareBazaar: sin clave ("
    )
    assert esperado in salida and "         VirusTotal: sin clave (" in salida, salida
    assert salida.index("Listas:") < salida.index("En línea (")  # la sección va tras las listas
    assert [u for u, *_ in peticiones] == [f"https://hashlookup.circl.lu/lookup/sha256/{ficha('suelto')['sha256']}"]

    peticiones.clear()
    salida = lanzar(str(tmp / "m.zip"), "--clave", "infected")  # una consulta por miembro, cada una con la huella de su miembro
    assert [u.rsplit("/", 1)[1] for u, *_ in peticiones] == [ficha("uno.txt")["sha256"], ficha("dos.txt")["sha256"]]
    assert salida.count("En línea (solo sale la huella, nunca el fichero):") == 2
finally:
    enlinea.abrir = abrir_falso
    for hijo in tmp.iterdir():
        hijo.unlink()
    tmp.rmdir()

print("OK")
