import json
import os
import socket
import urllib.error
import urllib.parse
from http.client import HTTPException

from argos import __version__
from argos.actualiza import abrir

# Consulta por huella a tres servicios. Solo sale la SHA-256: el fichero no se envía a ningún sitio
URL_CIRCL = "https://hashlookup.circl.lu/lookup/sha256/{}"  # sin clave
URL_MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"  # Auth-Key gratuita en https://auth.abuse.ch/
URL_VIRUSTOTAL = "https://www.virustotal.com/api/v3/files/{}"  # clave gratuita: 4 consultas por minuto y 500 al día

# ponytail: 10 s es por operación del socket (conectar, cada lectura), no total; las tres consultas van una detrás de otra, así que en el peor caso
# (todo caído) son 30 s por fichero. Lo normal es menos de 1 s por servicio. Mejorar: un hilo por servicio y un plazo total
ESPERA = 10

def _limpio(valor, largo=80):
    """Un texto que viene del servicio, listo para la terminal: sin caracteres de control (un nombre de fichero podría llevar secuencias de escape) y recortado."""
    texto = "".join(c for c in str(valor) if c.isprintable())
    return texto if len(texto) <= largo else texto[: largo - 1] + "…"


def _con(titulo, partes):
    """«titulo (a, b)» solo con las partes que vienen: los servicios no siempre traen todos los campos."""
    partes = [p for p in partes if p]
    return titulo + (f" ({', '.join(partes)})" if partes else "")


def _motivo(error):
    """El motivo corto de un fallo. A propósito no usa str(error): ninguna clave puede acabar en un mensaje."""
    causa = getattr(error, "reason", error)  # URLError guarda la causa real en .reason (casi siempre otra excepción, a veces un texto)
    if not isinstance(causa, Exception):
        causa = error
    if isinstance(causa, TimeoutError):
        return f"sin respuesta en {ESPERA} s"
    if isinstance(causa, socket.gaierror):
        return "no se resuelve el nombre del servidor (¿sin red?)"
    if isinstance(causa, (OSError, HTTPException)):
        return f"sin conexión ({type(causa).__name__})"
    return "respuesta con formato inesperado"  # JSON con otra forma (KeyError, TypeError...)


def _pedir(url, cabeceras=None, datos=None):
    """(código HTTP, JSON o None). Un 4xx o 5xx también es respuesta, y con ellos hablan los servicios; sin respuesta, deja pasar la excepción de la red."""
    cabeceras = {"User-Agent": f"argos/{__version__}", **(cabeceras or {})}
    try:
        with abrir(url, "POST" if datos else "GET", ESPERA, cabeceras, datos) as r:
            codigo, cuerpo = r.status, r.read()
    except urllib.error.HTTPError as error:
        codigo, cuerpo = error.code, error.read()
    try:
        return codigo, json.loads(cuerpo)
    except ValueError:  # no es JSON (ni UTF-8): quien llama decide si le importaba
        return codigo, None


def _fallo(codigo, limite="el servicio limita las consultas (HTTP 429): prueba más tarde"):
    """Lo que no es ni 200 ni 404. El texto sale de aquí y no de lo que conteste el servidor."""
    if codigo == 429:
        return {"estado": "límite", "detalle": limite}
    if codigo in (401, 403):
        return {"estado": "error", "detalle": f"acceso denegado (HTTP {codigo}; ¿clave incorrecta?)"}
    return {"estado": "error", "detalle": f"respuesta inesperada (HTTP {codigo})"}


def circl(sha256, clave):
    codigo, datos = _pedir(URL_CIRCL.format(sha256))
    if codigo == 404:
        return {"estado": "no figura", "detalle": "no figura"}
    if codigo != 200 or not isinstance(datos, dict):
        return _fallo(codigo)
    nombre = _limpio(datos.get("FileName") or "")
    producto = _limpio((datos.get("ProductCode") or {}).get("ProductName") or "")
    conocido = _con("software conocido", [nombre, producto and f"producto: {producto}"])
    # KnownMalicious solo viene si alguna fuente de CIRCL lo marcó (EICAR: malshare.com). Puede venir solo, sin nombre ni producto (un fichero de 4 bytes
    # de texto sale así): entonces no hay software que decir que conocemos. Y puede venir con ellos: EICAR figura también porque venía en una distribución de Linux
    if fuente := datos.get("KnownMalicious"):
        return {"estado": "malware", "detalle": f"MARCADO COMO MALICIOSO por {_limpio(fuente)}" + (f"; figura como {conocido}" if nombre or producto else "")}
    # CIRCL (NSRL) recoge software publicado, no software seguro: conocido no es seguro
    return {"estado": "conocido", "detalle": f"{conocido}; no garantiza que sea seguro"}


def malwarebazaar(sha256, clave):
    codigo, datos = _pedir(URL_MALWAREBAZAAR, {"Auth-Key": clave}, urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode())
    if codigo != 200 or not isinstance(datos, dict):
        return _fallo(codigo)
    estado = datos.get("query_status")
    if estado == "hash_not_found":
        return {"estado": "no figura", "detalle": "no figura"}
    if estado != "ok":
        return {"estado": "error", "detalle": f"respondió {_limpio(estado)}"}
    muestra = datos["data"][0]
    etiquetas = muestra.get("tags")
    detalle = _con("MALWARE CONOCIDO", [
        muestra.get("signature") and f"familia {_limpio(muestra['signature'])}",
        muestra.get("first_seen") and f"vista por primera vez el {_limpio(muestra['first_seen'])}",
        muestra.get("file_type") and f"tipo {_limpio(muestra['file_type'])}",
        etiquetas and "etiquetas: " + ", ".join(_limpio(e) for e in etiquetas),
    ])
    return {"estado": "malware", "detalle": detalle}


def virustotal(sha256, clave):
    codigo, datos = _pedir(URL_VIRUSTOTAL.format(sha256), {"x-apikey": clave})
    if codigo == 404:
        return {"estado": "no figura", "detalle": "no figura"}
    if codigo != 200 or not isinstance(datos, dict):
        return _fallo(codigo, "límite de la cuota gratuita (4 consultas por minuto y 500 al día): espera un poco o usa --sin-red")
    atributos = datos["data"]["attributes"]
    cuenta = atributos["last_analysis_stats"]
    malos, sospechosos = cuenta.get("malicious", 0), cuenta.get("suspicious", 0)
    # M son los motores que llegaron a analizar: sin los que dieron tiempo agotado, fallo o «tipo no soportado»
    total = malos + sospechosos + cuenta.get("undetected", 0) + cuenta.get("harmless", 0)
    if not total:
        return {"estado": "conocido", "detalle": "figura, pero todavía sin análisis de ningún motor"}
    etiqueta = (atributos.get("popular_threat_classification") or {}).get("suggested_threat_label")
    detalle = _con(f"{malos} de {total} motores lo detectan", [
        sospechosos and f"{sospechosos} más lo ven sospechoso",
        etiqueta and f"etiqueta sugerida: {_limpio(etiqueta)}",
    ])
    if not malos:
        detalle += "; no garantiza que sea seguro"
    return {"estado": "malware" if malos else "conocido", "detalle": detalle}


# (nombre, función, variable de entorno de la clave, cómo conseguirla); el orden es el del informe
SERVICIOS = (
    ("CIRCL", circl, None, None),
    ("MalwareBazaar", malwarebazaar, "ARGOS_ABUSECH_KEY", "consíguela gratis en https://auth.abuse.ch/"),
    ("VirusTotal", virustotal, "ARGOS_VT_KEY", "cuenta gratuita en https://www.virustotal.com/, la clave está en tu perfil"),
)


def consultar(sha256):
    """{servicio: {"estado": conocido | malware | no figura | sin clave | límite | error, "detalle": el texto para el informe}}, en el orden de SERVICIOS.
    Nunca lanza una excepción ni lleva una clave en ningún texto. Un servicio sin clave no recibe ninguna petición."""
    resultados = {}
    for nombre, consulta, variable, como in SERVICIOS:
        clave = (os.environ.get(variable) or "").strip() if variable else None
        if variable and not clave:
            resultados[nombre] = {"estado": "sin clave", "detalle": f"sin clave ({como}; ponla con setx {variable} tu-clave, en una terminal nueva)"}
            continue
        try:
            resultado = consulta(sha256, clave)
        except Exception as error:  # sin red, DNS, tiempo agotado, JSON raro...: la consulta nunca debe romper el análisis
            resultado = {"estado": "error", "detalle": _motivo(error)}
        if clave:  # por si un servicio devolviera la clave en un texto suyo
            resultado["detalle"] = resultado["detalle"].replace(clave, "***")
        resultados[nombre] = resultado
    return resultados
