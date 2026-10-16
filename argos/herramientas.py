import importlib.util
import json
import subprocess
import sys
from pathlib import Path

CARPETA = Path.home() / "argos-datos" / "herramientas"
# Carpeta de cada herramienta descargada → su ejecutable: la baja «argos actualiza». capa no está: viene con Argos por pip y solo se bajan sus reglas y firmas (datos_capa)
EJECUTABLES = {"die": "diec.exe"}
# Segundos que se le deja a cada una antes de darla por colgada.
# DIE (medido con notepad.exe): 0,8 s en caliente, 26 s la primera vez tras descargarla.
# capa (medido con notepad.exe): 124 s la primera vez, porque construye su caché de reglas, y 89 s en caliente.
# ponytail: 180 s es margen de 1,45x sobre el peor caso medido y un ejecutable grande puede pasarse (saldría «tiempo agotado»). Mejorar: en la interfaz del hito 5, correrlo en segundo plano y sin tope
ESPERA = {"capa": 180, "die": 90}
# Lo que DIE dice del fichero y Argos enseña: tipo en su JSON → etiqueta
TIPOS_DIE = {"compiler": "compilador", "language": "lenguaje", "packer": "empaquetador"}


def ruta(herramienta):
    """El ejecutable de una herramienta descargada, o None si falta. Según el zip queda en una subcarpeta, así que se busca dentro."""
    return next((CARPETA / herramienta).rglob(EJECUTABLES[herramienta]), None)


def datos_capa():
    """(carpeta de reglas, carpeta de firmas) que baja «argos actualiza»; None si faltan. Sin firmas FLIRT capa sale con código 1."""
    carpeta = CARPETA / "capa"
    reglas, firmas = carpeta / "reglas", carpeta / "sigs"
    # La instalación cambia la carpeta entera de golpe (ver actualiza.instalar_capa): o están las dos o ninguna
    return (reglas, firmas) if reglas.is_dir() and firmas.is_dir() else None


def _lanzar(orden, espera):
    """(código de salida, salida, errores) de la orden (lista: programa y argumentos), como proceso aparte y sin shell. TimeoutExpired si tarda más de espera."""
    with subprocess.Popen(
        orden,  # lista y sin shell: la ruta del fichero va como argumento suelto y un nombre raro no puede colar órdenes
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
    ) as proceso:
        try:
            salida, errores = proceso.communicate(timeout=espera)
        except subprocess.TimeoutExpired:
            # /T mata también a los procesos hijos: el python.exe de un venv de Windows es un lanzador que arranca al intérprete real como hijo
            # (medido), y matar solo al lanzador dejaría a capa corriendo
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proceso.pid)], capture_output=True)
            proceso.communicate()
            raise
        return proceso.returncode, salida, errores


def _correr(herramienta, orden, resumir):
    """{"estado": "ok", ...lo que saque resumir del JSON} o, si no se pudo, {"estado": motivo, "detalle": ...}. orden None: falta la herramienta."""
    if orden is None:
        return {"estado": "no disponible", "detalle": ""}
    espera = ESPERA[herramienta]
    try:
        codigo, salida, errores = _lanzar(orden, espera)
    except subprocess.TimeoutExpired:
        return {"estado": "tiempo agotado", "detalle": f"más de {espera} s"}
    except OSError as error:  # ni arranca: p. ej. Windows lo bloquea
        return {"estado": "error", "detalle": f"no se pudo lanzar: {error}"}
    if codigo != 0:
        # DIE cuenta sus errores por la salida normal y capa por la de errores
        ultima_linea = " ".join((errores or salida).strip().splitlines()[-1:])
        return {"estado": "error", "detalle": f"código {codigo}: {ultima_linea}"}
    try:
        return {"estado": "ok", **resumir(json.loads(salida))}
    except (ValueError, KeyError, TypeError):  # no era JSON, o no tenía la forma esperada
        return {"estado": "error", "detalle": "salida inesperada"}


def _resumen_capa(salida):
    """Las capacidades que capa encontró, [(nombre, técnica ATT&CK o "")]: primero las que tienen técnica, y por nombre."""
    capacidades = []
    for regla in salida["rules"].values():
        meta = regla["meta"]
        # Los mismos descartes que hace capa (capa/render/utils.py, capability_rules): reglas de apoyo, internas o de clasificación MAEC
        if meta.get("lib") or meta.get("is_subscope_rule") or (meta.get("namespace") or "").startswith("internal/") or any(meta.get("maec", {}).values()):
            continue
        ataque = meta.get("attack") or []
        tecnica = f"{ataque[0]['id']} {ataque[0]['subtechnique'] or ataque[0]['technique']}" if ataque else ""
        capacidades.append((meta["name"], tecnica))
    # ponytail: «relevantes» = las que tienen técnica ATT&CK, y solo se muestra la primera de cada una. Mejorar: ordenar por táctica
    return {"capacidades": sorted(capacidades, key=lambda c: (c[1] == "", c[0]))}


def _resumen_die(salida):
    """Lo que DIE dice del fichero: {"detectado": {"compilador": [...], "lenguaje": [...], "empaquetador": [...]}}, listas vacías si no detecta nada."""
    resumen = {etiqueta: [] for etiqueta in TIPOS_DIE.values()}
    for deteccion in salida["detects"]:
        for valor in deteccion["values"]:
            if valor["type"] in TIPOS_DIE:
                texto = f"{valor['name']} {valor['version']}".strip() + (f" [{valor['info']}]" if valor["info"] else "")
                resumen[TIPOS_DIE[valor["type"]]].append(texto)
    return {"detectado": resumen}


def capa(fichero):
    """Qué sabe hacer un ejecutable y con qué técnica ATT&CK, según capa (Mandiant). El fichero tiene que estar en el disco."""
    datos = datos_capa()
    if datos is None or importlib.util.find_spec("capa") is None:  # sin reglas y firmas, o sin la librería (falta instalar Argos con pip)
        return _correr("capa", None, _resumen_capa)
    # Como proceso aparte (y no llamando a la librería) para poder cortarlo pasado su tiempo máximo: dentro del mismo proceso no se puede
    # ponytail: sys.executable es el python del venv. En el hito 8 (Argos empaquetado con PyInstaller) será Argos.exe y «-m capa.main» no existirá: habrá que lanzarse a sí mismo con una orden interna
    # -I (aislado): sin él, «-m» busca primero en la carpeta desde la que se lanza Argos, y una carpeta capa\ plantada junto a una muestra
    # se ejecutaría en vez de la librería (comprobado). También ignora las variables PYTHON* y los paquetes del usuario
    return _correr("capa", [sys.executable, "-I", "-m", "capa.main", "-j", "-r", str(datos[0]), "-s", str(datos[1]), str(fichero)], _resumen_capa)


def die(fichero):
    """Compilador, lenguaje y empaquetador de un fichero, según Detect It Easy. El fichero tiene que estar en el disco."""
    exe = ruta("die")
    return _correr("die", None if exe is None else [str(exe), "-j", str(fichero)], _resumen_die)


def analizar(fichero, es_pe):
    """(capa, Detect It Easy) de un fichero que está en el disco. capa solo sirve con ejecutables de Windows (PE)."""
    sin_capa = {"estado": "no aplica", "detalle": "capa solo analiza ejecutables de Windows (PE)"}
    return (capa(fichero) if es_pe else sin_capa), die(fichero)
