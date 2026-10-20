# Se lanza con: python tests/test_herramientas.py (las partes 1 a 5 no necesitan nada; la 6 necesita Detect It Easy y las reglas y firmas
# de capa descargadas con «argos actualiza», y usa notepad.exe del propio Windows: capa de verdad tarda ~1,5 minutos, así que no te asustes.
# No usa la red ni escribe en tu argos-datos)
import atexit
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

import capa.version as version_capa

from argos import actualiza, estatico, herramientas
from argos.__main__ import texto_capa, texto_die
from argos.actualiza import Pendiente

notepad = r"C:\Windows\System32\notepad.exe"
carpeta_real = herramientas.CARPETA
tmp = Path(tempfile.mkdtemp(prefix="argos-test-herramientas-"))
atexit.register(shutil.rmtree, tmp, ignore_errors=True)  # se borra aunque el test falle


def zip_con(nombre_zip, miembros):
    ruta = tmp / nombre_zip
    with zipfile.ZipFile(ruta, "w") as z:
        for nombre, contenido in miembros.items():
            z.writestr(nombre, contenido)
    return ruta


# 1. El nombre de zip que se busca en GitHub encaja con el real y con ningún otro asset; capa no lo necesita: sus reglas salen del tag de la librería
assert re.fullmatch(actualiza.ZIP_DIE, "die_win64_portable_3.21_x64.zip") and not re.fullmatch(actualiza.ZIP_DIE, "die_lin64_portable_3.21_x64.zip")

# 2. Descomprimir: un zip normal se extrae; uno con una ruta fuera de su carpeta ("../escape.txt") no extrae NADA
descomprimir_ok = zip_con("ok.zip", {"die/diec.exe": "x", "die/db/a.sg": "y"})
actualiza.descomprimir(descomprimir_ok, tmp / "ok")
assert (tmp / "ok" / "die" / "diec.exe").is_file()
malo = zip_con("malo.zip", {"die/diec.exe": "x", "../escape.txt": "fuera"})
try:
    actualiza.descomprimir(malo, tmp / "malo")
    raise AssertionError("debía negarse a extraer un zip con una ruta fuera de su carpeta")
except OSError as error:
    assert "escape.txt" in str(error)
assert not (tmp / "malo").exists() and not (tmp / "escape.txt").exists()

# 2b. Lo que se saca del JSON de capa y de DIE, con la forma que dan en sus versiones 9.4.0 y 3.21 (capa: capa/render/result_document.py)
def regla(nombre, namespace=None, lib=False, maec=None, ataque=None):
    meta = {"name": nombre, "lib": lib, "is_subscope_rule": False, "maec": maec or {}, "attack": ataque or []}
    return {"meta": meta | ({"namespace": namespace} if namespace else {}), "source": "", "matches": []}


tecnica = {"parts": ["Execution", "Shared Modules"], "tactic": "Execution", "technique": "Shared Modules", "subtechnique": "", "id": "T1129"}
subtecnica = {"parts": ["Defense Evasion", "Process Injection", "Thread Execution Hijacking"], "tactic": "Defense Evasion",
              "technique": "Process Injection", "subtechnique": "Thread Execution Hijacking", "id": "T1055.003"}
de_capa = {"meta": {}, "rules": {
    "contain loop": regla("contain loop"),
    "link function at runtime": regla("link function at runtime", "linking/runtime-linking", ataque=[tecnica]),
    "hijack thread": regla("hijack thread", "host-interaction/process/inject", ataque=[subtecnica]),
    "ayuda": regla("ayuda", lib=True, ataque=[tecnica]),  # de apoyo: capa no la cuenta
    "interna": regla("interna", "internal/limitation/file", ataque=[tecnica]),
    "clasificacion": regla("clasificacion", maec={"malware_family": "algo"}),
}}
assert herramientas._resumen_capa(de_capa)["capacidades"] == [
    ("hijack thread", "T1055.003 Thread Execution Hijacking"), ("link function at runtime", "T1129 Shared Modules"), ("contain loop", ""),
]
assert herramientas._resumen_capa({"meta": {}, "rules": {}}) == {"capacidades": []}
valor = {"info": "LTCG/C", "name": "Microsoft Visual C/C++", "string": "", "type": "compiler", "version": "19.38.33145"}
de_die = {"detects": [{"filetype": "PE64", "values": [valor, {**valor, "type": "linker", "name": "Microsoft Linker"}, {**valor, "type": "packer", "name": "UPX", "version": "", "info": ""}]}]}
assert herramientas._resumen_die(de_die)["detectado"] == {"compilador": ["Microsoft Visual C/C++ 19.38.33145 [LTCG/C]"], "lenguaje": [], "empaquetador": ["UPX"]}
assert texto_die(herramientas._resumen_die(de_die)) == "compilador: Microsoft Visual C/C++ 19.38.33145 [LTCG/C]; empaquetador: UPX"
assert texto_die({"detectado": {"compilador": [], "lenguaje": [], "empaquetador": []}}) == "no detecta compilador, lenguaje ni empaquetador"
cinco = {"capacidades": [(f"cap {i}", f"T{i}" if i < 4 else "") for i in range(5)]}
assert texto_capa(cinco) == "5 (cap 0 [T0], cap 1 [T1], cap 2 [T2], y 2 más)" and texto_capa({"capacidades": []}) == "ninguna"

# capa() de principio a fin con lo que sacaría capa simulado (el proceso no se lanza): bien, con error (código 16 = no es un PE) y con basura
ruta_real, lanzar_real, datos_real = herramientas.ruta, herramientas._lanzar, herramientas.datos_capa
ordenes = []  # lo que se habría lanzado


def lanzar_falso(resultado):
    def lanzar(orden, espera):
        ordenes.append(orden)
        return resultado
    return lanzar


herramientas.datos_capa = lambda: (Path("reglas"), Path("sigs"))
herramientas._lanzar = lanzar_falso((0, json.dumps(de_capa), ""))
assert herramientas.capa(notepad)["capacidades"][0] == ("hijack thread", "T1055.003 Thread Execution Hijacking")
# La orden es la de capa como módulo del mismo Python, con reglas y firmas (sin firmas capa sale con código 1) y el fichero como argumento suelto
assert ordenes == [[sys.executable, "-I", "-m", "capa.main", "-j", "-r", "reglas", "-s", "sigs", notepad]], ordenes
herramientas._lanzar = lanzar_falso((16, "", "ERROR: input file does not appear to be a PE file\n"))
assert herramientas.capa(notepad) == {"estado": "error", "detalle": "código 16: ERROR: input file does not appear to be a PE file"}
herramientas._lanzar = lanzar_falso((0, "esto no es JSON", ""))
assert herramientas.capa(notepad) == {"estado": "error", "detalle": "salida inesperada"}
# Sin reglas o firmas descargadas: «no disponible» y ni se lanza
ordenes.clear()
herramientas.datos_capa = lambda: None
assert herramientas.capa(notepad) == {"estado": "no disponible", "detalle": ""} and not ordenes
# DIE sigue con su ejecutable: «diec.exe -j fichero»
herramientas.ruta = lambda herramienta: Path("diec-falso.exe")
herramientas._lanzar = lanzar_falso((0, json.dumps(de_die), ""))
assert herramientas.die(notepad)["detectado"]["empaquetador"] == ["UPX"] and ordenes == [["diec-falso.exe", "-j", notepad]], ordenes
herramientas.ruta, herramientas._lanzar, herramientas.datos_capa = ruta_real, lanzar_real, datos_real

# 2b2. cortar(): cerrar la ventana corta lo que _lanzar tiene en marcha (un python inofensivo que duerme 60 s, como si fuera capa), con sus procesos hijos
# (el python.exe de un venv es un lanzador que arranca al intérprete real como hijo), y a partir de ahí no se lanza nada más
hijos_de = lambda pid: [int(p) for p in subprocess.run(
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", f"(Get-CimInstance Win32_Process -Filter 'ParentProcessId={pid}').ProcessId"],
    capture_output=True, text=True, timeout=60).stdout.split()]
vive = lambda pid: f'"{pid}"' in subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=30).stdout
dormir = [sys.executable, "-c", "import time; time.sleep(60)"]
assert herramientas._en_marcha == set() and herramientas._cortado is False
salida_lanzar = []
hilo_lanzar = threading.Thread(target=lambda: salida_lanzar.append(herramientas._lanzar(dormir, 120)), daemon=True)
hilo_lanzar.start()
limite = time.monotonic() + 15
while not herramientas._en_marcha and time.monotonic() < limite:
    time.sleep(0.05)
(en_marcha,) = herramientas._en_marcha
pids = [en_marcha.pid]
while not hijos_de(en_marcha.pid) and time.monotonic() < limite:  # a los hijos les cuesta un poco aparecer
    time.sleep(0.2)
pids += hijos_de(en_marcha.pid)
assert all(vive(pid) for pid in pids), pids
inicio = time.monotonic()
herramientas.cortar()
hilo_lanzar.join(15)
assert not hilo_lanzar.is_alive() and time.monotonic() - inicio < 15, "_lanzar no volvió tras cortar()"  # volvió mucho antes de los 60 s (y de los 120 de espera)
assert salida_lanzar and salida_lanzar[0][0] != 0, salida_lanzar  # taskkill /F lo termina con código distinto de 0
assert herramientas._en_marcha == set()
assert not any(vive(pid) for pid in pids), [pid for pid in pids if vive(pid)]  # ni el lanzador ni su hijo
try:
    herramientas._lanzar(dormir, 5)
    raise AssertionError("tras cortar() no debía lanzarse nada")
except OSError as error:
    assert "cerrando" in str(error), error
assert herramientas._en_marcha == set()
# y las herramientas lo cuentan como un fallo normal (el análisis que sigue vivo en su hilo termina rápido y sin lanzar nada)
assert herramientas._correr("capa", dormir, lambda salida: {}) == {"estado": "error", "detalle": "no se pudo lanzar: Argos se está cerrando"}
herramientas._cortado = False  # solo para que el resto de las pruebas puedan lanzar procesos
print(f"cortar(): {len(pids)} procesos (lanzador e intérprete) muertos en {time.monotonic() - inicio:.1f} s")

# 2c.Un fichero que viene de un zip necesita copia en disco: con el envío automático de muestras activado (1 o 3) no se escribe NADA
# y capa y DIE lo dicen; si Defender bloquea la copia, también lo dicen en vez de fallar
crear_carpeta = tempfile.TemporaryDirectory


def no_escribir(*args, **kwargs):
    raise AssertionError("con el envío automático activado no se debe escribir nada en el disco")


tempfile.TemporaryDirectory = no_escribir
for valor in (1, 3):
    estatico.consentimiento_muestras = lambda: valor
    antivirus, firma, capa, die = estatico.analizar_copia(b"x", "x.exe", True)
    assert antivirus["estado"] == "omitido" and firma is None
    assert capa == die == {"estado": "no aplicado", "detalle": "Argos no escribe la muestra en disco con el envío automático de muestras activado"}
tempfile.TemporaryDirectory = crear_carpeta
estatico.consentimiento_muestras = lambda: 2
leer = Path.read_bytes


def bloqueado(self):
    raise PermissionError("Defender bloqueó el fichero")


Path.read_bytes = bloqueado  # lo mismo que ve Argos cuando Defender borra o bloquea la copia nada más escribirla
antivirus, firma, capa, die = estatico.analizar_copia(b"x", "x.exe", True)
Path.read_bytes = leer
assert antivirus["estado"] == "DETECTADO" and capa == die == {"estado": "no aplicado", "detalle": "Defender bloqueó la copia de la muestra"}
assert not list(Path(tempfile.gettempdir()).glob("argos-defender-*"))

# 3. Instalar (con un file:// en vez de GitHub): deja la carpeta con su versión anotada y sin restos; si falla, la copia vieja sigue intacta
herramientas.CARPETA = tmp / "herramientas"
carpeta = herramientas.CARPETA / "die"
buena = zip_con("buena.zip", {"die/diec.exe": "x"})
actualiza.instalar(Pendiente("die 1.0", "no hay copia", buena.stat().st_size, buena.as_uri(), carpeta, "1.0", actualiza.instalar))
assert (carpeta / "die" / "diec.exe").is_file() and (carpeta / "version.txt").read_text() == "1.0"
assert herramientas.ruta("die") == carpeta / "die" / "diec.exe"
assert sorted(p.name for p in herramientas.CARPETA.iterdir()) == ["die"]  # ni .zip ni .parte
try:
    actualiza.instalar(Pendiente("die 2.0", "x", malo.stat().st_size, malo.as_uri(), carpeta, "2.0", actualiza.instalar))
    raise AssertionError("debía fallar con el zip malo")
except OSError:
    pass
assert (carpeta / "version.txt").read_text() == "1.0" and sorted(p.name for p in herramientas.CARPETA.iterdir()) == ["die"]

# 3b. Instalar capa (con file:// en vez de GitHub: zip de reglas y firmas falsos). Antes, restos de la vía antigua (capa.exe descargado y su zip)
# y algo ajeno en la misma carpeta: la nueva instalación sustituye lo de capa* y no toca lo demás
version_real = version_capa.__version__
version_capa.__version__ = "1.2.3"  # la versión de la librería instalada es lo que decide qué reglas toca bajar
capa_dir = herramientas.CARPETA / "capa"
capa_dir.mkdir()
(capa_dir / "capa.exe").write_text("viejo")
(capa_dir / "version.txt").write_text("v1.2.3")  # la misma versión: lo que delata la copia vieja es que no tiene reglas ni firmas
(herramientas.CARPETA / "capa.zip").write_text("zip viejo")
(herramientas.CARPETA / "capa.zip.parte").write_text("a medias")
(herramientas.CARPETA / "capa.parte").mkdir()
(herramientas.CARPETA / "capa.parte" / "x").write_text("a medias")
(herramientas.CARPETA / "otro.zip").write_text("no es de capa")
pendiente = actualiza.pendiente_capa()
assert pendiente.motivo == "no hay copia" and pendiente.nombre == "reglas y firmas de capa v1.2.3" and pendiente.tamano is None
assert pendiente.url == "https://codeload.github.com/mandiant/capa-rules/zip/refs/tags/v1.2.3" and pendiente.destino == capa_dir
assert pendiente.version == "v1.2.3" and pendiente.instalador is actualiza.instalar_capa
assert actualiza.mb(None) == "tamaño sin anunciar" and actualiza.mb(1_500_000) == "1,5 MB"
reglas_zip = zip_con("reglas.zip", {"mandiant-capa-rules-abc123/a.yml": "rule", "mandiant-capa-rules-abc123/.github/ci.yml": "x"})
firmas = {"1.sig": b"uno", "2.sig": b"dos dos"}
for nombre, contenido in firmas.items():
    (tmp / nombre).write_bytes(contenido)
pedidas = []
actualiza.firmas_capa = lambda version: pedidas.append(version) or [(n, len(c), (tmp / n).as_uri()) for n, c in firmas.items()]
actualiza.instalar_capa(pendiente._replace(url=reglas_zip.as_uri()))  # el zip real no anuncia tamaño: tamano None, como aquí
assert pedidas == ["v1.2.3"]  # las firmas se piden al mismo tag
assert (capa_dir / "version.txt").read_text() == "v1.2.3" and not (capa_dir / "capa.exe").exists()
assert (capa_dir / "reglas" / "mandiant-capa-rules-abc123" / "a.yml").read_text() == "rule"
assert {f.name: f.read_bytes() for f in (capa_dir / "sigs").iterdir()} == firmas
assert herramientas.datos_capa() == (capa_dir / "reglas", capa_dir / "sigs")
assert sorted(f.name for f in herramientas.CARPETA.iterdir()) == ["capa", "die", "otro.zip"]  # ni capa.zip ni .parte; lo ajeno sigue
# Un zip cortado (como el que llega de codeload si se corta la conexión, sin tamaño con el que compararlo) o que no es un zip: OSError con mensaje claro, copia buena intacta, sin restos
for nombre, contenido in (("cortado.zip", reglas_zip.read_bytes()[:-30]), ("basura.zip", b"esto no es un zip")):
    (tmp / nombre).write_bytes(contenido)
    try:
        actualiza.instalar_capa(pendiente._replace(url=(tmp / nombre).as_uri(), version="v9.9.9"))
        raise AssertionError("debía fallar con un zip roto")
    except OSError as error:
        assert "cortado o corrupto" in str(error), error
    assert (capa_dir / "version.txt").read_text() == "v1.2.3" and herramientas.datos_capa()
    assert sorted(f.name for f in herramientas.CARPETA.iterdir()) == ["capa", "die", "otro.zip"]
# Un nombre de firma que intenta escapar de sigs (la API es de fuera) se queda dentro
actualiza.firmas_capa = lambda version: [("../../escape.sig", 3, (tmp / "1.sig").as_uri())]
actualiza.instalar_capa(pendiente._replace(url=reglas_zip.as_uri()))
assert [f.name for f in (capa_dir / "sigs").iterdir()] == ["escape.sig"] and not (herramientas.CARPETA / "escape.sig").exists()

# 4. Qué hay pendiente, con la última versión de GitHub falsa: sin copia, con la copia vieja y al día
actualiza.ultima_release = lambda api, patron, espera: ("3.21", {"size": 7, "browser_download_url": "https://ejemplo/die.zip"})
(carpeta / "version.txt").write_text("3.10")
viejo = actualiza.pendiente_herramienta("die", "Detect It Easy", actualiza.API_DIE, actualiza.ZIP_DIE, 5)
assert viejo.nombre == "Detect It Easy 3.21" and viejo.motivo == "tu copia es la 3.10" and viejo.instalador is actualiza.instalar and viejo.destino == carpeta
(carpeta / "version.txt").write_text("3.21")
assert actualiza.pendiente_herramienta("die", "Detect It Easy", actualiza.API_DIE, actualiza.ZIP_DIE, 5) is None

# 4b. Pendiente de capa, con la versión de la librería falsa y sin red: al día, con la copia vieja, con la librería más nueva que la copia y sin copia
assert actualiza.pendiente_capa() is None  # la 3b dejó la v1.2.3 y la librería «es» la 1.2.3
version_capa.__version__ = "1.2.4"
assert actualiza.pendiente_capa().motivo == "tu copia es la v1.2.3" and actualiza.pendiente_capa().version == "v1.2.4"
version_capa.__version__ = "1.2.3"
shutil.rmtree(capa_dir / "sigs")  # la versión coincide pero faltan las firmas: sin ellas capa no arranca
assert actualiza.pendiente_capa().motivo == "no hay copia"
herramientas.CARPETA = tmp / "no-hay-nada"
assert actualiza.pendiente_capa().motivo == "no hay copia"
herramientas.CARPETA = tmp / "herramientas"
version_capa.__version__ = version_real

# 5. Falta la herramienta: «no disponible», sin traza; un fichero que no es PE: capa «no aplica» (y ni la lanza)
texto = tmp / "texto.txt"
texto.write_text("hola, esto no es un ejecutable")
herramientas.CARPETA = tmp / "no-existe"
sin_capa, sin_die = herramientas.analizar(notepad, True)
assert sin_capa["estado"] == sin_die["estado"] == "no disponible"
assert herramientas.analizar(texto, False)[0]["estado"] == "no aplica"
herramientas.CARPETA = carpeta_real

# 6. Con las herramientas de verdad: Detect It Easy reconoce el compilador de notepad.exe (y de un texto no detecta ninguno)
assert herramientas.ruta("die"), "falta Detect It Easy: ejecuta «argos actualiza»"
die = herramientas.die(notepad)
assert die["estado"] == "ok" and any("Microsoft Visual C/C++" in c for c in die["detectado"]["compilador"]), die
die_texto = herramientas.die(texto)
assert die_texto["estado"] == "ok" and not die_texto["detectado"]["compilador"], die_texto

# Un fichero de un zip (aquí, bytes en memoria con un nombre que intenta escapar): una sola copia temporal que se borra, y se analiza
antivirus, firma, capa, die = estatico.analizar_copia(texto.read_bytes(), "../../escape.txt", False)
assert antivirus["estado"] == "sin amenazas" and firma is None and capa["estado"] == "no aplica" and die["estado"] == "ok", (antivirus, capa, die)
assert not list(Path(tempfile.gettempdir()).glob("argos-defender-*")) and not (Path(tempfile.gettempdir()).parent / "escape.txt").exists()

# Pasado su tiempo máximo, la herramienta se corta y se dice
maximo = herramientas.ESPERA["die"]
herramientas.ESPERA["die"] = 0.1
assert herramientas.die(notepad)["estado"] == "tiempo agotado"
herramientas.ESPERA["die"] = maximo

# capa de verdad: pasado su tiempo máximo se corta (el python.exe del venv es un lanzador con un hijo: «taskkill /T» tiene que llevárselos a los dos)...
assert herramientas.datos_capa(), "faltan las reglas y firmas de capa: ejecuta «argos actualiza»"
maximo = herramientas.ESPERA["capa"]
herramientas.ESPERA["capa"] = 3
assert herramientas.capa(notepad)["estado"] == "tiempo agotado"
herramientas.ESPERA["capa"] = maximo

# ...y da un resultado válido con notepad.exe, que casa con decenas de reglas (~1,5 minutos)
capa = herramientas.capa(notepad)
assert capa["estado"] == "ok" and capa["capacidades"], capa
assert all(isinstance(nombre, str) and isinstance(tecnica, str) for nombre, tecnica in capa["capacidades"]), capa

print("OK")
