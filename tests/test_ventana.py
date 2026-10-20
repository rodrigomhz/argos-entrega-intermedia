# Se lanza con: python tests/test_ventana.py (la parte 4 abre de verdad la ventana, oculta, unos segundos: necesita el WebView2 de Windows. No usa la red ni toca tu argos-datos;
# el motor de análisis se sustituye por uno falso salvo para la contraseña mala de un zip de prueba, y el soltar se simula con lo que hace pywebview al recibir de WebView2
# los ficheros soltados, porque un arrastre de verdad no se puede hacer desde un test. La parte 5 lanza un Python aparte donde pywebview cree que no hay WebView2.
# Nunca se abre un cuadro de mensaje ni un diálogo de verdad: aviso_nativo se sustituye siempre.
# Las líneas «[pywebview] Function ... does not exist» que salen son lo esperado: pywebview rechazando los mensajes de la página hostil)
import json
import logging
import logging.handlers
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pyzipper
import webview
from webview.dom import _dnd_state
from webview.event import Event

from argos import __version__, actualiza, analisis, enlinea, estatico, herramientas, ventana

# La CSP de la página, literal tal como estaba en bb0825e (con Windows 95): el estilo XP va con degradados CSS y no necesita nada más
CSP = "default-src 'none'; script-src 'nonce-__NONCE__'; style-src 'nonce-__NONCE__'; connect-src 'none'; base-uri 'none'; form-action 'none'"
LIMITE = 180  # segundos para toda la prueba de humo: si WebView2 no arranca o se cuelga, se corta con un error en vez de quedarse esperando
HOSTIL = "a\"b'c</script><script>window.__xss=1</script>\n\u2028x\\n&amp;<img src=x onerror=window.__xss=2>"  # un nombre de un zip puede traer cualquier cosa
EN_DISCO = "o'neil\u2028&amp;{{x}} $(calc) `x`.txt"  # lo más hostil que Windows deja en el nombre de un fichero (sin <>:"/\|?* ni controles)
HOSTIL_RICO = HOSTIL + " \U0001F600"  # con un emoji, para los informes completos
PARTES = list(ventana.PARTES)
tmp = Path(tempfile.mkdtemp(prefix="argos-test-ventana-"))


def _identificacion(sha256, sha1, tamano, malware):
    return {"sha256": sha256, "sha1": sha1, "bytes": tamano, "tipo": "PE Windows executable (executable)", "extension_engana": False,
            "extensiones_esperadas": ["exe", "dll"], "malwarebazaar": [malware, "2026-10-16"], "circl": [False, "2026-10-06"]}


def notepad_falso():
    """Un informe con la forma real de analisis.analizar (sin_red=True) y los datos de notepad.exe: ninguna señal de alarma."""
    return {
        "nombre": "notepad.exe",
        "identificacion": _identificacion("468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e", "76cd26b59923157e09d2bc927ba8fb059f3155dc", 360448, False),
        "en_linea": None,
        "pe": {"arquitectura": "x64 (64 bits)", "compilado": "1979-02-19", "firma_incrustada": False, "version": {"empresa": "Microsoft Corporation", "nombre_original": "NOTEPAD.EXE"},
               "zona_firma": None,
               "secciones": [{"nombre": ".text", "bytes": 159744, "entropia": 6.24}, {"nombre": ".rsrc", "bytes": 126976, "entropia": 7.12}],
               "importaciones": {"GDI32.dll": ["SetMapMode", "LPtoDP"], "COMCTL32.dll": ["ordinal 381"]}},
        "firma": {"estado": "válida", "tipo": "en un catálogo de Windows", "firmante": "CN=Microsoft Windows, O=Microsoft Corporation, C=US"},
        "suplantacion": [],
        "defender": {"estado": "sin amenazas", "detalle": ""},
        "yara": [],
        "ember": {"estado": "ok", "puntuacion": 0.03},
        "die": {"estado": "ok", "detectado": {"compilador": ["Microsoft Visual C/C++ 19.38.33145 [LTCG/C]"], "lenguaje": [], "empaquetador": []}},
        "capa": {"estado": "ok", "capacidades": [["accept command line arguments", "T1059 Command and Scripting Interpreter"]] + [[f"capacidad {i}", ""] for i in range(29)]},
    }


def azorult_falso():
    """Lo que sale de azorult.zip con sin_red=True (medido): MalwareBazaar y Defender dicen malware; ni YARA ni suplantación; capa y DIE sin aplicar."""
    return {
        "nombre": "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754.exe",
        "identificacion": _identificacion("7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754", "77543bde72105ae1a28cc71815d9ea89ea162052", 903680, True),
        "en_linea": None,
        "pe": {"arquitectura": "x86 (32 bits)", "compilado": "2020-10-19", "firma_incrustada": False, "version": {"empresa": "", "nombre_original": ""}, "zona_firma": None,
               "secciones": [{"nombre": ".text", "bytes": 833024, "entropia": 6.91}], "importaciones": {"mscoree.dll": ["_CorExeMain"]}},
        "firma": None,
        "suplantacion": [],
        "defender": {"estado": "DETECTADO", "detalle": "TrojanSpy:MSIL/AgentTesla.SP!MTB"},
        "yara": [],
        "ember": {"estado": "ok", "puntuacion": 0.93},
        "die": {"estado": "no aplicado", "detalle": "Defender bloqueó la copia de la muestra"},
        "capa": {"estado": "no aplicado", "detalle": "Defender bloqueó la copia de la muestra"},
    }


def texto_falso():
    """Un fichero que no es PE (un .txt con extensión que engaña): lo que no aplica sale None o «no aplica»."""
    d = notepad_falso()
    d["nombre"] = "nota.jpg"
    d["identificacion"].update(bytes=123, tipo="Text document (text)", extension_engana=True, extensiones_esperadas=["txt"])
    d.update(pe=None, firma=None, suplantacion=None, ember={"estado": "no aplica", "detalle": "solo ejecutables de Windows (PE)"},
             capa={"estado": "no aplica", "detalle": "capa solo analiza ejecutables de Windows (PE)"},
             die={"estado": "ok", "detectado": {"compilador": [], "lenguaje": [], "empaquetador": []}})
    return d


def hostil_falso(estados_hostiles=False):
    """Un informe completo con cadenas hostiles en TODOS los campos de texto: es lo que mandaría un zip con nombres de atacante, un PE con datos de versión
    y firmante de atacante, reglas YARA con descripciones de atacante y un servicio en línea comprometido. Con estados_hostiles=True también los estados
    (los textos que gobiernan la lógica: «DETECTADO», «ok»...) son hostiles: un estado desconocido se enseña tal cual, como dato."""
    h = HOSTIL_RICO
    estado = (lambda valor: h) if estados_hostiles else (lambda valor: valor)
    return {
        "nombre": h,
        "identificacion": {"sha256": h, "sha1": h, "bytes": 5, "tipo": h, "extension_engana": True, "extensiones_esperadas": [h], "malwarebazaar": [True, h], "circl": [True, h]},
        "en_linea": {"CIRCL": {"estado": estado("malware"), "detalle": h}, "MalwareBazaar": {"estado": estado("malware"), "detalle": h},
                     "VirusTotal": {"estado": estado("malware"), "detalle": h}, h: {"estado": h, "detalle": h}},
        "pe": {"arquitectura": h, "compilado": h, "firma_incrustada": True, "version": {"empresa": h, "nombre_original": h}, "zona_firma": {"tras": 0, "dentro": 0, "relleno": 0},
               "secciones": [{"nombre": h, "bytes": 5, "entropia": 7.5}], "importaciones": {h: [h, h]}},
        "firma": {"estado": h, "tipo": h, "firmante": h},
        "suplantacion": [h, h],
        "defender": {"estado": estado("DETECTADO"), "detalle": h},
        "yara": [[h, h]],
        "ember": {"estado": estado("ok"), "puntuacion": 0.5, "detalle": h},
        "die": {"estado": estado("ok"), "detectado": {h: [h], "lenguaje": [h], "empaquetador": []}, "detalle": h},
        "capa": {"estado": estado("ok"), "capacidades": [[h, h]] * 7, "detalle": h},
    }


class VentanaFalsa:
    """Lo mínimo de webview.Window que usa el puente: events.closed, evaluate_js (lo anota), create_file_dialog y dom."""

    def __init__(self):
        self.events = SimpleNamespace(closed=threading.Event())
        self.js = []
        self.dialogo = None  # lo que devuelve el diálogo: una tupla de rutas, None (cancelado) o una excepción
        self.dialogos = 0

    def evaluate_js(self, script):
        self.js.append(script)

    def create_file_dialog(self, tipo, *args, **kwargs):
        assert tipo == webview.FileDialog.OPEN, tipo
        self.dialogos += 1
        if isinstance(self.dialogo, Exception):
            raise self.dialogo
        return self.dialogo

    def mensajes(self):
        """Los mensajes que recibió la página, ya en JSON; limpia la lista. Cada uno tiene que ser exactamente argos.recibir(<JSON en ASCII>)."""
        recibidos = []
        for js in self.js:
            assert js.startswith("argos.recibir(") and js.endswith(")") and js.isascii() and "\n" not in js, js
            recibidos.append(json.loads(js[len("argos.recibir("):-1]))
        self.js.clear()
        return recibidos


def zip_aes(nombre, miembros, clave=b"infected"):
    ruta = tmp / nombre
    with pyzipper.AESZipFile(ruta, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(clave)
        for miembro, contenido in miembros.items():
            z.writestr(miembro, contenido)
    return str(ruta)


def fichero(nombre, contenido=b"hola argos"):
    ruta = tmp / nombre
    ruta.write_bytes(contenido)
    return str(ruta)


def entregar(*rutas):
    """Lo que hace pywebview (edgechromium) al recibir de WebView2 los ficheros que se acaban de soltar."""
    _dnd_state["paths"] += [(os.path.basename(ruta), ruta) for ruta in rutas]


def evento(*rutas):
    """El evento «drop» tal como le llega al manejador de Python cuando pywebview ya ha puesto pywebviewFullPath."""
    return {"type": "drop", "dataTransfer": {"files": [{"name": os.path.basename(ruta), "pywebviewFullPath": ruta} for ruta in rutas]}}


class Registro(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lineas = []

    def emit(self, registro):
        self.lineas.append(self.format(registro))


errores = Registro()
errores.setFormatter(logging.Formatter("%(levelname)s %(message)s"))  # con exc_info, format() añade la traza
logging.getLogger("argos").addHandler(errores)
registro = ventana.registro

try:
    # 1. El puente: la versión, y de público solo lo que la página puede llamar (un método «_privado» o nuevo sin pensar sería una puerta más desde la página)
    assert [nombre for nombre in dir(ventana.Puente) if not nombre.startswith("_")] == ["actualizar", "analizar", "elegir", "version"]
    assert ventana.Puente(VentanaFalsa()).version() == __version__

    # 2. La página: CSP cerrada y nada externo ni montado con HTML
    html = files("argos").joinpath("ventana.html").read_text(encoding="utf-8")
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]*)"', html).group(1)
    assert csp == CSP, csp  # literal: el cambio de estilo (Windows 95 → XP) no tocó la política
    directivas = {d.split()[0]: d.split()[1:] for d in csp.split("; ")}
    assert directivas["default-src"] == ["'none'"] and directivas["connect-src"] == ["'none'"], csp
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp, csp  # los scripts y estilos propios van por nonce
    for prohibido in ("http://", "https://", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "prefers-color-scheme", "alert(", "confirm(",
                      'setAttribute("style"', "setAttribute('style'"):
        assert prohibido not in html, prohibido
    assert not re.search(r"\b(?:src|href)=|@import|url\(", html), "la página no carga ficheros externos"
    assert html.count("<script") == 1 and html.count("<style") == 1, "un solo script y un solo estilo"
    # Windows XP (Luna): los colores de la paleta, las fuentes y la barra de título (que es solo decorativa: ningún botón dentro, y sus tres botones, de adorno)
    for color in ("#0831d9", "#ece9d8", "#d0d0bf", "#f6f5ef", "#0046d5", "#003c74", "#f8b33a", "#7f9db9", "#2bd23a", "#fff7d6", "#e5c365", "#c00", "#2a7d1e", "#808080",
                  "#0997ff", "Tahoma", '"Segoe UI"', '"Trebuchet MS"'):
        assert color in html, color
    for resto in ("#008080", "#c0c0c0", "#000080", "Microsoft Sans Serif", "Windows 95", "Bliss", "bliss"):  # nada del estilo anterior ni de la foto de Windows
        assert resto not in html, resto
    titulo = re.search(r'<div class="titulo">(.*?)</div>', html, re.S).group(1)
    assert "<h1>Argos — Analizador local de ficheros sospechosos</h1>" in titulo and "<button" not in titulo, titulo
    assert re.findall(r'<span class="bt( cerrar)?" aria-hidden="true">(.)</span>', titulo) == [("", "_"), ("", "□"), (" cerrar", "×")], titulo
    assert html.count('role="alertdialog"') == 1 and html.count('id="aviso-aceptar"') == 1  # un único cuadro de mensaje, dentro de la página
    # La entropía alta es la de la terminal: una sola definición en Python, la misma en la página
    assert float(re.search(r"const ENTROPIA_ALTA = ([\d.]+);", html).group(1)) == estatico.ENTROPIA_ALTA
    primera, segunda = ventana.pagina(), ventana.pagina()
    assert "__NONCE__" not in primera and primera != segunda  # un nonce nuevo en cada arranque
    nonce = re.search(r"script-src 'nonce-([^']+)'", primera).group(1)
    assert f"style-src 'nonce-{nonce}'" in primera and primera.count(f'nonce="{nonce}"') == 2  # el script y el estilo de la página

    # 3. El puente sin ventana: con una ventana falsa que anota lo que recibiría la página
    ventana.vigilar_soltados()
    w = VentanaFalsa()
    puente = ventana.Puente(w)

    # 3a. Lo que anota el registro de lo soltado: la ruta con el unquote que pywebview le aplica al entregarla
    entregar(r"C:\datos\a%41.txt")
    assert r"C:\datos\aA.txt" in ventana.soltadas

    # 3b. Soltar: el manejador fija el elegido con una ruta que WebView2 entregó
    texto = fichero("a.txt")
    entregar(texto)
    puente._soltar(evento(texto))
    assert puente._elegido == texto
    assert w.mensajes() == [{"tipo": "elegido", "nombre": "a.txt", "bytes": 10, "es_zip": False}]

    # 3c. es_zip se decide por el contenido, no por la extensión
    zip_ok = zip_aes("cifrado.dat", {"uno.txt": b"hola"})
    falso_zip = fichero("parece.zip", b"esto no es un zip")
    entregar(zip_ok, falso_zip)
    puente._soltar(evento(zip_ok))
    puente._soltar(evento(falso_zip))
    zip_elegido, falso_elegido = w.mensajes()
    assert zip_elegido["es_zip"] is True and zip_elegido["nombre"] == "cifrado.dat" and falso_elegido["es_zip"] is False, (zip_elegido, falso_elegido)

    # 3d. Una carpeta se rechaza con mensaje y el elegido no cambia
    carpeta = tmp / "carpeta"
    carpeta.mkdir()
    entregar(str(carpeta))
    puente._soltar(evento(str(carpeta)))
    [m] = w.mensajes()
    assert m["tipo"] == "rechazado" and "carpeta" in m["texto"] and puente._elegido == falso_zip, m

    # 3e. Varios ficheros: se coge el primero y se dice
    otro = fichero("b.txt", b"adios")
    entregar(texto, otro)
    puente._soltar(evento(texto, otro))
    elegido, aviso = w.mensajes()
    assert puente._elegido == texto and elegido["nombre"] == "a.txt" and aviso["tipo"] == "aviso", (elegido, aviso)
    assert "2 ficheros" in aviso["texto"] and "primero" in aviso["texto"], aviso

    # 3f. La página no puede dar una ruta: un evento falso (con su propio pywebviewFullPath) o roto no fija nada y no lanza excepciones
    secreto = fichero("secreto.txt")  # existe, pero WebView2 no lo entregó
    for falso in (evento(secreto), None, "texto", [], {}, {"dataTransfer": None}, {"dataTransfer": {"files": []}}, {"dataTransfer": {"files": {"0": 1}}},
                  {"dataTransfer": {"files": ["a.txt"]}}, {"dataTransfer": {"files": [{"name": "x"}]}},
                  {"dataTransfer": {"files": [{"pywebviewFullPath": 5}]}}, {"dataTransfer": {"files": [{"pywebviewFullPath": [texto]}]}}):
        puente._soltar(falso)
        [m] = w.mensajes()
        assert m["tipo"] == "rechazado" and puente._elegido == texto, (falso, m, puente._elegido)

    # 3g. El diálogo nativo: lo que elige el usuario se fija; cancelar no cambia nada; si falla, mensaje (sin traza) y el puente sigue vivo
    w.dialogo = (otro,)
    assert puente.elegir() is None and puente._elegido == otro and w.dialogos == 1
    assert w.mensajes() == [{"tipo": "elegido", "nombre": "b.txt", "bytes": 5, "es_zip": False}]
    w.dialogo = None
    puente.elegir()
    assert puente._elegido == otro and w.mensajes() == []
    w.dialogo = RuntimeError("fallo-interno-del-dialogo")
    puente.elegir()
    [m] = w.mensajes()
    assert m["tipo"] == "rechazado" and "fallo-interno" not in m["texto"] and puente._elegido == otro, m
    w.dialogo = (str(tmp / "no-existe.txt"),)  # borrado entre medias
    puente.elegir()
    [m] = w.mensajes()
    assert m["tipo"] == "rechazado" and puente._elegido == otro, m
    errores.lineas.clear()

    # 3h. analizar sin elegido se rechaza, y no arranca nada
    def reventar(*args, **kwargs):
        raise AssertionError(f"el motor no debía llamarse: {args}")

    vacio = ventana.Puente(VentanaFalsa())
    with mock.patch.object(analisis, "informes", reventar):
        r = vacio.analizar("infected", True)
        assert r["ok"] is False and "elegido" in r["motivo"] and vacio._hilo is None, r

        # 3i. Los argumentos de la página: contraseña que no es str o de más de 256, sin_red que no es bool
        for clave, sin_red in ((5, True), (None, True), (b"infected", True), (["x"], True), ({"a": 1}, True), ("a" * 257, True), ("ñ" * 257, False),
                               ("infected", "si"), ("infected", 1), ("infected", 0), ("infected", None), ("infected", [])):
            r = puente.analizar(clave, sin_red)
            assert r["ok"] is False and "elegido" not in r["motivo"] and puente._hilo is None and not puente._ocupado, (clave, sin_red, r)

        # 3i2. Los argumentos de actualizar: la casilla «Sin CIRCL» tiene que ser un booleano
        for valor in ("si", 1, None, [], {}):
            r = puente.actualizar(valor)
            assert r["ok"] is False and "Sin CIRCL" in r["motivo"] and puente._hilo is None and not puente._ocupado, (valor, r)
    assert w.mensajes() == []

    # 3j. analizar con un motor falso: cada parte llega con JSON válido, también con nombres y valores hostiles, y al final «terminado»
    llamadas = []

    def valor_de(parte):  # en_linea es None con sin_red: la página lo enseña como «no aplica»
        return None if parte == "en_linea" else {"parte": parte, "texto": HOSTIL, "lista": [1, None, True], "n": 0.5}

    def motor_falso(ruta, clave=None, sin_red=False, secciones=analisis.SECCIONES, avisar=None):
        llamadas.append((ruta, clave, sin_red))
        for indice, nombre in enumerate(("uno.txt", HOSTIL)):
            avisar(indice, "nombre", nombre)
            for parte in PARTES:
                avisar(indice, parte, valor_de(parte))
            yield {"nombre": nombre}

    def correr(puente, *argumentos):
        r = puente.analizar(*argumentos)
        if r["ok"]:
            puente._hilo.join(10)
            assert not puente._hilo.is_alive()
        return r

    with mock.patch.object(analisis, "informes", motor_falso):
        assert correr(puente, "infected", True) == {"ok": True} and puente._hilo.daemon is True  # daemon: cerrar la ventana a medias no deja el proceso colgado
        recibidos = w.mensajes()
        esperado = [{"tipo": "inicio", "partes": PARTES}]
        for indice, nombre in enumerate(("uno.txt", HOSTIL)):
            esperado.append({"tipo": "parte", "indice": indice, "parte": "nombre", "valor": nombre})
            esperado += [{"tipo": "parte", "indice": indice, "parte": parte, "valor": valor_de(parte)} for parte in PARTES]
        esperado.append({"tipo": "terminado", "ficheros": 2})
        assert recibidos == esperado, recibidos
        assert llamadas[-1] == (otro, "infected", True), llamadas  # la ruta es la elegida, no una que dé la página; la clave y el interruptor, los de la página
        assert not puente._ocupado
        # clave vacía = el zip como un fichero más (clave None en el motor); y sin_red por defecto apagado
        assert correr(puente, "", False) == {"ok": True}
        assert llamadas[-1] == (otro, None, False), llamadas
        assert correr(puente, "x" * 256, False) == {"ok": True}  # el tope es de 256 inclusive
        w.mensajes()

    # 3k. Contraseña mala de un zip AES de prueba (inofensivo, creado aquí), con el motor de verdad: el texto del motor como error y sin ninguna parte
    entregar(zip_ok)
    puente._soltar(evento(zip_ok))
    w.mensajes()
    assert correr(puente, "mala", True) == {"ok": True}
    assert w.mensajes() == [{"tipo": "inicio", "partes": PARTES}, {"tipo": "error", "texto": "contraseña incorrecta"}]
    assert not puente._ocupado and errores.lineas == []

    # 3l. Cualquier otra excepción: error genérico sin traza en la página (la traza va al registro) y el puente queda libre
    def motor_roto(ruta, clave=None, sin_red=False, secciones=analisis.SECCIONES, avisar=None):
        avisar(0, "nombre", "uno.txt")
        raise KeyError("detalle-interno-secreto")
        yield  # noqa: hace de esto un generador, como el motor de verdad

    with mock.patch.object(analisis, "informes", motor_roto):
        assert correr(puente, "", True) == {"ok": True}
        *_, final = w.mensajes()
        assert final["tipo"] == "error" and "secreto" not in final["texto"] and "Traceback" not in final["texto"] and "KeyError" not in final["texto"], final
        assert len(errores.lineas) == 1 and "detalle-interno-secreto" in errores.lineas[0] and "Traceback" in errores.lineas[0], errores.lineas
        assert not puente._ocupado
    errores.lineas.clear()

    # 3m. Dos analizar seguidos: el segundo se rechaza mientras dura el primero (y no se puede cambiar el fichero ni abrir el diálogo); al terminar, se puede otra vez
    seguir, dentro = threading.Event(), threading.Event()

    def motor_lento(ruta, clave=None, sin_red=False, secciones=analisis.SECCIONES, avisar=None):
        avisar(0, "nombre", "lento.txt")
        dentro.set()
        assert seguir.wait(20), "el test no soltó el motor"
        yield {"nombre": "lento.txt"}

    with mock.patch.object(analisis, "informes", motor_lento):
        assert puente.analizar("", True) == {"ok": True}
        assert dentro.wait(10)
        segundo = puente.analizar("", True)
        assert segundo["ok"] is False and "en marcha" in segundo["motivo"], segundo
        no_actualiza = puente.actualizar(False)  # tampoco se puede actualizar mientras analiza
        assert no_actualiza["ok"] is False and "en marcha" in no_actualiza["motivo"], no_actualiza
        w.mensajes()
        w.dialogo = (otro,)
        dialogos = w.dialogos
        puente.elegir()
        assert w.dialogos == dialogos and puente._fijar(otro) is False and puente._elegido == zip_ok  # mientras analiza, ni diálogo ni otro fichero
        assert [m["tipo"] for m in w.mensajes()] == ["rechazado", "rechazado"]
        seguir.set()
        puente._hilo.join(10)
        assert not puente._hilo.is_alive() and w.mensajes()[-1] == {"tipo": "terminado", "ficheros": 1}
        assert correr(puente, "", True) == {"ok": True}  # libre otra vez (seguir sigue puesto: el motor no espera)
        w.mensajes()

    # 3n. Cerrar la ventana a medias: _enviar deja de avisar (sin excepción ni traza), el hilo es daemon y termina solo
    seguir.clear()
    dentro.clear()

    def motor_a_medias(ruta, clave=None, sin_red=False, secciones=analisis.SECCIONES, avisar=None):
        avisar(0, "nombre", "uno.txt")
        dentro.set()
        assert seguir.wait(20)
        avisar(0, "identificacion", {})  # ya con la ventana cerrada
        yield {"nombre": "uno.txt"}

    with mock.patch.object(analisis, "informes", motor_a_medias):
        assert puente.analizar("", True) == {"ok": True}
        assert dentro.wait(10)
        w.mensajes()
        w.events.closed.set()
        seguir.set()
        puente._hilo.join(10)
        assert not puente._hilo.is_alive() and w.js == [] and not puente._ocupado and errores.lineas == [], (w.js, errores.lineas)

    # 3o. Si la ventana falla al recibir, el hilo no muere con una excepción sin más: se registra y sigue
    def evaluate_js_roto(script):
        raise RuntimeError("la página se rompió")

    w2 = VentanaFalsa()
    w2.evaluate_js = evaluate_js_roto
    ventana.Puente(w2)._enviar({"tipo": "aviso", "texto": "x"})
    assert len(errores.lineas) == 1 and "la página se rompió" in errores.lineas[0], errores.lineas
    errores.lineas.clear()

    # 3p. La actualización: sus fases llegan a la página como eventos, ocupa el puente como un análisis y, al terminar, lo libera
    w3 = VentanaFalsa()
    p3 = ventana.Puente(w3)
    dentro_act, seguir_act = threading.Event(), threading.Event()
    vistos = []

    def actualizar_lento(sin_circl=False, pendientes=None, evento=None):
        vistos.append(sin_circl)
        evento({"estado": "comprobando"})
        evento({"estado": "descargando", "nombre": "CIRCL", "motivo": "no hay copia", "tamano": 1000, "indice": 0, "total": 1})
        evento({"estado": "progreso", "nombre": "CIRCL", "recibidos": 500, "tamano": 1000, "indice": 0, "total": 1})
        dentro_act.set()
        assert seguir_act.wait(20)
        evento({"estado": "hecho", "nombre": "CIRCL", "indice": 0, "total": 1})

    with mock.patch.object(actualiza, "actualizar", actualizar_lento):
        assert p3.actualizar(False) == {"ok": True}
        assert dentro_act.wait(10)
        assert p3.actualizar(True)["ok"] is False  # una sola tarea a la vez
        no_analiza = p3.analizar("", True)
        assert no_analiza["ok"] is False and "en marcha" in no_analiza["motivo"], no_analiza
        seguir_act.set()
        p3._hilo.join(10)
        assert not p3._hilo.is_alive() and not p3._ocupado and p3._hilo.daemon
    assert vistos == [False], vistos
    assert [m.get("estado") for m in w3.mensajes()] == ["comprobando", "descargando", "progreso", "hecho", "fin"]

    # 3q. sin_trazas: un fallo del método (o unos argumentos que no encajan) llega a la página como rechazo genérico, y la traza al registro
    class Ejemplo:
        def uno(self, a, b=0):
            return {"ok": True, "a": a}

        def roto(self):
            raise KeyError("detalle-interno-secreto")

        def tipo_interno(self):
            return len(None)  # un TypeError que NO es de argumentos

    ejemplo = Ejemplo()
    uno, roto, tipo_interno = (ventana.sin_trazas(m) for m in (ejemplo.uno, ejemplo.roto, ejemplo.tipo_interno))
    assert (uno.__name__, roto.__name__) == ("uno", "roto")  # pywebview nombra la función de JS con __name__
    assert uno(1) == {"ok": True, "a": 1} and uno(1, 2) == {"ok": True, "a": 1}
    sobra = {"ok": False, "motivo": "Argumentos no válidos"}
    errores.lineas.clear()
    for args in ((), (1, 2, 3), ("clave-secreta-de-un-zip", 2, 3, 4, 5), (ventana._NO_LISTA,)):
        assert uno(*args) == sobra, args
    assert roto(1) == sobra and roto() == {"ok": False, "motivo": "Error inesperado"}
    assert tipo_interno() == {"ok": False, "motivo": "Error inesperado"}  # un TypeError de dentro no se hace pasar por uno de argumentos
    assert len(errores.lineas) == 7 and all("Traceback" in linea for linea in errores.lineas), errores.lineas  # la traza, entera, al registro
    assert any("detalle-interno-secreto" in linea for linea in errores.lineas) and not any("clave-secreta-de-un-zip" in linea for linea in errores.lineas)  # ni un valor
    errores.lineas.clear()

    # 3r. solo_listas: unos parámetros que no son una lista (null, un número, un texto, un dict) llegan al método como un argumento que no encaja
    recibidos_bridge = []
    falso_bridge = lambda window, func_name, param, value_id: recibidos_bridge.append((func_name, param))
    filtrada = ventana.solo_listas(falso_bridge)
    ventana_bridge = SimpleNamespace(_functions={"version": None})
    for param in ([], [1, 2], None, 5, "abc", {"a": 1}):
        filtrada(ventana_bridge, "version", param, "id")
    filtrada(ventana_bridge, "desconocida", None, "id")  # lo que no es un método expuesto no se toca: pywebview lo rechaza («does not exist»)
    assert recibidos_bridge == [("version", []), ("version", [1, 2])] + [("version", [ventana._NO_LISTA])] * 4 + [("desconocida", None)], recibidos_bridge
    assert filtrada.__wrapped__ is falso_bridge

    # 3s. configurar_registro: el fichero (rotativo, con fecha, nivel y traza), el logger de pywebview, las excepciones sin capturar de cualquier hilo y NINGUNA clave
    carpeta_log = tmp / "log"
    nivel_antes, ganchos_antes = registro.level, (sys.excepthook, threading.excepthook)
    manejadores_antes = {nombre: list(logging.getLogger(nombre).handlers) for nombre in ("argos", "pywebview")}
    claves = {"ARGOS_ABUSECH_KEY": "abuse-clave-falsa-0123456789", "ARGOS_VT_KEY": "vt-clave-falsa-9876543210"}
    sys.excepthook, threading.excepthook = (lambda *args: None), (lambda args: None)  # lo "anterior": para que la prueba no escriba trazas a la terminal
    try:
        with mock.patch.object(ventana, "REGISTRO", carpeta_log / "argos-ventana.log"), mock.patch.dict(os.environ, claves):
            manejador = ventana.configurar_registro()
            assert isinstance(manejador, logging.handlers.RotatingFileHandler) and (manejador.maxBytes, manejador.backupCount) == (1_000_000, 3)
            registro.info("información de prueba")
            registro.error("falló con la clave %s", claves["ARGOS_VT_KEY"])
            try:
                raise OSError(f"HTTP con {claves['ARGOS_ABUSECH_KEY']}")
            except OSError:
                registro.exception("traza con la clave %s", claves["ARGOS_ABUSECH_KEY"])
            logging.getLogger("pywebview").error("WebView2 initialization failed: prueba")

            def revienta():
                raise ValueError("fallo-en-un-hilo")

            hilo = threading.Thread(target=revienta, name="hilo-de-prueba")
            hilo.start()
            hilo.join()
            try:
                raise RuntimeError("fallo-sin-capturar")
            except RuntimeError:
                sys.excepthook(*sys.exc_info())  # lo que haría el intérprete con una excepción que nadie captura en el hilo principal
            hilo_salida = threading.Thread(target=lambda: sys.exit(0), name="hilo-que-sale")  # SystemExit en un hilo no es un fallo
            hilo_salida.start()
            hilo_salida.join()
            manejador.flush()
            texto_log = (carpeta_log / "argos-ventana.log").read_text(encoding="utf-8")
        assert re.search(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} INFO argos \[MainThread\] información de prueba$", texto_log, re.M), texto_log
        assert "ERROR argos" in texto_log and "Traceback (most recent call last)" in texto_log and "OSError: HTTP con" in texto_log, texto_log
        assert "ERROR pywebview" in texto_log and "WebView2 initialization failed" in texto_log, texto_log
        assert "CRITICAL argos [hilo-de-prueba] excepción sin capturar en el hilo hilo-de-prueba" in texto_log and "ValueError: fallo-en-un-hilo" in texto_log, texto_log
        assert "excepción sin capturar\nTraceback" in texto_log and "RuntimeError: fallo-sin-capturar" in texto_log and "hilo-que-sale" not in texto_log, texto_log
        assert not any(clave in texto_log for clave in claves.values()) and texto_log.count("***") == 3, texto_log  # ninguna clave (ni en el mensaje ni en el texto de la excepción), y se nota dónde estaba
        # Sin sitio donde escribir: no revienta, devuelve None y no toca nada más
        with mock.patch.object(ventana, "REGISTRO", carpeta_log / "argos-ventana.log" / "dentro"):  # «dentro» de un fichero
            ganchos_ahora = (sys.excepthook, threading.excepthook)
            assert ventana.configurar_registro() is None and (sys.excepthook, threading.excepthook) == ganchos_ahora
    finally:
        manejador.close()
        for nombre, antes in manejadores_antes.items():
            logging.getLogger(nombre).handlers[:] = antes
        registro.setLevel(nivel_antes)
        sys.excepthook, threading.excepthook = ganchos_antes
    errores.lineas.clear()

    # 3t. main() sin WebView2: pywebview elige otro motor (MSHTML, sin CSP) → no se abre la ventana, se registra y sale el cuadro nativo (sustituido aquí)
    def main_con(motor):
        """Lo que hace main() cuando pywebview elige este motor, con webview.create_window/start sustituidos: (ventana, avisos, argumentos de start, cortar)."""
        creadas, arranques, avisos = [], [], []

        class VentanaDeMain(VentanaFalsa):
            def __init__(self):
                super().__init__()
                self.events = SimpleNamespace(closed=Event(None), loaded=Event(None), initialized=Event(None, True))  # los de pywebview: should_lock en initialized
                self.expuestas = []

            def expose(self, *funciones):
                self.expuestas = list(funciones)

        def crear(*args, **kwargs):
            creadas.append(VentanaDeMain())
            return creadas[0]

        def arrancar(func=None, **kwargs):  # lo que hace start(): lanza initialized con el motor y, si nadie aborta, muestra la ventana (aquí, el usuario la cierra)
            arranques.append(kwargs)
            if not creadas[0].events.initialized.set(motor):
                creadas[0].events.closed.set()

        with mock.patch.object(webview, "create_window", crear), mock.patch.object(webview, "start", arrancar), \
                mock.patch.object(ventana, "aviso_nativo", lambda titulo, texto: avisos.append((titulo, texto))), \
                mock.patch.object(ventana, "configurar_registro"), mock.patch.object(herramientas, "cortar") as cortar:
            ventana.main()
            limite = time.monotonic() + 5
            while motor == "edgechromium" and not cortar.called and time.monotonic() < limite:  # events.closed corre el manejador en un hilo
                time.sleep(0.05)
        return creadas[0], avisos, arranques, cortar

    for motor in ("mshtml", "cef"):
        v, avisos, arranques, cortar = main_con(motor)
        assert avisos == [("Argos", ventana.TEXTO_SIN_WEBVIEW2)], (motor, avisos)
        assert ventana.URL_WEBVIEW2 == "https://developer.microsoft.com/microsoft-edge/webview2/" and ventana.URL_WEBVIEW2 in avisos[0][1] and "WebView2 Runtime" in avisos[0][1]
        assert arranques == [{"gui": "edgechromium", "debug": False}], arranques  # gui: PYWEBVIEW_GUI del entorno no puede elegir otro motor
        assert not v.events.loaded.is_set() and not cortar.called  # la página no se cargó, y no había nada que cortar
        assert any("sin WebView2" in linea and motor in linea for linea in errores.lineas), errores.lineas
        errores.lineas.clear()
    v, avisos, arranques, cortar = main_con("edgechromium")
    assert avisos == [] and cortar.called, (avisos, cortar.called)  # con WebView2 no hay aviso, y al cerrar la ventana se corta lo que haya en marcha
    assert [f.__name__ for f in v.expuestas] == ["actualizar", "analizar", "elegir", "version"]  # sin_trazas conserva los nombres
    assert v.expuestas[3]() == __version__ and v.expuestas[1](1, 2, 3) == sobra and v.expuestas[3](1) == sobra and v.expuestas[1]("x" * 300, True)["ok"] is False
    assert hasattr(webview.util.js_bridge_call, "__wrapped__")  # main() parchea js_bridge_call (solo_listas) antes de start()
    errores.lineas.clear()

    # 4. Prueba de humo real: la ventana de verdad (oculta), con el puente y la CSP dentro de WebView2, y lo que intentaría una página hostil
    resultado = {}
    privado = []  # un método «_privado» de mentira en Puente: si la página llega a llamarlo, aparece aquí
    instancias = []  # el Puente que crea main()
    notepad = r"C:\Windows\System32\notepad.exe"
    en_disco = fichero(EN_DISCO)
    zip_mala = zip_aes("mala.zip", {"nota.txt": b"hola"})
    bloqueo, bloqueado = threading.Event(), threading.Event()

    def motor_de_la_ventana(ruta, clave=None, sin_red=False, secciones=analisis.SECCIONES, avisar=None):
        """Falso: para el fichero de nombre hostil emite cuatro informes completos; para notepad.exe se queda a medias hasta que el test lo suelta."""
        if ruta == en_disco:
            llamadas.append((ruta, clave, sin_red))
            for indice, (nombre, informe) in enumerate((("uno.txt", notepad_falso()), ("azorult.exe", azorult_falso()),
                                                        (HOSTIL, hostil_falso()), ("nota.jpg", texto_falso()))):
                avisar(indice, "nombre", nombre)
                for parte in PARTES:
                    avisar(indice, parte, informe[parte])
                yield informe
        else:
            assert ruta == notepad, ruta
            avisar(0, "nombre", "notepad.exe")
            avisar(0, "identificacion", notepad_falso()["identificacion"])
            bloqueado.set()
            assert bloqueo.wait(30)
            avisar(0, "en_linea", None)  # ya con la ventana cerrada
            yield {"nombre": "notepad.exe"}

    class PuenteDeLaPrueba(ventana.Puente):
        def __init__(self, *args):
            super().__init__(*args)
            instancias.append(self)

    def esperar(w, js, esperado=True, segundos=30):
        limite = time.monotonic() + segundos
        while time.monotonic() < limite:
            valor = w.evaluate_js(js)
            if valor == esperado:
                return valor
            time.sleep(0.2)
        raise AssertionError(f"la página no llegó a {js!r} == {esperado!r}: {valor!r}")

    def en_bruto(w, nombre, parametros):
        """Un mensaje en bruto [nombre, parámetros en JSON, id] sin pasar por window.pywebview.api, como lo mandaría una página hostil."""
        w.evaluate_js(f"window.chrome.webview.postMessage({json.dumps([nombre, parametros, 'x'])}); null")

    def soltar_en_bruto(w, ruta, nodo):
        """Un «drop» como el que manda la página: sin ruta; pywebview la pone si coincide con un fichero que WebView2 entregó."""
        param = {"event": {"type": "drop", "dataTransfer": {"files": [{"name": os.path.basename(ruta)}]}}, "nodeId": nodo}
        en_bruto(w, "pywebviewEventHandler", json.dumps(param))

    NO_VALIDO, SIN_FICHERO = "Argumentos no válidos", "No hay ningún fichero elegido"
    # Lo que una página manda en bruto: (método, parámetros en JSON tal como los manda pywebview.stringify, motivo del rechazo). analizar con 0 o 1 argumentos SÍ encaja
    # (tiene valores por defecto) y se rechaza por no haber fichero; nunca se llama bien a elegir (abriría el diálogo) ni a actualizar (iría a la red)
    llamadas_raras = [
        ("analizar", "[]", SIN_FICHERO), ("analizar", '["a"]', SIN_FICHERO), ("analizar", '["a",true,3]', NO_VALIDO), ("analizar", '["a",true,3,4,5]', NO_VALIDO),
        ("version", "[1]", NO_VALIDO), ("version", "[1,2,3]", NO_VALIDO), ("elegir", "[1]", NO_VALIDO), ("actualizar", "[true,false]", NO_VALIDO),
        ("actualizar", "[1,2,3]", NO_VALIDO),
        # parámetros que ni siquiera son una lista: pywebview hace func(*param) y la excepción salta antes de entrar en el método
        ("analizar", "null", NO_VALIDO), ("analizar", "5", NO_VALIDO), ("analizar", '"abc"', NO_VALIDO), ("analizar", '{"a":1}', NO_VALIDO),
        ("version", "null", NO_VALIDO), ("version", "5", NO_VALIDO), ("elegir", "null", NO_VALIDO), ("actualizar", "7", NO_VALIDO),
    ]

    def comprobar():
        w = webview.windows[0]
        try:
            assert w.events.loaded.wait(30), "la ventana no cargó en 30 s"
            limite = time.monotonic() + 30
            while time.monotonic() < limite:  # el pie cambia cuando el puente contesta
                resultado["pie"] = w.evaluate_js("document.getElementById('pie').textContent")
                if resultado["pie"] == f"Versión {__version__}":
                    break
                time.sleep(0.2)
            resultado["api"] = w.evaluate_js("Object.keys(window.pywebview.api)")
            (puente,) = instancias
            # El puente con mensajes en bruto que no encajan, antes de elegir nada: la página recibe un rechazo, nunca la traza (el callback hace lo que window.pywebview.api)
            w.evaluate_js("""window.__r = {}; window.__llamar = (n, p, id) => {
                window.pywebview._returnValuesCallbacks[n][id] = r => { window.__r[id] = r; };
                window.chrome.webview.postMessage([n, p, id]); }; null""")
            for i, (nombre, parametros, _) in enumerate(llamadas_raras):
                w.evaluate_js(f"window.__llamar({json.dumps(nombre)}, {json.dumps(parametros)}, 'c{i}'); null")
            w.evaluate_js("window.__llamar('version', '[]', 'version'); null")
            esperar(w, f"Object.keys(window.__r).length === {len(llamadas_raras) + 1}")
            resultado["raras"] = json.loads(w.evaluate_js("JSON.stringify(window.__r)"))
            assert puente._elegido is None and not puente._ocupado and puente._hilo is None  # ninguna de ellas arrancó nada
            limite = time.monotonic() + 30
            while _dnd_state["num_listeners"] == 0 and time.monotonic() < limite:  # main() engancha el soltar cuando la página carga
                time.sleep(0.2)
            assert _dnd_state["num_listeners"] == 1, "el soltar no se enganchó a la zona"
            nodo = w.evaluate_js("document.getElementById('zona').getAttribute('data-pywebview-id')")
            w.evaluate_js("window.__v = []; document.addEventListener('securitypolicyviolation', e => window.__v.push(e.violatedDirective)); null")
            texto_de = lambda selector: w.evaluate_js(f"document.querySelector({json.dumps(selector)}).textContent")

            # Lo que enseña el cuadro de mensaje abierto: [título, clase (el tipo), id del elemento con el foco, ¿lo de detrás inert?, icono (el ::before de su círculo)]
            cuadro = lambda: w.evaluate_js("""[document.getElementById('aviso-titulo').textContent, document.getElementById('aviso').className, document.activeElement.id,
                [...document.querySelectorAll('.cuerpo, .estado-barra')].every(e => e.inert), getComputedStyle(document.querySelector('.cuadro-icono'), '::before').content]""")

            # Soltar de mentira: la página manda un «drop» con una ruta que ella elige y WebView2 no entregó. No se fija nada y el cuadro de mensaje lo dice
            en_bruto(w, "pywebviewEventHandler", json.dumps({"event": {"type": "drop", "dataTransfer": {"files": [{"name": "x.txt", "pywebviewFullPath": notepad}]}}, "nodeId": nodo}))
            esperar(w, "document.getElementById('aviso').hidden === false")
            resultado["falso_aviso"] = w.evaluate_js("document.getElementById('aviso').hidden")
            resultado["falso_texto"] = texto_de("#aviso-texto")
            resultado["falso_cuadro"] = cuadro()
            resultado["falso_elegido"] = puente._elegido
            resultado["falso_visible"] = w.evaluate_js("!document.getElementById('elegido').hidden")

            # Soltar de verdad (lo que pywebview recibe de WebView2 y luego el evento de la página): un fichero con nombre hostil
            entregar(en_disco)
            soltar_en_bruto(w, en_disco, nodo)
            esperar(w, "!document.getElementById('elegido').hidden")
            resultado["cuadro_al_elegir"] = w.evaluate_js("[document.getElementById('aviso').hidden, document.querySelector('.cuerpo').inert]")  # elegir otro fichero lo cierra
            resultado["elegido"] = puente._elegido
            resultado["nombre_mostrado"] = texto_de("#nombre")
            resultado["tamano_mostrado"] = texto_de("#tamano")
            resultado["clave_visible"] = w.evaluate_js("!document.getElementById('campo-clave').hidden")

            # El informe completo: cuatro ficheros falsos con la forma real (limpio, malware medido, hostil en todos los campos y un no-PE)
            def del_panel(js):
                return w.evaluate_js(f"(() => {{ const p = document.querySelector('#paneles .informe-fichero:not([hidden])'); return {js}; }})()")

            with mock.patch.object(analisis, "informes", motor_de_la_ventana):
                w.evaluate_js("document.getElementById('sinred').checked = true; document.getElementById('analizar').click(); null")
                esperar(w, "document.getElementById('resumen').textContent.startsWith('Terminado')")
            resultado["resumen"] = texto_de("#resumen")
            resultado["pestanas"] = w.evaluate_js("[...document.querySelectorAll('.pestana')].map(e => e.textContent)")
            resultado["seleccion_inicial"] = w.evaluate_js("[...document.querySelectorAll('.pestana')].map(e => e.getAttribute('aria-selected'))")
            resultado["visible"] = w.evaluate_js("document.querySelectorAll('.informe-fichero:not([hidden])').length")
            for i, nombre in enumerate(("uno", "azorult", "hostil", "texto")):
                if i:
                    w.evaluate_js(f"document.querySelectorAll('.pestana')[{i}].click(); null")
                resultado[f"resumen_{nombre}"] = del_panel("p.querySelector('.resumen-fichero').textContent")
                resultado[f"panel_{nombre}"] = del_panel("p.textContent")
                resultado[f"ember_{nombre}"] = del_panel("p.querySelector('.pista-ember .relleno')?.style.width ?? null")
                # El icono del aviso amarillo del resumen (el ::before de la caja), el titular (color y negrita) y los colores de estado que haya en el panel
                resultado[f"icono_{nombre}"] = del_panel("getComputedStyle(p.querySelector('.resumen-fichero'), '::before').content")
                resultado[f"titular_{nombre}"] = del_panel("(e => [getComputedStyle(e).color, getComputedStyle(e).fontWeight])(p.querySelector('.titular'))")
                resultado[f"colores_{nombre}"] = del_panel("['alarma', 'limpio', 'apagado'].map(c => { const e = p.querySelector('.' + c); return e && getComputedStyle(e).color; })")
                resultado[f"bloques_{nombre}"] = del_panel("(e => e && getComputedStyle(e).backgroundImage)(p.querySelector('.pista-ember .relleno'))")
            estilo_pestana = "e => { const s = getComputedStyle(e); return [s.backgroundColor, s.boxShadow]; }"  # la última pestaña (la cuarta) es la que quedó abierta
            resultado["pestana_activa"] = w.evaluate_js(f"({estilo_pestana})(document.querySelectorAll('.pestana')[3])")
            resultado["pestana_inactiva"] = w.evaluate_js(f"({estilo_pestana})(document.querySelectorAll('.pestana')[0])")
            resultado["botones"] = w.evaluate_js("['elegir', 'actualizar', 'analizar', 'clave', 'sinred', 'sincircl'].map(id => document.getElementById(id).disabled)")
            resultado["progreso_oculto"] = w.evaluate_js("document.getElementById('avance').hidden")

            # Pestañas con dos miembros de un zip, con los mensajes que mandaría Python (directo a la página): uno limpio y otro con hasta los ESTADOS hostiles
            mandar = lambda mensaje: w.evaluate_js(f"argos.recibir({json.dumps(mensaje)}); null")
            mandar({"tipo": "inicio", "partes": PARTES})
            for indice, (nombre, informe) in enumerate((("uno.txt", notepad_falso()), (HOSTIL, hostil_falso(estados_hostiles=True)))):
                mandar({"tipo": "parte", "indice": indice, "parte": "nombre", "valor": nombre})
                for parte in PARTES:
                    mandar({"tipo": "parte", "indice": indice, "parte": parte, "valor": informe[parte]})
            mandar({"tipo": "terminado", "ficheros": 2})
            pestanas_dos = "[...document.querySelectorAll('#pestanas .pestana')].map(e => [e.textContent, e.getAttribute('aria-selected')])"
            resultado["dos_pestanas"] = w.evaluate_js(pestanas_dos)
            resultado["dos_visible"] = del_panel("p.querySelector('.nombre-fichero').textContent")
            w.evaluate_js("document.querySelectorAll('.pestana')[1].click(); null")
            resultado["dos_tras_clic"] = w.evaluate_js(pestanas_dos)
            resultado["dos_visible_tras_clic"] = del_panel("p.querySelector('.nombre-fichero').textContent")
            resultado["dos_panel_hostil"] = del_panel("p.textContent")
            resultado["dos_visibles"] = w.evaluate_js("document.querySelectorAll('.informe-fichero:not([hidden])').length")

            # Los tres cuadros de mensaje (rechazado, aviso, error), con texto hostil: literal, con su icono, y se cierran con «Aceptar» y con Escape
            resultado["cuadros"] = {}
            for tipo in ("rechazado", "aviso", "error"):
                mandar({"tipo": tipo, "texto": HOSTIL})
                resultado["cuadros"][tipo] = [cuadro(), texto_de("#aviso-texto"), w.evaluate_js("document.getElementById('aviso').hidden")]
                w.evaluate_js("document.getElementById('aviso-aceptar').click(); null")
                resultado["cuadros"][tipo].append(w.evaluate_js("[document.getElementById('aviso').hidden, document.querySelector('.cuerpo').inert, document.querySelector('.estado-barra').inert, document.getElementById('aviso-texto').textContent]"))
            mandar({"tipo": "aviso", "texto": "se cierra con Escape"})
            w.evaluate_js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'})); null")
            resultado["cuadro_escape"] = w.evaluate_js("[document.getElementById('aviso').hidden, document.querySelector('.cuerpo').inert]")
            resultado["inyecciones"] = w.evaluate_js("[window.__xss, document.querySelectorAll('script').length, document.querySelectorAll('img').length]")
            resultado["motor"] = list(llamadas[-1])

            # La actualización, con un actualizador falso que se queda a medias: barra, texto y controles bloqueados
            act_dentro, act_seguir = threading.Event(), threading.Event()
            act_recibido = []

            def actualizar_lento(sin_circl=False, pendientes=None, evento=None):
                act_recibido.append(sin_circl)
                evento({"estado": "comprobando"})
                evento({"estado": "descargando", "nombre": "CIRCL", "motivo": "no hay copia", "tamano": 2_000_000, "indice": 0, "total": 2})
                evento({"estado": "progreso", "nombre": "CIRCL", "recibidos": 1_000_000, "tamano": 2_000_000, "indice": 0, "total": 2})
                act_dentro.set()
                assert act_seguir.wait(30)
                evento({"estado": "hecho", "nombre": "CIRCL", "indice": 0, "total": 2})
                evento({"estado": "hecho", "nombre": "reglas", "indice": 1, "total": 2})

            with mock.patch.object(actualiza, "actualizar", actualizar_lento):
                w.evaluate_js("document.getElementById('actualizar').click(); null")
                assert act_dentro.wait(30)
                resultado["act_visible"] = w.evaluate_js("!document.getElementById('actualizacion').hidden")
                resultado["act_texto"] = texto_de("#actividad-actualiza")
                resultado["act_barra"] = w.evaluate_js("document.getElementById('relleno-actualiza').style.width")
                resultado["act_botones"] = w.evaluate_js("['elegir', 'actualizar', 'analizar', 'clave', 'sinred', 'sincircl'].map(id => document.getElementById(id).disabled)")
                resultado["act_sincircl"] = list(act_recibido)
                act_seguir.set()
                esperar(w, "document.getElementById('actualizacion').hidden === true")
            resultado["act_estado"] = texto_de("#resumen")
            resultado["act_botones_fin"] = w.evaluate_js("['elegir', 'actualizar', 'analizar', 'clave', 'sinred', 'sincircl'].map(id => document.getElementById(id).disabled)")

            # Contraseña mala de un zip, con el motor de verdad: el aviso de error, sin ventana modal
            entregar(zip_mala)
            soltar_en_bruto(w, zip_mala, nodo)
            esperar(w, "document.getElementById('nombre').textContent == 'mala.zip'")
            resultado["clave_visible_zip"] = w.evaluate_js("!document.getElementById('campo-clave').hidden")
            w.evaluate_js("document.getElementById('clave').value = 'mala'; document.getElementById('analizar').click(); null")
            esperar(w, "document.getElementById('aviso').hidden === false")
            resultado["error_texto"] = texto_de("#aviso-texto")
            resultado["error_tipo"] = w.evaluate_js("document.getElementById('aviso').className")
            resultado["informe_tras_error"] = texto_de("#paneles")
            resultado["error_cuadro"] = cuadro()
            resultado["botones_tras_error"] = w.evaluate_js("['elegir', 'actualizar', 'analizar', 'clave', 'sinred', 'sincircl'].map(id => document.getElementById(id).disabled)")
            resultado["violaciones_nuevas"] = w.evaluate_js("window.__v")

            # Cerrar la ventana a medias de un análisis: el hilo se queda esperando al motor, y se suelta después de cerrar
            entregar(notepad)
            soltar_en_bruto(w, notepad, nodo)
            esperar(w, "document.getElementById('nombre').textContent == 'notepad.exe'")
            with mock.patch.object(analisis, "informes", motor_de_la_ventana):
                w.evaluate_js("document.getElementById('analizar').click(); null")
                assert bloqueado.wait(30)
                esperar(w, "document.getElementById('actividad').textContent.includes('notepad.exe')")
            # ...con un proceso de herramienta en marcha (un python que duerme 60 s, lanzado por la misma _lanzar que usa capa): cerrar la ventana tiene que matarlo
            resultado["dormir"] = []
            resultado["hilo_dormir"] = threading.Thread(
                target=lambda: resultado["dormir"].append(herramientas._lanzar([sys.executable, "-c", "import time; time.sleep(60)"], 120)), daemon=True)
            resultado["hilo_dormir"].start()
            limite = time.monotonic() + 15
            while not herramientas._en_marcha and time.monotonic() < limite:
                time.sleep(0.05)
            (resultado["dormir_proceso"],) = herramientas._en_marcha

            # Una página hostil manda el mensaje en bruto [nombre, parámetros en JSON, id] sin pasar por window.pywebview.api
            for nombre, parametros in (("_privado", "[]"), ("version.__globals__.update", '[{"__version__": "cambiada desde la página"}]'), ("_soltar", "[{}]"),
                                       ("_fijar", json.dumps([notepad]))):
                en_bruto(w, nombre, parametros)
            # ...y un script en línea sin nonce y una petición de red: la CSP tiene que cortar las dos antes de que salga nada (127.0.0.1:9 no escucha nadie)
            w.evaluate_js("""
                window.__violaciones = [];
                document.addEventListener('securitypolicyviolation', e => window.__violaciones.push(e.violatedDirective));
                const s = document.createElement('script'); s.textContent = 'window.__ejecutado = true'; document.body.appendChild(s);
                fetch('http://127.0.0.1:9/').catch(() => {});
                null
            """)
            time.sleep(1.5)  # que les dé tiempo a llegar (comprobar que algo NO pasa obliga a esperar)
            resultado["violaciones"] = w.evaluate_js("window.__violaciones")
            resultado["ejecutado"] = w.evaluate_js("window.__ejecutado === true")
            resultado["elegido_tras_hostil"] = puente._elegido

            # pywebview no debe haber abierto ningún puerto: todo socket TCP o UDP de este proceso saldría en netstat con su PID al final
            resultado["sockets"] = [linea for linea in subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout.splitlines()
                                    if linea.split()[-1:] == [str(os.getpid())]]
        except BaseException:
            resultado["error"] = traceback.format_exc()
        finally:
            w.destroy()  # con el análisis de notepad.exe sin terminar

    def cortar():
        print(f"FALLO: la prueba de humo no terminó en {LIMITE} s (¿WebView2 no arranca?)", flush=True)
        os._exit(1)

    # main() configura el registro (a un fichero de tmp, no al de argos-datos) y engancha las excepciones sin capturar: se guarda lo de antes para dejarlo como estaba
    nivel_antes, ganchos_antes = registro.level, (sys.excepthook, threading.excepthook)
    manejadores_antes = {nombre: list(logging.getLogger(nombre).handlers) for nombre in ("argos", "pywebview")}
    CLAVES_FALSAS = {"ARGOS_ABUSECH_KEY": "abuse-clave-falsa-0123456789", "ARGOS_VT_KEY": "vt-clave-falsa-9876543210"}
    vigilante = threading.Timer(LIMITE, cortar)
    vigilante.start()
    try:
        with mock.patch.object(ventana.Puente, "_privado", lambda self: privado.append("llamado"), create=True), mock.patch.object(ventana, "Puente", PuenteDeLaPrueba), \
                mock.patch.object(ventana, "REGISTRO", tmp / "registro" / "argos-ventana.log"), mock.patch.dict(os.environ, CLAVES_FALSAS):
            ventana.main(comprobar, hidden=True)  # vuelve cuando comprobar() cierra la ventana
    finally:
        vigilante.cancel()
    manejador_real = next(h for h in registro.handlers if h not in manejadores_antes["argos"])

    assert "error" not in resultado, resultado["error"]
    assert resultado["pie"] == f"Versión {__version__}", resultado  # el puente contestó desde dentro de la CSP
    assert resultado["api"] == ["actualizar", "analizar", "elegir", "version"], resultado  # lo único que la página ve del puente
    assert privado == [] and ventana.__version__ == __version__, (privado, ventana.__version__)  # la página no llegó a nada más que a lo expuesto
    assert resultado["falso_elegido"] is None and resultado["falso_visible"] is False, resultado  # el drop de mentira no fijó nada
    assert resultado["falso_aviso"] is False and "No se pudo leer la ruta" in resultado["falso_texto"], resultado  # el aviso sale en el cuadro de mensaje de la página, no en un popup
    assert resultado["falso_cuadro"] == ["Argos", "rechazado", "aviso-aceptar", True, '"!"'], resultado  # título, tipo, el foco en «Aceptar», lo de detrás inert y el icono de aviso
    assert resultado["cuadro_al_elegir"] == [True, False], resultado  # elegir un fichero cierra el cuadro y lo de detrás deja de ser inert
    assert resultado["elegido"] == en_disco and resultado["nombre_mostrado"] == EN_DISCO, resultado  # el nombre llegó como dato: el literal
    assert resultado["tamano_mostrado"] == "10 bytes" and resultado["clave_visible"] is False, resultado
    assert resultado["resumen"] == "Terminado: 4 ficheros analizados; 10 señales de alarma", resultado
    assert resultado["pestanas"] == ["uno.txt", "azorult.exe", HOSTIL, "nota.jpg"], resultado
    assert resultado["seleccion_inicial"] == ["true", "false", "false", "false"] and resultado["visible"] == 1, resultado  # una pestaña por fichero, la primera abierta
    assert resultado["resumen_uno"].startswith("Ninguna señal de alarma en lo analizado") and "0,03" in resultado["resumen_uno"], resultado
    assert resultado["ember_uno"] == "3%", resultado  # la barra de EMBER, redondeada
    assert "468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e" in resultado["panel_uno"], resultado
    assert "válida" in resultado["panel_uno"] and "sin amenazas" in resultado["panel_uno"] and "sin coincidencias" in resultado["panel_uno"], resultado
    assert "Microsoft Visual C/C++" in resultado["panel_uno"] and ".text" in resultado["panel_uno"], resultado
    assert resultado["resumen_azorult"].startswith("Señales de alarma: 2"), resultado
    # El aviso amarillo del resumen: icono verde «✓» sin señales y rojo «!» con ellas; el titular, #2a7d1e el limpio y #c00 en negrita el de alarma; y los bloques verdes #2bd23a de EMBER
    assert (resultado["icono_uno"], resultado["icono_azorult"], resultado["icono_hostil"], resultado["icono_texto"]) == ('"✓"', '"!"', '"!"', '"!"'), resultado
    assert resultado["titular_uno"] == ["rgb(42, 125, 30)", "700"] and resultado["titular_azorult"] == ["rgb(204, 0, 0)", "700"], resultado
    assert resultado["colores_uno"] == [None, "rgb(42, 125, 30)", "rgb(128, 128, 128)"], resultado  # alarma, limpio, no comprobado
    assert resultado["colores_azorult"] == ["rgb(204, 0, 0)", "rgb(42, 125, 30)", "rgb(128, 128, 128)"], resultado
    assert "rgb(43, 210, 58)" in resultado["bloques_uno"] and "rgb(43, 210, 58)" in resultado["bloques_azorult"] and resultado["bloques_texto"] is None, resultado
    assert "umbral sin calibrar hasta el hito 7" in resultado["resumen_uno"] and "umbral sin calibrar hasta el hito 7" in resultado["resumen_azorult"], resultado  # sin veredicto de EMBER
    assert resultado["pestana_activa"][0] == "rgb(252, 252, 254)" and "rgb(248, 179, 58)" in resultado["pestana_activa"][1], resultado  # la activa, blanca y con la línea naranja arriba
    assert resultado["pestana_inactiva"][0] != "rgb(252, 252, 254)" and resultado["pestana_inactiva"][1] == "none", resultado
    assert "MalwareBazaar" in resultado["resumen_azorult"] and "Microsoft Defender" in resultado["resumen_azorult"], resultado
    assert "0,93" in resultado["resumen_azorult"] and resultado["ember_azorult"] == "93%", resultado
    assert resultado["resumen_hostil"].startswith("Señales de alarma: 7") and "Esto solo cuenta señales" in resultado["resumen_hostil"], resultado
    assert resultado["ember_hostil"] == "50%" and HOSTIL in resultado["panel_hostil"], resultado  # el texto hostil se pinta como texto
    assert resultado["resumen_texto"].startswith("Señales de alarma: 1") and "Extensión que engaña" in resultado["resumen_texto"], resultado
    assert "no es un ejecutable de Windows" in resultado["panel_texto"] and resultado["ember_texto"] is None, resultado  # no-PE: ni EMBER ni estático
    assert resultado["botones"] == [False] * 6 and resultado["progreso_oculto"] is True, resultado  # al terminar se vuelve a poder todo
    assert resultado["dos_pestanas"] == [["uno.txt", "true"], [HOSTIL, "false"]] and resultado["dos_visible"] == "uno.txt", resultado  # dos miembros: dos pestañas, la primera abierta
    assert resultado["dos_tras_clic"] == [["uno.txt", "false"], [HOSTIL, "true"]] and resultado["dos_visible_tras_clic"] == HOSTIL and resultado["dos_visibles"] == 1, resultado
    assert HOSTIL in resultado["dos_panel_hostil"], resultado  # con los estados también hostiles, el panel los enseña como texto
    iconos = {"rechazado": ("Argos", '"!"'), "aviso": ("Argos", '"i"'), "error": ("Argos — Error", '"×"')}  # el título y el ::before del círculo de cada cuadro
    for tipo, (titulo_cuadro, icono) in iconos.items():
        abierto, texto_cuadro, oculto, cerrado = resultado["cuadros"][tipo]
        assert abierto == [titulo_cuadro, tipo, "aviso-aceptar", True, icono] and texto_cuadro == HOSTIL and oculto is False, (tipo, resultado["cuadros"][tipo])
        assert cerrado == [True, False, False, ""], (tipo, cerrado)  # «Aceptar» lo cierra, lo de detrás deja de ser inert y el texto se vacía
    assert resultado["cuadro_escape"] == [True, False], resultado  # Escape también lo cierra
    assert resultado["inyecciones"] == [None, 1, 0], resultado  # ni el script ni la imagen del nombre hostil existen: solo el script de la página
    assert resultado["motor"] == [en_disco, None, True], resultado  # la ruta elegida por Python; sin clave (vacía) y con el interruptor de la página
    assert resultado["act_visible"] is True and resultado["act_texto"] == "CIRCL: 1 MB de 2 MB" and resultado["act_barra"] == "25%", resultado
    assert resultado["act_botones"] == [True] * 6 and resultado["act_sincircl"] == [False], resultado  # durante la actualización no se toca nada
    assert resultado["act_estado"] == "Actualización terminada" and resultado["act_botones_fin"] == [False] * 6, resultado
    assert resultado["clave_visible_zip"] is True and resultado["error_texto"] == "contraseña incorrecta" and resultado["error_tipo"] == "error", resultado
    assert "Preparando" not in resultado["informe_tras_error"] and "No se pudo hacer el análisis" in resultado["informe_tras_error"], resultado
    assert resultado["error_cuadro"] == ["Argos — Error", "error", "aviso-aceptar", True, '"×"'], resultado  # el error del motor de verdad, en el cuadro rojo
    assert resultado["botones_tras_error"] == [False] * 6, resultado
    assert resultado["violaciones_nuevas"] == [], resultado  # nada de lo anterior rozó la CSP
    assert resultado["ejecutado"] is False and set(resultado["violaciones"]) == {"script-src-elem", "connect-src"}, resultado
    assert resultado["elegido_tras_hostil"] == notepad, resultado  # las llamadas en bruto a _soltar y _fijar no cambiaron nada
    assert resultado["sockets"] == [], resultado["sockets"]  # sin servidor HTTP
    assert webview.renderer == "edgechromium"  # la ventana real corrió en WebView2, no en MSHTML
    # El puente ante llamadas en bruto que no encajan: siempre un rechazo (sin isError, que es por donde pywebview manda la traza) y sin rutas del equipo
    for i, (nombre, parametros, motivo) in enumerate(llamadas_raras):
        respuesta = resultado["raras"][f"c{i}"]
        assert list(respuesta) == ["value"] and json.loads(respuesta["value"]) == {"ok": False, "motivo": motivo}, (nombre, parametros, respuesta)
        assert not re.search(r"Traceback|File \\|site-packages|venvs|\.py|[A-Za-z]:\\|Users|" + re.escape(Path.home().name), json.dumps(respuesta)), (nombre, parametros, respuesta)
    assert json.loads(resultado["raras"]["version"]["value"]) == __version__ and "isError" not in resultado["raras"]["version"]  # y una llamada buena, en bruto, sigue contestando
    # Cerrar es cerrar: el proceso de herramienta que había en marcha (como si fuera capa) murió con la ventana, y _lanzar volvió en segundos y no a los 60 s
    resultado["hilo_dormir"].join(20)
    assert not resultado["hilo_dormir"].is_alive() and resultado["dormir"] and resultado["dormir"][0][0] != 0, resultado["dormir"]
    assert resultado["dormir_proceso"].poll() is not None and herramientas._en_marcha == set() and herramientas._cortado is True
    herramientas._cortado = False
    # El registro: existe, tiene la traza de las llamadas que no encajaban (no la página), el motor elegido y ninguna clave
    texto_log = (tmp / "registro" / "argos-ventana.log").read_text(encoding="utf-8")
    assert f"INFO argos [MainThread] Argos {__version__}: arranca la ventana" in texto_log and "pywebview eligió el motor edgechromium" in texto_log, texto_log
    assert "la página llamó a analizar con argumentos que no encajan (5 posicionales)" in texto_log and "Traceback" in texto_log, texto_log
    assert not any(clave in texto_log for clave in CLAVES_FALSAS.values()), texto_log
    assert sys.excepthook is not ganchos_antes[0] and threading.excepthook is not ganchos_antes[1]  # main() enganchó las excepciones sin capturar
    # La ventana ya está cerrada y el análisis de notepad.exe sigue esperando al motor: soltarlo no puede petar ni colgar nada
    (puente_real,) = instancias
    assert puente_real._hilo.is_alive() and puente_real._ocupado
    bloqueo.set()
    puente_real._hilo.join(10)
    # (en errores quedan los INFO del arranque y los avisos de las llamadas que no encajaban; un ERROR o CRITICAL sería un fallo)
    assert not puente_real._hilo.is_alive() and not puente_real._ocupado, errores.lineas
    assert not [linea for linea in errores.lineas if not linea.startswith(("INFO ", "WARNING la página llamó a "))], errores.lineas
    errores.lineas.clear()
    manejador_real.close()
    for nombre, antes in manejadores_antes.items():
        logging.getLogger(nombre).handlers[:] = antes
    registro.setLevel(nivel_antes)
    sys.excepthook, threading.excepthook = ganchos_antes

    # 5. Sin WebView2 de verdad (en un Python aparte): pywebview cree que falta .NET 4.6.2, elige MSHTML y Argos no abre la ventana ni carga la página
    guion = tmp / "sin_webview2.py"
    guion.write_text('''
import json, sys, winreg
from pathlib import Path

# pywebview decide el motor al importar webview.platforms.winforms (_is_chromium): con un .NET anterior a 4.6.2 (Release 394802) lo da por no disponible
consultar = winreg.QueryValueEx
winreg.QueryValueEx = lambda clave, nombre: (0, winreg.REG_DWORD) if nombre == "Release" else consultar(clave, nombre)
import webview.platforms.mshtml as mshtml
mshtml._set_ie_mode = lambda: None  # lo que pywebview escribiría en HKCU al elegir MSHTML: aquí no se toca el registro
import webview
from argos import ventana

ventana.REGISTRO = Path(sys.argv[1])
avisos = []
ventana.aviso_nativo = lambda titulo, texto: avisos.append([titulo, texto])  # nunca un cuadro de verdad
ventana.main(hidden=True)
w = webview.windows[0]
print("RESULTADO" + json.dumps({"avisos": avisos, "renderer": webview.renderer, "formulario": w.native is not None, "cargada": w.events.loaded.is_set(), "mostrada": w.events.shown.is_set()}))
''', encoding="utf-8")
    sin_log = tmp / "sin_webview2.log"
    r = subprocess.run([sys.executable, "-I", str(guion), str(sin_log)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.returncode, r.stdout[-2000:], r.stderr[-2000:])
    salida = json.loads(next(linea for linea in r.stdout.splitlines() if linea.startswith("RESULTADO"))[len("RESULTADO"):])
    assert salida["renderer"] == "mshtml", salida  # el montaje es el bueno: pywebview eligió de verdad MSHTML...
    assert salida["avisos"] == [["Argos", ventana.TEXTO_SIN_WEBVIEW2]], salida  # ...y Argos paró con el cuadro nativo
    assert salida["formulario"] is False and salida["cargada"] is False and salida["mostrada"] is False, salida  # ni formulario, ni página, ni ventana
    assert "MSHTML is deprecated" in r.stderr  # el aviso que pywebview daba solo, y que hasta ahora nadie veía
    registro_sin = sin_log.read_text(encoding="utf-8")
    assert "pywebview eligió el motor mshtml" in registro_sin and "sin WebView2 no se abre la ventana" in registro_sin, registro_sin
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("OK")
