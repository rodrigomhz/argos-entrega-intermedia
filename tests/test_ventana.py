# Se lanza con: python tests/test_ventana.py (la parte 4 abre de verdad la ventana, oculta, unos segundos: necesita el WebView2 de Windows. No usa la red ni toca tu argos-datos;
# el motor de análisis se sustituye por uno falso salvo para la contraseña mala de un zip de prueba, y el soltar se simula con lo que hace pywebview al recibir de WebView2
# los ficheros soltados, porque un arrastre de verdad no se puede hacer desde un test.
# Las líneas «[pywebview] Function ... does not exist» que salen son lo esperado: pywebview rechazando los mensajes de la página hostil)
import json
import logging
import os
import re
import shutil
import subprocess
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

from argos import __version__, analisis, estatico, ventana

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

try:
    # 1. El puente: la versión, y de público solo lo que la página puede llamar (un método «_privado» o nuevo sin pensar sería una puerta más desde la página)
    assert [nombre for nombre in dir(ventana.Puente) if not nombre.startswith("_")] == ["analizar", "elegir", "version"]
    assert ventana.Puente(VentanaFalsa()).version() == __version__

    # 2. La página: CSP cerrada y nada externo ni montado con HTML
    html = files("argos").joinpath("ventana.html").read_text(encoding="utf-8")
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]*)"', html).group(1)
    directivas = {d.split()[0]: d.split()[1:] for d in csp.split("; ")}
    assert directivas["default-src"] == ["'none'"] and directivas["connect-src"] == ["'none'"], csp
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp, csp  # los scripts y estilos propios van por nonce
    for prohibido in ("http://", "https://", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "prefers-color-scheme", "alert(", "confirm(",
                      'setAttribute("style"', "setAttribute('style'"):
        assert prohibido not in html, prohibido
    assert not re.search(r"\b(?:src|href)=|@import|url\(", html), "la página no carga ficheros externos"
    assert html.count("<script") == 1 and html.count("<style") == 1, "un solo script y un solo estilo"
    # Windows 95: los colores de la paleta, la fuente y el texto de la barra de título (que es solo decorativa: ningún botón dentro)
    for color in ("#008080", "#c0c0c0", "#000080", "#1084d0", "#800000", "#008000", "#808080", "#ffffff", "#dfdfdf", "#0a0a0a", "Microsoft Sans Serif", "Tahoma"):
        assert color in html, color
    assert "<h1 class=\"titulo\">Argos — Analizador local de ficheros sospechosos</h1>" in html
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
            limite = time.monotonic() + 30
            while _dnd_state["num_listeners"] == 0 and time.monotonic() < limite:  # main() engancha el soltar cuando la página carga
                time.sleep(0.2)
            assert _dnd_state["num_listeners"] == 1, "el soltar no se enganchó a la zona"
            nodo = w.evaluate_js("document.getElementById('zona').getAttribute('data-pywebview-id')")
            w.evaluate_js("window.__v = []; document.addEventListener('securitypolicyviolation', e => window.__v.push(e.violatedDirective)); null")
            texto_de = lambda selector: w.evaluate_js(f"document.querySelector({json.dumps(selector)}).textContent")

            # Soltar de mentira: la página manda un «drop» con una ruta que ella elige y WebView2 no entregó. No se fija nada y la banda de aviso lo dice
            en_bruto(w, "pywebviewEventHandler", json.dumps({"event": {"type": "drop", "dataTransfer": {"files": [{"name": "x.txt", "pywebviewFullPath": notepad}]}}, "nodeId": nodo}))
            esperar(w, "document.getElementById('aviso').hidden === false")
            resultado["falso_aviso"] = w.evaluate_js("document.getElementById('aviso').hidden")
            resultado["falso_texto"] = texto_de("#aviso")
            resultado["falso_elegido"] = puente._elegido
            resultado["falso_visible"] = w.evaluate_js("!document.getElementById('elegido').hidden")

            # Soltar de verdad (lo que pywebview recibe de WebView2 y luego el evento de la página): un fichero con nombre hostil
            entregar(en_disco)
            soltar_en_bruto(w, en_disco, nodo)
            esperar(w, "!document.getElementById('elegido').hidden")
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
            resultado["botones"] = w.evaluate_js("['elegir', 'analizar', 'clave', 'sinred'].map(id => document.getElementById(id).disabled)")
            resultado["progreso_oculto"] = w.evaluate_js("document.getElementById('avance').hidden")
            resultado["inyecciones"] = w.evaluate_js("[window.__xss, document.querySelectorAll('script').length, document.querySelectorAll('img').length]")
            resultado["motor"] = list(llamadas[-1])

            # Contraseña mala de un zip, con el motor de verdad: el aviso de error, sin ventana modal
            entregar(zip_mala)
            soltar_en_bruto(w, zip_mala, nodo)
            esperar(w, "document.getElementById('nombre').textContent == 'mala.zip'")
            resultado["clave_visible_zip"] = w.evaluate_js("!document.getElementById('campo-clave').hidden")
            w.evaluate_js("document.getElementById('clave').value = 'mala'; document.getElementById('analizar').click(); null")
            esperar(w, "document.getElementById('aviso').hidden === false")
            resultado["error_texto"] = texto_de("#aviso")
            resultado["error_tipo"] = w.evaluate_js("document.getElementById('aviso').className")
            resultado["botones_tras_error"] = w.evaluate_js("['elegir', 'analizar', 'clave', 'sinred'].map(id => document.getElementById(id).disabled)")
            resultado["violaciones_nuevas"] = w.evaluate_js("window.__v")

            # Cerrar la ventana a medias de un análisis: el hilo se queda esperando al motor, y se suelta después de cerrar
            entregar(notepad)
            soltar_en_bruto(w, notepad, nodo)
            esperar(w, "document.getElementById('nombre').textContent == 'notepad.exe'")
            with mock.patch.object(analisis, "informes", motor_de_la_ventana):
                w.evaluate_js("document.getElementById('analizar').click(); null")
                assert bloqueado.wait(30)
                esperar(w, "document.getElementById('actividad').textContent.includes('notepad.exe')")

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

    vigilante = threading.Timer(LIMITE, cortar)
    vigilante.start()
    try:
        with mock.patch.object(ventana.Puente, "_privado", lambda self: privado.append("llamado"), create=True), mock.patch.object(ventana, "Puente", PuenteDeLaPrueba):
            ventana.main(comprobar, hidden=True)  # vuelve cuando comprobar() cierra la ventana
    finally:
        vigilante.cancel()

    assert "error" not in resultado, resultado["error"]
    assert resultado["pie"] == f"Versión {__version__}", resultado  # el puente contestó desde dentro de la CSP
    assert resultado["api"] == ["analizar", "elegir", "version"], resultado  # lo único que la página ve del puente
    assert privado == [] and ventana.__version__ == __version__, (privado, ventana.__version__)  # la página no llegó a nada más que a lo expuesto
    assert resultado["falso_elegido"] is None and resultado["falso_visible"] is False, resultado  # el drop de mentira no fijó nada
    assert resultado["falso_aviso"] is False and "No se pudo leer la ruta" in resultado["falso_texto"], resultado  # el aviso va en la banda, no en un popup
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
    assert "MalwareBazaar" in resultado["resumen_azorult"] and "Microsoft Defender" in resultado["resumen_azorult"], resultado
    assert "0,93" in resultado["resumen_azorult"] and resultado["ember_azorult"] == "93%", resultado
    assert resultado["resumen_hostil"].startswith("Señales de alarma: 7") and "Esto solo cuenta señales" in resultado["resumen_hostil"], resultado
    assert resultado["ember_hostil"] == "50%" and HOSTIL in resultado["panel_hostil"], resultado  # el texto hostil se pinta como texto
    assert resultado["resumen_texto"].startswith("Señales de alarma: 1") and "Extensión que engaña" in resultado["resumen_texto"], resultado
    assert "no es un ejecutable de Windows" in resultado["panel_texto"] and resultado["ember_texto"] is None, resultado  # no-PE: ni EMBER ni estático
    assert resultado["botones"] == [False] * 4 and resultado["progreso_oculto"] is True, resultado  # al terminar se vuelve a poder todo
    assert resultado["inyecciones"] == [None, 1, 0], resultado  # ni el script ni la imagen del nombre hostil existen: solo el script de la página
    assert resultado["motor"] == [en_disco, None, True], resultado  # la ruta elegida por Python; sin clave (vacía) y con el interruptor de la página
    assert resultado["clave_visible_zip"] is True and resultado["error_texto"] == "contraseña incorrecta" and resultado["error_tipo"] == "error", resultado
    assert resultado["botones_tras_error"] == [False] * 4, resultado
    assert resultado["violaciones_nuevas"] == [], resultado  # nada de lo anterior rozó la CSP
    assert resultado["ejecutado"] is False and set(resultado["violaciones"]) == {"script-src-elem", "connect-src"}, resultado
    assert resultado["elegido_tras_hostil"] == notepad, resultado  # las llamadas en bruto a _soltar y _fijar no cambiaron nada
    assert resultado["sockets"] == [], resultado["sockets"]  # sin servidor HTTP
    # La ventana ya está cerrada y el análisis de notepad.exe sigue esperando al motor: soltarlo no puede petar ni colgar nada
    (puente_real,) = instancias
    assert puente_real._hilo.is_alive() and puente_real._ocupado
    bloqueo.set()
    puente_real._hilo.join(10)
    assert not puente_real._hilo.is_alive() and not puente_real._ocupado and errores.lineas == [], errores.lineas
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("OK")
