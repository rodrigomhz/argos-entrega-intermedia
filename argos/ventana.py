"""La ventana de Argos: una página local dentro de WebView2 (pywebview), sin servidor HTTP y sin red.

El HTML va como cadena (html=), no como url=: con url pywebview levanta un servidor HTTP en 127.0.0.1 que cualquier proceso del equipo podría consultar.
Con debug=False WebView2 no abre herramientas de desarrollo, menú contextual ni atajos del navegador (F12, Ctrl+P...).
"""
import ctypes
import functools
import inspect
import json
import logging
import logging.handlers
import os
import secrets
import sys
import threading
import urllib.parse
from http.client import HTTPException
from importlib.resources import files
from pathlib import Path

import pyzipper
import webview
import webview.util
from webview.dom import _dnd_state

from argos import __version__, actualiza, analisis, enlinea, herramientas

registro = logging.getLogger("argos")
# argos-ventana.exe no tiene consola (pythonw: sys.stderr puede ser None), así que el registro va a un fichero. Solo lo configura main(): la terminal sigue como estaba
REGISTRO = Path.home() / "argos-datos" / "argos-ventana.log"
# La página oficial de descarga de WebView2 Runtime (redirige a su versión en el idioma del usuario). Solo se enseña como texto: Argos no abre nada por su cuenta
URL_WEBVIEW2 = "https://developer.microsoft.com/microsoft-edge/webview2/"
LIMITE_CLAVE = 256  # caracteres de la contraseña de un zip; la página no es de fiar y no hay motivo para aceptar más
# Las partes que el motor avisa por cada fichero, en orden (la página pinta la lista antes de que llegue la primera)
PARTES = ("identificacion", "en_linea", *analisis.PARTES_ESTATICAS)

# Las rutas que WebView2 ha entregado de verdad en un soltar. La página NO puede dar una ruta a Python, pero pywebview 6.2.1 no lo garantiza por sí solo (medido):
# - edgechromium.py:229-241: al soltar, el JS de pywebview manda 'FilesDropped' con los ficheros reales (CoreWebView2File, que la página no puede fabricar) y pywebview
#   guarda (nombre, ruta) en _dnd_state['paths'];
# - util.py:285-300 (js_bridge_call, 'pywebviewEventHandler'): el evento que llega al manejador de Python lo manda la página, y pywebview solo escribe
#   file['pywebviewFullPath'] si el nombre coincide con una ruta guardada (línea 296: si no, «continue» y el dict queda como lo mandó la página). Una página
#   hostil manda un evento «drop» falso con su propio pywebviewFullPath y el manejador lo recibe tal cual (probado en la ventana real);
# - util.py:300 borra la ruta de _dnd_state['paths'] justo antes de llamar al manejador, así que ahí ya no se puede comprobar.
# De modo que se anotan aquí al entrar (_Soltados) y _soltar solo se fía de una ruta de esta lista.
# ponytail: depende de _dnd_state, privado de pywebview 6.x (pyproject lo limita a <7). Si cambia, soltar falla cerrado (rechaza todo) y queda el botón «Elegir fichero»
soltadas = set()


class _Soltados(list):
    """Hace de _dnd_state['paths']: una lista que además apunta cada ruta que pywebview recibe de WebView2 (con el unquote que pywebview le aplicará al entregarla)."""

    def extend(self, pares):
        pares = list(pares)
        soltadas.update(urllib.parse.unquote(ruta) for _, ruta in pares)
        super().extend(pares)

    def __iadd__(self, pares):  # edgechromium hace «_dnd_state['paths'] += files», y list.__iadd__ no pasa por extend
        self.extend(pares)
        return self


def vigilar_soltados():
    if not isinstance(_dnd_state["paths"], _Soltados):
        _dnd_state["paths"] = _Soltados(_dnd_state["paths"])


def rechazo(motivo):
    return {"ok": False, "motivo": motivo}


# Lo que sin_trazas ve en lugar de unos parámetros que no eran una lista (ver solo_listas)
_NO_LISTA = object()


def sin_trazas(metodo):
    """El método tal como se le expone a la página (main() lo aplica a cada uno): un fallo no le llega con su traza, sino como un rechazo genérico.

    Medido con pywebview 6.2.1 (webview/util.py:253-266, js_bridge_call._call): si el método lanza una excepción, pywebview le devuelve a la página el mensaje, el nombre y
    la traza completa, con las rutas del equipo (venv, usuario). Eso pasaba con solo llamar con un número de argumentos equivocado. Aquí la traza va al registro.
    Conserva __name__ (functools.wraps): pywebview nombra la función en JS con él. Los valores de los argumentos no se registran: la contraseña de un zip va en uno.
    """
    firma = inspect.signature(metodo)

    @functools.wraps(metodo)
    def envuelto(*args, **kwargs):
        try:
            if any(a is _NO_LISTA for a in args):
                raise TypeError("los parámetros no eran una lista")
            firma.bind(*args, **kwargs)  # un TypeError de argumentos se distingue así de uno que salga de dentro del método
        except TypeError:
            registro.warning("la página llamó a %s con argumentos que no encajan (%d posicionales)", metodo.__name__, len(args), exc_info=True)
            return rechazo("Argumentos no válidos")
        try:
            return metodo(*args, **kwargs)
        except Exception:
            registro.exception("falló %s", metodo.__name__)
            return rechazo("Error inesperado")

    return envuelto


def solo_listas(js_bridge_call):
    """El js_bridge_call de pywebview, pero una llamada a un método expuesto cuyos parámetros no son una lista llega a sin_trazas como un argumento no válido.

    sin_trazas no puede cubrir esto: pywebview hace func(*param) (webview/util.py:255) y, si param es null o un número, la excepción salta ahí, antes de entrar en el
    método, y la traza vuelve a la página por el mismo camino (medido en la ventana real con param «null» y «5»).
    """
    @functools.wraps(js_bridge_call)
    def filtrada(window, func_name, param, value_id):
        if func_name in window._functions and not isinstance(param, list):
            param = [_NO_LISTA]
        return js_bridge_call(window, func_name, param, value_id)

    return filtrada


class _FormatoSinClaves(logging.Formatter):
    """El formato del registro, pero ninguna clave de API llega al fichero aunque algún texto la lleve: si el valor de una de las variables de enlinea
    aparece en una línea (mensaje o traza), sale «***». enlinea ya las oculta en sus textos; esto es el seguro en el último punto, el fichero."""

    def format(self, record):
        texto = super().format(record)
        for _, _, variable, _ in enlinea.SERVICIOS:
            clave = (os.environ.get(variable) or "").strip() if variable else ""
            if clave:
                texto = texto.replace(clave, "***")
        return texto


def configurar_registro():
    """El logger «argos» (y el de pywebview, con sus errores de WebView2) al fichero REGISTRO, y las excepciones sin capturar de cualquier hilo también.

    Devuelve el manejador, o None si no se puede escribir en el fichero (la ventana abre igual).
    """
    try:
        REGISTRO.parent.mkdir(parents=True, exist_ok=True)
        manejador = logging.handlers.RotatingFileHandler(REGISTRO, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    except OSError:
        # ponytail: sin sitio donde escribir (carpeta de solo lectura, disco lleno...) las trazas se pierden como hasta ahora. Mejorar: avisar en la ventana
        return None
    manejador.setFormatter(_FormatoSinClaves("%(asctime)s %(levelname)s %(name)s [%(threadName)s] %(message)s"))
    for nombre in ("argos", "pywebview"):
        logging.getLogger(nombre).addHandler(manejador)
    registro.setLevel(logging.INFO)
    # ponytail: dos ventanas abiertas a la vez pelean por el fichero y Windows no deja rotarlo mientras otro proceso lo tiene abierto (esa línea se pierde)
    anterior, anterior_hilo = sys.excepthook, threading.excepthook

    def excepcion(tipo, valor, traza):
        registro.critical("excepción sin capturar", exc_info=(tipo, valor, traza))
        anterior(tipo, valor, traza)  # con pythonw no tiene dónde escribir y no hace nada; desde una terminal, como siempre

    def excepcion_hilo(args):
        if args.exc_type is not SystemExit:
            registro.critical("excepción sin capturar en el hilo %s", args.thread.name if args.thread else "?", exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
        anterior_hilo(args)

    sys.excepthook, threading.excepthook = excepcion, excepcion_hilo
    return manejador


def donde_esta_la_traza():
    return f"la traza está en {REGISTRO}"


def aviso_nativo(titulo, texto):
    """Un cuadro de mensaje nativo de Windows, sin pywebview: para cuando la ventana no puede abrirse. Espera a que se pulse Aceptar."""
    ctypes.windll.user32.MessageBoxW(None, texto, titulo, 0x10)  # MB_OK | MB_ICONERROR


TEXTO_SIN_WEBVIEW2 = (
    "Argos necesita Microsoft Edge WebView2 Runtime (y .NET Framework 4.6.2 o posterior) para abrir su ventana, y no lo encuentra.\n\n"
    f"Instálalo desde esta página de Microsoft y vuelve a abrir Argos:\n{URL_WEBVIEW2}\n\n"
    "Puedes copiar este texto con Ctrl+C."
)


class Puente:
    """Lo que la página puede llamar de Python (window.pywebview.api). Solo es puente lo que main() expone por nombre.

    Cada método expuesto es una puerta de la página a Python: si algo se cuela en la página (un nombre dentro de un zip, un dato de un servicio en línea), puede
    llamarla con los argumentos que quiera. Un método nuevo tiene que tratar sus argumentos como no fiables y hacer lo mínimo. Y no lanzar excepciones: pywebview
    le manda la traza a la página. main() expone cada método envuelto en sin_trazas, que lo evita aunque el método falle, pero es la red de seguridad, no el diseño:
    un fallo que llegue a ella sale como «Error inesperado» sin explicación.

    La ruta del fichero que se analiza no pasa nunca por la página: solo la fija _fijar, y a _fijar solo llegan la ruta de un soltar (_soltar) y la del diálogo
    nativo de Windows (elegir). analizar() no recibe ruta: analiza el fichero elegido.
    """

    def __init__(self, ventana):
        self._ventana = ventana
        self._cerrojo = threading.Lock()  # protege _elegido y _ocupado
        self._elegido = None  # ruta del fichero elegido
        self._ocupado = False  # hay un análisis en marcha
        self._dialogo = threading.Lock()  # un solo diálogo abierto a la vez
        self._hilo = None

    def version(self):
        return __version__

    def elegir(self):
        """Abre el diálogo nativo de Windows y fija el fichero que el usuario elija. No devuelve nada: la página se entera por el aviso «elegido»."""
        if self._ocupado:
            return self._enviar({"tipo": "rechazado", "texto": "Hay una tarea en marcha: espera a que termine"})
        if not self._dialogo.acquire(blocking=False):
            return
        try:
            elegidos = self._ventana.create_file_dialog(webview.FileDialog.OPEN)
        except Exception:
            registro.exception("no se pudo abrir el diálogo de ficheros")
            return self._enviar({"tipo": "rechazado", "texto": "No se pudo abrir el diálogo de ficheros"})
        finally:
            self._dialogo.release()
        if elegidos:  # None si el usuario cancela
            self._fijar(elegidos[0])

    def analizar(self, clave="", sin_red=False):
        """Analiza el fichero elegido en un hilo aparte, avisando a la página parte a parte. Devuelve {"ok": True} o {"ok": False, "motivo": ...}."""
        # Los dos argumentos vienen de la página
        if not isinstance(clave, str) or len(clave) > LIMITE_CLAVE:
            return rechazo(f"La contraseña tiene que ser un texto de {LIMITE_CLAVE} caracteres como máximo")
        if not isinstance(sin_red, bool):
            return rechazo("El interruptor «Sin red» no es válido")
        with self._cerrojo:
            if self._ocupado:
                return rechazo("Ya hay una tarea en marcha")
            if self._elegido is None:
                return rechazo("No hay ningún fichero elegido")
            self._ocupado = True
            ruta = self._elegido
        # clave vacía = el zip se analiza como un fichero más. Daemon: si se cierra la ventana a medias (capa tarda minutos), el proceso termina sin esperarlo
        self._hilo = threading.Thread(target=self._trabajar, args=(ruta, clave or None, sin_red), daemon=True)
        self._hilo.start()
        return {"ok": True}

    def actualizar(self, sin_circl=False):
        """Comprueba y descarga los datos pendientes en un hilo aparte, avisando del progreso. Devuelve {"ok": True} o {"ok": False, "motivo": ...}."""
        if not isinstance(sin_circl, bool):  # la casilla la manda la página: que sea exactamente un booleano
            return rechazo("La casilla «Sin CIRCL» no es válida")
        with self._cerrojo:
            if self._ocupado:
                return rechazo("Ya hay una tarea en marcha")
            self._ocupado = True
        self._hilo = threading.Thread(target=self._actualizar, args=(sin_circl,), daemon=True)
        self._hilo.start()
        return {"ok": True}

    def _soltar(self, evento):
        """Manejador del soltar de la zona (lo registra main). El evento lo manda la página: la única ruta de fiar es una que WebView2 haya entregado (soltadas)."""
        try:
            soltados = evento["dataTransfer"]["files"]
            ruta = soltados[0]["pywebviewFullPath"]
        except (KeyError, IndexError, TypeError):
            ruta = None
        if not isinstance(ruta, str) or ruta not in soltadas:
            return self._enviar({"tipo": "rechazado", "texto": "No se pudo leer la ruta del fichero soltado: usa «Elegir fichero»"})
        if self._fijar(ruta) and len(soltados) > 1:
            self._enviar({"tipo": "aviso", "texto": f"Has soltado {len(soltados)} ficheros: solo se analiza el primero"})

    def _fijar(self, ruta):
        """Fija el fichero elegido (una ruta de fiar: del soltar o del diálogo) y avisa a la página. True si lo fijó."""
        try:
            if os.path.isdir(ruta):
                return self._rechazar("Eso es una carpeta: Argos analiza ficheros, suelta uno solo")
            tamano = os.path.getsize(ruta)
            es_zip = pyzipper.is_zipfile(ruta)  # por el contenido, no por la extensión
        except OSError as error:
            return self._rechazar(f"No se puede leer el fichero: {error.strerror or 'error del sistema'}")
        with self._cerrojo:
            if self._ocupado:
                return self._rechazar("Hay una tarea en marcha: espera a que termine")
            self._elegido = ruta
        self._enviar({"tipo": "elegido", "nombre": os.path.basename(ruta), "bytes": tamano, "es_zip": es_zip})
        return True

    def _rechazar(self, texto):
        self._enviar({"tipo": "rechazado", "texto": texto})
        return False

    def _enviar(self, mensaje):
        """Manda un mensaje a la página: argos.recibir(<JSON>). El valor va SIEMPRE por json.dumps, nunca formateado a mano dentro del JS: el nombre de un fichero
        o de un miembro de un zip es del atacante, y json.dumps (ASCII puro) escapa las comillas, los saltos de línea, \\u2028 y todo lo demás."""
        cerrada = self._ventana.events.closed.is_set
        if cerrada():
            return
        try:
            self._ventana.evaluate_js(f"argos.recibir({json.dumps(mensaje)})")
        except Exception:
            if not cerrada():  # con la ventana cerrándose a medias, que no pueda avisar es lo esperado
                registro.exception("no se pudo avisar a la página")

    def _trabajar(self, ruta, clave, sin_red):
        """El hilo del análisis: avisa de cada parte según el motor la termina, y al final de 'terminado' o del error."""
        try:
            self._enviar({"tipo": "inicio", "partes": list(PARTES)})
            ficheros = sum(1 for _ in analisis.informes(ruta, clave, sin_red, avisar=self._avisar))
            final = {"tipo": "terminado", "ficheros": ficheros}
        except analisis.ErrorAnalisis as error:  # contraseña mala o zip roto: su texto es para el usuario
            final = {"tipo": "error", "texto": str(error)}
        except Exception:  # la traza al registro; a la página, un error genérico
            registro.exception("falló el análisis de %s", ruta)
            final = {"tipo": "error", "texto": f"Error inesperado durante el análisis ({donde_esta_la_traza()})"}
        finally:
            with self._cerrojo:  # antes de avisar del final, para que la página pueda volver a analizar en cuanto lo vea
                self._ocupado = False
        self._enviar(final)

    def _avisar(self, indice, parte, valor):
        self._enviar({"tipo": "parte", "indice": indice, "parte": parte, "valor": valor})

    def _actualizar(self, sin_circl):
        """El hilo de la actualización: las fases de actualiza.actualizar se reenvían tal cual a la página."""
        try:
            actualiza.actualizar(sin_circl, evento=self._aviso_actualiza)
            final = {"tipo": "actualiza", "estado": "fin"}
        except (OSError, HTTPException) as error:  # sin red, descarga cortada, disco lleno...: el texto es para el usuario
            final = {"tipo": "actualiza", "estado": "error", "texto": f"No se pudo actualizar: {error}"}
        except Exception:  # respuesta rara de una API, un JSON que no es lo esperado: traza al registro y aviso genérico
            registro.exception("falló la actualización de datos")
            final = {"tipo": "actualiza", "estado": "error", "texto": f"Error inesperado durante la actualización ({donde_esta_la_traza()})"}
        finally:
            with self._cerrojo:  # antes de avisar del final, para que la página pueda volver a usar los controles en cuanto lo vea
                self._ocupado = False
        self._enviar(final)

    def _aviso_actualiza(self, evento):
        self._enviar({"tipo": "actualiza", **evento})

    def _registrar_soltar(self):
        """Engancha _soltar a la zona de la página. Hay que hacerlo con la página cargada, y de nuevo si se recarga."""
        self._ventana.dom.get_element("#zona").on("drop", self._soltar)


def pagina():
    """El HTML de ventana.html con un nonce nuevo para la CSP: solo el script y el estilo que lo llevan se ejecutan."""
    html = files("argos").joinpath("ventana.html").read_text(encoding="utf-8")
    return html.replace("__NONCE__", secrets.token_urlsafe(16))


def main(func=None, **opciones):
    """Abre la ventana y no vuelve hasta que se cierra. func y opciones (hidden=True...) son solo para la prueba de humo."""
    configurar_registro()
    registro.info("Argos %s: arranca la ventana", __version__)
    # text_select=True: si no, pywebview mete un <style> sin nonce para impedir seleccionar texto y la CSP lo bloquea; además hay que poder copiar una huella
    # background_color: el beige de la app, para que al abrir (o al cambiar de tamaño) no se vea un destello blanco antes de pintarla
    ventana = webview.create_window("Argos", html=pagina(), width=900, height=640, min_size=(560, 420), text_select=True, background_color="#ece9d8", **opciones)
    puente = Puente(ventana)
    vigilar_soltados()
    ventana.events.loaded += puente._registrar_soltar
    # Cerrar la ventana corta lo que el análisis tenga en marcha (capa tarda minutos): el hilo del análisis es daemon, pero sus procesos no morirían con él
    ventana.events.closed += herramientas.cortar
    # Solo EdgeChromium (WebView2). pywebview en Windows (6.2.1) decide el motor al importar webview/platforms/winforms.py, y si falta WebView2 o .NET 4.6.2
    # (_is_chromium, winforms.py:68-127) CAE EN SILENCIO a MSHTML, el motor de Internet Explorer, que no entiende la CSP (winforms.py:130-155: solo un aviso «MSHTML is
    # deprecated» al logger de pywebview, sin excepción). Medido en el código instalado:
    # - gui="edgechromium" NO fuerza nada en Windows: guilib.py:128 solo mira si es 'qt', y winforms.py:131 solo lo usa para no usar WebView2 si es 'mshtml'. Sí sirve
    #   para que la variable de entorno PYWEBVIEW_GUI (guilib.py:92-98, solo se lee si no se pasa gui) no pueda bajar a Argos a mshtml o cef;
    # - lo que sí permite parar es el evento initialized: window.py:212 lo lanza con el motor elegido (gui.renderer) ANTES de crear el formulario y de cargar la página,
    #   __init__.py:282-284 hace que start() vuelva sin abrir nada si un manejador devuelve False, y window.py:167 lo declara con should_lock (se ejecuta en el momento,
    #   no en un hilo). Ojo: event.py:48-49 se traga las excepciones de un manejador y entonces NO aborta, así que este solo compara y registra: el aviso va después de start().
    # Quedan dos cosas fuera de nuestro alcance: al elegir MSHTML pywebview ya ha escrito sus claves de emulación de IE en HKCU (winforms.py:154, antes de este evento), y si
    # WebView2 está instalado pero falla al arrancar, edgechromium.py:267-273 solo lo registra (en el fichero de registro) y la ventana se queda en blanco.
    motores = []

    def exigir_edge(motor):
        motores.append(motor)
        registro.info("pywebview eligió el motor %s", motor)
        return motor == "edgechromium"  # False aborta start()

    ventana.events.initialized += exigir_edge
    # expose() y no js_api=Puente(): con js_api pywebview solo oculta a la página los nombres con «_», pero cuando le llega un mensaje busca el nombre con getattr
    # sin filtrar (webview/util.py, js_bridge_call). Medido en 6.2.1: una página que manda el mensaje en bruto (chrome.webview.postMessage) llama a un método «_privado»
    # y hasta a «version.__globals__.update(...)», que le cambia las variables del módulo. Con expose() el nombre se busca exacto entre los expuestos y ahí acaba.
    ventana.expose(*map(sin_trazas, (puente.actualizar, puente.analizar, puente.elegir, puente.version)))
    # ponytail: parche de webview.util.js_bridge_call, que es interno de pywebview 6.x (pyproject lo limita a <7). Tiene que hacerse antes de webview.start(): edgechromium.py:25
    # lo importa por su nombre al cargarse, dentro de start(). Si pywebview cambia, el test de la ventana real (parámetros «null» y «5») lo canta. Mejorar: arreglarlo en pywebview
    if not hasattr(webview.util.js_bridge_call, "__wrapped__"):
        webview.util.js_bridge_call = solo_listas(webview.util.js_bridge_call)
    webview.start(func, gui="edgechromium", debug=False)
    if motores and motores[0] != "edgechromium":
        registro.error("sin WebView2 no se abre la ventana (pywebview eligió %s)", motores[0])
        aviso_nativo("Argos", TEXTO_SIN_WEBVIEW2)
