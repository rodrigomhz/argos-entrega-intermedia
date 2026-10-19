"""La ventana de Argos: una página local dentro de WebView2 (pywebview), sin servidor HTTP y sin red.

El HTML va como cadena (html=), no como url=: con url pywebview levanta un servidor HTTP en 127.0.0.1 que cualquier proceso del equipo podría consultar.
Con debug=False WebView2 no abre herramientas de desarrollo, menú contextual ni atajos del navegador (F12, Ctrl+P...).
"""
import json
import logging
import os
import secrets
import threading
import urllib.parse
from http.client import HTTPException
from importlib.resources import files

import pyzipper
import webview
from webview.dom import _dnd_state

from argos import __version__, actualiza, analisis

registro = logging.getLogger("argos")
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


class Puente:
    """Lo que la página puede llamar de Python (window.pywebview.api). Solo es puente lo que main() expone por nombre.

    Cada método expuesto es una puerta de la página a Python: si algo se cuela en la página (un nombre dentro de un zip, un dato de un servicio en línea), puede
    llamarla con los argumentos que quiera. Un método nuevo tiene que tratar sus argumentos como no fiables y hacer lo mínimo. Y no lanzar excepciones: pywebview
    le manda la traza a la página.

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
            final = {"tipo": "error", "texto": "Error inesperado durante el análisis (la traza está en la salida de errores de Argos)"}
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
            final = {"tipo": "actualiza", "estado": "error", "texto": "Error inesperado durante la actualización (la traza está en la salida de errores de Argos)"}
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
    # text_select=True: si no, pywebview mete un <style> sin nonce para impedir seleccionar texto y la CSP lo bloquea; además hay que poder copiar una huella
    # background_color: el verde azulado del escritorio de la página, para que al abrir (o al cambiar de tamaño) no se vea un destello blanco antes de pintarla
    ventana = webview.create_window("Argos", html=pagina(), width=900, height=640, min_size=(560, 420), text_select=True, background_color="#008080", **opciones)
    puente = Puente(ventana)
    vigilar_soltados()
    ventana.events.loaded += puente._registrar_soltar
    # expose() y no js_api=Puente(): con js_api pywebview solo oculta a la página los nombres con «_», pero cuando le llega un mensaje busca el nombre con getattr
    # sin filtrar (webview/util.py, js_bridge_call). Medido en 6.2.1: una página que manda el mensaje en bruto (chrome.webview.postMessage) llama a un método «_privado»
    # y hasta a «version.__globals__.update(...)», que le cambia las variables del módulo. Con expose() el nombre se busca exacto entre los expuestos y ahí acaba.
    ventana.expose(puente.actualizar, puente.analizar, puente.elegir, puente.version)
    webview.start(func, debug=False)
