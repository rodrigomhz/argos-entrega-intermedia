"""La ventana de Argos: una página local dentro de WebView2 (pywebview), sin servidor HTTP y sin red.

El HTML va como cadena (html=), no como url=: con url pywebview levanta un servidor HTTP en 127.0.0.1 que cualquier proceso del equipo podría consultar.
Con debug=False WebView2 no abre herramientas de desarrollo, menú contextual ni atajos del navegador (F12, Ctrl+P...).
"""
import secrets
from importlib.resources import files

import webview

from argos import __version__


class Puente:
    """Lo que la página puede llamar de Python (window.pywebview.api). Solo es puente lo que main() expone por nombre.

    Cada método expuesto es una puerta de la página a Python: si algo se cuela en la página (un nombre dentro de un zip, un dato de un servicio en línea), puede
    llamarla con los argumentos que quiera. Un método nuevo tiene que tratar sus argumentos como no fiables y hacer lo mínimo.
    """

    def version(self):
        return __version__


def pagina():
    """El HTML de ventana.html con un nonce nuevo para la CSP: solo el script y el estilo que lo llevan se ejecutan."""
    html = files("argos").joinpath("ventana.html").read_text(encoding="utf-8")
    return html.replace("__NONCE__", secrets.token_urlsafe(16))


def main(func=None, **opciones):
    """Abre la ventana y no vuelve hasta que se cierra. func y opciones (hidden=True...) son solo para la prueba de humo."""
    # text_select=True: si no, pywebview mete un <style> sin nonce para impedir seleccionar texto y la CSP lo bloquea; además hay que poder copiar una huella
    ventana = webview.create_window("Argos", html=pagina(), width=900, height=640, min_size=(560, 420), text_select=True, **opciones)
    # expose() y no js_api=Puente(): con js_api pywebview solo oculta a la página los nombres con «_», pero cuando le llega un mensaje busca el nombre con getattr
    # sin filtrar (webview/util.py, js_bridge_call). Medido en 6.2.1: una página que manda el mensaje en bruto (chrome.webview.postMessage) llama a un método «_privado»
    # y hasta a «version.__globals__.update(...)», que le cambia las variables del módulo. Con expose() el nombre se busca exacto entre los expuestos y ahí acaba.
    ventana.expose(Puente().version)
    webview.start(func, debug=False)
