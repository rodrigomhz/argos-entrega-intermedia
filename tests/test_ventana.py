# Se lanza con: python tests/test_ventana.py (la parte 3 abre de verdad la ventana, oculta, unos segundos: necesita el WebView2 de Windows. No usa la red ni toca tu argos-datos.
# Las dos líneas «[pywebview] Function ... does not exist» que salen son lo esperado: pywebview rechazando los mensajes de la página hostil)
import json
import os
import re
import subprocess
import threading
import time
import traceback
from importlib.resources import files
from unittest import mock

import webview

from argos import __version__, ventana

LIMITE = 90  # segundos para toda la prueba de humo: si WebView2 no arranca o se cuelga, se corta con un error en vez de quedarse esperando

# 1. El puente: la versión, y nada más de público (un método «_privado» o nuevo sin pensar sería una puerta más desde la página)
assert ventana.Puente().version() == __version__
assert [nombre for nombre in dir(ventana.Puente) if not nombre.startswith("_")] == ["version"]

# 2. La página: CSP cerrada y nada externo ni montado con HTML
html = files("argos").joinpath("ventana.html").read_text(encoding="utf-8")
csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]*)"', html).group(1)
directivas = {d.split()[0]: d.split()[1:] for d in csp.split("; ")}
assert directivas["default-src"] == ["'none'"] and directivas["connect-src"] == ["'none'"], csp
assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp, csp  # los scripts y estilos propios van por nonce
for prohibido in ("http://", "https://", "innerHTML"):
    assert prohibido not in html, prohibido
assert not re.search(r"\b(?:src|href)=|@import|url\(", html), "la página no carga ficheros externos"
primera, segunda = ventana.pagina(), ventana.pagina()
assert "__NONCE__" not in primera and primera != segunda  # un nonce nuevo en cada arranque
nonce = re.search(r"script-src 'nonce-([^']+)'", primera).group(1)
assert f"style-src 'nonce-{nonce}'" in primera and primera.count(f'nonce="{nonce}"') == 2  # el script y el estilo de la página

# 3. Prueba de humo real: la ventana de verdad (oculta), con el puente y la CSP dentro de WebView2, y lo que intentaría una página hostil
resultado = {}
privado = []  # un método «_privado» de mentira en Puente: si la página llega a llamarlo, aparece aquí


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

        # Una página hostil manda el mensaje en bruto [nombre, parámetros en JSON, id] sin pasar por window.pywebview.api
        for nombre, parametros in (("_privado", "[]"), ("version.__globals__.update", '[{"__version__": "cambiada desde la página"}]')):
            w.evaluate_js(f"window.chrome.webview.postMessage({json.dumps([nombre, parametros, 'x'])}); null")
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

        # pywebview no debe haber abierto ningún puerto: todo socket TCP o UDP de este proceso saldría en netstat con su PID al final
        resultado["sockets"] = [linea for linea in subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout.splitlines()
                                if linea.split()[-1:] == [str(os.getpid())]]
    except BaseException:
        resultado["error"] = traceback.format_exc()
    finally:
        w.destroy()


def cortar():
    print(f"FALLO: la prueba de humo no terminó en {LIMITE} s (¿WebView2 no arranca?)", flush=True)
    os._exit(1)


vigilante = threading.Timer(LIMITE, cortar)
vigilante.start()
try:
    with mock.patch.object(ventana.Puente, "_privado", lambda self: privado.append("llamado"), create=True):
        ventana.main(comprobar, hidden=True)  # vuelve cuando comprobar() cierra la ventana
finally:
    vigilante.cancel()

assert "error" not in resultado, resultado["error"]
assert resultado["pie"] == f"Versión {__version__}", resultado  # el puente contestó desde dentro de la CSP
assert resultado["api"] == ["version"], resultado  # lo único que la página ve del puente
assert privado == [] and ventana.__version__ == __version__, (privado, ventana.__version__)  # la página no llegó a nada más que a version()
assert resultado["ejecutado"] is False and set(resultado["violaciones"]) == {"script-src-elem", "connect-src"}, resultado
assert resultado["sockets"] == [], resultado["sockets"]  # sin servidor HTTP

print("OK")
