# Se lanza con: python tests/test_aviso.py (no usa la red ni toca tu argos-datos: la comprobación, la actualización y la entrada del usuario son falsas)
import io
import os
import sys
import tempfile
import time
import urllib.error
from pathlib import Path

from argos import __main__ as principal
from argos import actualiza
from argos.actualiza import Pendiente


class Flujo(io.StringIO):
    """Sustituye a stdin y stdout: guarda lo escrito y dice si es una terminal."""

    def __init__(self, terminal):
        super().__init__()
        self.terminal = terminal

    def isatty(self):
        return self.terminal


nuevos = [
    Pendiente("reglas YARA 20261020", "tu copia es la 20261011", 1_700_000, "url", Path("a"), "20261020"),
    Pendiente("CIRCL", "no hay copia", 1_002_366_384, "url", Path("b")),
]
llamadas = []  # lo que ha hecho Argos, en orden: "comprobar", "pregunta" y ("actualizar", pendientes)
ultima = Path(tempfile.gettempdir()) / "argos-test-aviso"  # sustituye a la marca de la última comprobación
actualiza.ULTIMA_COMPROBACION = ultima


def comprobar_ok(sin_circl, espera):
    llamadas.append("comprobar")
    return nuevos


def actualizar_falso(sin_circl=False, pendientes=None):
    llamadas.append(("actualizar", pendientes))


actualiza.comprobar = comprobar_ok
actualiza.actualizar = actualizar_falso


def reiniciar(horas):
    """Borra lo anotado y pone la última comprobación hace `horas` horas (None: nunca)."""
    llamadas.clear()
    ultima.unlink(missing_ok=True)
    if horas is not None:
        pasado = time.time() - horas * 3600
        ultima.touch()
        os.utime(ultima, (pasado, pasado))


def ejecutar(terminal, respuesta, funcion):
    """Lanza funcion() con stdin y stdout falsos (terminal o no) y la respuesta falsa a la pregunta; devuelve lo que imprimió."""
    actualiza.input = lambda pregunta: llamadas.append("pregunta") or respuesta
    reales = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = Flujo(terminal), Flujo(terminal)
    try:
        funcion()
        return sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = reales


# (a) con la última comprobación de hace menos de 24 h no comprueba nada; con una de hace más, sí, y la anota
reiniciar(horas=23)
assert ejecutar(True, "s", actualiza.avisar) == "" and llamadas == []
reiniciar(horas=25)
ejecutar(False, "", actualiza.avisar)
assert llamadas == ["comprobar"] and time.time() - ultima.stat().st_mtime < 60

# (b) sin terminal: avisa con nombre y tamaño y no pregunta ni actualiza
reiniciar(horas=None)
salida = ejecutar(False, "s", actualiza.avisar)
assert llamadas == ["comprobar"]
assert "Hay datos nuevos: reglas YARA 20261020 (1,7 MB), CIRCL (1002,4 MB)." in salida
assert "argos actualiza" in salida

# (c) en una terminal pregunta: con «s» actualiza justo lo pendiente; con «n» no, y recuerda «argos actualiza»
reiniciar(horas=None)
ejecutar(True, "s", actualiza.avisar)
assert llamadas == ["comprobar", "pregunta", ("actualizar", nuevos)]
reiniciar(horas=None)
salida = ejecutar(True, "n", actualiza.avisar)
assert llamadas == ["comprobar", "pregunta"]
assert "argos actualiza" in salida

# (d) sin red (o con una respuesta rara) el análisis sigue sin traza ni mensaje, y no se vuelve a intentar hasta dentro de 24 h
for error in (urllib.error.URLError("sin red"), KeyError("tag_name")):
    def comprobar_roto(sin_circl, espera):
        llamadas.append("comprobar")
        raise error

    actualiza.comprobar = comprobar_roto
    reiniciar(horas=None)
    assert ejecutar(True, "s", actualiza.avisar) == ""
    assert ejecutar(True, "s", actualiza.avisar) == ""
    assert llamadas == ["comprobar"]  # la segunda vez no lo intenta
actualiza.comprobar = comprobar_ok

# (e) --sin-red no comprueba; sin él, sí (el análisis se sustituye por uno falso: solo se prueba el cableado de main)
principal.identificar = lambda fichero: {}
principal.mostrar = lambda datos, sin_red: None


def lanzar(*opciones):
    sys.argv = ["argos", "identifica", __file__, *opciones]
    principal.main()


reiniciar(horas=25)  # marca vieja: tocaría comprobar
ejecutar(False, "", lambda: lanzar("--sin-red"))
assert llamadas == []
ejecutar(False, "", lambda: lanzar())
assert llamadas == ["comprobar"]

ultima.unlink(missing_ok=True)
print("OK")
