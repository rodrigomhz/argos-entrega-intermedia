# Se lanza con: python tests/test_aviso.py (no usa la red ni toca tu argos-datos: la comprobación, la actualización y la entrada del usuario son falsas)
import io
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
from pathlib import Path

from argos import __main__ as principal
from argos import actualiza, analisis
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
actualizar_real = actualiza.actualizar  # se guarda antes de sustituirla para la prueba de los eventos
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
analisis.analizar = lambda *args, **kwargs: [{}]
principal.mostrar = lambda informe: None


def lanzar(*opciones):
    sys.argv = ["argos", "identifica", __file__, *opciones]
    principal.main()


reiniciar(horas=25)  # marca vieja: tocaría comprobar
ejecutar(False, "", lambda: lanzar("--sin-red"))
assert llamadas == []
ejecutar(False, "", lambda: lanzar())
assert llamadas == ["comprobar"]

# (f) descargar() avisa del avance por bloques y solo deja el fichero bueno en su sitio (file://, sin red)
tmp_aviso = Path(tempfile.mkdtemp(prefix="argos-test-aviso-"))
origen, destino = tmp_aviso / "origen.bin", tmp_aviso / "destino.bin"
origen.write_bytes(b"x" * (2 * 1024 * 1024 + 7))
visto = []
actualiza.descargar(origen.as_uri(), destino, origen.stat().st_size, progreso=lambda recibidos, total: visto.append((recibidos, total)))
assert destino.read_bytes() == origen.read_bytes()
assert len(visto) >= 2 and visto[-1] == (origen.stat().st_size, origen.stat().st_size), visto
assert [r for r, _ in visto] == sorted(r for r, _ in visto), visto

# (f2) Una descarga que se interrumpe no deja .parte si el finally llega a correr (un fallo a medias), y si el proceso muere sin correrlo (cerrar la ventana en mitad de
# «Actualizar»: el hilo es daemon y el intérprete termina sin deshacer nada) el .parte se queda, pero la siguiente descarga lo pisa y no estorba a nadie
class Interrumpida(Exception):
    pass


def interrumpir(recibidos, total):
    raise Interrumpida


destino.unlink()
try:
    actualiza.descargar(origen.as_uri(), destino, origen.stat().st_size, progreso=interrumpir)
    raise AssertionError("tenía que interrumpirse")
except Interrumpida:
    pass
assert not destino.exists() and not destino.with_name(destino.name + ".parte").exists(), list(tmp_aviso.iterdir())  # el finally lo borró
muere = tmp_aviso / "muere.py"
muere.write_text("""import os, sys
from pathlib import Path
from argos import actualiza
origen, destino = map(Path, sys.argv[1:])
actualiza.descargar(origen.as_uri(), destino, origen.stat().st_size, progreso=lambda r, t: os._exit(7))  # _exit: el proceso muere sin correr ningún finally
""", encoding="utf-8")
muerto = subprocess.run([sys.executable, "-I", str(muere), str(origen), str(destino)], timeout=120)
parte = destino.with_name(destino.name + ".parte")
assert muerto.returncode == 7 and parte.is_file() and 0 < parte.stat().st_size < origen.stat().st_size and not destino.exists(), (muerto.returncode, list(tmp_aviso.iterdir()))
parte.write_bytes(b"z" * (origen.stat().st_size + 1000))  # peor aún: un .parte viejo MÁS GRANDE que la descarga nueva (open «wb» lo trunca, no se queda con la cola)
actualiza.descargar(origen.as_uri(), destino, origen.stat().st_size)
assert destino.read_bytes() == origen.read_bytes() and not parte.exists(), list(tmp_aviso.iterdir())

# (g) actualizar() con evento: las fases que pinta la ventana (descargando, progreso, hecho), sin red ni datos reales
descargar_real = actualiza.descargar
descargados = []


def descargar_falso(url, destino, esperado, huella=None, progreso=None):
    descargados.append((url, esperado))
    if progreso:
        progreso(esperado, esperado)


actualiza.descargar = descargar_falso
eventos = []
actualizar_real(pendientes=[Pendiente("dato", "no hay copia", 10, "url", tmp_aviso / "dato")], evento=eventos.append)
actualiza.descargar = descargar_real
assert descargados == [("url", 10)], descargados
assert [e["estado"] for e in eventos] == ["descargando", "progreso", "hecho"], eventos
assert eventos[0]["indice"] == 0 and eventos[0]["total"] == 1 and eventos[1]["recibidos"] == 10 and eventos[2]["nombre"] == "dato", eventos

ultima.unlink(missing_ok=True)
print("OK")
