# Se lanza con: python tests/test_defender.py (usa notepad.exe y el Defender del propio Windows; no provoca ninguna detección)
import subprocess
import tempfile
from pathlib import Path

from argos import estatico

notepad = r"C:\Windows\System32\notepad.exe"

# El nombre dentro del zip lo controla el atacante: nunca llega a la ruta del disco
assert estatico._nombre_seguro("../../escape.txt") == "muestra.txt"
assert estatico._nombre_seguro("C:\\Windows\\x.exe:stream") == "muestra"
assert estatico._nombre_seguro("a/b/factura.pdf") == "muestra.pdf"

# El ajuste se lee de verdad de Windows (0 preguntar, 1 enviar las seguras, 2 nunca, 3 enviar todas)
assert estatico.consentimiento_muestras() in (0, 1, 2, 3)

# Se anota cada orden externa que se lanza, para saber si se ha ejecutado MpCmdRun
lanzadas = []
lanzar = subprocess.run


def espia(orden, *args, **kwargs):
    lanzadas.append(Path(orden[0]).name)
    return lanzar(orden, *args, **kwargs)


estatico.subprocess.run = espia

# La puerta: con 1 o 3 (Windows enviaría muestras sin preguntar) no se ejecuta MpCmdRun ni se escribe nada en el disco
crear_carpeta = tempfile.TemporaryDirectory


def no_escribir(*args, **kwargs):
    raise AssertionError("con el envío automático activado no se debe escribir nada en el disco")


tempfile.TemporaryDirectory = no_escribir
for valor in (1, 3):
    estatico.consentimiento_muestras = lambda: valor
    assert estatico.defender(notepad)["estado"] == "omitido"
    assert estatico.defender_datos(b"x", "x.txt")[0]["estado"] == "omitido"
assert lanzadas == []
tempfile.TemporaryDirectory = crear_carpeta

# Con 0 o 2 sí se ejecuta
for valor in (0, 2):
    estatico.consentimiento_muestras = lambda: valor
    lanzadas.clear()
    assert estatico.defender(notepad)["estado"] == "sin amenazas"
    assert lanzadas == ["MpCmdRun.exe"]

# MpCmdRun también devuelve 2 cuando falla (aquí, un fichero que no existe): eso no es una amenaza
assert estatico.defender(r"C:\no\existe\argos.exe")["estado"] == "error"

# Un fichero que viene de un zip: se analiza en la carpeta temporal y esta se borra; el nombre "../../escape.txt" no escapa de ella
assert estatico.defender_datos(b"texto inofensivo", "../../escape.txt") == ({"estado": "sin amenazas", "detalle": ""}, None)
assert not list(Path(tempfile.gettempdir()).glob("argos-defender-*"))
assert not (Path(tempfile.gettempdir()).parent / "escape.txt").exists()

# Código 2 con una amenaza nombrada en la salida (formato real de MpCmdRun, con un nombre inventado) = detectado
salida = "Scanning x found 1 threats.\n\n----- Threat information -----\nThreat                  : Virus:Test/Falso\nResources               : 1 total\n"
estatico.subprocess.run = lambda orden, *args, **kwargs: subprocess.CompletedProcess(orden, 2, stdout=salida)
assert estatico.defender(notepad) == {"estado": "DETECTADO", "detalle": "Virus:Test/Falso"}

print("OK")
