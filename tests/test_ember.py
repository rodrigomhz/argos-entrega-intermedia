# Se lanza con: python tests/test_ember.py (las partes 1 a 4 no necesitan nada ni usan la red; la 5 necesita el modelo EMBER2024 descargado con
# «argos actualiza», usa notepad.exe del propio Windows y carga thrember y LightGBM (~4 s). No escribe en tu argos-datos)
import atexit
import contextlib
import hashlib
import io
import shutil
import sys
import tempfile
import warnings
from pathlib import Path

from argos import __main__ as principal
from argos import actualiza, ember
from argos.actualiza import Pendiente

notepad = r"C:\Windows\System32\notepad.exe"
carpeta_real, huella_real, tamano_real = ember.CARPETA, ember.SHA256, ember.TAMANO
tmp = Path(tempfile.mkdtemp(prefix="argos-test-ember-"))
atexit.register(shutil.rmtree, tmp, ignore_errors=True)  # se borra aunque el test falle

# 1. Qué hay pendiente del modelo, con la carpeta y la huella esperada redirigidas a un temporal y SIN red: sin copia, con una huella mala y al día
abrir_real = actualiza.abrir


def sin_red(*args, **kwargs):
    raise AssertionError("saber si el modelo está al día no debe usar la red")


actualiza.abrir = sin_red
modelo_falso = b"esto hace de modelo"
ember.CARPETA, ember.SHA256, ember.TAMANO = tmp / "modelos", hashlib.sha256(modelo_falso).hexdigest(), len(modelo_falso)
destino = ember.CARPETA / ember.MODELO
pendiente = actualiza.pendiente_modelo()  # la carpeta ni existe
assert pendiente.motivo == "no hay copia" and pendiente.nombre == "modelo EMBER2024" and pendiente.tamano == len(modelo_falso), pendiente
assert pendiente.url == ember.URL and pendiente.destino == destino and pendiente.huella == ember.SHA256
assert pendiente.version is None and pendiente.instalador is None  # se baja con descargar() a secas: nada que anotar ni instalar
ember.CARPETA.mkdir()
destino.write_bytes(b"otra cosa")
assert actualiza.pendiente_modelo().motivo == "tu copia no coincide con la huella publicada"
destino.write_bytes(modelo_falso)
assert actualiza.pendiente_modelo() is None

# Entra en comprobar() (y por tanto en el aviso): con todo lo demás «al día», es lo único que sale cuando falta, y nada cuando está
reales = {nombre: getattr(actualiza, nombre) for nombre in ("pendiente_reglas", "pendiente_lista", "pendiente_herramienta", "pendiente_capa")}
for nombre in reales:
    setattr(actualiza, nombre, lambda *args, **kwargs: None)
assert actualiza.comprobar(sin_circl=True) == []
destino.unlink()
assert [p.nombre for p in actualiza.comprobar(sin_circl=True)] == ["modelo EMBER2024"]
for nombre, funcion in reales.items():
    setattr(actualiza, nombre, funcion)
actualiza.abrir = abrir_real

# 2. Descargar (con un file:// en vez de HuggingFace): con la huella buena queda el fichero y nada más; con una mala, OSError claro, sin restos y la copia de antes intacta
fuente = tmp / "fuente.model"
fuente.write_bytes(modelo_falso)
bajada = tmp / "bajada" / ember.MODELO
nuevo = Pendiente("modelo EMBER2024", "no hay copia", len(modelo_falso), fuente.as_uri(), bajada, huella=ember.SHA256)
salida = io.StringIO()
with contextlib.redirect_stdout(salida):
    actualiza.actualizar(pendientes=[nuevo])  # lo que lanza «argos actualiza»: tiene que pasar la huella a descargar()
assert bajada.read_bytes() == modelo_falso and [f.name for f in bajada.parent.iterdir()] == [ember.MODELO]  # ni .parte
assert "modelo EMBER2024: descargando" in salida.getvalue() and "modelo EMBER2024: hecho" in salida.getvalue()


def descarga_rechazada(funcion):
    try:
        funcion()
        raise AssertionError("debía rechazar una descarga cuya huella no coincide")
    except OSError as error:
        assert "no coincide con la huella publicada" in str(error) and "0" * 64 in str(error), error


mala = "0" * 64
bajada.write_bytes(b"copia de antes")
descarga_rechazada(lambda: actualiza.descargar(fuente.as_uri(), bajada, len(modelo_falso), mala))
assert bajada.read_bytes() == b"copia de antes" and [f.name for f in bajada.parent.iterdir()] == [ember.MODELO]
with contextlib.redirect_stdout(io.StringIO()):
    descarga_rechazada(lambda: actualiza.actualizar(pendientes=[nuevo._replace(huella=mala)]))
assert bajada.read_bytes() == b"copia de antes"
bajada.unlink()  # sin copia de antes: tampoco queda nada
descarga_rechazada(lambda: actualiza.descargar(fuente.as_uri(), bajada, len(modelo_falso), mala))
assert list(bajada.parent.iterdir()) == []
# Sin huella (reglas, listas...) la descarga sigue como antes
actualiza.descargar(fuente.as_uri(), bajada, len(modelo_falso))
assert bajada.read_bytes() == modelo_falso

# 3. Puntuar sin el modelo: «no disponible», sin traza y SIN cargar thrember ni LightGBM (son ~4 s que no hay por qué pagar)
ember.CARPETA = tmp / "no-hay-modelos"
assert "thrember" not in sys.modules and "lightgbm" not in sys.modules
resultado = ember.puntuar(b"MZ")
assert resultado["estado"] == "no disponible" and ember.MODELO in resultado["detalle"], resultado
assert "thrember" not in sys.modules and "lightgbm" not in sys.modules
# Lo que no es un PE ni se puntúa
puntuar_real = ember.puntuar


def no_debe_puntuar(datos):
    raise AssertionError("un fichero que no es un ejecutable de Windows no se puntúa")


ember.puntuar = no_debe_puntuar
assert principal.puntuar_ember(b"hola", False) == {"estado": "no aplica", "detalle": "solo ejecutables de Windows (PE)"}
ember.puntuar = puntuar_real

# 4. La línea del informe: puntuación con coma decimal y dos decimales, y cada estado en el estilo de capa y Detect It Easy
sin_dato = {"estado": "no aplica", "detalle": ""}


def linea(resultado):
    salida = io.StringIO()
    with contextlib.redirect_stdout(salida):
        principal.mostrar_herramientas(sin_dato, sin_dato, resultado)
    return salida.getvalue().splitlines()[-1]  # las dos primeras son capa y DIE


assert linea({"estado": "ok", "puntuacion": 0.0289}) == "EMBER2024:     0,03 (0 = parece legítimo, 1 = parece malware; umbral sin calibrar hasta el hito 7)"
assert linea({"estado": "ok", "puntuacion": 0.5}).startswith("EMBER2024:     0,50 (") and linea({"estado": "ok", "puntuacion": 1.0}).startswith("EMBER2024:     1,00 (")
assert linea({"estado": "no disponible", "detalle": "falta x"}) == "EMBER2024:     no disponible (ejecuta «argos actualiza»)"
assert linea({"estado": "error", "detalle": "IndexError: x"}) == "EMBER2024:     error: IndexError: x"
assert linea(principal.puntuar_ember(b"hola", False)) == "EMBER2024:     no aplica: solo ejecutables de Windows (PE)"

# 4b. Lo que thrember y LightGBM dicen por su cuenta (print por stdout, warnings) no sale, y al terminar todo vuelve a su sitio
salida = io.StringIO()
with contextlib.redirect_stdout(salida), warnings.catch_warnings(record=True) as avisos:
    warnings.simplefilter("always")
    with ember._en_silencio():
        print("WARN: Unknown pefile warning: algo")
        warnings.warn("un aviso de Python")
    print("esto sí sale")
    warnings.warn("este también")
assert salida.getvalue() == "esto sí sale\n" and [str(a.message) for a in avisos] == ["este también"], (salida.getvalue(), avisos)

# 5. Con el modelo de verdad: notepad.exe parece legítimo
ember.CARPETA, ember.SHA256, ember.TAMANO = carpeta_real, huella_real, tamano_real
assert (ember.CARPETA / ember.MODELO).is_file(), "falta el modelo EMBER2024: ejecuta «argos actualiza»"
assert actualiza.pendiente_modelo() is None, "la copia del modelo no coincide con la huella publicada: ejecuta «argos actualiza»"
datos = Path(notepad).read_bytes()
resultado = ember.puntuar(datos)  # bytes en memoria, como los de un miembro de un zip
assert resultado["estado"] == "ok" and 0 <= resultado["puntuacion"] < 0.5, resultado

# Una muestra malformada nunca tumba el informe: con bytes basura que empiezan por MZ, o vacíos, da un resultado (ok o error) y no una excepción
for basura in (b"MZ" + bytes(range(256)) * 20, b"MZ", b""):
    assert ember.puntuar(basura)["estado"] in ("ok", "error"), basura
# ...y si thrember falla, sale como «error» con su motivo (aquí forzado)
import thrember

predecir = thrember.predict_sample


def falla(modelo, datos):
    raise ValueError("cabecera rota")


thrember.predict_sample = falla
assert ember.puntuar(datos) == {"estado": "error", "detalle": "ValueError: cabecera rota"}
thrember.predict_sample = predecir

# thrember imprime «WARN: Unknown pefile warning» cuando pefile avisa de algo que no conoce: se fuerza un aviso así, se comprueba que sin silenciar sale
# por stdout (que la prueba no es vacía) y que puntuar() no deja pasar nada
import pefile

avisos_reales = pefile.PE.get_warnings
pefile.PE.get_warnings = lambda self: ["Aviso inventado que thrember no conoce"]
directa = io.StringIO()
with contextlib.redirect_stdout(directa):
    thrember.predict_sample(ember._cargar(ember.CARPETA / ember.MODELO), datos)
callada = io.StringIO()
with contextlib.redirect_stdout(callada):
    resultado = ember.puntuar(datos)
pefile.PE.get_warnings = avisos_reales
assert "WARN: Unknown pefile warning: Aviso inventado" in directa.getvalue(), directa.getvalue()
assert callada.getvalue() == "" and resultado["estado"] == "ok", (callada.getvalue(), resultado)

# LightGBM manda sus mensajes nativos por stdout, como «[LightGBM] [Warning] ...» (aquí, con un parámetro inventado en predict): sin silenciar salen, silenciados no
modelo = ember._cargar(ember.CARPETA / ember.MODELO)
directa, callada = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(directa):
    modelo.predict([[0.0] * 2568], parametro_inventado=1)
with contextlib.redirect_stdout(callada), ember._en_silencio():
    modelo.predict([[0.0] * 2568], parametro_inventado=1)
assert "[LightGBM] [Warning]" in directa.getvalue() and callada.getvalue() == "", (directa.getvalue(), callada.getvalue())

print("OK")
