import contextlib
import functools
import io
import warnings
from pathlib import Path

CARPETA = Path.home() / "argos-datos" / "modelos"
MODELO = "EMBER2024_PE.model"  # el modelo de PE (Joyce et al., KDD 2025; Apache-2.0): un solo fichero que cubre Win32, Win64 y .NET
# Fijada a una revisión de joyce8/EMBER2024-benchmark-models en HuggingFace y no a «main»: el modelo que Argos puntúa no cambia solo.
# La huella es la que publica HuggingFace para ese fichero (cabecera X-Linked-ETag) y coincide con la de la copia descargada.
# Como la URL es fija, saber si la copia está al día no necesita la red: basta comparar su SHA-256 con esta (actualiza.pendiente_modelo)
URL = "https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2/EMBER2024_PE.model"
TAMANO = 3756042
SHA256 = "4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99"


@contextlib.contextmanager
def _en_silencio():
    """Lo que thrember y LightGBM dicen por su cuenta no sale: el informe de Argos no debe llevar líneas que no sean suyas."""
    # thrember (features.py) hace print("WARN: Unknown pefile warning: ...") por stdout cuando pefile avisa de algo que su lista no trae;
    # LightGBM manda sus mensajes nativos a print y los de Python a warnings.warn: las dos vías quedan cubiertas
    # ponytail: redirect_stdout y catch_warnings son estado global del proceso, no de un hilo: con Argos de un solo hilo basta; si la interfaz
    # del hito 5 puntúa desde un hilo mientras otros imprimen, se les tragaría la salida. Mejorar: logging propio con lightgbm.register_logger
    with warnings.catch_warnings(), contextlib.redirect_stdout(io.StringIO()):
        warnings.simplefilter("ignore")
        yield


@functools.cache  # el modelo se lee una sola vez por ejecución, aunque haya muchos ficheros (un zip); por ruta, para no guardar nunca un «falta»
def _cargar(ruta):
    import lightgbm  # perezoso, por lo mismo que thrember en puntuar

    return lightgbm.Booster(model_file=str(ruta))


def puntuar(datos):
    """{"estado": "ok", "puntuacion": de 0 (parece legítimo) a 1 (parece malware)} o {"estado": "no disponible" | "error", "detalle": ...}.

    Trabaja con los bytes en memoria y no escribe nada en el disco: vale igual para un fichero suelto que para un miembro de un zip.
    """
    ruta = CARPETA / MODELO
    if not ruta.is_file():
        return {"estado": "no disponible", "detalle": f"falta {ruta}"}
    try:
        with _en_silencio():
            # El import va aquí y no arriba: «import thrember» arrastra lightgbm, scikit-learn y polars y tarda ~4 s (medido; hasta ~9 s con la máquina
            # ocupada), y «argos actualiza», «argos identifica» y el aviso de antes de analizar no lo necesitan; la predicción en sí tarda entre 0,06 s
            # y 2,5 s por fichero y cargar el modelo, 0,1 s
            # ponytail: thrember añade ~466 MB al venv, de los que ~260 MB (polars, matplotlib, huggingface_hub) solo sirven para entrenar o
            # bajar el dataset. Hito 8 (empaquetado): copiar solo features.py y pefile_warnings.txt (Apache-2.0, con su aviso de licencia)
            # y depender de lightgbm, scikit-learn y signify
            import thrember

            return {"estado": "ok", "puntuacion": thrember.predict_sample(_cargar(ruta), datos)}
    except Exception as error:
        # Aquí sí se captura Exception: thrember saca ~2.500 características con pefile, signify y expresiones regulares de bytes que controla
        # quien hizo la muestra y no documenta qué lanza (medido: IndexError con un fichero vacío; pefile puede dar AttributeError con
        # cabeceras rotas), y una muestra malformada no puede tumbar el informe entero. También cubre una instalación rota (ImportError)
        # o un modelo corrupto (LightGBMError): salen como «error» con su motivo, no como traza
        return {"estado": "error", "detalle": f"{type(error).__name__}: {error}"}
