"""El motor de Argos: analiza y devuelve datos, no imprime nada. La terminal (__main__) y la ventana usan el mismo."""
import contextlib
import json
from pathlib import Path

import pyzipper
from magika import Magika

from argos import ember, enlinea, estatico, herramientas, identificacion

SECCIONES = ("identificacion", "estatico")
# Las partes del análisis estático, en el orden en que se calculan (de barata a cara): cuelgan de informe["estatico"]
PARTES_ESTATICAS = ("pe", "firma", "suplantacion", "defender", "yara", "ember", "die", "capa")


class ErrorAnalisis(Exception):
    """No se pudo ni empezar a analizar (contraseña mala, zip roto). El texto es el que se le enseña al usuario."""


def puntuar_ember(datos, es_pe):
    """Como herramientas.analizar: solo los ejecutables de Windows (PE) se puntúan. Trabaja con los bytes en memoria, sirve para un zip."""
    return ember.puntuar(datos) if es_pe else {"estado": "no aplica", "detalle": "solo ejecutables de Windows (PE)"}


def _miembros(ruta, clave):
    """[(nombre, bytes)] de cada fichero del zip; ErrorAnalisis si la contraseña o el zip fallan."""
    try:
        return list(identificacion.miembros_zip(ruta, clave))
    except RuntimeError:  # pyzipper lo lanza con la contraseña mala o vacía
        raise ErrorAnalisis("contraseña incorrecta") from None
    except pyzipper.BadZipFile:  # ojo: no es zipfile.BadZipFile, pyzipper lleva su propia copia
        raise ErrorAnalisis("el fichero no es un zip válido o está roto") from None


def _anotador(informe, indice, avisar):
    """listo(parte, valor): anota la parte en el informe y avisa de ella. Pasa el valor por JSON para que lo devuelto y lo avisado sea lo mismo."""
    def listo(parte, valor):
        # Ida y vuelta por JSON: las tuplas (listas, capacidades de capa, coincidencias de YARA) pasan a listas, y si algún día se cuela un objeto
        # que json.dumps no sabe escribir falla aquí, en el análisis, y no dentro de la ventana
        valor = json.loads(json.dumps(valor))
        if parte in PARTES_ESTATICAS:
            informe.setdefault("estatico", {})[parte] = valor
        else:
            informe[parte] = valor
        if avisar:
            avisar(indice, parte, valor)

    return listo


def _estatico(datos, nombre, ruta, listo):
    """Las partes del estático de unos bytes. ruta: el fichero en el disco; None si solo están en memoria (un miembro de un zip)."""
    pe = estatico.analizar_pe(datos)
    listo("pe", pe)
    es_pe = pe is not None
    suelto = ruta is not None
    with contextlib.ExitStack() as pila:  # la copia temporal de un miembro se borra al salir de aquí, tras capa y DIE
        sin_copia = None
        if not suelto:
            try:
                ruta = pila.enter_context(estatico.copia_temporal(datos, nombre))  # una sola copia para Defender, firma, capa y DIE
            except estatico.SinCopia as sin:
                sin_copia = sin
        firma = estatico.verificar_firma(ruta) if es_pe and not sin_copia else None
        listo("firma", firma)
        listo("suplantacion", estatico.suplantacion(pe, firma) if es_pe else None)
        # copia_temporal ya pasó la puerta de Defender antes de escribir; un fichero suelto la pasa aquí
        listo("defender", sin_copia.defender if sin_copia else estatico.defender(ruta, puerta=suelto))
        listo("yara", estatico.yara(datos))
        listo("ember", puntuar_ember(datos, es_pe))
        if sin_copia:
            listo("die", sin_copia.no_aplicado)
            listo("capa", sin_copia.no_aplicado)
        else:
            herramientas.analizar(ruta, es_pe, listo)


def analizar(ruta, clave=None, sin_red=False, secciones=SECCIONES, avisar=None):
    """Un informe (dict) por fichero analizado: uno si es suelto, uno por miembro si hay clave (el zip se lee en memoria, nunca se extrae).

    Cada informe lleva "nombre" y, según secciones: "identificacion" y "en_linea" (None con sin_red), "estatico" (un dict con
    PARTES_ESTATICAS: pe, firma, suplantacion... lo que no aplica sale None). Todo es JSON: se puede pasar tal cual a la ventana.
    avisar(indice, parte, valor), si se da, se llama primero con ("nombre", nombre) y después en cuanto cada parte está lista, de la
    barata a la cara: identificacion, en_linea, pe, firma, suplantacion, defender, yara, ember, die y capa (indice es la posición del
    fichero en la lista que se devuelve). ErrorAnalisis si la contraseña es mala o el zip está roto.
    """
    return list(informes(ruta, clave, sin_red, secciones, avisar))


def informes(ruta, clave=None, sin_red=False, secciones=SECCIONES, avisar=None):
    """Lo mismo que analizar(), pero entrega cada informe en cuanto está: la terminal imprime un fichero de un zip mientras se analiza el siguiente.

    ErrorAnalisis (contraseña mala, zip roto) salta al pedir el primero, antes de que haya nada que imprimir.
    """
    # (nombre, bytes); bytes None = el fichero se queda en el disco y se lee de ahí
    ficheros = [(Path(ruta).name, None)] if clave is None else _miembros(ruta, clave)
    # Un Magika para todo el zip (cargar el modelo cuesta); un fichero suelto lo crea identificacion.identificar
    magika = Magika() if clave is not None and "identificacion" in secciones else None
    for indice, (nombre, datos) in enumerate(ficheros):
        informe = {"nombre": nombre}
        if avisar:  # la ventana necesita el nombre de cada fichero de un zip antes de recibir sus partes
            avisar(indice, "nombre", nombre)
        listo = _anotador(informe, indice, avisar)
        if "identificacion" in secciones:
            ficha = identificacion.identificar(ruta) if datos is None else identificacion.identificar_datos(datos, nombre, magika)
            listo("identificacion", ficha)
            # ponytail: una consulta en línea por miembro, y el VirusTotal gratuito admite 4 por minuto: con un zip grande los últimos saldrán «límite».
            # Mejorar: esperar entre consultas o dejar de preguntar a VirusTotal al primer «límite»
            listo("en_linea", None if sin_red else enlinea.consultar(ficha["sha256"]))
        if "estatico" in secciones:
            if datos is None:
                # ponytail: el fichero entero en memoria; los ejecutables suelen ocupar poco
                _estatico(Path(ruta).read_bytes(), nombre, ruta, listo)
            else:
                _estatico(datos, nombre, None, listo)
        yield informe
