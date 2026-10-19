# Se lanza con: python tests/test_analisis.py (usa notepad.exe y el Defender del propio Windows; capa, DIE, YARA, EMBER y Defender se sustituyen por
# falsos donde importa el orden o lo que se llama, y van de verdad con los dos ficheros de texto del zip. No usa la red ni toca tu argos-datos)
import contextlib
import hashlib
import json
import tempfile
from pathlib import Path
from unittest import mock

import pyzipper

from argos import analisis, ember, enlinea, estatico, herramientas, identificacion, listas
from argos.analisis import ErrorAnalisis

notepad = r"C:\Windows\System32\notepad.exe"
listas.CARPETA = Path("carpeta-que-no-existe")  # sin listas: el test no depende de ellas
estatico.consentimiento_muestras = lambda: 2  # la puerta de Defender abierta, lo diga el Windows que sea (test_defender prueba la puerta)
ORDEN = ["nombre", "identificacion", "en_linea", "pe", "firma", "suplantacion", "defender", "yara", "ember", "die", "capa"]
tmp = Path(tempfile.mkdtemp(prefix="argos-test-analisis-"))


class SeLlamo(BaseException):
    """BaseException a propósito: consultar() se traga las Exception, y esto tiene que reventar el test si alguien llega a llamar."""


def reventar(*args, **kwargs):
    raise SeLlamo(f"no debía llamarse: {args}")


def zip_aes(nombre, miembros, clave=b"infected"):
    ruta = tmp / nombre
    with pyzipper.AESZipFile(ruta, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(clave)
        for miembro, contenido in miembros.items():
            z.writestr(miembro, contenido)
    return str(ruta)


def sustituir(pila, modulo, **nuevos):
    for nombre, nuevo in nuevos.items():
        pila.enter_context(mock.patch.object(modulo, nombre, nuevo))


try:
    # 1. Un zip AES con dos ficheros inofensivos: dos informes, con lo de verdad (Magika, Defender, YARA, DIE) y todo en JSON
    texto = zip_aes("dos.zip", {"uno.txt": b"hola argos", "dos.txt": b"adios argos"})
    informes = analisis.analizar(texto, "infected", sin_red=True)
    assert [i["nombre"] for i in informes] == ["uno.txt", "dos.txt"], informes
    assert informes[0]["identificacion"]["sha256"] == hashlib.sha256(b"hola argos").hexdigest()
    assert informes[1]["identificacion"]["sha256"] == hashlib.sha256(b"adios argos").hexdigest()
    for informe in informes:
        assert informe["en_linea"] is None  # con sin_red
        e = informe["estatico"]
        assert list(e) == list(analisis.PARTES_ESTATICAS), list(e)
        assert e["pe"] is None and e["firma"] is None and e["suplantacion"] is None and e["ember"]["estado"] == "no aplica"
        assert e["defender"]["estado"] == "sin amenazas" and e["capa"]["estado"] == "no aplica", e
        assert e["yara"] in ([], None) and e["die"]["estado"] in ("ok", "no disponible"), e
    assert json.loads(json.dumps(informes)) == informes  # serializable, y sin tuplas (volverían como listas)
    assert not list(Path(tempfile.gettempdir()).glob("argos-defender-*"))  # la copia temporal se borra

    # 2. Un fichero suelto es un informe, sobre el fichero del disco: pe y firma de verdad, lo demás falso para anotar el orden y qué ruta ve cada parte
    avisos, rutas = [], []
    firma_real = estatico.verificar_firma

    def avisar(indice, parte, valor):
        avisos.append((indice, parte, valor))

    def vista(nombre, resultado):
        def falsa(ruta, *args, **kwargs):
            # en cuanto cada parte está lista se avisa, sin esperar a las caras: al llegar a capa, ya se había avisado de todas las anteriores
            rutas.append((nombre, str(ruta), kwargs.get("puerta"), [parte for _, parte, _ in avisos]))
            return resultado
        return falsa

    with contextlib.ExitStack() as pila:
        sustituir(pila, estatico, defender=vista("defender", {"estado": "sin amenazas", "detalle": ""}),
                  verificar_firma=lambda ruta: rutas.append(("firma", str(ruta), None, None)) or firma_real(ruta),
                  yara=lambda datos: [("Regla_X", "una regla"), ("Otra", "")])  # tuplas: tienen que salir como listas
        sustituir(pila, ember, puntuar=lambda datos: {"estado": "ok", "puntuacion": 0.03})
        sustituir(pila, herramientas, die=vista("die", {"estado": "ok", "detectado": {"compilador": ["MSVC"], "lenguaje": [], "empaquetador": []}}),
                  capa=vista("capa", {"estado": "ok", "capacidades": [("hijack thread", "T1055.003 Thread Execution Hijacking")]}))
        [informe] = analisis.analizar(notepad, sin_red=True, avisar=avisar)
        assert [(i, p) for i, p, _ in avisos] == [(0, p) for p in ORDEN], avisos
        assert rutas[-1][3] == ORDEN[:-1] and rutas[-2][3] == ORDEN[:-2], rutas  # capa no arranca hasta que DIE y todo lo anterior se ha avisado
        assert {nombre: ruta for nombre, ruta, *_ in rutas} == {n: notepad for n in ("firma", "defender", "die", "capa")}, rutas  # el fichero, sin copiar
        assert [puerta for nombre, _, puerta, _ in rutas if nombre == "defender"] == [True]  # un fichero suelto pasa por la puerta de Defender
    assert informe["nombre"] == "notepad.exe" and informe["en_linea"] is None
    assert informe["estatico"]["pe"]["arquitectura"] == "x64 (64 bits)" and informe["estatico"]["firma"]["estado"] == "válida", informe["estatico"]
    assert informe["estatico"]["suplantacion"] == [] and informe["estatico"]["ember"]["puntuacion"] == 0.03
    assert informe["estatico"]["yara"] == [["Regla_X", "una regla"], ["Otra", ""]]  # listas, no tuplas
    assert informe["estatico"]["capa"]["capacidades"] == [["hijack thread", "T1055.003 Thread Execution Hijacking"]]
    assert json.loads(json.dumps(informe)) == informe
    assert [valor for _, parte, valor in avisos if parte == "pe"] == [informe["estatico"]["pe"]]  # lo avisado es lo devuelto

    # 3. Un miembro de un zip: se analiza una sola copia temporal para firma, Defender, capa y DIE (que se borra), sin la puerta repetida; con la puerta cerrada, nada se escribe
    mixto = zip_aes("mixto.zip", {"nota.txt": b"hola argos", "notepad.exe": Path(notepad).read_bytes()})
    avisos.clear()
    rutas.clear()
    with contextlib.ExitStack() as pila:
        sustituir(pila, estatico, defender=vista("defender", {"estado": "sin amenazas", "detalle": ""}),
                  verificar_firma=lambda ruta: rutas.append(("firma", str(ruta), None, None)) or firma_real(ruta), yara=lambda datos: [])
        sustituir(pila, ember, puntuar=lambda datos: {"estado": "ok", "puntuacion": 0.5})
        sustituir(pila, herramientas, die=vista("die", {"estado": "ok", "detectado": {}}), capa=vista("capa", {"estado": "ok", "capacidades": []}))
        informes = analisis.analizar(mixto, "infected", sin_red=True, avisar=avisar)
        assert [i["nombre"] for i in informes] == ["nota.txt", "notepad.exe"]
        assert [(i, p) for i, p, _ in avisos] == [(i, p) for i in (0, 1) for p in ORDEN], avisos
        # El texto no es PE: sin firma ni capa. Para cada miembro, todo lo que pide el disco ve la misma copia (con el nombre seguro, no el del zip)
        assert [nombre for nombre, *_ in rutas] == ["defender", "die", "firma", "defender", "die", "capa"], rutas
        (copia_texto,), (copia_pe,) = ({ruta for _, ruta, *_ in grupo} for grupo in (rutas[:2], rutas[2:]))
        assert Path(copia_texto).name == "muestra.txt" and Path(copia_pe).name == "muestra.exe", (copia_texto, copia_pe)
        assert Path(copia_texto).parent != Path(copia_pe).parent and all(Path(c).parent.name.startswith("argos-defender-") for c in (copia_texto, copia_pe))
        assert not Path(copia_texto).exists() and not Path(copia_pe).exists() and not list(Path(tempfile.gettempdir()).glob("argos-defender-*"))  # se borran
    # copia_temporal ya pasó la puerta de Defender antes de escribir: Defender no la repite
    assert [puerta for nombre, _, puerta, _ in rutas if nombre == "defender"] == [False, False]
    assert informes[0]["estatico"]["firma"] is None and informes[1]["estatico"]["firma"]["estado"] == "válida"
    assert informes[1]["estatico"]["suplantacion"] == [] and informes[1]["estatico"]["capa"] == {"estado": "ok", "capacidades": []}
    assert informes[0]["estatico"]["capa"]["estado"] == "no aplica"

    # ...y con el envío automático de muestras activado (1) no se escribe nada: Defender «omitido», firma sin leer, capa y DIE «no aplicado»
    rutas.clear()
    with contextlib.ExitStack() as pila:
        sustituir(pila, estatico, consentimiento_muestras=lambda: 1, defender=reventar, verificar_firma=reventar, yara=lambda datos: [])
        sustituir(pila, ember, puntuar=lambda datos: {"estado": "ok", "puntuacion": 0.5})
        sustituir(pila, herramientas, die=reventar, capa=reventar)
        sustituir(pila, tempfile, TemporaryDirectory=reventar)
        avisos.clear()
        _, pe = analisis.analizar(mixto, "infected", sin_red=True, secciones=("estatico",), avisar=avisar)
    e = pe["estatico"]
    assert e["defender"]["estado"] == "omitido" and e["firma"] is None and e["suplantacion"] == [], e
    assert e["die"] == e["capa"] and e["capa"]["estado"] == "no aplicado" and "no escribe la muestra en disco" in e["capa"]["detalle"], e
    assert [p for i, p, _ in avisos if i == 1] == [p for p in ORDEN if p not in ("identificacion", "en_linea")]  # se avisa de todas igual

    # 4. Con sin_red no sale ninguna petición; sin él, sí (si no, este test no vería nada)
    suelto = tmp / "suelto.txt"
    suelto.write_bytes(b"hola argos")
    with mock.patch.object(enlinea, "abrir", reventar):
        [informe] = analisis.analizar(str(suelto), sin_red=True, secciones=("identificacion",))
        assert informe["en_linea"] is None
        assert len(analisis.analizar(mixto, "infected", sin_red=True, secciones=("identificacion",))) == 2  # también por miembro
    peticiones = []

    def abrir_sin_red(url, *args, **kwargs):
        peticiones.append(url)
        raise OSError("sin red de prueba")

    with mock.patch.object(enlinea, "abrir", abrir_sin_red):
        [informe] = analisis.analizar(str(suelto), secciones=("identificacion",))
    assert len(peticiones) >= 1 and "hashlookup.circl.lu" in peticiones[0], peticiones  # CIRCL no pide clave: siempre se le pregunta
    assert set(informe["en_linea"]) == {"CIRCL", "MalwareBazaar", "VirusTotal"} and json.loads(json.dumps(informe)) == informe

    # 5. Contraseña mala o zip roto: ErrorAnalisis con el texto de siempre, y sin avisar de nada
    avisos.clear()
    for clave, ruta, texto_error in (
        ("mala", texto, "contraseña incorrecta"),
        ("", texto, "contraseña incorrecta"),
        ("infected", str(suelto), "el fichero no es un zip válido o está roto"),
    ):
        try:
            analisis.analizar(ruta, clave, sin_red=True, avisar=avisar)
            raise AssertionError("tendría que haber fallado")
        except ErrorAnalisis as error:
            assert str(error) == texto_error, error
    assert avisos == []

    # 6. Las secciones limitadas calculan solo lo pedido: sin el estático no se toca nada de él, y al revés
    with contextlib.ExitStack() as pila:
        sustituir(pila, estatico, analizar_pe=reventar, yara=reventar, defender=reventar, verificar_firma=reventar, copia_temporal=reventar)
        sustituir(pila, ember, puntuar=reventar)
        sustituir(pila, herramientas, analizar=reventar, die=reventar, capa=reventar)
        [informe] = analisis.analizar(str(suelto), sin_red=True, secciones=("identificacion",))
        assert set(informe) == {"nombre", "identificacion", "en_linea"} and informe["nombre"] == "suelto.txt", informe
        informes = analisis.analizar(texto, "infected", sin_red=True, secciones=("identificacion",))
        assert [set(i) for i in informes] == [{"nombre", "identificacion", "en_linea"}] * 2
    avisos.clear()
    with contextlib.ExitStack() as pila:
        sustituir(pila, identificacion, identificar=reventar, identificar_datos=reventar)
        sustituir(pila, enlinea, consultar=reventar)
        sustituir(pila, analisis, Magika=reventar)
        sustituir(pila, estatico, yara=lambda datos: [], defender=lambda ruta, puerta=True: {"estado": "sin amenazas", "detalle": ""})
        sustituir(pila, herramientas, analizar=lambda ruta, es_pe, listo: None)
        [informe] = analisis.analizar(str(suelto), secciones=("estatico",), avisar=avisar)  # sin sin_red: tampoco consulta, porque no se pidió
        assert set(informe) == {"nombre", "estatico"}, informe
        informes = analisis.analizar(texto, "infected", secciones=("estatico",))
        assert [set(i) for i in informes] == [{"nombre", "estatico"}] * 2
    assert [p for _, p, _ in avisos][:4] == ["nombre", "pe", "firma", "suplantacion"]
finally:
    for hijo in tmp.iterdir():
        hijo.unlink()
    tmp.rmdir()

print("OK")
