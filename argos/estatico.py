import contextlib
import functools
import json
import os
import re
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

import pefile
import yara_x

from argos import herramientas

ARQUITECTURAS = {0x14C: "x86 (32 bits)", 0x8664: "x64 (64 bits)", 0xAA64: "ARM64"}
# Por encima de esto, una sección parece comprimida o cifrada: indicio de empaquetado
ENTROPIA_ALTA = 7.0
# Palabras que no distinguen a un fabricante de otro: no cuentan al comparar nombres
PALABRAS_GENERICAS = {
    "the", "corporation", "corp", "incorporated", "inc", "ltd", "limited", "llc", "gmbh",
    "company", "technologies", "technology", "software", "systems", "group", "international", "services",
}
# Lista corta y editable de fabricantes conocidos: no aparecer aquí no significa nada malo, solo que no se reconoce
FABRICANTES_CONOCIDOS = {
    "microsoft", "google", "apple", "mozilla", "adobe", "oracle", "intel", "nvidia", "amd", "dell",
    "lenovo", "cisco", "ibm", "valve", "jetbrains", "python", "canonical", "vmware", "realtek",
    "fortinet", "kaspersky", "bitdefender", "sophos", "avast", "malwarebytes", "mcafee", "symantec",
}


def _version(pe):
    """Lo que el fichero dice de sí mismo en su bloque de versión: empresa y nombre original ("" si no los lleva)."""
    campos = {}
    for fileinfo in getattr(pe, "FileInfo", None) or []:
        for entrada in fileinfo:
            if entrada.Key == b"StringFileInfo":
                for tabla in entrada.StringTable:
                    for clave, valor in tabla.entries.items():
                        campos[clave.decode(errors="replace")] = valor.decode(errors="replace").rstrip("\0")
    # Sin CompanyName, algunos ficheros de Windows solo llevan ProductName: sirve igual para comparar
    return {
        "empresa": campos.get("CompanyName", "") or campos.get("ProductName", ""),
        "nombre_original": campos.get("OriginalFilename", ""),
    }


def _relleno_certificado(blob):
    """Bytes del certificado que no son el bloque PKCS#7 en sí: su tamaño real está en la cabecera DER."""
    if len(blob) < 4 or blob[0] != 0x30:
        return 0
    if blob[1] < 0x80:
        cabecera, contenido = 2, blob[1]
    else:
        n = blob[1] & 0x7F
        if 2 + n > len(blob):
            return 0
        cabecera, contenido = 2 + n, int.from_bytes(blob[2:2 + n], "big")
    return max(0, len(blob) - cabecera - contenido)


def _zona_firma(datos, seguridad):
    """Números de la zona de firma incrustada: bytes añadidos al final, huecos sin certificado y relleno de más.

    Aquí no se valida el certificado (eso es cosa de Windows): se mira que los bytes cuadren con lo que la firma declara.
    None si el fichero no lleva firma incrustada.
    """
    if seguridad.Size == 0:
        return None
    offset, fin = seguridad.VirtualAddress, seguridad.VirtualAddress + seguridad.Size
    pos, relleno = offset, 0
    while pos + 8 <= fin:
        largo = int.from_bytes(datos[pos:pos + 4], "little")
        if largo < 8 or pos + largo > fin:
            break  # entrada rota o que se sale de la tabla: lo que quede se cuenta como hueco
        relleno += _relleno_certificado(datos[pos + 8:pos + largo])
        pos += (largo + 7) & ~7  # cada entrada empieza en un múltiplo de 8
    return {"tras": len(datos) - fin, "dentro": fin - pos, "relleno": relleno}


def analizar_pe(datos):
    """Cabecera, secciones e importaciones de un ejecutable de Windows, sin ejecutarlo. None si no es un PE."""
    try:
        pe = pefile.PE(data=datos)
    except pefile.PEFormatError:
        return None
    maquina = pe.FILE_HEADER.Machine
    secciones = [
        {
            "nombre": s.Name.rstrip(b"\0").decode(errors="replace"),
            "bytes": s.SizeOfRawData,
            "entropia": round(s.get_entropy(), 2),
        }
        for s in pe.sections
    ]
    importaciones = {
        e.dll.decode(errors="replace"): [
            f.name.decode(errors="replace") if f.name else f"ordinal {f.ordinal}" for f in e.imports
        ]
        for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    }
    seguridad = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    return {
        "arquitectura": ARQUITECTURAS.get(maquina, hex(maquina)),
        "compilado": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, timezone.utc).date().isoformat(),
        "firma_incrustada": seguridad.Size > 0,
        "version": _version(pe),
        "zona_firma": _zona_firma(datos, seguridad),
        "secciones": secciones,
        "importaciones": importaciones,
    }


ESTADOS_FIRMA = {
    "Valid": "válida",
    "NotSigned": "sin firma",
    "HashMismatch": "ROTA: el fichero se ha modificado después de firmarlo",
    "NotTrusted": "no es de confianza: Windows no reconoce el certificado",
}


def verificar_firma(ruta):
    """Pregunta a Windows (Get-AuthenticodeSignature) si el fichero está firmado, por quién y si la firma es válida."""
    # La ruta va en una variable de entorno y no dentro de la orden, para que un nombre raro no pueda inyectar código
    orden = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:ARGOS_RUTA; "
        "@{estado=[string]$s.Status; tipo=[string]$s.SignatureType; firmante=$s.SignerCertificate.Subject} | ConvertTo-Json"
    )
    salida = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", orden],
        capture_output=True, text=True, env={**os.environ, "ARGOS_RUTA": str(ruta)}, check=True,
    ).stdout
    firma = json.loads(salida)
    return {
        "estado": ESTADOS_FIRMA.get(firma["estado"], firma["estado"]),
        "tipo": {"Authenticode": "incrustada en el fichero", "Catalog": "en un catálogo de Windows"}.get(firma["tipo"], ""),
        "firmante": firma["firmante"] or "",
    }


def nombre_firmante(firma):
    """«CN=Microsoft Windows, O=...» → «Microsoft Windows»"""
    return firma["firmante"].split(",")[0].removeprefix("CN=").strip()


def _palabras(texto):
    """Palabras sueltas para comparar nombres: en minúsculas y sin las genéricas («Corporation», «Ltd»...)."""
    return {p for p in re.findall(r"[a-z0-9]+", texto.lower()) if len(p) > 2 and p not in PALABRAS_GENERICAS}


def suplantacion(datos, firma):
    """Indicios de suplantación de un PE ya analizado, en texto llano (lista; vacía si no hay).

    Compara los datos de versión con el firmante, avisa de firmantes desconocidos y revisa la zona de firma.
    Con firma=None (fichero en memoria que no se pudo verificar) solo se puede revisar la zona de firma.
    """
    avisos = []
    version = datos["version"]
    empresa = version["empresa"]
    nombre_original = f" ({version['nombre_original']})" if version["nombre_original"] else ""
    palabras_empresa = _palabras(empresa)
    if firma is not None:
        palabras_firma = _palabras(firma["firmante"])
        # Marcas conocidas que el fichero dice ser: si lo firma otra cosa (o nadie), es el caso clásico de suplantación
        marca = palabras_empresa & FABRICANTES_CONOCIDOS
        if firma["estado"] == "sin firma":
            if datos["firma_incrustada"]:
                avisos.append("hay firma incrustada, pero Windows ya no la reconoce: el fichero se modificó después de firmarlo")
            elif marca:
                avisos.append(f"posible suplantación: dice ser «{empresa}»{nombre_original} y el fichero no está firmado")
        else:
            # «microsoft» va aparte: Microsoft firma también software de otros (controladores con WHQL)
            if marca and "microsoft" not in palabras_firma and not (marca & palabras_firma):
                avisos.append(f"posible suplantación: dice ser «{empresa}»{nombre_original} y firma «{nombre_firmante(firma)}»")
    zona = datos["zona_firma"]
    if zona is not None:
        if zona["tras"] > 0:
            avisos.append(f"{zona['tras']} bytes añadidos después de la firma incrustada")
        elif zona["tras"] < 0:
            avisos.append("la zona de firma incrustada se sale del fichero: recortado o manipulado")
        if zona["dentro"] > 0:
            avisos.append(f"{zona['dentro']} bytes dentro de la zona de firma que no pertenecen a ningún certificado")
        if zona["relleno"] > 7:
            avisos.append(f"{zona['relleno']} bytes de relleno dentro de la firma, más de lo que ocupa el certificado")
    return avisos


MPCMDRUN = Path(os.environ["ProgramFiles"]) / "Windows Defender" / "MpCmdRun.exe"


def consentimiento_muestras():
    """SubmitSamplesConsent de Defender: 0 preguntar, 1 enviar las seguras, 2 no enviar nunca, 3 enviar todas."""
    # ponytail: Get-MpPreference tarda ~3 s (arranca PowerShell y carga el módulo de Defender); mejorar: leer el valor del registro, respetando también la directiva de grupo
    salida = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-MpPreference).SubmitSamplesConsent"],
        capture_output=True, text=True, check=True,
    ).stdout
    return int(salida)


def _puerta():
    """None si se puede usar Defender; si no, el resultado que hay que mostrar. Argos nunca cambia el ajuste."""
    try:
        consentimiento = consentimiento_muestras()
    except (subprocess.CalledProcessError, ValueError):  # sin Defender, o PowerShell no puede leer el ajuste
        return {"estado": "no disponible", "detalle": ""}
    if consentimiento not in (0, 2):  # con 1 y 3, Windows enviaría el fichero a Microsoft sin preguntar
        return {"estado": "omitido", "detalle": "el envío automático de muestras está activado"}
    if not MPCMDRUN.is_file():
        return {"estado": "no disponible", "detalle": ""}
    return None


def _escanear(ruta):
    """Escanea un fichero con MpCmdRun (la orden de Defender); -DisableRemediation: no borra ni pone en cuarentena nada."""
    # ponytail: sin timeout; si el servicio de Defender se cuelga, Argos espera. Mejorar: timeout= y tratar TimeoutExpired como error
    # abspath: MpCmdRun no entiende rutas relativas (falla con 0x80508023)
    # errors="replace": la salida va en la página de códigos de la consola y solo leemos su parte ASCII
    r = subprocess.run(
        [str(MPCMDRUN), "-Scan", "-ScanType", "3", "-File", os.path.abspath(ruta), "-DisableRemediation"],
        capture_output=True, text=True, errors="replace",
    )
    if r.returncode == 0:
        return {"estado": "sin amenazas", "detalle": ""}
    # El código 2 también lo da MpCmdRun cuando falla (p. ej. si el fichero no existe): solo es una amenaza si su salida la nombra
    amenaza = re.search(r"^Threat\s*:\s*(.+)$", r.stdout, re.MULTILINE)
    if r.returncode == 2 and amenaza:
        return {"estado": "DETECTADO", "detalle": amenaza.group(1).strip()}
    ultima_linea = " ".join(r.stdout.strip().splitlines()[-1:])
    return {"estado": "error", "detalle": f"MpCmdRun devolvió el código {r.returncode}: {ultima_linea}"}


def defender(ruta):
    """Veredicto de Microsoft Defender, en local, para un fichero que está en el disco."""
    return _puerta() or _escanear(ruta)


def _nombre_seguro(nombre):
    """El nombre dentro del zip lo controla el atacante ("../../x"): nombre fijo y, solo si es normal, su extensión."""
    extension = PureWindowsPath(nombre).suffix
    return "muestra" + (extension if re.fullmatch(r"\.\w{1,10}", extension) else "")


def _amenaza_registrada(carpeta):
    """Nombre que Defender apuntó para un fichero de esta carpeta (Get-MpThreatDetection y Get-MpThreat, solo lectura); "" si no hay."""
    # Se busca por el nombre de la carpeta (único) y no por la ruta entera: TEMP puede venir en formato corto (JUAN~1) y Defender apunta la ruta larga
    orden = (
        "$d = Get-MpThreatDetection | Where-Object { $_.Resources -like ('*' + $env:ARGOS_CARPETA + '*') } | Select-Object -First 1; "
        "if ($d) { (Get-MpThreat -ThreatID $d.ThreatID).ThreatName }"
    )
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", orden],
        capture_output=True, text=True, env={**os.environ, "ARGOS_CARPETA": carpeta},
    ).stdout.strip()


class SinCopia(Exception):
    """No se escribió la muestra en el disco. defender: el veredicto de Defender que hay que mostrar; motivo: lo que dicen capa y DIE."""

    def __init__(self, defender, motivo):
        super().__init__(motivo)
        self.defender = defender
        self.motivo = motivo


@contextlib.contextmanager
def copia_temporal(datos, nombre):
    """Da la ruta de una copia en disco de unos bytes, en una carpeta temporal que se borra siempre. SinCopia si no se debe o no se puede."""
    puerta = _puerta()  # antes de escribir: guardar el fichero en el disco es lo que haría que Windows lo enviase a Microsoft
    if puerta:
        if puerta["estado"] == "omitido":
            motivo = "Argos no escribe la muestra en disco con el envío automático de muestras activado"
        else:
            motivo = "Argos no puede comprobar el envío automático de muestras de Windows y no escribe la muestra en disco"
        raise SinCopia(puerta, motivo)
    with tempfile.TemporaryDirectory(prefix="argos-defender-") as carpeta:
        ruta = Path(carpeta) / _nombre_seguro(nombre)
        try:
            ruta.write_bytes(datos)
            ruta.read_bytes()
        except OSError:
            # Defender lo ha borrado o bloqueado nada más escribirlo: eso ES una detección
            # ponytail: cualquier OSError se toma por una detección; también puede ser disco lleno o falta de permisos
            amenaza = _amenaza_registrada(Path(carpeta).name)
            raise SinCopia({"estado": "DETECTADO", "detalle": amenaza or "nombre no disponible"}, "Defender bloqueó la copia de la muestra")
        yield ruta


def defender_datos(datos, nombre, verificar=False):
    """(veredicto de Defender, firma o None) de unos bytes que solo están en memoria.

    Se escriben en una carpeta temporal que se borra siempre. Con verificar=True se comprueba también la firma de esa copia.
    """
    # ponytail: lee el ajuste y lanza MpCmdRun por cada fichero del zip; mejorar: leer el ajuste una vez y escanear la carpeta entera
    try:
        with copia_temporal(datos, nombre) as ruta:
            return _escanear(ruta), (verificar_firma(ruta) if verificar else None)
    except SinCopia as sin:
        return sin.defender, None


def analizar_copia(datos, nombre, es_pe):
    """(veredicto de Defender, firma o None, capa, Detect It Easy) de unos bytes que solo están en memoria, sobre una sola copia en disco."""
    try:
        with copia_temporal(datos, nombre) as ruta:
            return (_escanear(ruta), verificar_firma(ruta) if es_pe else None, *herramientas.analizar(ruta, es_pe))
    except SinCopia as sin:
        sin_copia = {"estado": "no aplicado", "detalle": sin.motivo}
        return sin.defender, None, sin_copia, sin_copia


REGLAS = Path.home() / "argos-datos" / "reglas"
REGLAS_ZIP = "yara-forge-rules-core.zip"  # paquete "core" de YARA Forge: lo baja «argos actualiza»


@functools.cache  # se compila una sola vez por ejecución, aunque haya muchos ficheros (un zip)
def cargar_reglas():
    """Las reglas de YARA Forge compiladas, o None si no se han descargado."""
    ruta = REGLAS / REGLAS_ZIP
    if not ruta.is_file():
        return None
    with zipfile.ZipFile(ruta) as z:
        # El zip trae un solo .yar con todas las reglas
        fuente = z.read(next(n for n in z.namelist() if n.endswith(".yar"))).decode()
    # ponytail: compila las reglas en cada ejecución (~3,2 s las ~5.000 reglas de core, medido); mejorar: guardarlas ya compiladas con Rules.serialize_into y cargarlas con Rules.deserialize_from
    return yara_x.compile(fuente)


def yara(datos):
    """[(nombre, descripción)] de las reglas YARA que coinciden con unos bytes; None si faltan las reglas."""
    reglas = cargar_reglas()
    if reglas is None:
        return None
    return [(r.identifier, dict(r.metadata).get("description", "")) for r in reglas.scan(datos).matching_rules]
