import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

import pefile

ARQUITECTURAS = {0x14C: "x86 (32 bits)", 0x8664: "x64 (64 bits)", 0xAA64: "ARM64"}
# Por encima de esto, una sección parece comprimida o cifrada: indicio de empaquetado
ENTROPIA_ALTA = 7.0


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


def defender_datos(datos, nombre, verificar=False):
    """(veredicto de Defender, firma o None) de unos bytes que solo están en memoria.

    Se escriben en una carpeta temporal que se borra siempre. Con verificar=True se comprueba también la firma de esa copia.
    """
    # ponytail: lee el ajuste y lanza MpCmdRun por cada fichero del zip; mejorar: leer el ajuste una vez y escanear la carpeta entera
    puerta = _puerta()  # antes de escribir: guardar el fichero en el disco es lo que haría que Windows lo enviase a Microsoft
    if puerta:
        return puerta, None
    with tempfile.TemporaryDirectory(prefix="argos-defender-") as carpeta:
        ruta = Path(carpeta) / _nombre_seguro(nombre)
        try:
            ruta.write_bytes(datos)
            ruta.read_bytes()
        except OSError:
            # Defender lo ha borrado o bloqueado nada más escribirlo: eso ES una detección
            # ponytail: cualquier OSError se toma por una detección; también puede ser disco lleno o falta de permisos
            amenaza = _amenaza_registrada(Path(carpeta).name)
            return {"estado": "DETECTADO", "detalle": amenaza or "nombre no disponible"}, None
        return _escanear(ruta), (verificar_firma(ruta) if verificar else None)
