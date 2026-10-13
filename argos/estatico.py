import json
import os
import subprocess
from datetime import datetime, timezone

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
