import argparse
import sys
from pathlib import Path

import pyzipper

from argos import __version__, listas
from argos.identificacion import identificar, identificar_zip


def mostrar(datos):
    print(f"SHA-256: {datos['sha256']}")
    print(f"SHA-1:   {datos['sha1']}")
    print(f"Tamaño:  {datos['bytes']:,} bytes".replace(",", "."))
    print(f"Tipo:    {datos['tipo']}, según Magika")
    if datos["extension_engana"]:
        esperadas = ", ".join("." + e for e in datos["extensiones_esperadas"])
        print(f"AVISO:   la extensión no corresponde al contenido (se esperaba {esperadas})")

    # Cada lista da None (falta el fichero) o (está, fecha)
    if datos["malwarebazaar"] is None:
        malware = f": no disponible (falta {listas.MALWAREBAZAAR})"
    else:
        esta, fecha = datos["malwarebazaar"]
        malware = f" (lista del {fecha}): " + ("MALWARE CONOCIDO" if esta else "no figura como malware conocido")
    if datos["circl"] is None:
        legitimo = f": no disponible (falta {listas.CIRCL})"
    else:
        esta, fecha = datos["circl"]
        # CIRCL (NSRL) recoge software publicado, no software seguro: EICAR figura porque venía en una distribución de Linux
        legitimo = f" (descargada el {fecha}): " + (
            "software conocido; no garantiza que sea seguro (indicio: se equivoca 1 de cada 10.000)"
            if esta
            else "no figura como software conocido"
        )
    print(f"Listas:  MalwareBazaar{malware}")
    print(f"         CIRCL{legitimo}")


def main():
    parser = argparse.ArgumentParser(prog="argos", description="Analizador local de ficheros sospechosos")
    parser.add_argument("--version", action="version", version=f"argos {__version__}")
    ordenes = parser.add_subparsers(dest="orden")
    identifica = ordenes.add_parser("identifica", help="huella y tamaño de un fichero")
    identifica.add_argument("fichero")
    identifica.add_argument("--clave", help="contraseña: abre el fichero como zip e identifica cada fichero de dentro, sin extraerlo")
    args = parser.parse_args()

    if args.orden == "identifica":
        if not Path(args.fichero).is_file():
            parser.error(f"no existe el fichero: {args.fichero}")
        if args.clave is None:
            mostrar(identificar(args.fichero))
        else:
            try:
                fichas = identificar_zip(args.fichero, args.clave)
            except RuntimeError:  # pyzipper lo lanza con la contraseña mala o vacía
                sys.exit("error: contraseña incorrecta")
            except pyzipper.BadZipFile:  # ojo: no es zipfile.BadZipFile, pyzipper lleva su propia copia
                sys.exit("error: el fichero no es un zip válido o está roto")
            for i, (nombre, datos) in enumerate(fichas):
                if i:
                    print()
                print(f"Dentro de {Path(args.fichero).name}: {nombre}")
                mostrar(datos)


if __name__ == "__main__":
    main()
