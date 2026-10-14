import argparse
import sys
from http.client import HTTPException
from pathlib import Path

import pyzipper

from magika import Magika

from argos import __version__, listas
from argos.actualiza import actualizar
from argos.estatico import ENTROPIA_ALTA, analizar_pe, defender, defender_datos, nombre_firmante, suplantacion, verificar_firma, yara
from argos.identificacion import identificar, identificar_datos, miembros_zip


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
        malware = f": no disponible (falta {listas.MALWAREBAZAAR}; ejecuta «argos actualiza»)"
    else:
        esta, fecha = datos["malwarebazaar"]
        malware = f" (lista del {fecha}): " + ("MALWARE CONOCIDO" if esta else "no figura como malware conocido")
    if datos["circl"] is None:
        legitimo = f": no disponible (falta {listas.CIRCL}; ejecuta «argos actualiza»)"
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


def mostrar_defender(antivirus):
    detalle = f" ({antivirus['detalle']})" if antivirus["detalle"] else ""
    print(f"Defender:      {antivirus['estado']}{detalle}")


def mostrar_yara(coincidencias):
    if coincidencias is None:
        resultado = "no disponible (ejecuta «argos actualiza»)"
    elif not coincidencias:
        resultado = "sin coincidencias"
    else:
        reglas = ", ".join(f"{nombre} ({descripcion})" if descripcion else nombre for nombre, descripcion in coincidencias)
        resultado = f"{len(coincidencias)} {'regla' if len(coincidencias) == 1 else 'reglas'}: {reglas}"
    print(f"YARA:          {resultado}")


def mostrar_suplantacion(avisos, firma_leida):
    if not avisos:
        falta = "sin indicios" if firma_leida else "sin comprobar (no se leyó la firma: el fichero está en memoria)"
        print(f"Suplantación:  {falta}")
        return
    for i, aviso in enumerate(avisos):
        print(("Suplantación:  " if i == 0 else "               ") + aviso)


def mostrar_estatico(datos, antivirus, coincidencias, firma=None):
    if datos is None:
        print("No es un ejecutable de Windows (PE): no hay análisis estático de ejecutable.")
        mostrar_defender(antivirus)
        mostrar_yara(coincidencias)
        return
    print(f"Arquitectura:  {datos['arquitectura']}")
    print(f"Compilado:     {datos['compilado']} (lo escribe el compilador: puede ser falso)")
    if firma is None:
        incrustada = "lleva firma incrustada" if datos["firma_incrustada"] else "no lleva firma incrustada"
        print(f"Firma:         {incrustada}; sin verificar (el fichero está en memoria)")
    else:
        firmante = nombre_firmante(firma)  # "CN=Microsoft Windows, O=..." → "Microsoft Windows"
        detalles = ", ".join(x for x in (firma["tipo"], firmante and f"firmante: {firmante}") if x)
        print(f"Firma:         {firma['estado']}" + (f" ({detalles})" if detalles else ""))
    mostrar_suplantacion(suplantacion(datos, firma), firma is not None)
    mostrar_defender(antivirus)
    mostrar_yara(coincidencias)
    print("Secciones:")
    for s in datos["secciones"]:
        alta = "  ← ENTROPÍA ALTA" if s["entropia"] > ENTROPIA_ALTA else ""
        print(f"  {s['nombre']:<9}{s['bytes']:>12,} bytes   entropía {s['entropia']:.2f}{alta}".replace(",", "."))
    total = sum(len(funciones) for funciones in datos["importaciones"].values())
    print(f"Importaciones: {total} funciones de {len(datos['importaciones'])} DLL")
    for dll, funciones in datos["importaciones"].items():
        print(f"  {dll} ({len(funciones)}): {', '.join(funciones[:5])}{', …' if len(funciones) > 5 else ''}")


def ficheros_del_zip(args):
    """(nombre, bytes) de cada fichero del zip; si la contraseña o el zip fallan, sale con un mensaje."""
    try:
        return list(miembros_zip(args.fichero, args.clave))
    except RuntimeError:  # pyzipper lo lanza con la contraseña mala o vacía
        sys.exit("error: contraseña incorrecta")
    except pyzipper.BadZipFile:  # ojo: no es zipfile.BadZipFile, pyzipper lleva su propia copia
        sys.exit("error: el fichero no es un zip válido o está roto")


def main():
    parser = argparse.ArgumentParser(prog="argos", description="Analizador local de ficheros sospechosos")
    parser.add_argument("--version", action="version", version=f"argos {__version__}")
    ordenes = parser.add_subparsers(dest="orden")
    actualiza = ordenes.add_parser("actualiza", help="descarga y pone al día las reglas YARA y las listas")
    actualiza.add_argument("--sin-circl", action="store_true", help="no descarga el filtro de CIRCL (1 GB)")
    for orden, ayuda in (("identifica", "huella, tipo y listas de un fichero"), ("estatico", "mira dentro de un ejecutable sin ejecutarlo")):
        sub = ordenes.add_parser(orden, help=ayuda)
        sub.add_argument("fichero")
        sub.add_argument("--clave", help="contraseña: abre el fichero como zip y analiza cada fichero de dentro, sin extraerlo")
    args = parser.parse_args()
    if args.orden is None:
        parser.print_help()
        return
    if args.orden == "actualiza":
        try:
            actualizar(args.sin_circl)
        except (OSError, HTTPException) as error:  # sin red, servidor caído, disco lleno...: un mensaje, sin traza
            sys.exit(f"error: no se pudo actualizar: {error}")
        return
    if not Path(args.fichero).is_file():
        parser.error(f"no existe el fichero: {args.fichero}")

    if args.clave is None:
        if args.orden == "identifica":
            mostrar(identificar(args.fichero))
        else:
            # ponytail: el fichero entero en memoria; los ejecutables suelen ocupar poco
            contenido = Path(args.fichero).read_bytes()
            datos = analizar_pe(contenido)
            mostrar_estatico(datos, defender(args.fichero), yara(contenido), verificar_firma(args.fichero) if datos else None)
        return

    magika = Magika() if args.orden == "identifica" else None
    for i, (nombre, datos) in enumerate(ficheros_del_zip(args)):
        if i:
            print()
        print(f"Dentro de {Path(args.fichero).name}: {nombre}")
        if args.orden == "identifica":
            mostrar(identificar_datos(datos, nombre, magika))
        else:
            pe = analizar_pe(datos)
            antivirus, firma = defender_datos(datos, nombre, verificar=pe is not None)
            mostrar_estatico(pe, antivirus, yara(datos), firma)


if __name__ == "__main__":
    main()
