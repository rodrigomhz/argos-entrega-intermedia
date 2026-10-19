import argparse
import sys
from http.client import HTTPException
from pathlib import Path

import pyzipper

from magika import Magika

from argos import __version__, ember, enlinea, herramientas, listas
from argos.actualiza import actualizar, avisar
from argos.estatico import ENTROPIA_ALTA, analizar_copia, analizar_pe, defender, nombre_firmante, suplantacion, verificar_firma, yara
from argos.identificacion import identificar, identificar_datos, miembros_zip


MOSTRAR_CAPACIDADES = 3  # cuántas capacidades de capa se enseñan; el resto solo se cuenta


def visible(texto):
    """Un texto que puede venir del atacante (nombres dentro de un zip, datos de versión) listo para la terminal.

    Los caracteres de control salen escapados («\\n», «\\x1b»): un nombre con un salto de línea no puede fingir una línea
    del informe («Defender: sin amenazas») ni una secuencia de escape tocar la terminal.
    """
    return "".join(c if c.isprintable() else ascii(c)[1:-1] for c in texto)


def mostrar(datos, sin_red):
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
    mostrar_en_linea(datos["sha256"], sin_red)


def mostrar_en_linea(sha256, sin_red):
    """Lo que dicen los servicios por huella. Es información aparte: no cambia nada más del informe."""
    if sin_red:
        print("En línea: omitido (--sin-red)")
        return
    print("En línea (solo sale la huella, nunca el fichero):", flush=True)  # flush: si algún servicio tarda, que se vea que está trabajando
    for servicio, resultado in enlinea.consultar(sha256).items():
        print(f"         {servicio}: {resultado['detalle']}")


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


def mostrar_herramienta(titulo, resultado, texto):
    """Una línea de capa, Detect It Easy o EMBER2024: texto(resultado) si funcionó; si no, el estado y su motivo."""
    estado = resultado["estado"]
    if estado == "ok":
        linea = texto(resultado)
    elif estado == "no disponible":
        linea = "no disponible (ejecuta «argos actualiza»)"
    else:
        linea = estado + (f": {resultado['detalle']}" if resultado["detalle"] else "")
    print(f"{titulo}{linea}")


def texto_capa(resultado):
    """«12 (create process [T1106 Native API], …, y 9 más)»: pocas capacidades, con su técnica ATT&CK, y cuántas quedan."""
    capacidades = resultado["capacidades"]
    if not capacidades:
        return "ninguna"
    muestra = ", ".join(f"{nombre} [{tecnica}]" if tecnica else nombre for nombre, tecnica in capacidades[:MOSTRAR_CAPACIDADES])
    resto = len(capacidades) - MOSTRAR_CAPACIDADES
    return f"{len(capacidades)} ({muestra}{f', y {resto} más' if resto > 0 else ''})"


def texto_die(resultado):
    """«compilador: Microsoft Visual C/C++ 19.38.33145; …»: lo que DIE detectó y, de lo que no, que no detectó nada."""
    detectado = [f"{etiqueta}: {', '.join(valores)}" for etiqueta, valores in resultado["detectado"].items() if valores]
    return "; ".join(detectado) or "no detecta compilador, lenguaje ni empaquetador"


def texto_ember(resultado):
    """«0,03 (0 = parece legítimo, 1 = parece malware; umbral sin calibrar hasta el hito 7)»: la puntuación con coma decimal y dos decimales."""
    # Sin umbral a propósito: decir «sospechoso» a partir de un número sin haber medido sus falsos positivos sería inventárselo (se calibra en el hito 7)
    puntuacion = f"{resultado['puntuacion']:.2f}".replace(".", ",")
    return f"{puntuacion} (0 = parece legítimo, 1 = parece malware; umbral sin calibrar hasta el hito 7)"


def puntuar_ember(datos, es_pe):
    """Como herramientas.analizar: solo los ejecutables de Windows (PE) se puntúan. Trabaja con los bytes en memoria, sirve para un zip."""
    return ember.puntuar(datos) if es_pe else {"estado": "no aplica", "detalle": "solo ejecutables de Windows (PE)"}


def mostrar_herramientas(capa, die, puntuacion):
    mostrar_herramienta("Capacidades:   ", capa, texto_capa)
    mostrar_herramienta("Detect It Easy: ", die, texto_die)
    mostrar_herramienta("EMBER2024:     ", puntuacion, texto_ember)


def mostrar_suplantacion(avisos, firma_leida):
    if not avisos:
        falta = "sin indicios" if firma_leida else "sin comprobar (no se leyó la firma: el fichero está en memoria)"
        print(f"Suplantación:  {falta}")
        return
    for i, aviso in enumerate(avisos):
        print(("Suplantación:  " if i == 0 else "               ") + visible(aviso))  # el aviso cita la empresa que dice ser el fichero


def mostrar_estatico(datos, antivirus, coincidencias, firma, capa, die, puntuacion):
    if datos is None:
        print("No es un ejecutable de Windows (PE): no hay análisis estático de ejecutable.")
        mostrar_defender(antivirus)
        mostrar_yara(coincidencias)
        mostrar_herramientas(capa, die, puntuacion)
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
    mostrar_herramientas(capa, die, puntuacion)
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
    actualiza = ordenes.add_parser("actualiza", help="descarga y pone al día las reglas YARA, las listas, capa, Detect It Easy y el modelo EMBER2024")
    actualiza.add_argument("--sin-circl", action="store_true", help="no descarga el filtro de CIRCL (1 GB)")
    for orden, ayuda in (("identifica", "huella, tipo y listas de un fichero"), ("estatico", "mira dentro de un ejecutable sin ejecutarlo")):
        sub = ordenes.add_parser(orden, help=ayuda)
        sub.add_argument("fichero")
        sub.add_argument("--clave", help="contraseña: abre el fichero como zip y analiza cada fichero de dentro, sin extraerlo")
        sub.add_argument("--sin-red", action="store_true",
                         help="no comprueba por red si hay datos nuevos ni, en identifica, consulta la huella en CIRCL, MalwareBazaar y VirusTotal")
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
    if not args.sin_red:
        avisar()

    if args.clave is None:
        if args.orden == "identifica":
            mostrar(identificar(args.fichero), args.sin_red)
        else:
            # ponytail: el fichero entero en memoria; los ejecutables suelen ocupar poco
            contenido = Path(args.fichero).read_bytes()
            datos = analizar_pe(contenido)
            capa, die = herramientas.analizar(args.fichero, datos is not None)
            mostrar_estatico(datos, defender(args.fichero), yara(contenido), verificar_firma(args.fichero) if datos else None, capa, die,
                             puntuar_ember(contenido, datos is not None))
        return

    magika = Magika() if args.orden == "identifica" else None
    for i, (nombre, datos) in enumerate(ficheros_del_zip(args)):
        if i:
            print()
        print(f"Dentro de {Path(args.fichero).name}: {visible(nombre)}")
        if args.orden == "identifica":
            # ponytail: una consulta en línea por miembro, y el VirusTotal gratuito admite 4 por minuto: con un zip grande los últimos saldrán «límite».
            # Mejorar: esperar entre consultas o dejar de preguntar a VirusTotal al primer «límite»
            mostrar(identificar_datos(datos, nombre, magika), args.sin_red)
        else:
            pe = analizar_pe(datos)
            antivirus, firma, capa, die = analizar_copia(datos, nombre, pe is not None)
            mostrar_estatico(pe, antivirus, yara(datos), firma, capa, die, puntuar_ember(datos, pe is not None))


if __name__ == "__main__":
    main()
