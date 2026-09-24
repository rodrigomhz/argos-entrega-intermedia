# 00 — Qué es Argos

Proyecto de TFG. Empezado el 21 de septiembre de 2026.

> Argos Panoptes, el gigante de cien ojos que lo veía todo y nunca dormía del todo.

## En tres frases

Argos es un **analizador de ficheros sospechosos** que funciona entero en tu ordenador.
Le das un fichero y te devuelve un informe: qué es, qué lleva dentro, y qué hace cuando se
ejecuta. Lo mismo que hacen VirusTotal y any.run, pero **sin mandar el fichero a nadie**.

## Qué no es

- **No es un antivirus.** No vigila tu ordenador ni se queda residente.
- **No bloquea nada.** Tú le pides que analice un fichero, lees el informe, y decides tú.
- **No sube nada a internet.** Ese es el requisito que lo justifica: hay entornos donde subir
  una muestra a VirusTotal avisa al atacante de que le han detectado.

## Cómo funciona, por dentro

Cuando le das un fichero, Argos hace cuatro cosas, en este orden:

1. **Mirarlo sin abrirlo.** Qué tipo de fichero es, su huella digital (hash), su tamaño.
2. **Mirarlo por dentro sin ejecutarlo.** Quién lo firma, qué funciones del sistema usa, si está
   comprimido a propósito para esconder su contenido.
3. **Ejecutarlo en una máquina virtual de usar y tirar.** Apuntar qué procesos abre, qué ficheros
   toca y a quién intenta conectarse. Después, esa máquina se borra y vuelve a estar limpia.
4. **Enseñarte el informe** en una página web que se abre en tu propio navegador.

Los pasos 1 y 2 son rápidos (segundos). El 3 es lento (minutos), por eso va el último.

## Los pasos que vamos a dar

Uno cada vez. No se empieza el siguiente hasta que el anterior funcione y lo entiendas.

| Paso | Qué hacemos                                        | Cómo sabes que está hecho                           |
| ---- | -------------------------------------------------- | --------------------------------------------------- |
| 1    | Este documento                                     | Lo has leído y estás de acuerdo                     |
| 2    | Preparar el entorno de trabajo (Python y carpetas) | Un comando responde con la versión                  |
| 3    | Leer un fichero y sacar su huella digital          | Le das un fichero y te dice su hash                 |
| 4    | Mirar dentro de un ejecutable de Windows           | Te dice quién lo firma y qué usa                    |
| 5    | La página web para no usar comandos                | Arrastras un fichero y ves el informe               |
| 6    | La máquina virtual de usar y tirar                 | Ejecuta el fichero y cuenta qué hizo                |
| 7    | Probarlo con ficheros de verdad y medir si acierta | Tienes números para el TFG                          |
| 8    | Empaquetarlo en un ejecutable                      | Lo abres en otro sitio y funciona sin instalar nada |

Cada paso deja su propio documento numerado en esta bóveda, explicando qué se hizo y por qué.

## Decisiones ya tomadas

- **No se sube ningún fichero a servicios externos.** Ni VirusTotal, ni any.run.
- **Se escribe en Python.**
- **Se hace en solitario.**
- **La máquina virtual va donde tú digas.** Por defecto en `C:`, que es el disco rápido. La ruta
  se pone en un fichero de configuración, no va fija en el código: así puedes moverla a `D:` o a
  un disco externo el día de la demo sin tocar nada.
- **Tiene que acabar siendo un ejecutable** que se pueda abrir en otro ordenador y funcione, para
  poder enseñarlo el día de la defensa. Eso condiciona cómo se escribe desde el principio.

## Dónde está todo

    C:\Users\rodri\Nextcloud\Argos\     <- esta bóveda: documentación del TFG

Al estar dentro de Nextcloud, **se sincroniza sola** entre la torre y el portátil.
