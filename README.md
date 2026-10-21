# Argos

> Analizador local de ficheros sospechosos: una alternativa sin conexión a any.run, VirusTotal y CAPE

Argos analiza ficheros sospechosos íntegramente en tu equipo. **Por defecto, ninguna muestra sale de tu máquina.**

## Qué hace

- **Identificación**: huellas SHA-256 y SHA-1, tipo real del fichero con Magika (avisa si la extensión engaña) y si figura en listas locales de malware conocido (MalwareBazaar) y de software conocido (CIRCL hashlookup). Analiza ficheros dentro de zips cifrados sin extraerlos al disco.
- **Análisis estático**: cabeceras PE, firma, secciones y entropía, funciones importadas, reglas YARA, detección de empaquetadores, Microsoft Defender en local y el modelo de detección EMBER2024.
- **Análisis dinámico**: máquina virtual desechable con VMware y `vmrun`; el comportamiento se recoge con CAPEsolo, Noriben o ambos.
- **Informe**: árbol de procesos, conexiones de red y cambios en ficheros y registro, en una ventana propia (pywebview sobre WebView2, sin servidor HTTP ni puertos).
- **Veredicto**: combina todas las evidencias con reglas explícitas; cada conclusión se puede seguir hasta la prueba que la produjo.

**Modo conectado:** por defecto, `argos identifica` consulta [CIRCL hashlookup](https://hashlookup.circl.lu/), [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) y [VirusTotal](https://www.virustotal.com/) enviando SOLO la huella SHA-256 del fichero: una huella no publica la muestra, y el fichero y su contenido nunca se suben. Su resultado sale en su propia sección («En línea») y no cambia el veredicto ni nada más del informe; que un servicio conozca un fichero no quiere decir que sea seguro. `--sin-red` lo apaga (y apaga también el aviso de datos nuevos). CIRCL no pide clave; MalwareBazaar y VirusTotal piden una gratuita, que se guarda en una variable de entorno con `setx` y vale en una terminal nueva:

```
setx ARGOS_ABUSECH_KEY tu-clave     (clave gratuita en https://auth.abuse.ch/)
setx ARGOS_VT_KEY tu-clave          (cuenta gratuita en VirusTotal: la clave está en tu perfil)
```

Sin la clave de un servicio, Argos no le pregunta nada y lo dice. La clave nunca se imprime. VirusTotal gratuito admite 4 consultas por minuto y 500 al día: con un zip grande, los últimos ficheros saldrán con «límite». Los dominios e IP que aparezcan en el análisis dinámico se consultarán igual cuando esa parte exista.

## Por qué en local

Requisito de partida: las muestras no se envían a servicios externos. Argos sustituye a any.run, VirusTotal o CAPE en laboratorios sin salida a internet o cuando la muestra es confidencial.

## Arquitectura

```
muestra ──► identificación ──► huellas · tipo (Magika) · listas locales
        │
        ├─► estático ───────► PE · firma · entropía · importaciones · YARA · Defender · EMBER2024
        │
        └─► dinámico ───────► VM con vmrun ──► CAPEsolo / Noriben
                                                     │
                       combinación de evidencias ◄───┘
                                │
                                └──► veredicto e informe web
```

## Tecnología

- **Anfitrión**: Windows 10/11
- **Lenguaje**: Python 3.12
- **Identificación**: hashlib, Magika, pyzipper
- **Estático**: pefile, YARA-X, capa, Detect It Easy, Microsoft Defender, EMBER2024 (LightGBM)
- **Dinámico**: VMware Workstation y `vmrun`; CAPEsolo y Noriben
- **Interfaz**: pywebview 6.2 sobre WebView2, con HTML, CSS y JavaScript propios: sin servidor, con CSP con nonce y sin nada externo
- **IA**: solo modelos locales para analizar (Magika, EMBER2024); un modelo de lenguaje opcional, solo para explicar el informe

## Estado

En desarrollo, por hitos. Hechos: entorno de desarrollo, identificación de ficheros, análisis estático (probado con una muestra real de malware: secciones, entropía, importaciones, firma, suplantación, Defender, reglas YARA, capa, Detect It Easy y EMBER2024, de momento solo con su puntuación) e interfaz en ventana propia (informe completo, pestañas por fichero de un zip, progreso, aviso de datos nuevos y botón para actualizarlos), probada a mano con `notepad.exe` y AZORult. Después: análisis dinámico en máquina virtual, evaluación con muestras reales y empaquetado.

## Uso (lo que funciona hoy)

**1. Instalar**

```
python -m venv %USERPROFILE%\venvs\argos
%USERPROFILE%\venvs\argos\Scripts\pip install -e .
```

**2. Descargar los datos**

```
%USERPROFILE%\venvs\argos\Scripts\argos actualiza
```

Baja a `%USERPROFILE%\argos-datos\` las reglas YARA (paquete core de YARA Forge), las listas de MalwareBazaar y CIRCL y las dos herramientas externas, cada una de su repositorio oficial de GitHub y con su licencia: [capa](https://github.com/mandiant/capa) de Mandiant (Apache-2.0), que dice qué sabe hacer un ejecutable y con qué técnica de MITRE ATT&CK, y [Detect It Easy](https://github.com/horsicq/DIE-engine) (MIT), que dice compilador, lenguaje y empaquetador. capa se instala con Argos (es una dependencia de pip, `flare-capa`) y `argos actualiza` solo baja sus reglas y firmas, siempre de la misma versión que la librería instalada; Detect It Easy se baja entero. `argos estatico` las ejecuta por su cuenta (capa tarda de uno a dos minutos con un ejecutable como notepad.exe). Baja también el modelo [EMBER2024](https://huggingface.co/joyce8/EMBER2024-benchmark-models) (3,8 MB, de HuggingFace, Apache-2.0): un modelo de LightGBM que da a un ejecutable de Windows una puntuación de 0 (parece legítimo) a 1 (parece malware) solo por su estructura, sin ejecutarlo; `argos estatico` la enseña, pero de momento no decide nada con ella (el umbral se calibra en el hito 7). La versión está fijada y se comprueba con su huella SHA-256 antes de guardarla, y saber si la copia está al día no usa la red; su código de extracción de características (`thrember`) llega con Argos por pip, desde un zip de GitHub. Solo descarga lo que haya cambiado, así que puedes repetirlo cuando quieras. El filtro de CIRCL pesa 1 GB; `argos actualiza --sin-circl` se lo salta.

**3. Usar**

```
%USERPROFILE%\venvs\argos\Scripts\argos identifica <fichero>
%USERPROFILE%\venvs\argos\Scripts\argos estatico <fichero>
%USERPROFILE%\venvs\argos\Scripts\argos estatico muestra.zip --clave infected
%USERPROFILE%\venvs\argos\Scripts\argos-ventana.exe
```

`argos-ventana.exe` abre la ventana: se suelta un fichero (o se elige con el diálogo de Windows), se escribe la contraseña si es un zip y se pulsa «Analizar». El informe se pinta según llega cada parte, con una pestaña por fichero del zip, las señales de alarma contadas y la barra de EMBER2024 (sin umbral hasta el hito 7). «Actualizar» comprueba y baja lo que falte (reglas, listas, herramientas y modelo), con la opción de saltarse CIRCL (1 GB).

Antes de analizar, Argos comprueba (como mucho una vez cada 24 horas) si hay datos nuevos y, si los hay, te lo dice y te ofrece actualizarlos al momento; con `--sin-red` no comprueba nada por red, ni datos nuevos ni las huellas en CIRCL, MalwareBazaar y VirusTotal (ver «Modo conectado»).

## Requisitos

- Windows 10/11 de 64 bits y Python 3.12
- Para el análisis dinámico: VMware Workstation y una máquina virtual Windows con una instantánea limpia

---

*Proyecto de la asignatura Proyectos de Ciberseguridad (U-tad) y parte de un laboratorio personal para aprender análisis de malware e ingeniería de detección.*
