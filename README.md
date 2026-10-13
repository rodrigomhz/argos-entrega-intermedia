# Argos

> Analizador local de ficheros sospechosos: una alternativa sin conexión a any.run, VirusTotal y CAPE

Argos analiza ficheros sospechosos íntegramente en tu equipo. **Por defecto, ninguna muestra sale de tu máquina.**

## Qué hace

- **Identificación**: huellas SHA-256 y SHA-1, tipo real del fichero con Magika (avisa si la extensión engaña) y si figura en listas locales de malware conocido (MalwareBazaar) y de software conocido (CIRCL hashlookup). Analiza ficheros dentro de zips cifrados sin extraerlos al disco.
- **Análisis estático**: cabeceras PE, firma, secciones y entropía, funciones importadas, reglas YARA, detección de empaquetadores, Microsoft Defender en local y el modelo de detección EMBER2024.
- **Análisis dinámico**: máquina virtual desechable con VMware y `vmrun`; el comportamiento se recoge con CAPEsolo, Noriben o ambos.
- **Informe**: árbol de procesos, conexiones de red y cambios en ficheros y registro, en una interfaz web local.
- **Veredicto**: combina todas las evidencias con reglas explícitas; cada conclusión se puede seguir hasta la prueba que la produjo.

**Modo conectado (opcional):** consulta VirusTotal, abuse.ch y CIRCL enviando solo huellas e indicadores de red, nunca el fichero. Su resultado se muestra aparte y no cambia el veredicto.

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
- **IA**: solo modelos locales para analizar (Magika, EMBER2024); un modelo de lenguaje opcional, solo para explicar el informe

## Estado

En desarrollo, por hitos. Hechos: entorno de desarrollo e identificación de ficheros. Siguiente: análisis estático. Después: interfaz web, análisis dinámico, evaluación con muestras reales y empaquetado.

## Uso (lo que funciona hoy)

```
python -m venv %USERPROFILE%\venvs\argos
%USERPROFILE%\venvs\argos\Scripts\pip install -e .
%USERPROFILE%\venvs\argos\Scripts\argos identifica <fichero>
%USERPROFILE%\venvs\argos\Scripts\argos identifica muestra.zip --clave infected
```

Las listas locales van en `%USERPROFILE%\argos-datos\listas\`:

- `malwarebazaar-sha256.zip`: https://bazaar.abuse.ch/export/txt/sha256/full/
- `circl-hashlookup-full.bloom`: https://cra.circl.lu/hashlookup/hashlookup-full.bloom (1 GB)

## Requisitos

- Windows 10/11 de 64 bits y Python 3.12
- Para el análisis dinámico: VMware Workstation y una máquina virtual Windows con una instantánea limpia

---

*Proyecto de la asignatura Proyectos de Ciberseguridad (U-tad) y parte de un laboratorio personal para aprender análisis de malware e ingeniería de detección.*
