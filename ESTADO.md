# ESTADO — dónde está Argos ahora mismo

> Documento de traspaso. Actualizado el **26 de septiembre de 2026** (segunda revisión del día).
> Léelo entero antes de proponer nada. Si algo de aquí contradice a otro documento, gana este.

---

## 1. Qué es Argos

Analizador de ficheros sospechosos que funciona **entero en el ordenador de Calvo**. Le das un
fichero y devuelve un informe: qué es, qué lleva dentro, y qué hace al ejecutarse en una máquina
virtual desechable. Lo que hacen VirusTotal y any.run, **sin enviar la muestra a nadie**.

**No es un antivirus. No bloquea nada. No se queda residente. Analiza e informa.**

Nació como proyecto de la asignatura *Proyectos de Ciberseguridad (4º)* en U-tad. Calvo también lo
ha llamado su TFG; si es una cosa, la otra, o las dos, **sigue sin confirmar**.

Se llamó `ZeroTrustLauncher`, luego `Cerbero`. El nombre definitivo es **Argos**, por Argos
Panoptes, el gigante de cien ojos.

---

## 2. Dónde está cada cosa

| Qué | Dónde |
|---|---|
| Bóveda del proyecto + repo git | `C:\Users\rodri\Nextcloud\Argos\` |
| Repo remoto privado | `https://github.com/rodrigomhz/argos` (origin) |
| Documento de arranque | `Argos\00 - Que es Argos.md` |
| **Memoria de la asignatura** | `Nextcloud\mi-cerebro-digital\1 - Universidad\Cuarto\Proyectos de Ciberseguridad\Memoria - Planteamiento final y estructura.md` |
| Enunciado del profesor (md + pdf) | misma carpeta, subcarpeta `Entrega\` |
| Material viejo, descartado | `D:\Universidad\Cuarto\Primer_Cuatri\Proyectos4\zerotrust-launcher\` |

La bóveda está dentro de Nextcloud, así que **sincroniza sola** entre la torre y el portátil.
Consecuencias que hay que respetar:

- Nextcloud sincroniza también `.git`, y usa ficheros virtuales: la carpeta va **anclada en cada
  máquina**. Hecho: torre el 24-09-2026, portátil el 26-09-2026. Comprobado que no queda ningún
  fichero con atributo `O` (solo en la nube). Si hiciera falta repetirlo:
  `attrib -U +P "C:\Users\rodri\Nextcloud\Argos\*" /S /D` (el `\*` es obligatorio).
- Cambiar de máquina solo con Nextcloud al día, y hacer push al cerrar cada hito.
- Un `.gitignore` no frena a Nextcloud. El entorno de Python, las muestras y los ejecutables
  generados tienen que vivir **fuera de esta carpeta**, no solo fuera de git.

---

## 3. Estado a 26-09-2026

**Código escrito: ninguno.** Hito 1 cerrado, hito 2 sin empezar.

- Bóveda creada, con `00 - Que es Argos.md` aprobado por Calvo el 21-09-2026.
- Repo git creado el 24-09-2026: `git init -b main`, commit `5e2bc94 Paso 1: qué es Argos`,
  vinculado a GitHub privado. Verificado que el remoto lo tiene y que sin sesión da 404.
- **Memoria de la asignatura: 6 de 8 apartados escritos** (ver punto 5).

---

## 4. Los 8 hitos del desarrollo

| Hito | Contenido | Criterio de terminación | Estado |
|---|---|---|---|
| 1 | Planteamiento del proyecto | Documento revisado y aprobado | **Cerrado** |
| 2 | Entorno de desarrollo | Un comando devuelve la versión instalada | Sin empezar |
| 3 | Identificación de un fichero | Devuelve huella digital y tipo | Sin empezar |
| 4 | Análisis estático de ejecutables | Devuelve firmante, secciones y APIs | Sin empezar |
| 5 | Interfaz web local | Se arrastra un fichero y sale el informe | Sin empezar |
| 6 | Máquina virtual desechable | Ejecuta la muestra y recoge su comportamiento | Sin empezar |
| 7 | Evaluación sobre muestras reales | Tasas de acierto y falso positivo medidas | Sin empezar |
| 8 | Empaquetado | Ejecutable que corre en otro equipo sin instalar | Sin empezar |

**Estructura de la herramienta: cuatro capas en cascada.** Cada una puede dar veredicto y cortar,
para que el análisis caro solo se ejecute si el barato no resuelve:

1. Identificación — tipo, huella digital, tamaño
2. Análisis estático — firma Authenticode, entropía por secciones, APIs, reglas
3. Análisis dinámico — VM desechable, red simulada, restauración tras cada muestra
4. Informe — interfaz web local

---

## 5. La entrega de la asignatura

El profesor pide un documento con 8 apartados. Estado:

| # | Apartado | Estado |
|---|---|---|
| 1 | Investigaciones y desarrollos similares, incluidas las basadas en IA | Escrito |
| 2 | Tipo de planteamiento elegido, justificado | Escrito |
| 3 | Estrategia de uso de IA en el desarrollo | Escrito |
| 4 | Componente de IA integrado | Escrito (como ampliación aplazada) |
| 5 | Diagrama de flujo | **PENDIENTE** |
| 6 | Hitos y estructura | Escrito |
| 7 | Tecnologías y lenguajes | Escrito |
| 8 | Hardware necesario y coste | **PENDIENTE** (falta medir el equipo) |

El apartado 1 se escribió el 26-09-2026 a partir del material viejo de `D:`. Cubre VirusTotal,
any.run, Hatching Triage, CAPEv2, DRAKVUF y `darama22/ZeroTrustLauncher`, y como herramienta
basada en IA cita **VirusTotal Code Insight** (abril de 2023, sobre Sec-PaLM), cuya clave es que
el modelo **no detecta, solo explica** — el mismo reparto que defiende el apartado 2.

**Aviso dentro del documento (línea ~96): falta verificar qué funciones de IA tiene any.run hoy**
antes de entregar. Lo de VirusTotal sí está verificado; lo de any.run no.

---

## 6. Decisiones cerradas — no se rediscuten

1. **No se sube ningún fichero a servicios externos.** Ni VirusTotal, ni any.run, ni ninguna API.
   Es el requisito que justifica el proyecto, no una limitación que haya que disculpar. Descargar
   muestras de fuentes públicas sí vale: bajar no es publicar.
2. **Analiza e informa; no bloquea nada.** Entre el 15 y el 18-09-2026 el proyecto derivó hacia un
   "portero" que interceptaba la ejecución con WDAC e IFEO. Calvo no reconocía su proyecto y se
   descartó. No volver a proponerlo.
3. **Argos no lleva IA dentro.** Claude se usa solo para desarrollarlo. Razones: reproducibilidad,
   auditabilidad, coherencia con el punto 1, y el precedente de VirusTotal.
4. **Python.** Trabajo individual.
5. **Nada de CAPEv2 ni DRAKVUF**: piden anfitrión Linux con KVM o Xen, y el anfitrión es Windows.
   La VM se orquesta a mano con `vmrun` de VMware.
6. **El servidor bitboss está fuera**: 4 GB de RAM y hardware viejo.
7. **No se forkea `darama22/ZeroTrustLauncher`**: 5 commits de Python con análisis estático básico.
   Es inspiración y referencia del estado del arte, no base de código.
8. **Tiene que acabar siendo un ejecutable empaquetado** que funcione en otro equipo sin instalar
   nada, para enseñarlo en la defensa. Condiciona cómo se escribe desde el principio: rutas
   relativas, nada clavado a su usuario, dependencias empaquetables.
9. **Todo se queda en `Nextcloud\Argos`: notas y repo git juntos.** El 26-09-2026 se le propuso
   separar el código de las notas y dijo que no: *"lo ponemos en github y ya"*. La carpeta está
   anclada en las dos máquinas y funciona. **No volver a sacar el tema**: le roba tiempo de lo que
   puntúa.

---

## 7. La capa de IA: aplazada, no cerrada

Argos no integra IA, pero la integración quedó **analizada y escrita** en el apartado 4 de la
memoria. **Se reevalúa al cerrar el hito 7**, no en una fecha. Antes de ese hito, no proponerla.

Si llegara a hacerse: capa explicativa al final, que recibe el informe ya generado y redacta un
resumen. **Nunca participa en el veredicto.** Modelo local; API externa excluida.

El argumento que da valor a esa sección: en un analizador de malware **el contenido de entrada lo
controla el atacante por definición**. Un binario puede llevar cadenas escritas para manipular al
modelo que vaya a leerlas. El atacante no necesita comprometer nada: le basta con que su fichero
sea analizado. Mitigaciones escritas: separar veredicto de explicación; tratar el contenido de la
muestra siempre como dato y nunca como instrucción; componente sin capacidad de acción; salida
marcada como no verificada; y prueba adversaria con cadenas de inyección deliberadas.

---

## 8. Cómo trabajar con Calvo en este proyecto

Esto no es estilo, es un requisito del proyecto. El 21-09-2026 se montó Argos entero de golpe
(código funcionando, entorno, 7 documentos) y mandó **borrarlo todo**.

- **Un hito por turno.** Se acaba, se enseña funcionando, se para y se espera su visto bueno. No se
  empieza el siguiente hasta que él lo entienda.
- **Cada hito deja su documento numerado** en la bóveda, escrito **para que lo lea él**, no para
  otra IA. Sin jerga; lo que sea jerga, se traduce.
- **Ningún fichero que no haya pedido o aceptado.** Nada de andamiaje preventivo.
- **Evidencia ejecutada.** Si dices que algo funciona, pega la salida que lo demuestra.
- **Nada de estimaciones de tiempo inventadas.** Solo con una medida real; si no, di de qué depende.
- Tiene TDAH: primero la acción, pasos numerados, un único siguiente paso al final.
- Español de España, tuteo, sin ceremonia.

El motivo de fondo: **es su trabajo y lo defiende él.** Código que no ha visto nacer no le sirve.

---

## 9. Entorno

Medido en el **portátil** (hostname `PORTATIL`, ASUS TUF FX505DT, Ryzen 7 3750H, 4 núcleos / 8
hilos, 13,9 GB de RAM):

- `C:` — Micron NVMe de 477 GB. **635 MB/s** de escritura. Aquí va el código.
- `D:` — **Seagate Expansion, disco USB externo** de 932 GB. **71 MB/s**. Aquí van las VMs de
  laboratorio (Kali, Parrot) y la carrera en `D:\Universidad`. **No sincroniza** y solo está si el
  disco está enchufado.
- Windows 11 25H2 build 26200, **edición Home**: no hay Windows Sandbox ni rol Hyper-V. No importa.
- **VMware Workstation 17.6.4** con `vmrun`. Usar VMware, **no VirtualBox**: con VBS/HVCI activos,
  VirtualBox cae a un backend de compatibilidad y va mucho más lento.
- Python 3.12.10 y git 2.51 resuelven por nombre. `gh` **no está instalado** en el portátil.
- La torre (`DESKTOP-2ETQ43Q`, Ryzen 5 7600X + RX 7800 XT) es la otra máquina.

**La VM de análisis de Argos**: ruta **configurable**, por defecto en `C:`. A Calvo le da igual
dónde esté mientras pueda moverla el día de la demo. Por eso la ruta va en un fichero de
configuración y nunca fija en el código.

---

## 10. Lo siguiente

Dos frentes abiertos. Calvo elige por cuál seguir:

1. **Terminar la memoria de la asignatura.** Quedan dos apartados:
   - **8 — Hardware.** Se cierra rápido: medir el equipo y escribirlo. Es lo inmediato.
   - **5 — Diagrama de flujo.** Las cuatro capas en cascada, sin puntos de IA. Hay que decidir si
     se dibuja en Mermaid dentro del documento o como imagen aparte.
2. **Empezar el hito 2** — preparar el entorno de desarrollo.

Antes de entregar, resolver el aviso del apartado 1: verificar las funciones de IA de any.run.

Pendiente menor: confirmar si Argos es el TFG o solo el proyecto de la asignatura.
