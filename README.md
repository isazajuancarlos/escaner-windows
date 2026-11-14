# escaner-windows

Auditor de seguridad de **solo lectura** para Windows 11. Hermano Windows de
`escaner-android` y de `endurecer-debian-local.sh --check`: mide la **postura**
de seguridad de la máquina y **caza persistencia/anomalías**.

Trabajo de seguridad **defensiva** sobre la propia máquina. Autor: Juan Carlos Isaza.
`SPDX-License-Identifier: LicenseRef-Propietario`.

## Uso

```bat
run.bat
```

`run.bat` pide elevación (UAC) y corre el escaneo. También directo:

```powershell
# Escaneo (como admin para cobertura completa):
pwsh -NoProfile -ExecutionPolicy Bypass -File .\escaner.ps1

# Sin escribir informe, solo consola:
pwsh ... -File .\escaner.ps1 -SinInforme

# Autoprueba de discriminación (D33): planta positivos sintéticos y verifica:
pwsh ... -File .\escaner.ps1 -Autoprueba

# Carpeta de salida personalizada:
pwsh ... -File .\escaner.ps1 -Salida C:\ruta\informe

# Comparar contra un informe previo concreto (por defecto se compara solo):
pwsh ... -File .\escaner.ps1 -Comparar C:\ruta\volcado-...\informe.json

# No comparar con la línea base previa:
pwsh ... -File .\escaner.ps1 -SinComparar
```

## Comparación automática con la corrida anterior

En **cada** corrida, la herramienta compara automáticamente los hallazgos
actuales contra el `informe.json` del último `volcado-*` y muestra una sección
**«Cambios desde la última corrida»**. Es la señal fuerte contra spyware:
importa menos el estado absoluto que lo que **cambió** entre dos fotos.

Clasifica (clave estable = `Categoría|Nombre`):
- **NUEVO** — persistencia/entrada que no estaba antes (p. ej. un autorun recién
  plantado).
- **DESAPARECIDO** — estaba y ya no.
- **CAMBIO-ESTADO** — la misma entrada pasó de `OK` a `ALERTA`, etc.
- **CAMBIO-DETALLE** (menor) — mismo estado, solo cambió el texto (p. ej. una
  versión en la ruta de un actualizador); se cuenta aparte para no hacer ruido,
  salvo que el estado sea `ALERTA`.

Los cambios quedan también en el informe sellado (`cambios` en el JSON, sección
propia en el MD), para cadena de custodia y diffs entre fechas. En la primera
corrida (sin línea base) lo dice; no inventa cambios.

## Qué comprueba

**Postura / higiene**
- Defender: motor (tiempo real/antivirus/servicio/comportamiento), Tamper
  Protection, edad de firmas, **exclusiones** (táctica de evasión).
- Firewall por perfil (Domain/Private/Public).
- BitLocker de **todos los volúmenes fijos** (C:, Z:, …) *(admin)*.
- UAC, SmartScreen, Secure Boot *(admin)*, LSA protegida (RunAsPPL).
- Exposición remota: RDP, WinRM, SMBv1 *(admin)*.
- Cuentas: administradores locales (por SID), Invitado, flag de contraseña.

**Caza de persistencia / anomalías**
- Autoruns: claves Run/RunOnce (HKLM+HKCU) y carpetas de inicio, con
  verificación de **firma Authenticode** y de rutas escribibles por usuario.
- Tareas programadas: comandos codificados/de descarga, o binarios sin firma de
  confianza en ruta de usuario.
- Servicios: binario en ruta blanda sin firma, o ruta con espacios sin comillas
  (secuestro).
- Suscripciones **WMI permanentes** (persistencia APT clásica) *(admin)*.
- Red: puertos a la escucha de procesos en ruta blanda; archivo `hosts`.
- **Tripwire de integridad de `Z:`** (ver sección propia): hash de ejecutables/
  scripts en raíces configurables; marca lo nuevo/cambiado entre corridas.

## Tripwire de integridad de `Z:`

`Z:` está **excluido del escaneo en tiempo real de Defender** (falso positivo del
AV sobre la herramienta de seguridad: `nuclei`/`subfinder` y familia se marcan
como `HackTool`). Para compensar esa cobertura perdida **sin añadir fricción**,
el escáner incluye un tripwire de integridad: en cada corrida calcula el
**SHA256** de los ejecutables y scripts de un conjunto de **raíces configurables**
y marca lo **NUEVO** o **CAMBIADO** desde la última corrida.

- **Config:** `tripwire.txt` (una raíz por línea; `#` = comentario). Se crea con
  el default `Z:\conocimiento` + `Z:\scripts` la primera vez. Añade las raíces
  **estables y de alto valor** que quieras vigilar.
- **Por qué no todo `Z:`:** medido — vigilar el disco entero son 16 000+ archivos
  y >90 s por corrida (árboles de build/dependencias); sería lento y ruidoso. Se
  podan `target`, `node_modules`, `.git`, `.cargo`, y **nunca** se toca
  `Z:\documentos`.
- **Severidad calibrada (D23):** un **binario** (`.exe/.dll/.scr/.msi`) nuevo o
  cambiado → **ALERTA** (rara vez los editas a mano; si no tiene firma válida,
  alta). Un **script** (`.ps1/.bat/.js…`) nuevo o cambiado → **INFO** (casi
  siempre tuyo), pero se lista para que lo revises.
- **Reporte-una-vez:** el manifiesto (`tripwire-manifiesto.json`) se actualiza
  cada corrida, así un cambio se reporta una vez y pasa a ser la nueva base.
- **Flags:** `-SinTripwire` (omitir), `-TripwireReset` (reestablecer la base sin
  alertar, p. ej. tras un cambio legítimo grande).

`tripwire.txt` y `tripwire-manifiesto.json` son locales a la máquina (no se
versionan).

## Principios de diseño (las directivas, aplicadas)

- **Solo lectura.** No modifica el sistema. La única excepción es `-Autoprueba`,
  que planta positivos sintéticos **reversibles** en HKCU + carpeta de inicio
  (sin admin) y los limpia en un bloque `finally`.
- **Tri-estado (D20/D30).** Cada comprobación da `OK` / `ALERTA` /
  `NO-DETERMINADO`. Un *"sin amenazas"* **no** se confunde con *"el chequeo no
  corrió"*: lo que no se pudo determinar se dice ruidosamente (p. ej. falta de
  privilegios). El resumen cierra con el positivo de control: cuántas corrieron,
  cuántas alertaron, cuántas quedaron sin determinar.
- **Discrimina de verdad (D23/D33).** Las reglas enumeran lo *demostrablemente
  benigno* (binario firmado por Microsoft en el SO, actualizador de proveedor
  firmado en ruta de usuario) y mandan el resto a revisión. No marcan la
  operación normal de Windows (`rundll32`/`cmd` firmados, Defender en
  `ProgramData\...\Platform`). La discriminación se prueba con `-Autoprueba`:
  planta un positivo conocido y confirma que lo caza (banco de solo-negativos
  sobre una máquina limpia no discriminaría).

## Código de salida

- `0` — limpio (sin alertas ni indeterminadas).
- `1` — hay al menos una ALERTA.
- `2` — hay comprobaciones NO-DETERMINADAS sin alertas (normalmente: correr como admin).

## Informe

Por defecto escribe `volcado-<máquina>-<fecha>/` junto al script, con:
- `informe.json` — estructurado (para diffs entre corridas / cadena de custodia).
- `informe.md` — legible.

## Limitaciones conocidas

- Los `.lnk` en carpetas de inicio se listan como INFO (no se resuelve el
  destino del acceso directo para verificar su firma — pendiente de mejora).
- La caza de red marca listeners de procesos en ruta blanda; no hace análisis de
  conexiones salientes ni reputación de IP.
- No envuelve herramientas forenses (MVT/Autoruns de Sysinternals); es un
  **pre-vuelo** de higiene y persistencia, no un análisis forense completo.
