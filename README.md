# escaner-windows

Read-only security auditor for Windows 11 (PowerShell): security posture, hygiene checks, and persistence hunting. Proprietary software, source available on request.

**English** · [Español](#español)

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it is not distributed through any package registry.

This is not abandonment, not an incident, and there was no breach. It is a decision: through 2026 the package registries and code-hosting platforms were hit by sustained, chained supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious extensions that exfiltrated thousands of private repositories. For a security tool, hosting the source there stopped being a neutral decision.

**The source is available on request**, under its licence terms — delivered with a signature and a checksum. This is proprietary software; the terms are provided with the delivery. Request it at **xiliux.com**.

---

## What it does

`escaner-windows` is a **read-only** PowerShell security auditor for Windows 11. It never modifies the system; it only reads and reports.

### Security posture and hygiene

Checks the configuration of the core Windows security controls:

- **Windows Defender** — real-time protection status, signature currency
- **Firewall** — active profiles, inbound/outbound rules
- **BitLocker** — encryption status per volume
- **UAC** — User Account Control level
- **Automatic updates** — Windows Update configuration
- Related hardening settings

### Persistence hunting

Enumerates the locations where malware establishes persistence:

- **Autorun registry keys** — HKLM/HKCU Run, RunOnce, and related keys
- **Scheduled tasks** — all registered tasks with their actions and triggers
- **Services** — installed services, start type, and binary paths
- **WMI subscriptions** — event filters and consumer bindings

The output is a human-readable report suitable for a security review, a device hardening engagement, or a threat-assessment workflow.

---

## Español

Auditor de seguridad de **solo lectura** para Windows 11 (PowerShell): postura de seguridad, higiene y caza de persistencia. Software propietario, fuente a petición.

---

## El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni se distribuye por ningún registro de paquetes.

No es abandono ni un incidente: es una decisión. A lo largo de 2026 los registros de paquetes y las plataformas de código han sufrido ataques encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto, extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar aquí el código de una herramienta de seguridad dejó de ser una decisión neutra.

**El fuente se entrega a petición**, bajo sus términos de licencia, con su firma y su suma de verificación. Es software propietario; los términos se incluyen con la entrega. Solicítalo en **xiliux.com**.

---

## Qué hace

`escaner-windows` es un auditor de seguridad **de solo lectura** en PowerShell para Windows 11. No modifica el sistema; solo lee y reporta.

### Postura e higiene de seguridad

Verifica la configuración de los controles de seguridad centrales de Windows:

- **Windows Defender** — estado de la protección en tiempo real, vigencia de firmas
- **Firewall** — perfiles activos, reglas de entrada y salida
- **BitLocker** — estado del cifrado por volumen
- **UAC** — nivel del Control de Cuentas de Usuario
- **Actualizaciones automáticas** — configuración de Windows Update
- Ajustes de endurecimiento relacionados

### Caza de persistencia

Enumera los puntos donde el malware establece persistencia:

- **Claves de autoarranque en el registro** — Run, RunOnce y claves relacionadas (HKLM/HKCU)
- **Tareas programadas** — todas las tareas registradas con sus acciones y disparadores
- **Servicios** — servicios instalados, tipo de inicio y rutas de los binarios
- **Suscripciones WMI** — filtros de eventos y bindings de consumidores

La salida es un informe legible apto para una revisión de seguridad, un trabajo de endurecimiento de equipos o un proceso de evaluación de amenazas.

---

*escaner-windows* — © 2026 Juan Carlos Isaza. Software propietario, fuente a petición.
