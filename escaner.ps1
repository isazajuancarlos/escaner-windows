<#
.SINOPSIS
    escaner-windows — auditor de seguridad de SOLO LECTURA para Windows 11.

.DESCRIPCION
    Hermano Windows de escaner-android y de endurecer-debian-local.sh --check.
    Mide la POSTURA de seguridad (Defender, firewall, BitLocker, UAC, exposicion
    remota, cuentas) y CAZA PERSISTENCIA/anomalias (autoruns firmados, tareas,
    servicios, suscripciones WMI permanentes, red, hosts).

    Contrato: NO modifica el sistema. Solo lee. La UNICA excepcion es -Autoprueba,
    que planta positivos sinteticos reversibles en HKCU + carpeta Startup del
    usuario (sin admin) para demostrar que los detectores discriminan, y limpia.

    Cada comprobacion es TRI-ESTADO (D20/D30): OK / ALERTA / NO-DETERMINADO. Un
    "sin amenazas" NO se confunde con "el chequeo no corrio": lo que no se pudo
    determinar se dice ruidosamente. El informe cierra con un positivo de control:
    cuantas comprobaciones corrieron, cuantas alertaron y cuantas quedaron sin
    determinar.

.PARAMETER Salida
    Carpeta donde escribir el informe sellado (JSON + Markdown). Por defecto, un
    subdirectorio volcado-<fecha> junto al script.

.PARAMETER SinInforme
    No escribe archivos; solo imprime el resumen en consola.

.PARAMETER Autoprueba
    Ejecuta la discriminacion D33: planta positivos sinteticos, verifica que los
    detectores los cazan, y limpia. Modifica HKCU temporalmente (reversible).

.NOTES
    Autor: Juan Carlos Isaza
    SPDX-License-Identifier: LicenseRef-Propietario
    Trabajo de seguridad DEFENSIVA sobre la propia maquina.
#>
[CmdletBinding()]
param(
    [string]$Salida,
    [switch]$SinInforme,
    [switch]$Autoprueba,
    [string]$Comparar,     # informe.json previo explicito (por defecto: el ultimo volcado-*)
    [switch]$SinComparar,  # no comparar con la linea base previa
    [switch]$SinTripwire,  # no correr el tripwire de integridad de Z:
    [switch]$TripwireReset # reestablecer la linea base del tripwire (no alerta este turno)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$OutputEncoding = [System.Text.Encoding]::UTF8

# --- Estado global del escaneo -------------------------------------------------
$script:Hallazgos = [System.Collections.Generic.List[object]]::new()

function Nuevo-Hallazgo {
    param(
        [Parameter(Mandatory)][string]$Categoria,
        [Parameter(Mandatory)][string]$Nombre,
        [Parameter(Mandatory)][ValidateSet('OK','ALERTA','NO-DETERMINADO','INFO')][string]$Estado,
        [string]$Detalle = '',
        [ValidateSet('alta','media','baja','-')][string]$Severidad = '-'
    )
    $script:Hallazgos.Add([pscustomobject]@{
        Categoria = $Categoria
        Nombre    = $Nombre
        Estado    = $Estado
        Severidad = $Severidad
        Detalle   = $Detalle
    })
}

# Envoltura: si el bloque revienta, se registra NO-DETERMINADO (nunca OK silencioso).
function Comprobar {
    param(
        [string]$Categoria,
        [string]$Nombre,
        [scriptblock]$Bloque
    )
    try {
        & $Bloque
    } catch {
        Nuevo-Hallazgo -Categoria $Categoria -Nombre $Nombre -Estado 'NO-DETERMINADO' `
            -Detalle "la comprobacion no pudo ejecutarse: $($_.Exception.Message)" -Severidad 'media'
    }
}

function Es-Admin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# Rutas escribibles por el usuario = terreno tipico de persistencia de malware.
$script:RutasBlandas = @(
    $env:TEMP, $env:TMP, $env:APPDATA, $env:LOCALAPPDATA,
    "$env:USERPROFILE\Downloads", "$env:PUBLIC", "C:\Windows\Temp",
    "$env:ProgramData"
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }

# Extrae la ruta del ejecutable de una linea de comando (comillas o argumentos).
function Extraer-Exe {
    param([string]$Ruta)
    if (-not $Ruta) { return '' }
    $exe = $Ruta.Trim()
    if ($exe.StartsWith('"')) {
        $fin = $exe.IndexOf('"', 1)
        if ($fin -gt 0) { return $exe.Substring(1, $fin - 1) }
        return $exe.Trim('"')
    }
    $m = [regex]::Match($exe, '^(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|scr|com))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($exe -split '\s+')[0]
}

function Ruta-Blanda {
    param([string]$Ruta)
    if (-not $Ruta) { return $false }
    $exe = (Extraer-Exe $Ruta).ToLower()
    foreach ($b in $script:RutasBlandas) { if ($b -and $exe.StartsWith($b)) { return $true } }
    return $false
}

function Firma-De {
    param([string]$Ruta)
    # Devuelve {Estado; Firmante} de la firma Authenticode del ejecutable.
    $exe = [Environment]::ExpandEnvironmentVariables((Extraer-Exe $Ruta))
    if (-not $exe -or $exe -match '\$\(' ) { return [pscustomobject]@{ Estado='sin-archivo'; Firmante='' } }
    if (-not (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Estado='sin-archivo'; Firmante='' }
    }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
        $firmante = ''
        if ($s.SignerCertificate) { $firmante = $s.SignerCertificate.Subject }
        return [pscustomobject]@{ Estado=$s.Status.ToString(); Firmante=$firmante }
    } catch {
        return [pscustomobject]@{ Estado='sin-determinar'; Firmante='' }
    }
}

# Firma valida de cualquier editor (actualizador de proveedor conocido, etc.).
function Firma-Confiable { param($F) return ($F.Estado -eq 'Valid') }
# Firma valida y emitida por Microsoft (binarios del propio SO).
function Es-Microsoft {
    param($F)
    return ($F.Estado -eq 'Valid' -and $F.Firmante -match 'O=Microsoft (Corporation|Windows)')
}

# ==============================================================================
#  POSTURA / HIGIENE
# ==============================================================================

function Auditar-Defender {
    $cat = 'Defender'
    Comprobar $cat 'Estado del motor' {
        $st = Get-MpComputerStatus -ErrorAction Stop
        $probl = @()
        if (-not $st.RealTimeProtectionEnabled) { $probl += 'proteccion en tiempo real APAGADA' }
        if (-not $st.AntivirusEnabled)          { $probl += 'antivirus apagado' }
        if (-not $st.AMServiceEnabled)          { $probl += 'servicio antimalware apagado' }
        if (-not $st.BehaviorMonitorEnabled)    { $probl += 'monitor de comportamiento apagado' }
        if ($probl.Count) {
            Nuevo-Hallazgo $cat 'Estado del motor' 'ALERTA' ($probl -join '; ') 'alta'
        } else {
            Nuevo-Hallazgo $cat 'Estado del motor' 'OK' 'tiempo real, antivirus, servicio y comportamiento activos'
        }
        # Tamper Protection
        if ($st.PSObject.Properties.Name -contains 'IsTamperProtected') {
            if ($st.IsTamperProtected) { Nuevo-Hallazgo $cat 'Tamper Protection' 'OK' 'activa' }
            else { Nuevo-Hallazgo $cat 'Tamper Protection' 'ALERTA' 'desactivada (permite apagar Defender)' 'media' }
        }
        # Edad de firmas
        $edad = [int]$st.AntivirusSignatureAge
        if ($edad -le 3) { Nuevo-Hallazgo $cat 'Edad de firmas' 'OK' "$edad dia(s)" }
        elseif ($edad -le 7) { Nuevo-Hallazgo $cat 'Edad de firmas' 'INFO' "$edad dias" 'baja' }
        else { Nuevo-Hallazgo $cat 'Edad de firmas' 'ALERTA' "$edad dias sin actualizar firmas" 'media' }
    }
    # Exclusiones: tactica clasica de evasion. Cualquier exclusion es, como minimo, INFO.
    Comprobar $cat 'Exclusiones' {
        $pref = Get-MpPreference -ErrorAction Stop
        $ex = @()
        foreach ($campo in 'ExclusionPath','ExclusionProcess','ExclusionExtension') {
            $v = $pref.$campo
            if ($v) { foreach ($x in $v) { $ex += "$campo=$x" } }
        }
        # Sin admin, Get-MpPreference devuelve el texto "N/A: Must be an administrator...".
        if ($ex | Where-Object { $_ -match 'Must be an administrator' }) {
            Nuevo-Hallazgo $cat 'Exclusiones' 'NO-DETERMINADO' 'requiere administrador para ver las exclusiones de Defender' 'media'
            return
        }
        if ($ex.Count -eq 0) {
            Nuevo-Hallazgo $cat 'Exclusiones' 'OK' 'sin exclusiones definidas'
        } else {
            # Exclusion en ruta blanda, o a RAIZ de disco (C:\, Z:\), = mas grave:
            # un atacante que la conoce deja su carga ahi. Siempre: confirmar autoria.
            $sev = 'media'; $raiz = $false
            foreach ($e in $ex) {
                $ruta = ($e -replace '^[^=]+=','')
                if (Ruta-Blanda $ruta) { $sev = 'alta' }
                if ($ruta -match '^[A-Za-z]:\\?$') { $sev = 'alta'; $raiz = $true }
            }
            $nota = if ($raiz) { ' [exclusion a RAIZ de disco — confirma que la pusiste TU]' } else { ' [confirma que las pusiste TU]' }
            Nuevo-Hallazgo $cat 'Exclusiones' 'ALERTA' ("revisar: " + ($ex -join ' | ') + $nota) $sev
        }
    }
}

function Auditar-Firewall {
    $cat = 'Firewall'
    Comprobar $cat 'Perfiles' {
        $perf = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $perf) {
            if ($p.Enabled) { Nuevo-Hallazgo $cat "Perfil $($p.Name)" 'OK' 'activo' }
            else { Nuevo-Hallazgo $cat "Perfil $($p.Name)" 'ALERTA' 'DESACTIVADO' 'alta' }
        }
    }
}

function Auditar-BitLocker {
    $cat = 'BitLocker'
    if (-not (Es-Admin)) {
        Nuevo-Hallazgo $cat 'Cifrado de discos' 'NO-DETERMINADO' 'requiere ejecutar como administrador' 'media'
        return
    }
    # TODOS los volumenes fijos, no solo el de sistema: en esta maquina el trabajo
    # vive en un disco aparte (Z:), que importa tanto o mas que C:.
    Comprobar $cat 'Cifrado de discos' {
        $sys = ($env:SystemDrive).TrimEnd('\')
        $fijos = Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
        $n = 0
        foreach ($v in ($fijos | Sort-Object DriveLetter)) {
            $mp = "$($v.DriveLetter):"
            $n++
            try {
                $bl = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
                $esSys = ($mp -eq $sys)
                $etqSys = if ($esSys) { ' [sistema]' } else { '' }
                if ($bl.ProtectionStatus -eq 'On') {
                    Nuevo-Hallazgo $cat "Volumen $mp" 'OK' "cifrado ($($bl.EncryptionPercentage)%)$etqSys"
                } else {
                    $sev = if ($esSys) { 'alta' } else { 'media' }
                    Nuevo-Hallazgo $cat "Volumen $mp" 'ALERTA' "SIN proteccion BitLocker$etqSys" $sev
                }
            } catch {
                Nuevo-Hallazgo $cat "Volumen $mp" 'NO-DETERMINADO' "no se pudo consultar BitLocker: $($_.Exception.Message)" 'media'
            }
        }
        if ($n -eq 0) { Nuevo-Hallazgo $cat 'Cifrado de discos' 'NO-DETERMINADO' 'no se enumeraron volumenes fijos' 'media' }
    }
}

function Auditar-UAC {
    $cat = 'UAC/SmartScreen'
    Comprobar $cat 'UAC' {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $luaProp = Get-ItemProperty -Path $k -Name EnableLUA -ErrorAction Stop
        if ($luaProp.EnableLUA -eq 1) { Nuevo-Hallazgo $cat 'UAC' 'OK' 'EnableLUA=1' }
        else { Nuevo-Hallazgo $cat 'UAC' 'ALERTA' 'UAC desactivado (EnableLUA=0)' 'alta' }
    }
    Comprobar $cat 'SmartScreen' {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        $v = $null
        if ($p -and ($p.PSObject.Properties.Name -contains 'SmartScreenEnabled')) { $v = $p.SmartScreenEnabled }
        if ($null -eq $v) { Nuevo-Hallazgo $cat 'SmartScreen' 'INFO' 'sin politica explicita (valor por defecto del sistema)' 'baja' }
        elseif ($v -eq 'Off') { Nuevo-Hallazgo $cat 'SmartScreen' 'ALERTA' 'SmartScreen apagado' 'media' }
        else { Nuevo-Hallazgo $cat 'SmartScreen' 'OK' "SmartScreen=$v" }
    }
}

function Auditar-SecureBoot {
    $cat = 'Arranque/Credenciales'
    Comprobar $cat 'Secure Boot' {
        if (-not (Es-Admin)) {
            Nuevo-Hallazgo $cat 'Secure Boot' 'NO-DETERMINADO' 'requiere administrador para Confirm-SecureBootUEFI' 'baja'
            return
        }
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) { Nuevo-Hallazgo $cat 'Secure Boot' 'OK' 'activo' }
        else { Nuevo-Hallazgo $cat 'Secure Boot' 'ALERTA' 'desactivado' 'media' }
    }
    Comprobar $cat 'LSA protegida (RunAsPPL)' {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $v = (Get-ItemProperty -Path $k -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
        if ($v -eq 1) { Nuevo-Hallazgo $cat 'LSA protegida (RunAsPPL)' 'OK' 'activa (dificulta volcado de credenciales)' }
        else { Nuevo-Hallazgo $cat 'LSA protegida (RunAsPPL)' 'INFO' 'no activa (endurecimiento opcional)' 'baja' }
    }
}

function Auditar-ExposicionRemota {
    $cat = 'Exposicion remota'
    Comprobar $cat 'RDP' {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $v = (Get-ItemProperty -Path $k -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
        if ($v -eq 1) { Nuevo-Hallazgo $cat 'RDP' 'OK' 'escritorio remoto deshabilitado' }
        else { Nuevo-Hallazgo $cat 'RDP' 'ALERTA' 'escritorio remoto HABILITADO' 'media' }
    }
    Comprobar $cat 'WinRM' {
        $s = Get-Service -Name WinRM -ErrorAction Stop
        if ($s.Status -eq 'Running') { Nuevo-Hallazgo $cat 'WinRM' 'INFO' 'servicio WinRM en ejecucion (gestion remota)' 'baja' }
        else { Nuevo-Hallazgo $cat 'WinRM' 'OK' "WinRM detenido ($($s.Status))" }
    }
    Comprobar $cat 'SMBv1' {
        if (-not (Es-Admin)) {
            Nuevo-Hallazgo $cat 'SMBv1' 'NO-DETERMINADO' 'requiere administrador' 'baja'
            return
        }
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($f.State -eq 'Enabled') { Nuevo-Hallazgo $cat 'SMBv1' 'ALERTA' 'SMBv1 HABILITADO (protocolo obsoleto, EternalBlue)' 'alta' }
        else { Nuevo-Hallazgo $cat 'SMBv1' 'OK' "SMBv1 $($f.State)" }
    }
}

function Auditar-Cuentas {
    $cat = 'Cuentas'
    Comprobar $cat 'Administradores locales' {
        # Por SID (S-1-5-32-544): el nombre del grupo esta localizado ("Administradores").
        $grupo = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        $m = Get-LocalGroupMember -Group $grupo.Name -ErrorAction Stop
        $nombres = ($m | ForEach-Object { $_.Name }) -join ', '
        Nuevo-Hallazgo $cat 'Administradores locales' 'INFO' "miembros: $nombres" 'baja'
    }
    Comprobar $cat 'Cuenta Invitado' {
        # SID relativo -501; el nombre esta localizado ("Invitado").
        $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like 'S-1-5-*-501' }
        if (-not $g) { Nuevo-Hallazgo $cat 'Cuenta Invitado' 'OK' 'no existe cuenta Invitado'; return }
        if ($g.Enabled) { Nuevo-Hallazgo $cat 'Cuenta Invitado' 'ALERTA' 'habilitada' 'media' }
        else { Nuevo-Hallazgo $cat 'Cuenta Invitado' 'OK' 'deshabilitada' }
    }
    Comprobar $cat 'Contrasena no requerida' {
        $u = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop |
             Where-Object { $_.PasswordRequired -eq $false -and $_.Disabled -eq $false }
        if ($u) {
            $n = ($u | ForEach-Object { $_.Name }) -join ', '
            # No discrimina entre contrasena en blanco y login por PIN/Hello (lo normal en Win11).
            Nuevo-Hallazgo $cat 'Contrasena no requerida' 'INFO' "cuentas con flag 'password not required': $n (normal si usan PIN/Hello; riesgo solo si es contrasena local en blanco)" 'baja'
        } else {
            Nuevo-Hallazgo $cat 'Contrasena no requerida' 'OK' 'todas las cuentas activas exigen contrasena'
        }
    }
}

# ==============================================================================
#  CAZA DE PERSISTENCIA / ANOMALIAS
# ==============================================================================

function Auditar-Autoruns {
    $cat = 'Autoruns'
    $claves = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    Comprobar $cat 'Claves Run/RunOnce' {
        $total = 0
        foreach ($c in $claves) {
            if (-not (Test-Path $c)) { continue }
            $props = Get-ItemProperty -Path $c -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                $total++
                $cmd = [string]$p.Value
                $blanda = Ruta-Blanda $cmd
                $firma = Firma-De $cmd
                $txt = "$c :: $($p.Name) => $cmd"
                # Regla (D23): enumera lo demostrablemente benigno; el resto, a revision.
                #  - ruta blanda + firma invalida/ausente -> ALERTA alta (lo que planta el malware)
                #  - ruta blanda + firma valida          -> INFO (actualizador de proveedor firmado)
                #  - ruta de sistema + firma no valida   -> ALERTA media (binario no firmado donde deberia)
                #  - resto                                -> OK
                if ($blanda -and -not (Firma-Confiable $firma)) {
                    Nuevo-Hallazgo $cat "Run: $($p.Name)" 'ALERTA' "$txt [ruta escribible por usuario + firma=$($firma.Estado)]" 'alta'
                } elseif ($blanda) {
                    Nuevo-Hallazgo $cat "Run: $($p.Name)" 'INFO' "$txt [ruta de usuario, firmado: $($firma.Firmante)]" 'baja'
                } elseif ($firma.Estado -notin 'Valid','sin-archivo') {
                    Nuevo-Hallazgo $cat "Run: $($p.Name)" 'ALERTA' "$txt [firma=$($firma.Estado) fuera de ruta de usuario]" 'media'
                } else {
                    Nuevo-Hallazgo $cat "Run: $($p.Name)" 'OK' $txt
                }
            }
        }
        if ($total -eq 0) { Nuevo-Hallazgo $cat 'Claves Run/RunOnce' 'OK' 'sin entradas' }
        else { Nuevo-Hallazgo $cat 'Claves Run/RunOnce' 'INFO' "$total entrada(s) examinadas (positivo de control)" 'baja' }
    }
    Comprobar $cat 'Carpetas de inicio' {
        $carpetas = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        ) | Where-Object { $_ }
        $total = 0
        foreach ($d in $carpetas) {
            if (-not (Test-Path $d)) { continue }
            Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -eq 'desktop.ini') { return }  # metadato de carpeta, no un programa
                $total++
                $firma = Firma-De $_.FullName
                if ($_.Extension -in '.lnk','.ini' -or (Firma-Confiable $firma)) {
                    Nuevo-Hallazgo $cat "Startup: $($_.Name)" 'INFO' "archivo de inicio: $($_.FullName)" 'baja'
                } else {
                    Nuevo-Hallazgo $cat "Startup: $($_.Name)" 'ALERTA' "archivo de inicio NO firmado: $($_.FullName)" 'media'
                }
            }
        }
        if ($total -eq 0) { Nuevo-Hallazgo $cat 'Carpetas de inicio' 'OK' 'carpetas de inicio vacias' }
    }
}

function Auditar-TareasProgramadas {
    $cat = 'Tareas programadas'
    Comprobar $cat 'Acciones sospechosas' {
        # La senal NO es "usa rundll32/cmd" (lo hace medio Windows), sino el comando
        # codificado/de descarga (tecnica de ataque) o un binario sin firma de confianza
        # en ruta de usuario. Lo firmado por Microsoft en system32 NO se marca (D18/D23).
        $codificado = '-enc\b|-encodedcommand|downloadstring|frombase64|invoke-expression|\biex\b|certutil.*-urlcache|bitsadmin.*/transfer|-nop\b.*-w\b|hidden.*-c\b'
        $tareas = Get-ScheduledTask -ErrorAction Stop
        $marcadas = 0; $total = 0
        foreach ($t in $tareas) {
            foreach ($a in @($t.Actions)) {
                if ($a.PSObject.Properties.Name -notcontains 'Execute') { continue }
                if (-not $a.Execute) { continue }
                $total++
                $linea = "$($a.Execute) $($a.Arguments)".Trim()
                $coincide = [regex]::IsMatch($linea, $codificado, 'IgnoreCase')
                if ($coincide) {
                    $marcadas++
                    Nuevo-Hallazgo $cat "Tarea: $($t.TaskName)" 'ALERTA' "$($t.TaskPath)$($t.TaskName) => $linea [comando codificado/de descarga]" 'alta'
                    continue
                }
                if (Ruta-Blanda $a.Execute) {
                    $firma = Firma-De $a.Execute
                    if (-not (Es-Microsoft $firma) -and -not (Firma-Confiable $firma)) {
                        $marcadas++
                        Nuevo-Hallazgo $cat "Tarea: $($t.TaskName)" 'ALERTA' "$($t.TaskPath)$($t.TaskName) => $linea [ruta de usuario, firma=$($firma.Estado)]" 'alta'
                    }
                }
            }
        }
        Nuevo-Hallazgo $cat 'Acciones sospechosas' 'INFO' "$total accion(es) examinadas, $marcadas marcada(s) (positivo de control)" 'baja'
    }
}

function Auditar-Servicios {
    $cat = 'Servicios'
    Comprobar $cat 'Rutas de servicio' {
        $svc = Get-CimInstance Win32_Service -ErrorAction Stop
        $marcados = 0
        foreach ($s in $svc) {
            if (-not $s.PathName) { continue }
            $blanda = Ruta-Blanda $s.PathName
            # Ruta no entrecomillada con espacios y fuera de system32 = secuestro potencial.
            $noComillas = ($s.PathName -notmatch '^\s*"') -and ($s.PathName -match '\s') -and
                          ($s.PathName -notmatch '(?i)^[A-Za-z]:\\Windows\\')
            if ($blanda -or $noComillas) {
                $firma = Firma-De $s.PathName
                # Microsoft-firmado (p.ej. Defender vive en ProgramData\...\Platform) NO es hallazgo.
                if (Es-Microsoft $firma) { continue }
                $marcados++
                if ($blanda -and -not (Firma-Confiable $firma)) {
                    Nuevo-Hallazgo $cat "Servicio: $($s.Name)" 'ALERTA' "binario en ruta blanda sin firma de confianza: $($s.PathName) [firma=$($firma.Estado)]" 'alta'
                } elseif ($blanda) {
                    Nuevo-Hallazgo $cat "Servicio: $($s.Name)" 'INFO' "binario en ruta de usuario, firmado: $($s.PathName)" 'baja'
                } else {
                    Nuevo-Hallazgo $cat "Servicio: $($s.Name)" 'ALERTA' "ruta con espacios sin comillas (secuestro): $($s.PathName)" 'media'
                }
            }
        }
        Nuevo-Hallazgo $cat 'Rutas de servicio' 'INFO' "$($svc.Count) servicio(s) examinados, $marcados marcado(s) (positivo de control)" 'baja'
    }
}

function Auditar-WMI {
    $cat = 'Persistencia WMI'
    if (-not (Es-Admin)) {
        Nuevo-Hallazgo $cat 'Suscripciones permanentes' 'NO-DETERMINADO' 'root/subscription requiere administrador' 'media'
        return
    }
    Comprobar $cat 'Suscripciones permanentes' {
        $consumers = @(Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue)
        $filtros = @(Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue)
        $cmdCons = @($consumers | Where-Object { $_.CimClass.CimClassName -eq 'CommandLineEventConsumer' -or $_.CimClass.CimClassName -eq 'ActiveScriptEventConsumer' })
        if ($cmdCons.Count -gt 0) {
            foreach ($c in $cmdCons) {
                $det = $c.CommandLineTemplate
                if (-not $det) { $det = $c.ScriptText }
                Nuevo-Hallazgo $cat "Consumer: $($c.Name)" 'ALERTA' "$($c.CimClass.CimClassName) => $det" 'alta'
            }
        } else {
            Nuevo-Hallazgo $cat 'Suscripciones permanentes' 'OK' "sin consumers de linea/script ($($consumers.Count) consumer(s), $($filtros.Count) filtro(s) totales; positivo de control)"
        }
    }
}

function Auditar-Red {
    $cat = 'Red'
    Comprobar $cat 'Puertos a la escucha' {
        $esc = Get-NetTCPConnection -State Listen -ErrorAction Stop
        $procs = @{}
        foreach ($c in $esc) {
            $procId = $c.OwningProcess
            if (-not $procs.ContainsKey($procId)) {
                $pr = Get-Process -Id $procId -ErrorAction SilentlyContinue
                $procs[$procId] = if ($pr) { $pr.Path } else { '' }
            }
        }
        $marcados = 0
        foreach ($c in $esc) {
            $ruta = $procs[$c.OwningProcess]
            if (Ruta-Blanda $ruta) {
                $marcados++
                Nuevo-Hallazgo $cat "Escucha :$($c.LocalPort)" 'ALERTA' "proceso en ruta blanda escuchando: $ruta (PID $($c.OwningProcess))" 'alta'
            }
        }
        Nuevo-Hallazgo $cat 'Puertos a la escucha' 'INFO' "$($esc.Count) socket(s) a la escucha, $marcados marcado(s) (positivo de control)" 'baja'
    }
    Comprobar $cat 'Archivo hosts' {
        $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
        $lineas = @(Get-Content -LiteralPath $hosts -ErrorAction Stop |
                  Where-Object { $_ -and ($_.Trim() -notmatch '^#') -and ($_.Trim() -ne '') })
        if ($lineas.Count -eq 0) {
            Nuevo-Hallazgo $cat 'Archivo hosts' 'OK' 'sin redirecciones activas'
        } else {
            Nuevo-Hallazgo $cat 'Archivo hosts' 'ALERTA' ("entradas activas: " + ($lineas -join ' | ')) 'media'
        }
    }
}

# ==============================================================================
#  AUTOPRUEBA (D33): plantar positivos sinteticos y verificar deteccion.
# ==============================================================================

function Invoke-Autoprueba {
    Write-Host ""
    Write-Host "=== AUTOPRUEBA D33: discriminacion de los detectores ===" -ForegroundColor Cyan
    $marcaRun = '__ESCANER_AUTOPRUEBA__'
    $claveRun = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $cargaRun = "$env:TEMP\__escaner_autoprueba__.exe"  # ruta blanda inexistente: doble senal
    $startup  = [Environment]::GetFolderPath('Startup')
    $archivoStartup = Join-Path $startup '__escaner_autoprueba__.bat'
    $resultados = [System.Collections.Generic.List[object]]::new()
    try {
        # --- Plantar ---
        Set-ItemProperty -Path $claveRun -Name $marcaRun -Value $cargaRun -ErrorAction Stop
        if (Test-Path $startup) { Set-Content -LiteralPath $archivoStartup -Value '@echo off' -Encoding ASCII -ErrorAction Stop }

        # --- Reescanear solo autoruns en una lista aparte ---
        $script:Hallazgos = [System.Collections.Generic.List[object]]::new()
        Auditar-Autoruns
        $h = $script:Hallazgos

        # Positivo 1: la clave Run sintetica debe aparecer como ALERTA (ruta blanda).
        $cazoRun = @($h | Where-Object { $_.Nombre -eq "Run: $marcaRun" -and $_.Estado -eq 'ALERTA' }).Count -gt 0
        $r1 = if ($cazoRun) { 'PASA' } else { 'FALLA' }
        $resultados.Add([pscustomobject]@{ Prueba='clave Run en ruta blanda'; Resultado=$r1 })

        # Positivo 2: el archivo de Startup sintetico debe aparecer como ALERTA.
        $cazoStartup = @($h | Where-Object { $_.Nombre -eq 'Startup: __escaner_autoprueba__.bat' -and $_.Estado -eq 'ALERTA' }).Count -gt 0
        $r2 = if ($cazoStartup) { 'PASA' } else { 'FALLA' }
        $resultados.Add([pscustomobject]@{ Prueba='archivo en carpeta de inicio'; Resultado=$r2 })

        # Control negativo: una entrada benigna en C:\Windows NO debe marcarse por ruta blanda.
        $falsoPos = @($h | Where-Object { $_.Estado -eq 'ALERTA' -and $_.Detalle -match 'ruta escribible' -and $_.Nombre -ne "Run: $marcaRun" -and $_.Detalle -match 'C:\\Windows\\' }).Count -gt 0
        $r3 = if ($falsoPos) { 'FALLA' } else { 'PASA' }
        $resultados.Add([pscustomobject]@{ Prueba='control negativo (sin falso positivo en C:\Windows)'; Resultado=$r3 })
    }
    finally {
        # --- Limpiar SIEMPRE (reversible) ---
        Remove-ItemProperty -Path $claveRun -Name $marcaRun -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $archivoStartup) { Remove-Item -LiteralPath $archivoStartup -Force -ErrorAction SilentlyContinue }
    }
    # --- Comparador (D33): dos instantaneas sinteticas, en memoria ---
    $base = @(
        [pscustomobject]@{Categoria='Autoruns';Nombre='Run: X';Estado='OK';Severidad='-';Detalle='c:\a'},
        [pscustomobject]@{Categoria='Autoruns';Nombre='Run: Y';Estado='OK';Severidad='-';Detalle='c:\y'}
    )
    $despues = @(
        [pscustomobject]@{Categoria='Autoruns';Nombre='Run: X';Estado='ALERTA';Severidad='alta';Detalle='c:\a'}, # cambio de estado
        [pscustomobject]@{Categoria='Autoruns';Nombre='Run: Z';Estado='ALERTA';Severidad='alta';Detalle='c:\z'}  # nuevo (Y desaparece)
    )
    $ch = Calcular-Cambios -Previos $base -Actuales $despues
    $okN = @($ch | Where-Object { $_.Tipo -eq 'NUEVO' -and $_.Nombre -eq 'Run: Z' }).Count -eq 1
    $okD = @($ch | Where-Object { $_.Tipo -eq 'DESAPARECIDO' -and $_.Nombre -eq 'Run: Y' }).Count -eq 1
    $okE = @($ch | Where-Object { $_.Tipo -eq 'CAMBIO-ESTADO' -and $_.Nombre -eq 'Run: X' -and $_.Antes -eq 'OK' -and $_.Ahora -eq 'ALERTA' }).Count -eq 1
    $r4 = if ($okN -and $okD -and $okE) { 'PASA' } else { 'FALLA' }
    $resultados.Add([pscustomobject]@{ Prueba='comparador caza nuevo/desaparecido/cambio-estado'; Resultado=$r4 })
    # Control negativo: instantaneas identicas -> lista VACIA (no $null; ese era el bug)
    # y 0 cambios relevantes (no inventa ruido).
    $vacio = Calcular-Cambios -Previos $base -Actuales $base
    $sinRuido = ($null -ne $vacio) -and (@($vacio | Where-Object { $_.Relevante }).Count -eq 0)
    $r5 = if ($sinRuido) { 'PASA' } else { 'FALLA' }
    $resultados.Add([pscustomobject]@{ Prueba='comparador: lista vacia no-null, sin ruido'; Resultado=$r5 })

    # --- Tripwire (D33): mapas sinteticos en memoria ---
    $mBase = @{ 'a.exe'=[pscustomobject]@{Ruta='a.exe';Hash='H1';Ext='.exe'}; 'b.ps1'=[pscustomobject]@{Ruta='b.ps1';Hash='H2';Ext='.ps1'} }
    $mDesp = @{ 'a.exe'=[pscustomobject]@{Ruta='a.exe';Hash='H1X';Ext='.exe'}; 'c.exe'=[pscustomobject]@{Ruta='c.exe';Hash='H3';Ext='.exe'} } # a cambio, c nuevo, b desaparece
    $tc = Comparar-Tripwire -Previo $mBase -Actual $mDesp
    $okC = @($tc | Where-Object { $_.Tipo -eq 'CAMBIADO' -and $_.Ruta -eq 'a.exe' }).Count -eq 1
    $okNn = @($tc | Where-Object { $_.Tipo -eq 'NUEVO' -and $_.Ruta -eq 'c.exe' }).Count -eq 1
    $okDd = @($tc | Where-Object { $_.Tipo -eq 'DESAPARECIDO' -and $_.Ruta -eq 'b.ps1' }).Count -eq 1
    $r6 = if ($okC -and $okNn -and $okDd) { 'PASA' } else { 'FALLA' }
    $resultados.Add([pscustomobject]@{ Prueba='tripwire caza nuevo/cambiado(hash)/desaparecido'; Resultado=$r6 })
    $tv = Comparar-Tripwire -Previo $mBase -Actual $mBase
    $r7 = if (($null -ne $tv) -and (@($tv).Count -eq 0)) { 'PASA' } else { 'FALLA' }
    $resultados.Add([pscustomobject]@{ Prueba='tripwire: identico -> vacio no-null'; Resultado=$r7 })

    $resultados | Format-Table -AutoSize | Out-String | Write-Host
    $fallas = @($resultados | Where-Object { $_.Resultado -eq 'FALLA' }).Count
    if ($fallas -eq 0) {
        Write-Host "AUTOPRUEBA: $($resultados.Count)/$($resultados.Count) PASA — los detectores discriminan y se limpio el estado." -ForegroundColor Green
    } else {
        Write-Host "AUTOPRUEBA: $fallas FALLA(s) — un detector no caza su positivo sintetico." -ForegroundColor Red
    }
    return $fallas
}

# ==============================================================================
#  ORQUESTACION
# ==============================================================================

function Invoke-Escaneo {
    Auditar-Defender
    Auditar-Firewall
    Auditar-BitLocker
    Auditar-UAC
    Auditar-SecureBoot
    Auditar-ExposicionRemota
    Auditar-Cuentas
    Auditar-Autoruns
    Auditar-TareasProgramadas
    Auditar-Servicios
    Auditar-WMI
    Auditar-Red
    if (-not $SinTripwire) { Auditar-Tripwire -Reset:$TripwireReset }
}

function Mostrar-Resumen {
    param([object[]]$H)
    $color = @{ 'OK'='Green'; 'ALERTA'='Red'; 'NO-DETERMINADO'='Yellow'; 'INFO'='Gray' }
    $catActual = ''
    foreach ($x in $H) {
        if ($x.Categoria -ne $catActual) {
            $catActual = $x.Categoria
            Write-Host ""
            Write-Host "## $catActual" -ForegroundColor Cyan
        }
        $marca = switch ($x.Estado) { 'OK'{'[ OK ]'} 'ALERTA'{'[ALERTA]'} 'NO-DETERMINADO'{'[ ?? ]'} default {'[INFO]'} }
        Write-Host ("  {0,-8} {1}" -f $marca, $x.Nombre) -ForegroundColor $color[$x.Estado] -NoNewline
        if ($x.Detalle) { Write-Host "  — $($x.Detalle)" -ForegroundColor DarkGray } else { Write-Host "" }
    }
}

# ==============================================================================
#  TRIPWINE DE INTEGRIDAD DE Z: (compensa que Z: esta excluido de Defender)
# ==============================================================================
# Z: esta excluido del escaneo en tiempo real de Defender (falso positivo sobre
# la herramienta de seguridad). Como compensacion SIN friccion, este tripwire
# baselinea los EJECUTABLES/SCRIPTS de un conjunto configurable de raices
# estables y marca lo NUEVO o CAMBIADO (por hash) entre corridas. Vigilar todo
# Z: medido como inviable (16k+ archivos, >90 s): se acota por archivo de config.

$script:TripwireExt   = @('.exe','.dll','.scr','.msi','.ps1','.bat','.cmd','.vbs','.js','.psm1')
$script:TripwireBin   = @('.exe','.dll','.scr','.msi')   # binarios: cambio = ALERTA
$script:TripwirePodar = @('target','node_modules','.git','.cargo')

function Ruta-Config-Tripwire { Join-Path $PSScriptRoot 'tripwire.txt' }
function Ruta-Manifiesto-Tripwire { Join-Path $PSScriptRoot 'tripwire-manifiesto.json' }

# Lee las raices a vigilar; si no existe el archivo, lo crea con el default.
function Leer-Raices-Tripwire {
    $cfg = Ruta-Config-Tripwire
    if (-not (Test-Path -LiteralPath $cfg)) {
        @(
            '# Raices que vigila el tripwire de integridad (una por linea; # = comentario).',
            '# Elige arboles ESTABLES y de alto valor; evita los que editas a diario si no',
            '# quieres ver tus propios cambios. Vigilar todo Z: es inviable (16k+ archivos).',
            'Z:\conocimiento',
            'Z:\scripts'
        ) | Set-Content -LiteralPath $cfg -Encoding UTF8
    }
    return @(Get-Content -LiteralPath $cfg -ErrorAction Stop |
             ForEach-Object { $_.Trim() } |
             Where-Object { $_ -and ($_ -notmatch '^#') })
}

# Camina las raices (podando build/.git y SIEMPRE Z:\documentos) y devuelve un
# mapa ruta -> {Hash;Size;Ext}. SHA256 por archivo (el conjunto acotado es pequeno).
function Construir-Manifiesto-Tripwire {
    param([string[]]$Raices)
    $mapa = @{}
    foreach ($raiz in $Raices) {
        if (-not (Test-Path -LiteralPath $raiz)) { continue }
        $cola = [System.Collections.Generic.Queue[string]]::new(); $cola.Enqueue($raiz)
        while ($cola.Count -gt 0) {
            $d = $cola.Dequeue()
            try {
                foreach ($s in [System.IO.Directory]::GetDirectories($d)) {
                    if ($s -ieq 'Z:\documentos') { continue }   # regla dura: nunca lo personal
                    $n = [System.IO.Path]::GetFileName($s)
                    if ($script:TripwirePodar -contains $n) { continue }
                    $cola.Enqueue($s)
                }
                foreach ($f in [System.IO.Directory]::GetFiles($d)) {
                    $ext = [System.IO.Path]::GetExtension($f).ToLower()
                    if ($script:TripwireExt -notcontains $ext) { continue }
                    try {
                        $hash = (Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop).Hash
                        $sz = ([System.IO.FileInfo]$f).Length
                        $mapa[$f] = [pscustomobject]@{ Ruta=$f; Hash=$hash; Size=$sz; Ext=$ext }
                    } catch {}
                }
            } catch {}
        }
    }
    return $mapa
}

# Compara dos mapas (ruta -> obj con .Hash). Testable en memoria (autoprueba D33).
function Comparar-Tripwire {
    param($Previo, $Actual)
    $cambios = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $Actual.Keys) {
        if (-not $Previo.ContainsKey($k)) {
            $cambios.Add([pscustomobject]@{ Tipo='NUEVO'; Ruta=$k; Ext=$Actual[$k].Ext })
        } elseif ($Previo[$k].Hash -ne $Actual[$k].Hash) {
            $cambios.Add([pscustomobject]@{ Tipo='CAMBIADO'; Ruta=$k; Ext=$Actual[$k].Ext })
        }
    }
    foreach ($k in $Previo.Keys) {
        if (-not $Actual.ContainsKey($k)) {
            $cambios.Add([pscustomobject]@{ Tipo='DESAPARECIDO'; Ruta=$k; Ext=$Previo[$k].Ext })
        }
    }
    return ,$cambios
}

function Auditar-Tripwire {
    param([switch]$Reset)
    $cat = 'Integridad Z: (tripwire)'
    $raices = @()
    try { $raices = Leer-Raices-Tripwire } catch {
        Nuevo-Hallazgo $cat 'Configuracion' 'NO-DETERMINADO' "no se pudo leer tripwire.txt: $($_.Exception.Message)" 'media'; return
    }
    if ($raices.Count -eq 0) { Nuevo-Hallazgo $cat 'Configuracion' 'INFO' 'tripwire.txt sin raices: desactivado' 'baja'; return }

    $actual = Construir-Manifiesto-Tripwire -Raices $raices
    $rutaMan = Ruta-Manifiesto-Tripwire
    $previo = $null
    if (-not $Reset -and (Test-Path -LiteralPath $rutaMan)) {
        try {
            $previo = @{}
            foreach ($o in (Get-Content -LiteralPath $rutaMan -Raw | ConvertFrom-Json)) { $previo[$o.Ruta] = $o }
        } catch { $previo = $null }
    }

    if ($Reset -or $null -eq $previo) {
        $motivo = if ($Reset) { 'reinicio pedido (-TripwireReset)' } else { 'primera corrida: sin linea base' }
        Nuevo-Hallazgo $cat 'Linea base' 'INFO' "$motivo — baselineados $($actual.Count) ejecutable(s)/script(s) en $($raices.Count) raiz(ces)" 'baja'
    } else {
        $cambios = Comparar-Tripwire -Previo $previo -Actual $actual
        $nNuevo = 0; $nCamb = 0; $nDesap = 0
        foreach ($c in $cambios) {
            $esBin = ($script:TripwireBin -contains $c.Ext)
            switch ($c.Tipo) {
                'NUEVO' {
                    $nNuevo++
                    if ($esBin) {
                        $firma = Firma-De $c.Ruta
                        if (Firma-Confiable $firma) { Nuevo-Hallazgo $cat "NUEVO binario firmado" 'INFO' "$($c.Ruta) [firmado: $($firma.Firmante)]" 'baja' }
                        else { Nuevo-Hallazgo $cat "NUEVO binario SIN firma" 'ALERTA' "$($c.Ruta) [firma=$($firma.Estado)]" 'alta' }
                    } else {
                        Nuevo-Hallazgo $cat "NUEVO script" 'INFO' "$($c.Ruta) (probablemente tuyo; revisa si no)" 'baja'
                    }
                }
                'CAMBIADO' {
                    $nCamb++
                    if ($esBin) {
                        $firma = Firma-De $c.Ruta
                        if (Firma-Confiable $firma) { Nuevo-Hallazgo $cat "CAMBIADO binario firmado" 'INFO' "$($c.Ruta) [firmado: $($firma.Firmante)]" 'baja' }
                        else { Nuevo-Hallazgo $cat "CAMBIADO binario SIN firma" 'ALERTA' "$($c.Ruta) [firma=$($firma.Estado)]" 'alta' }
                    } else {
                        Nuevo-Hallazgo $cat "CAMBIADO script" 'INFO' "$($c.Ruta) (probablemente tuyo; revisa si no)" 'baja'
                    }
                }
                'DESAPARECIDO' { $nDesap++ }
            }
        }
        Nuevo-Hallazgo $cat 'Resumen' 'INFO' "$($actual.Count) vigilados en $($raices.Count) raiz(ces): $nNuevo nuevo(s), $nCamb cambiado(s), $nDesap desaparecido(s) (positivo de control)" 'baja'
    }

    # Guarda SIEMPRE el manifiesto actual = base para la proxima corrida (reporte-una-vez).
    try { @($actual.Values) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $rutaMan -Encoding UTF8 } catch {
        Nuevo-Hallazgo $cat 'Manifiesto' 'NO-DETERMINADO' "no se pudo guardar el manifiesto: $($_.Exception.Message)" 'media'
    }
}

# ==============================================================================
#  COMPARACION CON LA LINEA BASE PREVIA (automatica)
# ==============================================================================

# Localiza el informe.json de la corrida ANTERIOR (el volcado-* mas reciente).
# Se llama ANTES de escribir el nuevo, para no compararse consigo mismo.
function Hallar-Previo {
    param([string]$Explicito)
    if ($Explicito) {
        if (Test-Path -LiteralPath $Explicito) { return $Explicito }
        return $null
    }
    $cand = Get-ChildItem -LiteralPath $PSScriptRoot -Directory -Filter 'volcado-*' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
    foreach ($d in $cand) {
        $j = Join-Path $d.FullName 'informe.json'
        if (Test-Path -LiteralPath $j) { return $j }
    }
    return $null
}

# Devuelve la lista de cambios entre dos conjuntos de hallazgos.
# Clave estable = "Categoria|Nombre". Clasifica:
#   NUEVO / DESAPARECIDO / CAMBIO-ESTADO (relevantes) y CAMBIO-DETALLE (menor).
function Calcular-Cambios {
    param($Previos, $Actuales)
    $pa = @{}; foreach ($h in $Previos)  { $pa["$($h.Categoria)|$($h.Nombre)"] = $h }
    $ac = @{}; foreach ($h in $Actuales) { $ac["$($h.Categoria)|$($h.Nombre)"] = $h }
    $cambios = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $ac.Keys) {
        if (-not $pa.ContainsKey($k)) {
            $n = $ac[$k]
            $cambios.Add([pscustomobject]@{ Tipo='NUEVO'; Categoria=$n.Categoria; Nombre=$n.Nombre; Antes=''; Ahora=$n.Estado; Detalle=$n.Detalle; Relevante=$true })
        } else {
            $p = $pa[$k]; $n = $ac[$k]
            if ($p.Estado -ne $n.Estado) {
                $cambios.Add([pscustomobject]@{ Tipo='CAMBIO-ESTADO'; Categoria=$n.Categoria; Nombre=$n.Nombre; Antes=$p.Estado; Ahora=$n.Estado; Detalle=$n.Detalle; Relevante=$true })
            } elseif ($p.Detalle -ne $n.Detalle) {
                # Mismo estado, solo cambio el detalle (p.ej. version en la ruta): menor,
                # salvo que el estado sea ALERTA (ahi el cambio importa).
                $rel = ($n.Estado -eq 'ALERTA')
                $cambios.Add([pscustomobject]@{ Tipo='CAMBIO-DETALLE'; Categoria=$n.Categoria; Nombre=$n.Nombre; Antes=$p.Detalle; Ahora=$n.Detalle; Detalle=$n.Detalle; Relevante=$rel })
            }
        }
    }
    foreach ($k in $pa.Keys) {
        if (-not $ac.ContainsKey($k)) {
            $p = $pa[$k]
            $cambios.Add([pscustomobject]@{ Tipo='DESAPARECIDO'; Categoria=$p.Categoria; Nombre=$p.Nombre; Antes=$p.Estado; Ahora=''; Detalle=$p.Detalle; Relevante=$true })
        }
    }
    # La coma evita que PowerShell desenvuelva la lista VACIA a $null al retornar
    # (si no, el llamante recibe $null y "$null | Where {...}" revienta en StrictMode).
    return ,$cambios
}

function Mostrar-Cambios {
    param($Cambios, [string]$FuentePrevia)
    if (-not $Cambios) { $Cambios = @() }  # nunca piping de $null bajo StrictMode
    Write-Host ""
    Write-Host "## Cambios desde la ultima corrida" -ForegroundColor Cyan
    Write-Host "   (linea base: $FuentePrevia)" -ForegroundColor DarkGray
    $rel = @($Cambios | Where-Object { $_.Relevante })
    $men = @($Cambios | Where-Object { -not $_.Relevante })
    if ($rel.Count -eq 0) {
        Write-Host "   sin cambios relevantes (persistencia y postura estables)" -ForegroundColor Green
    } else {
        $color = @{ 'NUEVO'='Red'; 'DESAPARECIDO'='Yellow'; 'CAMBIO-ESTADO'='Red'; 'CAMBIO-DETALLE'='Yellow' }
        foreach ($c in $rel) {
            $flecha = if ($c.Tipo -eq 'CAMBIO-ESTADO') { "$($c.Antes) -> $($c.Ahora)" } else { $c.Ahora }
            Write-Host ("   [{0}] {1} :: {2}  {3}" -f $c.Tipo, $c.Categoria, $c.Nombre, $flecha) -ForegroundColor $color[$c.Tipo]
            if ($c.Detalle) { Write-Host "         $($c.Detalle)" -ForegroundColor DarkGray }
        }
    }
    if ($men.Count -gt 0) { Write-Host "   (+$($men.Count) cambio(s) menor(es) de detalle, p.ej. versiones; en el informe.json)" -ForegroundColor DarkGray }
}

# --- Main ----------------------------------------------------------------------

$host.UI.RawUI.WindowTitle = 'escaner-windows'
Write-Host "escaner-windows — auditor de seguridad de SOLO LECTURA" -ForegroundColor White
Write-Host ("maquina: {0}   usuario: {1}   admin: {2}   fecha: {3}" -f `
    $env:COMPUTERNAME, $env:USERNAME, (Es-Admin), (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray
if (-not (Es-Admin)) {
    Write-Host "AVISO: sin privilegios de administrador — varias comprobaciones saldran NO-DETERMINADO (ruidoso, D30)." -ForegroundColor Yellow
}

if ($Autoprueba) {
    $fallas = Invoke-Autoprueba
    exit ([int]($fallas -gt 0))
}

Invoke-Escaneo
$H = $script:Hallazgos
Mostrar-Resumen -H $H

# --- Positivo de control (D30) -------------------------------------------------
$nTotal = $H.Count
$nAlerta = @($H | Where-Object { $_.Estado -eq 'ALERTA' }).Count
$nIndet  = @($H | Where-Object { $_.Estado -eq 'NO-DETERMINADO' }).Count
$nOK     = @($H | Where-Object { $_.Estado -eq 'OK' }).Count
Write-Host ""
Write-Host ("===== RESUMEN: {0} comprobaciones | {1} OK | {2} ALERTAS | {3} NO-DETERMINADAS =====" -f `
    $nTotal, $nOK, $nAlerta, $nIndet) -ForegroundColor White
if ($nAlerta) { Write-Host "Revisa las $nAlerta ALERTA(s) de arriba." -ForegroundColor Red }
if ($nIndet)  { Write-Host "$nIndet comprobacion(es) NO pudieron determinarse (probablemente faltan privilegios): no son 'OK'." -ForegroundColor Yellow }

# --- Comparacion automatica con la linea base previa ---------------------------
$cambios = [System.Collections.Generic.List[object]]::new()
$rutaPrevio = $null
if (-not $SinComparar) {
    $rutaPrevio = Hallar-Previo -Explicito $Comparar
    if (-not $rutaPrevio) {
        Write-Host ""
        Write-Host "## Cambios desde la ultima corrida" -ForegroundColor Cyan
        Write-Host "   primera corrida: no hay linea base previa con la que comparar." -ForegroundColor DarkGray
    } else {
        try {
            $previos = (Get-Content -LiteralPath $rutaPrevio -Raw | ConvertFrom-Json).hallazgos
            $cambios = Calcular-Cambios -Previos $previos -Actuales $H
            Mostrar-Cambios -Cambios $cambios -FuentePrevia $rutaPrevio
        } catch {
            Write-Host ""
            Write-Host "## Cambios desde la ultima corrida" -ForegroundColor Cyan
            Write-Host "   NO-DETERMINADO: no se pudo leer la linea base ($rutaPrevio): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
$nCambiosRel = @($cambios | Where-Object { $_.Relevante }).Count

# --- Informe sellado -----------------------------------------------------------
if (-not $SinInforme) {
    if (-not $Salida) {
        $Salida = Join-Path $PSScriptRoot ("volcado-{0}-{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd-HHmmss'))
    }
    New-Item -ItemType Directory -Force -Path $Salida | Out-Null
    $meta = [pscustomobject]@{
        herramienta = 'escaner-windows'
        maquina     = $env:COMPUTERNAME
        usuario     = $env:USERNAME
        admin       = (Es-Admin)
        fecha       = (Get-Date -Format 'o')
        resumen     = [pscustomobject]@{ total=$nTotal; ok=$nOK; alertas=$nAlerta; no_determinadas=$nIndet; cambios_relevantes=$nCambiosRel }
        base_previa = $rutaPrevio
        cambios     = $cambios
        hallazgos   = $H
    }
    $jsonPath = Join-Path $Salida 'informe.json'
    $meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine("# Informe escaner-windows")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("- Maquina: $($env:COMPUTERNAME)")
    [void]$md.AppendLine("- Usuario: $($env:USERNAME) (admin: $(Es-Admin))")
    [void]$md.AppendLine("- Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$md.AppendLine("- Resumen: $nTotal comprobaciones | $nOK OK | $nAlerta ALERTAS | $nIndet NO-DETERMINADAS")
    [void]$md.AppendLine("- Cambios relevantes desde la ultima corrida: $nCambiosRel" + $(if ($rutaPrevio) { " (base: $rutaPrevio)" } else { ' (sin linea base previa)' }))
    [void]$md.AppendLine("")
    if (@($cambios).Count -gt 0) {
        [void]$md.AppendLine("## Cambios desde la ultima corrida`n")
        foreach ($c in $cambios) {
            $marca = if ($c.Relevante) { '**' } else { '' }
            [void]$md.AppendLine("- $marca[$($c.Tipo)]$marca $($c.Categoria) :: $($c.Nombre)" + $(if ($c.Tipo -eq 'CAMBIO-ESTADO') { " ($($c.Antes) -> $($c.Ahora))" } else { '' }))
        }
        [void]$md.AppendLine("")
    }
    $catActual = ''
    foreach ($x in $H) {
        if ($x.Categoria -ne $catActual) { $catActual = $x.Categoria; [void]$md.AppendLine("## $catActual`n") }
        [void]$md.AppendLine("- **[$($x.Estado)]** $($x.Nombre)" + $(if ($x.Detalle) { " — $($x.Detalle)" } else { '' }))
    }
    $mdPath = Join-Path $Salida 'informe.md'
    $md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

    Write-Host ""
    Write-Host "Informe sellado en: $Salida" -ForegroundColor Green
    Write-Host "  - informe.json   (estructurado)" -ForegroundColor DarkGray
    Write-Host "  - informe.md      (legible)" -ForegroundColor DarkGray
}

# Codigo de salida: 0 limpio, 1 hay alertas, 2 hay no-determinadas sin alertas.
if ($nAlerta -gt 0) { exit 1 } elseif ($nIndet -gt 0) { exit 2 } else { exit 0 }
