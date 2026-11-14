<#
.SYNOPSIS
  Copia documentos del usuario con sesion iniciada a un enlace compartido de
  Nextcloud (Windows 10 / 11).

.DESCRIPTION
  Sin carpetas: revisa Escritorio, Documentos y Descargas del usuario que lo
  ejecuta, sea cual sea (incluye carpetas redirigidas a OneDrive).
  En el enlace, los archivos quedan en  EQUIPO_usuario\Escritorio\..., etc.
  Omite los archivos que ya existen en Nextcloud con el mismo tamano.

  Configuracion: se busca en este orden
    1) subir_nextcloud.conf junto a este script
    2) %APPDATA%\nextcloud-subida.conf
  Contenido:
    NC_ENLACE="https://servidor/index.php/s/TOKEN"
    NC_ENLACE_PASS=""
    NC_EXTENSIONES="txt doc docx jpg jpeg pdf xls xlsx xlsm csv ppt pptx pps ppsx"
    NC_IGNORAR_CERT=0

.EXAMPLE
  .\subir_nextcloud.ps1 -Simulacion
  .\subir_nextcloud.ps1
  .\subir_nextcloud.ps1 -Carpetas "D:\Trabajo","E:\Otros"
#>
[CmdletBinding()]
param(
    [string[]]$Carpetas,
    [switch]$Simulacion,
    [string]$Config
)

$ErrorActionPreference = 'Stop'

# ---------- Configuracion ----------
if (-not $Config) {
    foreach ($c in @((Join-Path $PSScriptRoot 'subir_nextcloud.conf'),
                     (Join-Path $env:APPDATA 'nextcloud-subida.conf'))) {
        if (Test-Path -LiteralPath $c) { $Config = $c; break }
    }
}
$cfg = @{}
if ($Config -and (Test-Path -LiteralPath $Config)) {
    foreach ($linea in Get-Content -LiteralPath $Config -Encoding UTF8) {
        if ($linea -match '^\s*(NC_[A-Z_]+)\s*=\s*"?([^"#]*?)"?\s*(#.*)?$') {
            $cfg[$Matches[1]] = $Matches[2].Trim()
        }
    }
}
function Obtener-Valor($nombre, $defecto) {
    $v = [Environment]::GetEnvironmentVariable($nombre)
    if ($v) { return $v }
    if ($cfg.ContainsKey($nombre) -and $cfg[$nombre]) { return $cfg[$nombre] }
    return $defecto
}
$NC_ENLACE       = Obtener-Valor 'NC_ENLACE' $null
$NC_ENLACE_PASS  = Obtener-Valor 'NC_ENLACE_PASS' ''
$NC_IGNORAR_CERT = (Obtener-Valor 'NC_IGNORAR_CERT' '0') -eq '1'
$NC_EXTENSIONES  = (Obtener-Valor 'NC_EXTENSIONES' 'txt doc docx jpg jpeg pdf xls xlsx xlsm csv ppt pptx pps ppsx') -split '\s+' |
                   Where-Object { $_ } | ForEach-Object { '.' + $_.TrimStart('.').ToLower() }

if (-not $NC_ENLACE) {
    Write-Host "Error: falta NC_ENLACE. Crea subir_nextcloud.conf junto a este script." -ForegroundColor Red
    exit 2
}
if ($NC_ENLACE -notmatch '^(https?://.+?)/(index\.php/)?s/([A-Za-z0-9]+)/?$') {
    Write-Host "Error: NC_ENLACE no parece un enlace compartido de Nextcloud (.../index.php/s/TOKEN)." -ForegroundColor Red
    exit 2
}
$SERVIDOR = $Matches[1]
$TOKEN    = $Matches[3]

# ---------- Usuario y carpetas ----------
$USUARIO = $env:USERNAME
$EQUIPO  = $env:COMPUTERNAME
$DESTINO = "${EQUIPO}_${USUARIO}"

function Carpeta-Descargas {
    try {
        $clave = '{374DE290-123F-4565-9164-39C4925E467B}'
        $p = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name $clave -ErrorAction Stop).$clave
        $p = [Environment]::ExpandEnvironmentVariables($p)
        if (Test-Path -LiteralPath $p) { return $p }
    } catch { }
    return (Join-Path $env:USERPROFILE 'Downloads')
}

if (-not $Carpetas -or $Carpetas.Count -eq 0) {
    $Carpetas = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('MyDocuments'),
        (Carpeta-Descargas)
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    if (-not $Carpetas) {
        Write-Host 'Error: no se encontro ninguna carpeta para revisar.' -ForegroundColor Red
        exit 1
    }
}

# ---------- Cliente HTTP (WebDAV del enlace) ----------
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http
$handler = New-Object System.Net.Http.HttpClientHandler

if ($NC_IGNORAR_CERT) {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    } else {
        # Windows PowerShell 5.1: callback compilado (un scriptblock falla en hilos en segundo plano)
        if (-not ('NcCertificado' -as [type])) {
            Add-Type -TypeDefinition @'
using System.Net;
public static class NcCertificado {
    public static void AceptarTodos() {
        ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
    }
}
'@
        }
        [NcCertificado]::AceptarTodos()
    }
}

$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromMinutes(30)
$auth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${TOKEN}:${NC_ENLACE_PASS}"))
$client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Basic', $auth)
[void]$client.DefaultRequestHeaders.TryAddWithoutValidation('X-Requested-With', 'XMLHttpRequest')

$DAV_BASE = "$SERVIDOR/public.php/webdav"

function Codificar-Ruta([string]$ruta) {
    ($ruta -split '/' | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
}

function Enviar([string]$metodo, [string]$url, $contenido = $null, [hashtable]$cabeceras = @{}) {
    $req = New-Object System.Net.Http.HttpRequestMessage((New-Object System.Net.Http.HttpMethod($metodo)), $url)
    foreach ($k in $cabeceras.Keys) { [void]$req.Headers.TryAddWithoutValidation($k, $cabeceras[$k]) }
    if ($contenido) { $req.Content = $contenido }
    try {
        return $client.SendAsync($req).GetAwaiter().GetResult()
    } finally {
        $req.Dispose()
    }
}

$carpetasCreadas = @{}
function Crear-CarpetaRemota([string]$ruta) {
    $parcial = ''
    foreach ($parte in ($ruta -split '/' | Where-Object { $_ })) {
        $parcial += "/$parte"
        if ($carpetasCreadas.ContainsKey($parcial)) { continue }
        $r = Enviar 'MKCOL' ($DAV_BASE + (Codificar-Ruta $parcial))
        $code = [int]$r.StatusCode; $r.Dispose()
        if ($code -ne 201 -and $code -ne 405) {   # 405 = ya existia
            throw "No se pudo crear la carpeta '$parcial' (HTTP $code)"
        }
        $carpetasCreadas[$parcial] = $true
    }
}

function Tamano-Remoto([string]$url) {
    $r = Enviar 'HEAD' $url
    try {
        if ([int]$r.StatusCode -eq 200) { return $r.Content.Headers.ContentLength }
        return $null
    } finally { $r.Dispose() }
}

# ---------- Verificar el enlace ----------
if (-not $Simulacion) {
    $code = 0; $detalle = ''
    try {
        $r = Enviar 'PROPFIND' "$DAV_BASE/" $null @{ 'Depth' = '0' }
        $code = [int]$r.StatusCode; $r.Dispose()
    } catch {
        $detalle = $_.Exception.GetBaseException().Message
    }
    switch ($code) {
        { $_ -in 200, 207 } { break }
        401 { Write-Host 'Error: acceso denegado. Revisa que el enlace sea correcto y, si tiene contrasena, NC_ENLACE_PASS.' -ForegroundColor Red; exit 1 }
        404 { Write-Host 'Error: el enlace no existe o caduco.' -ForegroundColor Red; exit 1 }
        0 {
            Write-Host "Error: no se pudo conectar a $SERVIDOR. $detalle" -ForegroundColor Red
            if ($detalle -match 'trust|confianza|certific|SSL|TLS') {
                Write-Host 'Si el servidor usa un certificado autofirmado, pon NC_IGNORAR_CERT=1 en la configuracion.' -ForegroundColor Yellow
            }
            exit 1
        }
        default { Write-Host "Aviso: respuesta inesperada del servidor (HTTP $code); se intentara subir igual." -ForegroundColor Yellow }
    }
}

# ---------- Buscar y subir ----------
Write-Host "Usuario: $USUARIO   Equipo: $EQUIPO   Destino en el enlace: $DESTINO/"
$subidos = 0; $omitidos = 0; $errores = 0

foreach ($origen in $Carpetas) {
    if (-not (Test-Path -LiteralPath $origen -PathType Container)) {
        Write-Host "Aviso: '$origen' no es una carpeta, se omite." -ForegroundColor Yellow
        continue
    }
    $origen = (Resolve-Path -LiteralPath $origen).ProviderPath.TrimEnd('\')
    $nombreOrigen = Split-Path $origen -Leaf
    Write-Host "Buscando en: $origen" -ForegroundColor Cyan

    $archivos = Get-ChildItem -LiteralPath $origen -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { ($NC_EXTENSIONES -contains $_.Extension.ToLower()) -and -not $_.Name.StartsWith('~$') }

    foreach ($a in $archivos) {
        $relativo = $a.FullName.Substring($origen.Length).TrimStart('\').Replace('\', '/')
        $rutaRemota = "$DESTINO/$nombreOrigen/$relativo"
        $url = "$DAV_BASE/" + (Codificar-Ruta $rutaRemota)

        if ($Simulacion) {
            Write-Host "  [simulacion] $relativo -> $rutaRemota"
            $subidos++; continue
        }

        try {
            if ((Tamano-Remoto $url) -eq $a.Length) {
                Write-Host "  = Ya existe: $relativo" -ForegroundColor DarkGray
                $omitidos++; continue
            }

            Crear-CarpetaRemota ($rutaRemota.Substring(0, $rutaRemota.LastIndexOf('/')))

            $fs = [IO.File]::Open($a.FullName, 'Open', 'Read', 'ReadWrite')
            try {
                $r = Enviar 'PUT' $url (New-Object System.Net.Http.StreamContent($fs))
                $code = [int]$r.StatusCode; $r.Dispose()
            } finally { $fs.Dispose() }

            if ($code -eq 201 -or $code -eq 204) {
                Write-Host "  + Subido: $relativo" -ForegroundColor Green
                $subidos++
            } else {
                Write-Host "  x Error al subir $relativo (HTTP $code)" -ForegroundColor Red
                $errores++
            }
        } catch {
            Write-Host "  x Error con ${relativo}: $($_.Exception.GetBaseException().Message)" -ForegroundColor Red
            $errores++
        }
    }
}

$client.Dispose()
Write-Host ""
Write-Host "Resumen: $subidos subidos, $omitidos ya existian, $errores con error."
if ($errores -gt 0) { exit 1 } else { exit 0 }
