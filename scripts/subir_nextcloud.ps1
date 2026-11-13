<#
.SYNOPSIS
  Busca archivos .docx y .txt y los sube a Nextcloud por WebDAV (Windows 10 / 11).

.DESCRIPTION
  Sin carpetas: busca en Escritorio, Documentos y Descargas del usuario con la
  sesion iniciada (incluye carpetas redirigidas a OneDrive).
  Mantiene la estructura de subcarpetas y omite los archivos que ya existen en
  Nextcloud con el mismo tamano.

  Configuracion en %APPDATA%\nextcloud-subida.conf (o variables de entorno):
    NC_URL="https://tu-nextcloud.ejemplo.com"
    NC_USER="tu_usuario"
    NC_PASS="xxxxx-xxxxx-xxxxx-xxxxx-xxxxx"
    NC_DESTINO="Respaldos/Documentos"
    NC_EXTENSIONES="docx txt"

.EXAMPLE
  .\subir_nextcloud.ps1 -Simulacion
  .\subir_nextcloud.ps1
  .\subir_nextcloud.ps1 -Carpetas "D:\Trabajo","E:\Otros"
#>
[CmdletBinding()]
param(
    [string[]]$Carpetas,
    [switch]$Simulacion,
    [string]$Config = (Join-Path $env:APPDATA 'nextcloud-subida.conf')
)

$ErrorActionPreference = 'Stop'

# ---------- Configuracion ----------
$cfg = @{}
if (Test-Path -LiteralPath $Config) {
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
$NC_URL         = Obtener-Valor 'NC_URL' $null
$NC_USER        = Obtener-Valor 'NC_USER' $null
$NC_PASS        = Obtener-Valor 'NC_PASS' $null
$NC_DESTINO     = (Obtener-Valor 'NC_DESTINO' 'Subidas').Trim('/')
$NC_EXTENSIONES = (Obtener-Valor 'NC_EXTENSIONES' 'docx txt') -split '\s+' |
                  Where-Object { $_ } | ForEach-Object { '.' + $_.TrimStart('.').ToLower() }

foreach ($n in 'NC_URL','NC_USER','NC_PASS') {
    if (-not (Get-Variable $n -ValueOnly)) {
        Write-Host "Error: falta $n. Configuralo en $Config" -ForegroundColor Red
        exit 2
    }
}
$NC_URL = $NC_URL.TrimEnd('/')

# ---------- Carpetas por defecto del usuario actual ----------
function Carpeta-Descargas {
    try {
        $p = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' `
              -Name '{374DE290-123F-4565-9164-39C4925E467B}' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
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

# ---------- Cliente HTTP (WebDAV) ----------
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromMinutes(30)
$token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${NC_USER}:${NC_PASS}"))
$client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Basic', $token)

function Codificar-Ruta([string]$ruta) {
    ($ruta -split '/' | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
}
$DAV_BASE = "$NC_URL/remote.php/dav/files/" + [Uri]::EscapeDataString($NC_USER)

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

# ---------- Verificar conexion ----------
if (-not $Simulacion) {
    try {
        $r = Enviar 'PROPFIND' "$DAV_BASE/" $null @{ 'Depth' = '0' }
        $code = [int]$r.StatusCode; $r.Dispose()
    } catch {
        $code = "sin respuesta: $($_.Exception.GetBaseException().Message)"
    }
    if ($code -ne 207) {
        Write-Host "Error: no se pudo conectar a Nextcloud ($code). Revisa NC_URL, NC_USER y NC_PASS." -ForegroundColor Red
        exit 1
    }
}

# ---------- Buscar y subir ----------
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
        $rutaRemota = "$NC_DESTINO/$nombreOrigen/$relativo"
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
