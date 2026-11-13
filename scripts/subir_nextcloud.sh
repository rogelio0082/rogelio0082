#!/usr/bin/env bash
# subir_nextcloud.sh — Busca archivos .docx y .txt y los sube a Nextcloud por WebDAV.
#
# Uso:
#   ./subir_nextcloud.sh [-n] [-c config] [CARPETA_ORIGEN ...]
#
#   Sin carpetas: busca en Escritorio, Documentos y Descargas del usuario
#   con la sesión iniciada (detecta nombres en español o inglés).
#
#   -n          Simulación: muestra qué subiría, sin subir nada.
#   -c ARCHIVO  Archivo de configuración (por defecto: ~/.config/nextcloud-subida.conf)
#
# Configuración (en el archivo o como variables de entorno):
#   NC_URL="https://tu-nextcloud.ejemplo.com"   # URL base del servidor
#   NC_USER="tu_usuario"
#   NC_PASS="xxxxx-xxxxx-xxxxx-xxxxx-xxxxx"     # Contraseña de aplicación (recomendado)
#   NC_DESTINO="Respaldos/Documentos"            # Carpeta destino en Nextcloud
#   NC_EXTENSIONES="docx txt"                    # Opcional
#
# Mantiene la estructura de subcarpetas y omite los archivos que ya existen
# en Nextcloud con el mismo tamaño.

set -uo pipefail

CONFIG="${HOME}/.config/nextcloud-subida.conf"
DRY_RUN=0

while getopts ":nc:h" opt; do
  case "$opt" in
    n) DRY_RUN=1 ;;
    c) CONFIG="$OPTARG" ;;
    h) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "Opción no válida. Usa -h para ver la ayuda." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

[[ -f "$CONFIG" ]] && source "$CONFIG"

: "${NC_URL:?Falta NC_URL}" "${NC_USER:?Falta NC_USER}" "${NC_PASS:?Falta NC_PASS}"
NC_DESTINO="${NC_DESTINO:-Subidas}"
NC_EXTENSIONES="${NC_EXTENSIONES:-docx txt}"
NC_URL="${NC_URL%/}"

# Si no se indican carpetas, usar Escritorio, Documentos y Descargas del usuario actual
if [[ $# -eq 0 ]]; then
  carpetas=()
  for par in "DESKTOP:Escritorio:Desktop" "DOCUMENTS:Documentos:Documents" "DOWNLOAD:Descargas:Downloads"; do
    IFS=: read -r xdg es en <<< "$par"
    dir=""
    # Linux: carpeta configurada por el escritorio (respeta el idioma)
    if command -v xdg-user-dir >/dev/null; then
      dir="$(xdg-user-dir "$xdg" 2>/dev/null)"
      [[ "$dir" == "$HOME" ]] && dir=""   # xdg devuelve $HOME si no está definida
    fi
    [[ -z "$dir" && -d "$HOME/$es" ]] && dir="$HOME/$es"
    [[ -z "$dir" && -d "$HOME/$en" ]] && dir="$HOME/$en"
    if [[ -n "$dir" && -d "$dir" ]]; then
      carpetas+=("$dir")
    else
      echo "Aviso: no se encontró la carpeta $es ($en) en $HOME" >&2
    fi
  done
  [[ ${#carpetas[@]} -gt 0 ]] || { echo "Error: no se encontró ninguna carpeta para revisar." >&2; exit 1; }
  set -- "${carpetas[@]}"
fi
if ! command -v curl >/dev/null; then
  echo "Error: se necesita curl." >&2
  if command -v apt-get >/dev/null; then   # Debian, Ubuntu, Kali, Mint...
    echo "Instálalo con:  sudo apt-get install -y curl" >&2
  fi
  exit 1
fi

# Codifica cada segmento de una ruta para la URL (espacios, tildes, ñ, etc.)
urlencode_path() {
  local LC_ALL=C s="$1" out="" c i
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_/-]) out+="$c" ;;
      *) printf -v c '%%%02X' "'$c"; out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

DAV_BASE="${NC_URL}/remote.php/dav/files/$(urlencode_path "$NC_USER")"
CURL=(curl -sS --user "${NC_USER}:${NC_PASS}" --retry 3 --retry-delay 2)

declare -A CARPETAS_CREADAS=()

# Crea la carpeta remota y todas sus carpetas padre si no existen
crear_carpeta_remota() {
  local ruta="$1" parcial="" parte
  IFS='/' read -ra partes <<< "$ruta"
  for parte in "${partes[@]}"; do
    [[ -z "$parte" ]] && continue
    parcial+="/$parte"
    [[ -n "${CARPETAS_CREADAS[$parcial]:-}" ]] && continue
    local code
    code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X MKCOL "${DAV_BASE}$(urlencode_path "$parcial")")
    # 201 = creada, 405 = ya existía
    if [[ "$code" != "201" && "$code" != "405" ]]; then
      echo "  ✗ No se pudo crear la carpeta '$parcial' (HTTP $code)" >&2
      return 1
    fi
    CARPETAS_CREADAS[$parcial]=1
  done
}

# Devuelve el tamaño remoto del archivo o vacío si no existe
tamano_remoto() {
  "${CURL[@]}" -I "$1" 2>/dev/null | awk 'tolower($1)=="content-length:" {gsub("\r",""); print $2}' | tail -1
}

# Verificar credenciales
if [[ $DRY_RUN -eq 0 ]]; then
  code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X PROPFIND -H 'Depth: 0' "${DAV_BASE}/")
  if [[ "$code" != "207" ]]; then
    echo "Error: no se pudo conectar a Nextcloud (HTTP $code). Revisa NC_URL, NC_USER y NC_PASS." >&2
    exit 1
  fi
fi

# Construir filtro de find:  ( -iname *.docx -o -iname *.txt )
FILTRO=()
for ext in $NC_EXTENSIONES; do
  [[ ${#FILTRO[@]} -gt 0 ]] && FILTRO+=(-o)
  FILTRO+=(-iname "*.${ext}")
done

subidos=0; omitidos=0; errores=0

for origen in "$@"; do
  if [[ ! -d "$origen" ]]; then
    echo "Aviso: '$origen' no es una carpeta, se omite." >&2
    continue
  fi
  origen="$(cd "$origen" && pwd)"
  nombre_origen="$(basename "$origen")"
  echo "📂 Buscando en: $origen"

  while IFS= read -r -d '' archivo; do
    relativo="${archivo#"$origen"/}"
    # Ignorar archivos temporales de Word (~$documento.docx)
    [[ "$(basename "$archivo")" == '~$'* ]] && continue

    ruta_remota="${NC_DESTINO%/}/${nombre_origen}/${relativo}"
    url="${DAV_BASE}/$(urlencode_path "$ruta_remota")"
    tam_local=$(wc -c < "$archivo" | tr -d ' ')

    if [[ $DRY_RUN -eq 1 ]]; then
      echo "  [simulación] $relativo → $ruta_remota"
      ((subidos++)); continue
    fi

    if [[ "$(tamano_remoto "$url")" == "$tam_local" ]]; then
      echo "  = Ya existe: $relativo"
      ((omitidos++)); continue
    fi

    crear_carpeta_remota "$(dirname "$ruta_remota")" || { ((errores++)); continue; }

    code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -T "$archivo" "$url")
    if [[ "$code" == "201" || "$code" == "204" ]]; then
      echo "  ✓ Subido: $relativo"
      ((subidos++))
    else
      echo "  ✗ Error al subir $relativo (HTTP $code)" >&2
      ((errores++))
    fi
  done < <(find "$origen" -type f \( "${FILTRO[@]}" \) -print0)
done

echo
echo "Resumen: $subidos subidos, $omitidos ya existían, $errores con error."
[[ $errores -eq 0 ]]
