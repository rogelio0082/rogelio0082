#!/usr/bin/env bash
# subir_nextcloud.sh — Copia documentos del usuario con sesión iniciada a un
# enlace compartido de Nextcloud (Debian, Ubuntu, Kali y derivados).
#
# Uso:
#   ./subir_nextcloud.sh [-n] [-c config] [CARPETA_ORIGEN ...]
#
#   -n          Simulación: muestra qué subiría, sin subir nada.
#   -c ARCHIVO  Archivo de configuración. Si no se indica, se busca en este orden:
#                 1) subir_nextcloud.conf junto a este script
#                 2) ~/.config/nextcloud-subida.conf
#
#   Sin carpetas: revisa Escritorio, Documentos y Descargas del usuario con la
#   sesión iniciada (nombres en español o inglés). Si se ejecuta con sudo,
#   usa las carpetas del usuario que llamó a sudo, no las de root.
#
# Configuración (archivo o variables de entorno):
#   NC_ENLACE="https://servidor/index.php/s/TOKEN"   # Enlace compartido (obligatorio)
#   NC_ENLACE_PASS=""                                 # Contraseña del enlace, si tiene
#   NC_EXTENSIONES="txt doc docx jpg jpeg pdf xls xlsx xlsm csv ppt pptx pps ppsx"
#   NC_IGNORAR_CERT=0                                 # 1 = aceptar certificado autofirmado
#
# En el enlace, los archivos quedan en:  EQUIPO_usuario/Escritorio/..., etc.
# Omite los archivos que ya existen en Nextcloud con el mismo tamaño.

set -uo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG=""
DRY_RUN=0

while getopts ":nc:h" opt; do
  case "$opt" in
    n) DRY_RUN=1 ;;
    c) CONFIG="$OPTARG" ;;
    h) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "Opción no válida. Usa -h para ver la ayuda." >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

# ---------- Usuario con sesión iniciada ----------
USUARIO="$(id -un)"
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  USUARIO="$SUDO_USER"
  HOME="$(getent passwd "$USUARIO" | cut -d: -f6)"
  export HOME
fi
EQUIPO="$(hostname -s 2>/dev/null || hostname)"

# ---------- Configuración ----------
if [[ -z "$CONFIG" ]]; then
  for c in "$DIR_SCRIPT/subir_nextcloud.conf" "$HOME/.config/nextcloud-subida.conf"; do
    [[ -f "$c" ]] && { CONFIG="$c"; break; }
  done
fi
[[ -n "$CONFIG" && -f "$CONFIG" ]] && source <(tr -d '\r' < "$CONFIG")   # tolera archivos editados en Windows

: "${NC_ENLACE:?Falta NC_ENLACE (enlace compartido de Nextcloud). Revisa el archivo de configuración.}"
NC_ENLACE_PASS="${NC_ENLACE_PASS:-}"
NC_EXTENSIONES="${NC_EXTENSIONES:-txt doc docx jpg jpeg pdf xls xlsx xlsm csv ppt pptx pps ppsx}"
NC_IGNORAR_CERT="${NC_IGNORAR_CERT:-0}"

# Separar servidor y token:  https://servidor[/ruta]/index.php/s/TOKEN
if [[ "$NC_ENLACE" =~ ^(https?://.+)/s/([A-Za-z0-9]+)/?$ ]]; then
  SERVIDOR="${BASH_REMATCH[1]%/index.php}"
  TOKEN="${BASH_REMATCH[2]}"
else
  echo "Error: NC_ENLACE no parece un enlace compartido de Nextcloud (…/index.php/s/TOKEN)." >&2
  exit 2
fi

if ! command -v curl >/dev/null; then
  echo "Error: se necesita curl." >&2
  command -v apt-get >/dev/null && echo "Instálalo con:  sudo apt-get install -y curl" >&2
  exit 1
fi

# ---------- Carpetas por defecto ----------
if [[ $# -eq 0 ]]; then
  carpetas=()
  for par in "DESKTOP:Escritorio:Desktop" "DOCUMENTS:Documentos:Documents" "DOWNLOAD:Descargas:Downloads"; do
    IFS=: read -r xdg es en <<< "$par"
    dir=""
    if command -v xdg-user-dir >/dev/null; then
      dir="$(xdg-user-dir "$xdg" 2>/dev/null)"
      [[ "$dir" == "$HOME" ]] && dir=""
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

# ---------- WebDAV del enlace compartido ----------
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

DAV_BASE="${SERVIDOR}/public.php/webdav"
CURL=(curl -sS --user "${TOKEN}:${NC_ENLACE_PASS}" -H 'X-Requested-With: XMLHttpRequest' --retry 3 --retry-delay 2)
[[ "$NC_IGNORAR_CERT" == "1" ]] && CURL+=(-k)

declare -A CARPETAS_CREADAS=()
crear_carpeta_remota() {
  local ruta="$1" parcial="" parte code
  IFS='/' read -ra partes <<< "$ruta"
  for parte in "${partes[@]}"; do
    [[ -z "$parte" ]] && continue
    parcial+="/$parte"
    [[ -n "${CARPETAS_CREADAS[$parcial]:-}" ]] && continue
    code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X MKCOL "${DAV_BASE}$(urlencode_path "$parcial")")
    if [[ "$code" != "201" && "$code" != "405" ]]; then   # 405 = ya existía
      echo "  ✗ No se pudo crear la carpeta '$parcial' (HTTP $code)" >&2
      return 1
    fi
    CARPETAS_CREADAS[$parcial]=1
  done
}

tamano_remoto() {
  "${CURL[@]}" -I "$1" 2>/dev/null | awk 'tolower($1)=="content-length:" {gsub("\r",""); print $2}' | tail -1
}

# ---------- Verificar el enlace ----------
if [[ $DRY_RUN -eq 0 ]]; then
  err_file="$(mktemp)"
  code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X PROPFIND -H 'Depth: 0' "${DAV_BASE}/" 2>"$err_file")
  err="$(cat "$err_file")"; rm -f "$err_file"
  case "$code" in
    207|200) ;;
    401) echo "Error: acceso denegado. Revisa que el enlace sea correcto y, si tiene contraseña, NC_ENLACE_PASS." >&2; exit 1 ;;
    404) echo "Error: el enlace no existe o caducó." >&2; exit 1 ;;
    000)
      echo "Error: no se pudo conectar a $SERVIDOR. $err" >&2
      [[ "$err" == *certificate* || "$err" == *SSL* ]] && \
        echo "Si el servidor usa un certificado autofirmado, pon NC_IGNORAR_CERT=1 en la configuración." >&2
      exit 1 ;;
    *) echo "Aviso: respuesta inesperada del servidor (HTTP $code); se intentará subir igual." >&2 ;;
  esac
fi

# ---------- Buscar y subir ----------
FILTRO=()
for ext in $NC_EXTENSIONES; do
  [[ ${#FILTRO[@]} -gt 0 ]] && FILTRO+=(-o)
  FILTRO+=(-iname "*.${ext#.}")
done

DESTINO="${EQUIPO}_${USUARIO}"
echo "Usuario: $USUARIO   Equipo: $EQUIPO   Destino en el enlace: $DESTINO/"
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
    [[ "$(basename "$archivo")" == '~$'* ]] && continue   # temporales de Office

    ruta_remota="${DESTINO}/${nombre_origen}/${relativo}"
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
  done < <(find "$origen" -type f \( "${FILTRO[@]}" \) -print0 2>/dev/null)
done

echo
echo "Resumen: $subidos subidos, $omitidos ya existían, $errores con error."
[[ $errores -eq 0 ]]
