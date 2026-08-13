#!/usr/bin/env bash
#
# srecon — instalação reprodutível do toolchain (ProjectDiscovery + testssl + srecon).
# Portável: usa `go install` (nomes canônicos httpx/dnsx/...) e o resolve_bin da tool
# acha tanto esses nomes quanto os renomeados do Kali (httpx-toolkit/testssl).
#
# Uso:   ./install.sh
# Pins podem ser sobrescritos por env, ex:  NUCLEI_VERSION=v3.12.0 ./install.sh
#
# NÃO instala Metasploit (pesado, ~1GB Ruby). `srecon msf` só precisa do cache
# ~/.msf4/store/modules_metadata.json — gere com `msfconsole -q -x exit` uma vez,
# ou aponte SRECON_MSF_METADATA para um cache existente.
set -euo pipefail

# ------------------------------- pins (2026-08-07, comprovados) ---------------------------- #
SUBFINDER_VERSION="${SUBFINDER_VERSION:-v2.14.0}"
DNSX_VERSION="${DNSX_VERSION:-v1.3.0}"
KATANA_VERSION="${KATANA_VERSION:-v1.6.1}"
HTTPX_VERSION="${HTTPX_VERSION:-v1.9.0}"
NUCLEI_VERSION="${NUCLEI_VERSION:-v3.11.0}"
TESTSSL_REF="${TESTSSL_REF:-v3.2.2}"   # tags upstream têm prefixo 'v' (v3.2.2, não 3.2.2)
TESTSSL_DIR="${TESTSSL_DIR:-$HOME/.local/share/testssl.sh}"

SRECON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[1;36m[srecon-install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[srecon-install] aviso:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[srecon-install] ERRO:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------ prereqs ---------------------------------------------- #
have go      || die "Go não encontrado (necessário p/ as ferramentas ProjectDiscovery). Instale go>=1.21."
have git     || die "git não encontrado."
have python3 || die "python3 não encontrado (>=3.11)."
have pipx    || die "pipx não encontrado. Instale: python3 -m pip install --user pipx && pipx ensurepath"

GOBIN="$(go env GOBIN)"; [ -n "$GOBIN" ] || GOBIN="$(go env GOPATH)/bin"
mkdir -p "$GOBIN"
case ":$PATH:" in
  *":$GOBIN:"*) : ;;
  *) warn "GOBIN ($GOBIN) não está no PATH — adicione ao seu shell rc." ;;
esac

# --------------------------- ferramentas Go (pinadas) -------------------------------------- #
install_go_tool() {  # <nome> <modulo@versao>
  local name="$1" mod="$2"
  log "instalando $name ($mod) ..."
  go install "$mod" || die "falha ao instalar $name"
}
install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}"
install_go_tool dnsx      "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}"
install_go_tool katana    "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
install_go_tool httpx     "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
install_go_tool nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"

# ------------------------------- testssl.sh (pinado) --------------------------------------- #
if [ -x "$TESTSSL_DIR/testssl.sh" ]; then
  log "testssl.sh já presente em $TESTSSL_DIR"
else
  log "clonando testssl.sh @ ${TESTSSL_REF} ..."
  git clone --depth 1 --branch "$TESTSSL_REF" \
    https://github.com/testssl/testssl.sh.git "$TESTSSL_DIR" \
    || die "falha ao clonar testssl.sh (tag/branch '${TESTSSL_REF}' existe?)"
fi
ln -sf "$TESTSSL_DIR/testssl.sh" "$GOBIN/testssl.sh"   # exposto no PATH via GOBIN

# ------------------------------ templates do nuclei ---------------------------------------- #
log "atualizando templates do nuclei ..."
"$GOBIN/nuclei" -update-templates >/dev/null 2>&1 || warn "não atualizei templates (segue)"

# ---------------------------------- srecon (pipx) ------------------------------------------ #
log "instalando srecon (pipx editable) ..."
pipx install -e "$SRECON_DIR" --force

# ------------------------------------ verificação ------------------------------------------ #
log "rodando selftest (offline) ..."
srecon selftest

log "pronto ✅  ferramentas em $GOBIN"
log "próximos passos:  srecon init   (API key Shodan)   |   opcional: cache MSF p/ 'srecon msf'"
