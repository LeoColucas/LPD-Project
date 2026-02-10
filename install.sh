#!/usr/bin/env bash
set -euo pipefail

# ===== Config =====
REPO_URL_DEFAULT="https://github.com/LeoColucas/LPD-Project.git"
PYTHON_BIN_DEFAULT="python3"

# Se estiveres dentro de um repo (ou pasta com main.py), por defeito instala AQUI.
APP_DIR_DEFAULT="$(pwd)"

# ===== Helpers =====
info(){ echo -e "\033[1;34m[i]\033[0m $*"; }
ok(){ echo -e "\033[1;32m[✓]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[!]\033[0m $*"; }
die(){ echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Falta o comando: $1"; }

# ===== Args =====
# Uso:
#   ./install.sh                          -> instala no diretório atual
#   ./install.sh <repo_url> <app_dir>     -> clona/instala noutro dir
#   ./install.sh <repo_url> <app_dir> python3
REPO_URL="${1:-$REPO_URL_DEFAULT}"
APP_DIR="${2:-$APP_DIR_DEFAULT}"
PYTHON_BIN="${3:-$PYTHON_BIN_DEFAULT}"

# ===== Checks =====
need_cmd sudo
need_cmd git

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  die "Não encontrei $PYTHON_BIN. Ex: ./install.sh <repo_url> <app_dir> python3"
fi

# ===== System deps =====
info "A instalar dependências do sistema (apt)..."
sudo apt-get update -y

# libpcap-dev: útil para scapy/sniffing em algumas distros
sudo apt-get install -y \
  git \
  "$PYTHON_BIN" \
  "${PYTHON_BIN}-venv" \
  "${PYTHON_BIN}-dev" \
  build-essential \
  libssl-dev \
  libffi-dev \
  libpcap-dev \
  sqlite3 \
  ca-certificates

ok "Dependências do sistema instaladas."

# ===== Clone / use existing =====
# Se APP_DIR já for um repo git -> pull
# Se APP_DIR existir mas vazio -> clone
# Se APP_DIR existir e não for repo e não estiver vazio -> falha (para evitar confusão)
if [ -d "$APP_DIR/.git" ]; then
  info "Repo já existe em $APP_DIR. Vou fazer git pull..."
  (cd "$APP_DIR" && git pull)
elif [ -d "$APP_DIR" ] && [ "$(ls -A "$APP_DIR" 2>/dev/null | wc -l)" -eq 0 ]; then
  info "Pasta $APP_DIR está vazia. A clonar o repositório..."
  git clone "$REPO_URL" "$APP_DIR"
  ok "Clone concluído."
elif [ -d "$APP_DIR" ] && [ ! -d "$APP_DIR/.git" ] && [ "$(ls -A "$APP_DIR" 2>/dev/null | wc -l)" -gt 0 ]; then
  # Se estás numa pasta já com o projeto (ex: copiaste ficheiros sem git),
  # só aceitamos se tiver main.py (ou ajusta conforme o teu layout)
  if [ -f "$APP_DIR/main.py" ]; then
    warn "$APP_DIR não é repo git, mas parece conter o projeto (main.py encontrado). Vou instalar aqui sem clonar."
  else
    die "$APP_DIR existe e não está vazio, mas não é repo git e não encontrei main.py. Aborto para evitar instalar no sítio errado."
  fi
else
  info "A clonar o repositório para $APP_DIR..."
  git clone "$REPO_URL" "$APP_DIR"
  ok "Clone concluído."
fi

cd "$APP_DIR"

# ===== requirements.txt é obrigatório =====
if [ ! -f "requirements.txt" ]; then
  die "requirements.txt não encontrado na raiz do projeto. Cria-o (pip freeze > requirements.txt) e faz commit."
fi

# ===== Virtualenv =====
if [ ! -d ".venv" ]; then
  info "A criar virtualenv em .venv..."
  "$PYTHON_BIN" -m venv .venv
  ok "Virtualenv criado."
else
  info "Virtualenv .venv já existe."
fi

# shellcheck disable=SC1091
source .venv/bin/activate

info "A atualizar pip/setuptools/wheel..."
python -m pip install --upgrade pip setuptools wheel

# ===== Python deps =====
info "A instalar requirements.txt..."
pip install -r requirements.txt
ok "Dependências Python instaladas."

# ===== Project dirs =====
info "A garantir pastas do projeto..."
mkdir -p data/password_manager reports data

# GeoIP esperado pelo teu código:
if [ ! -f "data/GeoLite2-Country.mmdb" ]; then
  warn "GeoIP MMDB não encontrado em data/GeoLite2-Country.mmdb"
  warn "Coloca o ficheiro aí (se estiveres a usar GeoLite2)."
else
  ok "GeoIP MMDB encontrado."
fi

# ===== Permissions note =====
cat <<'EOF'

============================================================
Notas importantes:
- Para ler /var/log/auth.log e /var/log/syslog na funcionalidade
  "Análise de Logs", pode ser necessário correr com sudo:
      sudo -E .venv/bin/python main.py
============================================================

EOF

# ===== Quick sanity check =====
if [ -f "main.py" ]; then
  info "Teste rápido: importar main.py (não executa menu)..."
  python -c "import importlib.util; spec=importlib.util.spec_from_file_location('main','main.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print('OK: main.py carregou')"
  ok "Sanity check ok."
else
  warn "Não encontrei main.py na raiz. Ajusta o script ao teu layout."
fi

ok "Instalação concluída."
info "Para executar:"
echo "  cd \"$APP_DIR\""
echo "  source .venv/bin/activate"
echo "  python main.py"
