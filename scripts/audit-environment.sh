#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

errors=0

report() {
  printf '%-10s %s\n' "$1" "$2"
}

require_command() {
  local command_name="$1"
  local version_command="$2"

  if command -v "$command_name" >/dev/null 2>&1; then
    report "OK" "$command_name: $($version_command 2>&1 | head -n 1)"
  else
    report "FALTA" "$command_name no esta instalado"
    errors=$((errors + 1))
  fi
}

printf 'Auditoria de entorno: %s\n' "$ROOT_DIR"
printf 'Requisitos: Node.js >= 20, Rust/cargo y Docker Compose v2\n\n'

if command -v node >/dev/null 2>&1; then
  node_major="$(node -p 'process.versions.node.split(".")[0]')"
  if [ "$node_major" -ge 20 ]; then
    report "OK" "node: $(node --version)"
  else
    report "ERROR" "node: $(node --version) (se requiere >= 20)"
    errors=$((errors + 1))
  fi
else
  report "FALTA" "node no esta instalado"
  errors=$((errors + 1))
fi

require_command "npm" "npm --version"
require_command "rustc" "rustc --version"
require_command "cargo" "cargo --version"
require_command "docker" "docker --version"

if command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    compose_version="$(docker compose version 2>&1 | head -n 1)"
    case "$compose_version" in
      *"Docker Compose version v"*)
        report "OK" "docker compose: $compose_version"
        ;;
      *)
        report "ERROR" "docker compose no parece ser Compose v2: $compose_version"
        errors=$((errors + 1))
        ;;
    esac
  else
    report "FALTA" "docker compose (se requiere Compose v2)"
    errors=$((errors + 1))
  fi
fi

printf '\n'
if [ "$errors" -eq 0 ]; then
  printf 'Resultado: entorno compatible.\n'
else
  printf 'Resultado: %s requisito(s) no cumplido(s).\n' "$errors"
  exit 1
fi