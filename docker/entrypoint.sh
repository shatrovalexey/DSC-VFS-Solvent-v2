#!/bin/sh
# ==========================================================================
# Entrypoint для Docker-образа dsc-vfs-solvent.
#
# Создаёт каталог config/, при необходимости генерирует config/settings.json
# (значения берутся из переменных окружения), затем запускает сервер.
# ==========================================================================
set -e

mkdir -p /app/config

if [ ! -f /app/config/settings.json ]; then
  cat > /app/config/settings.json <<EOF
{
  "db_host": "${DB_HOST:-db}",
  "db_port": ${DB_PORT:-5432},
  "db_user": "${DB_USER:-dsc}",
  "db_password": "${DB_PASSWORD:-dsc}",
  "db_name": "${DB_NAME:-dsc_vfs_solvent}",
  "api_host": "${API_HOST:-0.0.0.0}",
  "api_port": ${API_PORT:-8000},
  "smtp_host": "${SMTP_HOST:-}",
  "smtp_port": ${SMTP_PORT:-587},
  "smtp_user": "${SMTP_USER:-}",
  "smtp_password": "${SMTP_PASSWORD:-}",
  "smtp_from": "${SMTP_FROM:-noreply@ashatrov.ru}"
}
EOF
fi

echo "Запуск dsc-vfs-solvent..."
exec python run.py