# ==========================================================================
# dsc-vfs-solvent: многоступенчатая сборка Docker-образа.
#
#   Стадия web-build — сборка веб-интерфейса (Node.js + Gulp/esbuild).
#   Стадия runtime   — Python-приложение + собранные статические файлы.
# ==========================================================================

# --- Сборка веб-интерфейса ------------------------------------------------
FROM node:20-alpine AS web-build

WORKDIR /web

# Сначала копируем манифесты, чтобы слой npm install кэшировался.
COPY package.json tsconfig.json gulpfile.js ./
COPY src/dsc_vfs_solvent/web ./src/dsc_vfs_solvent/web

RUN npm install --no-audit --no-fund && npm run build

# --- Runtime (Python-приложение) -----------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Копируем исходники пакета и собранный веб-интерфейс ДО установки,
# чтобы setuptools включил web/dist в устанавливаемый пакет.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY --from=web-build /web/src/dsc_vfs_solvent/web/dist ./src/dsc_vfs_solvent/web/dist

RUN pip install --no-cache-dir .

COPY run.py ./
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

CMD ["/entrypoint.sh"]