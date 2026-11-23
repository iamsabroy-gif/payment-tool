# Single-service image: builds the React frontend, then serves it and the
# FastAPI backend from one origin. Used by render.yaml; runs anywhere Docker does.

# ---- 1. Frontend build -----------------------------------------------------
FROM node:22-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/yarn.lock* ./
RUN yarn install --frozen-lockfile --network-timeout 600000
COPY frontend/ ./
# Empty backend URL => the app calls /api on its own origin.
ENV REACT_APP_BACKEND_URL="" \
    GENERATE_SOURCEMAP=false \
    DISABLE_ESLINT_PLUGIN=true
RUN yarn build

# ---- 2. Backend + static frontend -------------------------------------------
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FRONTEND_BUILD_DIR=/app/frontend_build
WORKDIR /app/backend
COPY backend/requirements.txt ./requirements.txt
# emergentintegrations is private to Emergent hosting; billing is disabled without it.
RUN grep -v '^emergentintegrations' requirements.txt > requirements.render.txt \
 && pip install -r requirements.render.txt
COPY backend/ ./
COPY --from=frontend /app/frontend/build /app/frontend_build
RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app
# Render sets $PORT; default 8000 for local runs.
CMD ["sh", "-c", "exec uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
