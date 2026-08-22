<div align="center">

# 🦉 NOCTUA.osint — Ultra OSINT Intelligence

**Plataforma OSINT full-stack para análisis de dominios y superficie de ataque.**
WHOIS · DNS · SSL/TLS · subdominios · puertos · fingerprinting · inteligencia predictiva con IA · Bug Bounty Toolkit.

![Backend](https://img.shields.io/badge/backend-FastAPI-009688)
![Frontend](https://img.shields.io/badge/frontend-React_19-61dafb)
![DB](https://img.shields.io/badge/db-MongoDB-47A248)
![Python](https://img.shields.io/badge/python-3.11+-3776AB)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

---

## ✨ Qué es

NOCTUA es un escáner OSINT web que analiza cualquier dominio y presenta un panel visual de ciberseguridad con:

- **Escaneo base:** WHOIS, DNS, SSL/TLS, subdominios, cabeceras HTTP/HTTPS, IP + geolocalización, escaneo de puertos y fingerprinting de tecnologías.
- **Módulos avanzados:** Shodan, AbuseIPDB, Have I Been Pwned, BreachDirectory, Wayback Machine, Cloud Storage Radar (S3/Azure/GCS), extractor de metadatos, mapa de inteligencia (React Flow), detección de subdomain takeover (80 fingerprints), monitor de pastes, CT logs y más.
- **Inteligencia Predictiva (IA):** Attack Path Mapper con personas APT, Oráculo de Riesgos, ADN Digital, Guardián de Marca (typosquatting), Generador de PoC y Simulador de Phishing.
- **Bug Bounty Toolkit:** parameter miner, WAF bypass, análisis IDOR, supply-chain, API auditor, etc.
- **Plataforma:** autenticación Google, historial en MongoDB, exportación PDF/JSON, plan Pro con Stripe, alertas por Slack y Telegram, y tareas programadas con motor de diffs.

> ⚠️ **Uso responsable.** Esta herramienta es para investigación de seguridad **autorizada**. Escanea únicamente dominios que te pertenezcan o para los que tengas permiso explícito. El uso indebido puede ser ilegal.

---

## 🏗️ Arquitectura

```
┌─────────────┐      ┌──────────────────────┐      ┌───────────┐
│  React 19    │─────▶│  FastAPI (backend)    │────▶│  MongoDB   │
│  (frontend)  │◀─────│  92 endpoints /api/*   │◀────│  (motor)   │
└─────────────┘      │  ~50 módulos OSINT     │      └───────────┘
                     └──────────┬───────────┘
                                │
          ┌─────────────────────┼──────────────────────┐
          ▼                     ▼                      ▼
     LLM (Claude/GPT/       Stripe (pagos)        Telegram / Slack
     Gemini)                                       (alertas)
```

| Capa      | Tecnología |
|-----------|------------|
| Backend   | FastAPI · Motor (MongoDB async) · httpx · Pydantic v2 |
| Frontend  | React 19 · CRACO · TailwindCSS · Radix UI · React Flow · Leaflet |
| IA        | Claude / GPT / Gemini (vía `emergentintegrations` + `litellm`) |
| Pagos     | Stripe |
| Notif.    | Telegram Bot · Slack webhooks · email (Resend) |

---

## 🚀 Arranque rápido

### Opción A — Docker (recomendada)

Requisitos: Docker y Docker Compose.

```bash
# 1. Copia y rellena las variables de entorno
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# 2. Levanta todo (Mongo + backend + frontend)
make up          # o: docker compose up --build

# Frontend → http://localhost:3000
# Backend  → http://localhost:8001/api
# API docs → http://localhost:8001/docs
```

### Opción B — Local (sin Docker)

Requisitos: Python 3.11+, Node 18+, Yarn y una instancia de MongoDB.

```bash
# --- Backend ---
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # rellena MONGO_URL, DB_NAME, etc.
uvicorn server:app --reload --port 8001

# --- Frontend (en otra terminal) ---
cd frontend
yarn install
cp .env.example .env          # rellena REACT_APP_BACKEND_URL
yarn start
```

---

## 🔑 Variables de entorno

El backend **no arranca** sin `MONGO_URL` y `DB_NAME`. El resto de claves habilitan integraciones concretas (si faltan, ese módulo se desactiva con elegancia). Ver [`backend/.env.example`](backend/.env.example) y [`frontend/.env.example`](frontend/.env.example) para el listado completo comentado.

| Variable | Obligatoria | Para qué |
|----------|:----------:|----------|
| `MONGO_URL` | ✅ | Conexión a MongoDB |
| `DB_NAME` | ✅ | Nombre de la base de datos |
| `CORS_ORIGINS` | ⚠️ prod | Orígenes permitidos (coma-separados). **No usar `*` en producción.** |
| `EMERGENT_LLM_KEY` | – | Resúmenes y módulos con IA |
| `AUTHORIZED_EMAILS` | – | Modo acceso privado (allowlist de emails) |
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | – | Pagos del plan Pro |
| `RESEND_API_KEY` / `SENDER_EMAIL` | – | Alertas por email |
| `SHODAN_KEY`, `ABUSEIPDB_KEY`, `HIBP_KEY`, `RAPIDAPI_KEY`, `INTELX_KEY`, `URLSCAN_KEY` | – | Proveedores OSINT |
| `PUBLIC_BASE_URL` | – | URL pública del backend (webhooks) |
| `REACT_APP_BACKEND_URL` | ✅ (front) | URL del backend que consume el frontend |

---

## 🧪 Tests y calidad

```bash
make test        # pytest (backend)
make lint        # ruff + black --check + mypy
make format      # black + ruff --fix
```

El pipeline de CI (`.github/workflows/ci.yml`) ejecuta lint, tipos, tests de backend y build de frontend en cada push y PR.

---

## 📂 Estructura del proyecto

```
.
├── backend/                # FastAPI
│   ├── server.py           # wiring + endpoints /api/*
│   ├── osint_engine.py     # motor de escaneo base
│   ├── integrations/       # ~50 módulos OSINT
│   ├── config.py           # ⭐ configuración centralizada (nuevo)
│   ├── security.py         # ⭐ cabeceras de seguridad + guard SSRF (nuevo)
│   ├── requirements.txt        # dependencias de runtime
│   ├── requirements-dev.txt    # ⭐ herramientas de desarrollo (nuevo)
│   └── tests/              # pytest
├── frontend/               # React 19 + Tailwind + Radix
│   └── src/{pages,components,lib,hooks}/
├── docker-compose.yml      # ⭐ Mongo + backend + frontend (nuevo)
├── Makefile                # ⭐ atajos de dev (nuevo)
└── .github/workflows/      # ⭐ CI (nuevo)
```

Los archivos marcados con ⭐ se añadieron en esta versión "Pro". Ver [`IMPROVEMENTS.md`](IMPROVEMENTS.md) para el detalle de todos los cambios.

---

## 🔒 Seguridad

Antes de exponer NOCTUA a Internet, revisa [`SECURITY.md`](SECURITY.md). Puntos clave:
- Define `CORS_ORIGINS` con una allowlist explícita (nunca `*` con credenciales).
- Activa la validación anti-SSRF de dominios (`backend/security.py`).
- Pon la API detrás de rate limiting y HTTPS.

---

## 📄 Licencia

[MIT](LICENSE) — puedes cambiarla si prefieres un modelo distinto (p. ej. AGPL para proteger el SaaS).

---

## 🙌 Contribuir

Lee [`CONTRIBUTING.md`](CONTRIBUTING.md). Issues y PRs bienvenidos.
