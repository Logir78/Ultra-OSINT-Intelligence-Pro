# 🚀 Despliegue de NOCTUA.osint

Guía para poner NOCTUA **online 24/7**. Recomendado: **Railway** (lo más fácil) o
**Fly.io**. La base de datos: **MongoDB Atlas** (tier gratuito). El worker de
escaneos corre *dentro* del backend, así que no necesitas un servicio aparte para
empezar.

---

## 0. Base de datos — MongoDB Atlas (gratis, 5 min)

1. Crea una cuenta en <https://www.mongodb.com/atlas> → *Create* un cluster **M0 (Free)**.
2. *Database Access* → crea un usuario/contraseña.
3. *Network Access* → *Add IP* → `0.0.0.0/0` (o la IP de tu hosting).
4. *Connect* → *Drivers* → copia la cadena `mongodb+srv://usuario:password@...`.
   Esa cadena es tu `MONGO_URL`. `DB_NAME` puede ser `noctua`.

---

## Opción A — Railway (recomendada)

1. Sube el repo a GitHub (ya está listo).
2. En <https://railway.app> → *New Project* → *Deploy from GitHub repo* → elige el repo.
3. Railway detecta el `backend/Dockerfile`. Si crea el servicio en la raíz, en
   *Settings → Root Directory* pon `backend`.
4. *Variables* → añade (mínimo):
   ```
   MONGO_URL = mongodb+srv://...            (de Atlas)
   DB_NAME = noctua
   CORS_ORIGINS = https://TU-FRONTEND.up.railway.app
   LOG_FORMAT = json
   ```
   Y las opcionales que uses (Stripe, LLM, claves OSINT…). Ver `backend/.env.example`.
5. *Settings → Networking → Generate Domain* → tienes la URL del backend.
6. **Frontend:** *New Service* → mismo repo → *Root Directory* = `frontend` →
   variable de build `REACT_APP_BACKEND_URL = https://TU-BACKEND.up.railway.app` →
   genera dominio. Ese dominio es el que pones en `CORS_ORIGINS` del backend.

> Railway también puede darte un MongoDB propio (*New → Database → MongoDB*) en
> vez de Atlas; usa su `MONGO_URL`.

---

## Opción B — Fly.io

Requiere la CLI `flyctl` (<https://fly.io/docs/hands-on/install-flyctl/>).

```bash
# desde la raíz del repo (usa el fly.toml incluido)
fly launch --no-deploy            # crea la app (acepta el fly.toml)
fly secrets set \
  MONGO_URL="mongodb+srv://..." \
  DB_NAME="noctua" \
  CORS_ORIGINS="https://tu-frontend" \
  EMERGENT_LLM_KEY="..."          # y las que uses
fly deploy
fly open                          # abre la URL
```

El frontend puedes servirlo en Fly (otro `fly launch` apuntando a
`frontend/Dockerfile`) o en Vercel/Netlify con `REACT_APP_BACKEND_URL` = la URL de Fly.

---

## 3. Comprobar que está vivo

```bash
curl https://TU-BACKEND/api/health      # -> {"status":"ok","db":true}
```

Docs de la API: `https://TU-BACKEND/docs`.

---

## 4. Escaneos en segundo plano (ya incluido)

- `POST /api/scan/async` encola y devuelve un `job_id` al instante.
- `GET /api/scan/jobs/{job_id}` da el progreso (`queued → running → done`).
- El worker arranca solo con el backend. **Para varias instancias del backend**,
  mueve el worker a un proceso aparte (o usa `arq`/Redis) para no duplicar trabajo:
  hoy el claim de jobs es atómico (`find_one_and_update`), seguro con **una**
  instancia; con varias, un job podría tomarse dos veces sin un lock distribuido.

---

## 5. Antes de abrirlo al público (checklist P0)

- [ ] `CORS_ORIGINS` = tu dominio real (no `*`).
- [ ] `COOKIE_SECURE=1` (HTTPS) y `SSRF_GUARD=1`.
- [ ] Backups de MongoDB activados (Atlas los hace en el tier de pago; en M0
      exporta con `mongodump` periódicamente).
- [ ] Términos, Privacidad y Uso Aceptable publicados (ver hoja de ruta "Élite").
- [ ] Un dominio propio + HTTPS (Railway/Fly lo dan; añade Cloudflare delante si quieres WAF).
