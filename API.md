# 🔌 API pública de NOCTUA.osint

NOCTUA expone una API REST. Toda la superficie (los ~120 endpoints) es accesible
de forma programática con una **API key**, además de por sesión de navegador.

- **Documentación interactiva:** `https://TU-BACKEND/docs` (Swagger, autogenerado)
- **Esquema OpenAPI:** `https://TU-BACKEND/openapi.json`

---

## 1. Crear una API key

Desde la web (con sesión iniciada) o por API:

```bash
curl -X POST https://TU-BACKEND/api/apikeys \
  -H "Content-Type: application/json" \
  -b "session_token=TU_SESION" \
  -d '{"name":"mi-script"}'
```

Respuesta (la clave se muestra **una sola vez** — guárdala):

```json
{ "key_id": "key_abc123", "name": "mi-script",
  "prefix": "nk_0bcdc607", "api_key": "nk_xxxxxxxx…",
  "warning": "Guarda esta clave ahora — no se volverá a mostrar." }
```

Gestionar claves: `GET /api/apikeys` (lista, sin exponer la clave) ·
`DELETE /api/apikeys/{key_id}` (revocar).

---

## 2. Autenticarte con la key

Dos formas equivalentes:

```bash
# a) cabecera X-API-Key
curl https://TU-BACKEND/api/auth/me -H "X-API-Key: nk_xxxxxxxx…"

# b) Authorization: Bearer
curl https://TU-BACKEND/api/auth/me -H "Authorization: Bearer nk_xxxxxxxx…"
```

---

## 3. Ejemplos de uso

**Escaneo asíncrono (recomendado, no bloquea):**

```bash
# lanzar
curl -X POST https://TU-BACKEND/api/scan/async \
  -H "X-API-Key: nk_…" -H "Content-Type: application/json" \
  -d '{"domain":"ejemplo.com","ai_summary":true}'
# -> {"job_id":"job_…","status":"queued"}

# consultar progreso
curl https://TU-BACKEND/api/scan/jobs/job_… -H "X-API-Key: nk_…"
# -> {"status":"done","progress":100,"scan_id":"scan_…"}
```

**Diferenciadores sobre un escaneo:**

```bash
curl -X POST https://TU-BACKEND/api/scans/scan_…/verify-exploitability -H "X-API-Key: nk_…"
curl -X POST https://TU-BACKEND/api/scans/scan_…/notarize             -H "X-API-Key: nk_…"
curl      https://TU-BACKEND/api/scans/scan_…/exploit-score           -H "X-API-Key: nk_…"
curl -X POST https://TU-BACKEND/api/scans/scan_…/autopilot            -H "X-API-Key: nk_…"
```

---

## 4. Buenas prácticas
- Trata la key como una contraseña; no la subas a repos ni la pongas en el frontend.
- Usa una key por integración y **revócala** si se filtra.
- Respeta el rate limiting (cabecera `Retry-After` en respuestas `429`).
- Recuerda la [Política de Uso Aceptable](legal/USO_ACEPTABLE.md): solo dominios
  autorizados.
