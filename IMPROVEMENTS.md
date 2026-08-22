# Mejoras aplicadas — versión "Pro"

Este documento resume qué se añadió/cambió respecto al repositorio original
`Logir78/Ultra-OSINT-Intelligence`, y qué queda como trabajo futuro. La lógica de
negocio **no se ha reescrito**: los cambios son aditivos o de bajo riesgo, para
que la app siga funcionando igual mientras ganas profesionalidad.

---

## ✅ Añadido (archivos nuevos)

### Documentación y gobernanza
| Archivo | Qué aporta |
|---------|-----------|
| `README.md` | Documentación real: qué es, arquitectura, arranque en Docker y local, tabla de variables, estructura. (Antes: placeholder `# Here are your Instructions`.) |
| `backend/.env.example` | Todas las variables del backend, comentadas. |
| `frontend/.env.example` | Variables del frontend (`REACT_APP_*`). |
| `LICENSE` | MIT (cámbiala si prefieres AGPL u otra). |
| `SECURITY.md` | Política de reporte + checklist de despliegue seguro. |
| `CONTRIBUTING.md` | Flujo de contribución, estilo, tests. |

### Infraestructura y reproducibilidad
| Archivo | Qué aporta |
|---------|-----------|
| `docker-compose.yml` | Stack completo: MongoDB + backend + frontend con un comando. |
| `backend/Dockerfile` | Imagen del backend (usuario no-root, healthcheck). |
| `frontend/Dockerfile` + `frontend/nginx.conf` | Build de producción servido por nginx. |
| `Makefile` | Atajos: `make up`, `make test`, `make lint`, `make format`… |
| `.dockerignore` | Builds más pequeños y limpios. |
| `backend/pyproject.toml` | Config de `black`, `ruff`, `mypy`, `pytest`. |
| `backend/requirements-dev.txt` | Herramientas de desarrollo separadas del runtime. |
| `.github/workflows/ci.yml` | CI: lint + tipos + tests backend + build frontend + audit. |
| `.pre-commit-config.yaml` | Hooks de formato/lint y detección de secretos. |

### Código (backend, aditivo)
| Archivo | Qué aporta |
|---------|-----------|
| `backend/config.py` | Configuración centralizada y tipada (`settings`). Opcional: el código existente sigue leyendo `os.environ`. |
| `backend/security.py` | `SecurityHeadersMiddleware` (cabeceras de seguridad) + guard **anti-SSRF** (`assert_public_host`). |

---

## 🔧 Modificado

### `backend/server.py` (cambios mínimos y localizados)
1. **Endpoint `/api/health`** — sonda de liveness/readiness que comprueba la
   conexión a MongoDB (usado por el healthcheck de Docker). *Aditivo.*
2. **Cabeceras de seguridad** — `app.add_middleware(SecurityHeadersMiddleware)`.
   *Aditivo (solo añade headers a las respuestas).*
3. **Guard anti-SSRF** — en `/api/scan` y en `/api/public/takeover-check` se
   valida el dominio con `assert_public_host()` antes de escanear. Solo bloquea
   destinos internos (localhost, rangos privados, metadatos cloud). Controlable
   con `SSRF_GUARD=0`. *Riesgo bajo: no afecta a dominios públicos legítimos.*
4. **CORS más seguro** ⚠️ — se elimina el default `"*"`. Ahora, si
   `CORS_ORIGINS` no está definido, usa `http://localhost:3000` y registra un
   aviso. **Cambio de comportamiento a verificar:** en producción **debes**
   definir `CORS_ORIGINS` con tu dominio real, o el frontend no podrá llamar al
   backend.

### `.gitignore`
Reescrito y limpiado: se ignoran `.emergent/`, `.gitconfig`, cachés y secretos;
se eliminaron rutas específicas del generador.

### Limpieza del repo
Se quitaron del árbol: `.emergent/` (cron/webhooks/markers del generador),
`.gitconfig` (identidad `emergent-agent`), cachés `__pycache__`/`.pack`.

---

## ✔️ Verificado
- Todos los módulos Python del backend **compilan** (`py_compile`) tras los cambios.
- El guard SSRF pasa sus casos (bloquea `localhost`, `127.0.0.1`,
  `169.254.169.254`, `10/8`, `192.168/16`; permite `8.8.8.8`, `example.com`).
- `docker-compose.yml`, el workflow de CI y `.pre-commit-config.yaml` son **YAML válido**.
- `config.py` carga y `require_core()` funciona.

> No se ejecutó la app completa end-to-end (requiere MongoDB y claves reales de
> Emergent/Stripe/LLM). Verifica el arranque con `make up` en tu entorno.

---

## 🧩 Fase 1 (refactor) — `server.py` dividido en un paquete

El monolito de ~2.000 líneas se partió en un paquete `app/` (sin cambiar la lógica):

| Antes | Después |
|-------|---------|
| `server.py` (2.004 líneas, 95 rutas) | `server.py` (~100 líneas: solo el ensamblado) |
| — | `app/core.py` — DB, `get_current_user`, helpers y LLM compartidos |
| — | `app/models.py` — los 12 modelos Pydantic |
| — | `app/routers/{auth,scans,intel,settings,breaches,copilot,commerce,public}.py` |

Los endpoints se movieron **verbatim** (solo cambió el decorador `@api_router`/`@app`
por `@router`). Las importaciones de integraciones ya eran locales a cada función,
así que viajaron con ellas. El `server.py` original se conserva como
`backend/server_original_backup.py` por si necesitas comparar.

**Verificado (esta vez sí en ejecución):**
- Los 8 routers + `server.py` **importan** correctamente (con las libs de terceros
  stubbeadas).
- `pyflakes` no reporta **ningún nombre indefinido** en todo el paquete.
- Paridad de rutas **95 = 95** (mismos paths exactos que el original; 0 perdidos, 0 extra).
- Con `TestClient`, la app monta **102 rutas** (95 + payments/schedules/telegram) y
  `GET /api/health` responde `200`.

> Sigue sin probarse contra un MongoDB real ni con las claves de Emergent/Stripe;
> verifica el arranque con `make up`.

---

## 📈 Fase 2 (robustez) — rate limiting global + observabilidad

Nuevo módulo `app/observability.py`, conectado en `server.py` (todo aditivo):

- **Rate limiting global por IP** — middleware propio de ventana fija
  (`RATE_LIMIT_DEFAULT`, p. ej. `240/minute`), con `Retry-After` y exención de
  `/api/health` y `/docs`. Se descartó `slowapi`: sus `default_limits` **no
  aplican** cuando los endpoints no reciben `request: Request` (la mayoría aquí) o
  están en routers anidados — verificado. El middleware propio no depende de la
  firma de cada endpoint. *(Para varias instancias, respáldalo con Redis.)*
- **Logging estructurado** — `LOG_FORMAT=json` produce logs JSON con `request_id`,
  `path`, `method`, `status`, `duration_ms` y `client`; `plain` mantiene el formato
  legible. Alinea también los loggers de uvicorn.
- **Request-ID** — cada respuesta lleva `X-Request-ID` (acepta uno entrante) para
  trazar peticiones extremo a extremo.
- **Handler catch-all 500** — las excepciones no controladas devuelven un JSON
  limpio (`{"error":"internal_error"}`) en vez de una traza.

Nuevas variables (en `backend/.env.example`): `LOG_LEVEL`, `LOG_FORMAT`,
`RATE_LIMIT_ENABLED`, `RATE_LIMIT_DEFAULT`.

**Verificado (TestClient):** ruta protegida devuelve `401,401,401,429,429,429`
(corta tras el límite y mantiene la auth); `/api/health` nunca se limita;
`X-Request-ID` y `Retry-After` presentes; 102 rutas intactas.

---

## 🎨 Fase 3 (frontend) — páginas React troceadas

Se extrajeron las piezas reutilizables y auto-contenidas de las 3 pantallas más
grandes a componentes propios (movimiento **verbatim** + `import`):

| Página | Antes | Después | Extraído a |
|--------|------:|--------:|-----------|
| `ScanDetail.jsx` | 796 | **537** | `components/scan/ScanUI.jsx` (Panel, MetricCard, KV, StatusIcon, SecurityChecks, ScoreCircle) y `components/scan/FactorHumanoTab.jsx` |
| `Settings.jsx` | 1.155 | **1.101** | `constants/settingsData.js` (PROVIDERS, AI_PROVIDERS, AI_MODES) y `components/settings/SettingsUI.jsx` (TestBadge, KeyInput) |
| `BountyTab.jsx` | 1.038 | **971** | `components/bounty/BountyUI.jsx` (CopyLink, SevBadge, useRunner, Section) |

**Verificado:** los 8 archivos (3 páginas + 5 nuevos) pasan la validación de
sintaxis JSX con `esbuild`, y las piezas importadas siguen usándose en cada página
(p. ej. `Section`×35, `Panel`×23, `TestBadge`×5).

> ⚠️ `esbuild` valida la **sintaxis**, no que la app se renderice. Como no puedo
> levantar el frontend aquí, **corre `yarn build` (o `make up`) y abre las 3
> pantallas** antes de desplegar. El workflow de CI ya ejecuta `yarn build`, que
> detectará cualquier import que falte.

---

## 🔓 Fase 4 (desacople) — auth propia + LLM directo

El acoplamiento a Emergent estaba en dos sitios: el **login** (validaba el OAuth
contra `demobackend.emergentagent.com`) y la **IA** (`emergentintegrations`). Se
añadieron alternativas propias, sin quitar lo existente:

**Auth nativa** (`app/auth_native.py` + `app/routers/auth_native.py`):
- `POST /api/auth/register` y `POST /api/auth/login` con email + contraseña
  (hash **bcrypt** directo). Crean **la misma sesión de servidor** que ya usaba la
  app (`db.user_sessions` + cookie), así que `get_current_user` y los 95 endpoints
  no cambian. Sesiones revocables en servidor (más robusto que un JWT sin estado).
- Respeta la allowlist `AUTHORIZED_EMAILS`. Activable con `AUTH_NATIVE_ENABLED`.
- Los usuarios OAuth existentes conviven: simplemente no tienen `password_hash`.

**LLM directo** (`app/llm.py`): usa `litellm` oficial con tu propia clave
(`DEFAULT_LLM_PROVIDER`/`_KEY`/`_MODEL`) y **cae a Emergent** si no configuras nada.
`app/core.py` ya **no importa** `emergentintegrations` (queda solo como respaldo
perezoso), reduciendo el acoplamiento.

Nuevas variables: `AUTH_NATIVE_ENABLED`, `SESSION_DAYS`, `COOKIE_SECURE`,
`DEFAULT_LLM_PROVIDER`, `DEFAULT_LLM_KEY`, `DEFAULT_LLM_MODEL`.

**Verificado (TestClient + Mongo en memoria):**
- Registro → cookie de sesión → `/api/auth/me` devuelve el usuario (vía
  `get_current_user`, sin tocarlo). Login correcto `200`, incorrecto `401`,
  duplicado `409`. La app monta **104 rutas** (102 + register/login).
- Dispatch del LLM: proveedor directo (litellm) ✓, respaldo Emergent ✓, mensaje
  claro si no hay nada ✓.

> El backend ya está listo y **la pantalla de login nativa se añadió en la Fase 5**
> (ver abajo). Pruébalo en tu entorno antes de desplegar.

---

## 🖥️ Fase 5 (frontend) — pantalla de login/registro nativo

`pages/Login.jsx` ahora incluye un formulario de **email + contraseña** con pestañas
**Entrar / Crear cuenta**, que llama a `POST /api/auth/login` y `/api/auth/register`
(con `withCredentials`, así que la cookie de sesión se guarda). Tras el éxito llama a
`checkAuth()` y redirige a `/dashboard`. Se mantiene el botón **Continuar con Google**
(Emergent) como alternativa, y el estilo/tema originales.

**Verificado:** `Login.jsx` pasa la validación JSX de `esbuild`; `checkAuth` está
expuesto en el contexto de auth. Falta solo la prueba visual (`yarn build` / `make up`).

---

## 🗺️ Trabajo futuro recomendado (no incluido)
Requiere refactor o un entorno de pruebas; ordenado por valor:

1. ~~**Dividir `server.py`** en routers por dominio~~ ✅ **hecho (Fase 1).** Queda
   pendiente añadir una capa de servicios/repositorios para Mongo con índices definidos,
   y trocear `app/routers/intel.py` (573 líneas) si sigue creciendo.
2. ~~**Trocear las páginas React gigantes**~~ ✅ **hecho (Fase 3)** — extraídas las
   piezas reutilizables; los componentes principales aún pueden seguir dividiéndose.
3. ~~**Rate limiting global**~~ ✅ **hecho (Fase 2)** — middleware propio por IP.
4. **Sustituir los ~132 `except Exception`** amplios por manejo específico + logging.
5. ~~**Desacoplar de Emergent**~~ ✅ **hecho (Fase 4)** — auth nativa + litellm directo (backend). Falta la UI de login nativa en el frontend y migrar copilot/user_settings al nuevo `app/llm.py`.
6. **Tests de frontend** (Vitest + Testing Library) y renombrar los tests de
   backend por dominio (no por "iteración").
7. **i18n**: extraer el texto es-ES hardcodeado a claves de traducción.
8. **Endurecer CI**: quitar los `|| true` del workflow cuando el código pase limpio.
9. **Observabilidad**: logging estructurado (JSON) + Sentry opcional.

---

## 🏆 Diferenciadores (para ser #1)

### ✅ #2 · Evidencia notarizada (cadena de custodia persistente)

Convierte el sello de evidencia (que era efímero) en un **registro notarial
permanente y re-verificable**. Módulos nuevos `app/notary.py` +
`app/routers/notary.py` (aditivos; los endpoints antiguos siguen igual):

- `POST /api/scans/{id}/notarize` — sella los hallazgos críticos (SHA-256 +
  chain hash), pide un **timestamp real RFC3161** a FreeTSA y guarda un registro
  **inmutable** (append-only) en `db.evidence_notarizations`.
- `GET /api/scans/{id}/notarizations` — historial inmutable de notarizaciones.
- `GET /api/notary/{nid}` — el registro completo.
- `GET /api/notary/{nid}/verify` — re-deriva todos los hashes y devuelve
  **INTACT** o **TAMPERED**, señalando qué hallazgo cambió.
- `GET /api/notary/{nid}/bundle` — paquete de evidencia autónomo (JSON) con el
  TSR y las instrucciones `openssl` para verificarlo de forma independiente.

**Por qué diferencia:** nadie en el segmento indie ofrece "OSINT notariado":
prueba con sello de tiempo de *primer descubridor* para disputas de disclosure y
evidencia admisible para auditoría/compliance.

**Verificado (TestClient + Mongo en memoria + FreeTSA stubbeado):** notarizar →
`INTACT` + timestamped; historial; bundle con instrucciones OpenSSL; y tras
manipular un hallazgo guardado la verificación devuelve `TAMPERED` señalando
`finding[0]`. La app monta **109 rutas**.

> Pendiente (frontend): botón "Notarizar" + insignia INTACT/TAMPERED en la pestaña
> de evidencia de `ScanDetail`. El backend ya está listo.

### ✅ #1 · Verificación segura de explotabilidad

Cierra el "validation gap": cada hallazgo crítico pasa de "expuesto" a un veredicto
**Verificado / Probable / Teórico** con prueba **no destructiva (solo lectura)**.
Módulos nuevos `app/verifier.py` + `app/routers/exploit.py`:

- `POST /api/scans/{id}/verify-exploitability` — comprueba en vivo y etiqueta.
- `GET  /api/scans/{id}/exploitability` — resultado cacheado.

Comprobaciones seguras por tipo: **takeover** (firma de reclamo viva), **bucket
abierto** (listado legible), **fuga de config** (`.git`/`.env` realmente servidos).
Los **secretos** se quedan en *probable* a propósito — usarlos sería acceso no
autorizado. Todas las peticiones pasan por el guard anti-SSRF y degradan con
elegancia si el destino no responde.

**Verificado (fetcher stubbeado):** takeover con firma viva → `verified`;
inalcanzable → `probable`; bucket S3 listable → `verified`; `.git/config` servido →
`verified`; secreto AWS → `probable`. Resumen `{verified:3, probable:2, theoretical:0}`.
La app monta **111 rutas**.

> Pendiente (frontend): panel con el semáforo Verificado/Probable/Teórico en `ScanDetail`.

### ✅ #3 · Modo Bug Bounty "First-to-Find"

El nicho que las suites enterprise ignoran. Módulos nuevos `app/bounty_scope.py`,
`app/bounty_report.py` + router `app/routers/bounty_pro.py`:

- `POST /api/bounty/scope` · `GET /api/bounty/scopes` — guarda el scope de un
  programa (pega texto con `*.wildcards`, `!fuera-de-scope`); se parsea y guarda.
- `POST /api/scans/{id}/scope-check` — clasifica **cada activo** del escaneo como
  `in_scope` / `out_of_scope` / `unknown` (out-of-scope siempre gana; el wildcard
  cubre subdominios, no el apex — semántica correcta).
- `POST /api/scans/{id}/bounty-report` — genera un **reporte Markdown listo para
  HackerOne/Bugcrowd** (título, severidad, pasos, impacto, evidencia, remediación)
  que **incorpora el veredicto de explotabilidad (#1)** y el **hash notarizado con
  sello de tiempo (#2)**. Ningún competidor te entrega esto.

**Por qué diferencia:** scope-awareness + reporte enviable + prueba notarizada, en
una herramienta asequible pensada para el cazador de bugs. Censys/Xpanse/Tenable
ni miran a este usuario.

**Verificado:** matching de scope (wildcards, out-of-scope, apex) 7/7 casos OK;
`scope-check` clasifica activos; el reporte generado incluye `VERIFIED` y el hash
notarizado. La app monta **115 rutas**.

> Pendiente (frontend): pestaña para pegar el scope y botón "Generar reporte".

### ✅ #6 · Score de explotabilidad real (no CVSS)

Nuevo `app/exploit_score.py` + endpoint `GET /api/scans/{id}/exploit-score`.
Puntúa cada hallazgo 0–100 con: severidad (o CVSS) × **veredicto de #1**
(verificado 1.0 / probable 0.65 / teórico 0.35) × alcanzabilidad + bonus de
exploit − **penalización por honeypot** (×0.25). Devuelve bandas y un indicador de
**reducción de ruido** frente al "todo crítico por CVSS".

**Por qué diferencia:** casi todos muestran CVSS crudo; NOCTUA prioriza lo
accionable. "CVE 9.8 pero no alcanzable → riesgo real bajo."

**Verificado:** mismo takeover crítico → `98` (verificado), `58` (probable),
`31` (teórico), `24` (con honeypot); CVE 9.8 teórico no alcanzable → `21` (low).
La app monta **116 rutas**.

### ✅ #5 · IA "caja de cristal" (explicable + anti-alucinación)

Nuevo `app/glassbox.py` + endpoint `GET /api/scans/{id}/explain`. Pide a la IA
conclusiones **estructuradas** (claim + evidencia + confianza) y luego **contrasta
cada cita contra los datos reales del escaneo**: si la IA cita algo que no existe,
se marca `grounded:false` (posible alucinación) aunque el modelo diga alta
confianza. Devuelve un `trust_score` global.

**Por qué diferencia:** la IA de la competencia es caja negra. Aquí cada veredicto
enseña su evidencia y se autovalida — responde al problema nº1 de la IA-OSINT y a
la exigencia de explicabilidad (EU AI Act).

**Verificado:** con 2 conclusiones reales + 1 inventada (puerto 9999 inexistente),
funda­menta las 2 y **caza la alucinación pese a confianza 0.95 del modelo**;
`trust_score=67 (2/3)`. La app monta **117 rutas**.

### ✅ #4 · Copiloto agéntico "Autopilot"

Nuevo `app/autopilot.py` + endpoint `POST /api/scans/{id}/autopilot`. Un agente
inspecciona el estado del escaneo, **decide qué módulos ejecutar y los encadena**
(un hallazgo dispara el siguiente), narrando cada decisión, y para cuando una
pasada completa no aporta nada nuevo (loop-until-dry). El planificador es puro y
determinista; el ejecutor se inyecta (el router llama a los módulos reales, los
tests usan uno falso).

**Encadenamiento (reactivo, no lista fija):** secreto en JS → `api_audit`;
takeover encontrado → `verify_exploitability` (#1); críticos confirmados →
`notarize` (#2). Ata los diferenciadores entre sí.

**Por qué diferencia:** "agentic OSINT" es la tendencia 2026, pero casi nadie
encadena hallazgos de verdad — la mayoría son 50 botones que pulsas a mano.

**Verificado:** con subdominios + pista cloud, el agente ejecuta en orden
`js_miner → takeover → cloud_scanner → api_audit → verify_exploitability →
notarize` (6 pasos); los pasos reactivos solo aparecen tras producirse el hallazgo
que los dispara. La app monta **118 rutas**.

---

## 🏁 Estado de los 6 diferenciadores

| # | Diferenciador | Estado |
|---|---------------|--------|
| 1 | Verificación segura de explotabilidad | ✅ backend |
| 2 | Evidencia notarizada (cadena de custodia) | ✅ backend |
| 3 | Bug Bounty "First-to-Find" (scope + reporte) | ✅ backend |
| 4 | Copiloto agéntico "Autopilot" | ✅ backend |
| 5 | IA "caja de cristal" (explicable) | ✅ backend |
| 6 | Score de explotabilidad real | ✅ backend |

Los 6 están implementados y verificados en ejecución (TestClient + Mongo en
memoria + dependencias stubbeadas). **Pendiente común:** la UI en el frontend para
cada uno (botones/paneles) y la prueba contra objetivos reales con `make up`.

---

## 🖥️ Frontend de los diferenciadores — pestaña "Ventaja Competitiva"

Nuevo `frontend/src/components/edge/EdgeTab.jsx`, añadido como pestaña en
`ScanDetail`. Reúne los 6 diferenciadores en paneles conectados a los endpoints:

- **#1** semáforo Verificado/Probable/Teórico (botón "Verificar").
- **#6** score real con bandas + indicador de reducción de ruido.
- **#2** botón "Notarizar" + "Verificar integridad" (insignia INTACT/TAMPERED) +
  descarga del bundle JSON.
- **#3** textarea de scope → clasificación in/out/unknown + generación de reporte
  Markdown (con botón "Copiar MD") a partir de los hallazgos verificados en #1.
- **#4** botón "Ejecutar Autopilot" con la narración paso a paso.
- **#5** conclusiones de la IA con insignia "fundada/sin fundar" y confianza.

Los paneles **comparten estado**: al verificar (#1) se habilitan los reportes (#3),
y al notarizar (#2) el reporte incrusta el hash sellado. Validado con `esbuild`.

> Falta la prueba visual real (`yarn build` / `make up`) y, si quieres, un botón de
> Autopilot también en el Dashboard.
