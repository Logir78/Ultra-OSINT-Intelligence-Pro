# NOCTUA.osint — OSINT Domain Scanner (PRD)

## Original Problem Statement
Herramienta OSINT web que analice cualquier dominio y muestre WHOIS, DNS, SSL, subdominios, cabeceras HTTP/HTTPS, IP, seguridad básica/media/avanzada, puertos abiertos, y resumen final con riesgos. Interfaz moderna de ciberseguridad (deep dark + cyan/neon-green) con dashboard visual y suite completa Pro (Stripe), alertas Slack/Telegram, mapa React Flow, exportación PDF, y capacidades avanzadas de Bug Bounty e Inteligencia Predictiva IA.

## Language
Spanish (es-ES).

## Architecture
- **Backend**: FastAPI + Motor (Mongo) + Stripe + Emergent LLM Key (Claude/GPT/Gemini via `emergentintegrations`).
  - `server.py` — FastAPI wiring, ~40 endpoints
  - `osint_engine.py`, `intel.py`, `pdf_export.py`, `user_settings.py`, `schedules.py`, `payments.py`
  - `integrations/` — 20 módulos: shodan, cloud_scanner, metadata, takeover_scanner (80 fingerprints), pastes, threat_intel, js_miner (con .map), ct_logs, shodan_deep, dna_fingerprint, risk_oracle, brand_guardian, phishing_sim, attack_path (7 APT personas), poc_generator, param_miner, cloud_config, api_auditor, scan_delta, auto_tags, global_correlation, version_tracker, idor_analyzer, supply_chain
- **Frontend**: React 19 + Tailwind + Shadcn + React Flow + Leaflet + Sonner.
  - 7 tabs en `ScanDetail`: Resumen · Infraestructura · Seguridad Técnica · Factor Humano · Mapa · Inteligencia Predictiva · Bug Bounty Toolkit
  - Landing pública con contador global animado + escáner takeover gratuito

## Complete Feature List

### Escaneo base
- WHOIS, DNS, SSL/TLS, subdominios, headers, IP+geoloc, port scan (sync+extendido), tech fingerprinting
- Emergent Google OAuth, historial MongoDB, PDF export, JSON export
- Stripe Pro ($9/mo), Landing viral con `/api/public/{stats,takeover-check}` + rate-limit

### Alertas & scheduling
- Schedules CRUD, scheduler loop 60s, diff engine, alertas por tipo
- Slack webhook + **Telegram bot (bot_token+chat_id + test endpoint)**
- New-asset alerts con severidad `high` y emoji 🎯

### Módulos avanzados
- Shodan (100 créditos) + AbuseIPDB + HIBP + BreachDirectory
- Wayback Machine timeline
- Cloud Storage Radar (S3/Azure/GCS)
- Document Metadata Extractor (PDF/DOCX)
- React Flow Intelligence Map
- Subdomain Takeover con 80 fingerprints
- Pastebin monitor + URLScan + IntelX
- Settings avanzados: 6 API keys, AI provider selector (OpenAI/Anthropic/Gemini/Emergent), YAML config export, preferences (risk_threshold + notes)

### Inteligencia Predictiva (IA)
- **Attack Path Mapper** con 7 APT personas (Cozy Bear, APT41, Lazarus, Conti, script kiddie, insider, none)
- **Oráculo de Riesgos** — probabilidad de brecha 90d con verdict no-técnico
- **ADN Digital** — fingerprint infra + búsqueda de activos hermanos (crt.sh org + shodan html_hash)
- **Guardián de Marca** — typosquat gen + DNS resolve + IA clone detection
- **Generador de PoC** — scripts seguros no destructivos por vulnerabilidad crítica
- **Simulador Phishing** (Pro-only) — plantilla email + página objetivo con disclaimer legal
- **PDF Ejecutivo** — página nueva con Attack Path diagram + Oracle verdict box en lenguaje no técnico

### Bug Bounty Toolkit (7 secciones)
- **Parameter Miner** — extrae params ocultos (?admin=, ?debug=) de JS/HTML + wordlist
- **Cloud & Dev Config Hunter** — probe de 40+ paths peligrosos (.env, .git/config, wp-config.php.bak, kubeconfig, id_rsa, dumps SQL…)
- **API Auditor** — descubre /api/vN + GraphQL introspection + endpoints sensibles
- **Version Tracker** — detector de rollbacks (versión bajó → posible vulnerable)
- **Grafo Global de Amenazas** — correlación cross-user por IP/certificado + flag system
- **IDOR Analyzer** — mapeo de patrones IDs (numeric+UUID) + fuzz variations + IA reasoning
- **Supply Chain Security** — cruza libs con OSV.dev (CVEs reales, ecosystems mapeados sin ruido)

### Sistema colaborativo
- **Time-Travel Diff** — compara 2 escaneos del mismo dominio (puertos, subs, tech, headers, IP, TLS)
- **Auto-Tagging IA** — 30+ tags ontology + heurística + IA
- **Bug Bounty Report Manager** — CRUD `/api/bounty/reports` con status submitted/duplicate/accepted/…
- **Flag system** — marcar scans como sospechosos alimenta el Grafo Global

## API endpoints (~40)
### Publics
- `GET /api/public/stats` (cache 5min), `GET /api/public/takeover-check` (rate-limit 5/h por IP)

### Auth
- `GET /api/auth/{session,me,logout}`, `GET /api/apt-personas`

### Settings
- `/api/settings/{keys,slack,telegram,telegram/test,preferences,ai}`

### Scans
- `POST /api/scan`, `GET /api/scans[/{id}]`, `GET /api/scans/history/{domain}`, `DELETE /api/scans/{id}`
- `GET /api/scans/{id}/{pdf,intel,shodan,cloud,metadata,takeover,pastes,threat-intel,reputation}`
- `GET /api/scans/{id}/{js-miner,ct-logs,shodan-deep,dna,risk-oracle,brand-guardian,poc,param-miner,cloud-config,api-audit,idor,supply-chain,version-track,correlate,diff}`
- `POST /api/scans/{id}/{phishing-sim,attack-path,predict,auto-tag,tags,flag}`

### Bug Bounty Reports
- `POST /api/bounty/reports`, `GET /api/bounty/reports`, `PATCH/DELETE /api/bounty/reports/{finding_key}`

### Stripe
- `POST /api/payments/checkout`, `GET /api/payments/status/{id}`, `POST /api/stripe/webhook`, `/api/payments/{plan,cancel}`

## Testing
| Iteration | Backend | Frontend | Highlights |
|-----------|---------|----------|-----------|
| 1 (Free MVP) | 12/12 | – | Core scan engine |
| 2 (Pro) | 23/23 | – | Stripe + schedules + Slack |
| 3 (Telegram + Landing) | 17/17 | 10/10 | Public stats + Telegram dispatch |
| 4 (Predictive x10) | 20/20 | 17/18 | Attack Path + 6 IA modules |
| 5 (Collaborative x9) | 26/26 | 100% | Delta + tags + bounty reports |
| 6 (Bounty x4) | 37/37 | 100% | IDOR + Supply Chain OSV.dev live |
| 7 (Bounty x4) | 100% (1 HIGH bug fixed) | 100% | Logic Flow + Reverse IP + GitHub Miner + Bot Resistance |
| 8 (Project Genesis) | 15/15 · 65/65 regression | UI ready | Stealth Module + JARM + Honeypot Detector + Evidence Seal (deterministic) + Sleeping Infra + Org Map + Dev Profile |
| 9 (RFC3161 timestamp) | 4/4 · **69/69 total regression** | UI ready | FreeTSA.org signed timestamps for chain_hash — legal-grade proof |
| 10 (Multi-tenant Isolation + Whitelist) | +N tests | UI ready | strict per-user scan isolation + `AUTHORIZED_EMAILS` private-access gate + security log + Telegram alert on blocked login |
| 11 (RFC3161 · sealing) | | | (dup) |
| **13 (Bot Conversacional)** | 15/15 · 233/233 total | UI ready | `/scan <domain>` · `/scans` · `/pricing` · `/help` con ack + ejecución en background + link a informe · Stripe Checkout desde Telegram |
| **14 (Claude AI Models · Feb 2026)** | 13/13 · **246/246 total** | UI ready | Nuevos modelos Claude integrados: Haiku 4.5 (fast) · **Sonnet 4.6** (balanced/default) · Opus 4.8 (deep). Endpoint `/api/settings/claude` + selector en Settings. Aplicados en intel, WAF bypass, key validation. |
| **15 (Ollama + Google Auth audit)** | 17/17 · **263/263 total** | UI ready | Ollama como 5º proveedor de IA (URL + modelo, validación /api/tags con listado interactivo). Auditoría del flujo de Emergent Google Auth: 100% conforme al playbook (window.location.origin, useRef, X-Session-ID, samesite=none). |
| **16 (Competitive Killers)** | 15/15 · **278/278 total** | UI ready | **CVE + EPSS + KEV Engine** · **Typosquatting Hunter** · **MITRE ATT&CK Mapping** · **SSL Cert Expiration Monitor** · **AI Copilot Chatbot** |
| **17 (Enterprise-grade)** | 11/11 · **289/289 total** | UI ready | **Compliance Scorecard** (SOC2/ISO27001/GDPR/PCI-DSS con overall grade A+/F) · **ASM Inventory + Drift** (cross-scan asset aggregate, detección automática de +/- subdominios/puertos/techs) · **CVE Feed real-time** (NVD + filtro por tech stack del usuario) · **Stripe Marketplace** (6 productos à-la-carte, checkout individual, webhook maneja unlocks) |

**Total 289 tests, 100% pass rate on iteration 17 (Feb 2026).**

## Modules Snapshot (~33 features)
- Base OSINT · Alerts (Slack + Telegram + **Email via Resend**) · Stripe Pro · Landing viral
- **Telegram Bot** — `/start` welcome banner (Project Genesis), `/status`, `/id`; admin-only responses; webhook secured by URL-secret path
- Cloud Radar · Metadata Extractor · Intelligence Map · Takeover (80 fingerprints) · Pastes · URLScan + IntelX
- **Predictive**: Attack Path (7 APT personas) · Oracle · DNA · Brand Guardian · PoC · Phishing Sim · PDF Executive
- **Bug Bounty Toolkit** (14 sections): Param Miner · Cloud Config · API Auditor · Version Track · Global Correlation · IDOR · Supply Chain · Logic Flow · Reverse IP · GitHub Miner · Bot Resistance · Diff · Sleeping Infra · **WAF Bypass Suggestor**
- **Project Genesis** (7 sections): Stealth Module · JARM · Honeypot · Evidence Seal · Org Map · Dev Profile · Sleeping Infra
- **Collaborative**: Time-Travel Diff · Auto-Tagging · Bug Bounty Report Manager · Flag system · Global Threat Graph

## Prioritized Backlog
### P1 (DONE ✓ — iteration 12, Feb 2026)
- ~~WAF Bypass Suggestor~~ ✅
- ~~Email notifications via Resend~~ ✅
- ~~Retrofit HTTP clients → StealthClient~~ ✅
- ~~Telegram Bot /start welcome + admin-only auto-response~~ ✅

### P1 (pending)
- Idempotency + unique index en alertas
- Redis rate limiter distribuido (hoy es in-memory)

### P2
- Feed RSS/Atom del Grafo Global de Amenazas
- Export STIX/OASIS para SIEMs enterprise (Splunk, Sentinel, QRadar)
- Team sharing / multi-tenant workspaces
- Real-time SSE scan progress
- Filtro por tags en Dashboard (UI, backend ya soportado)
- Custom fingerprint DB user-editable

### P3
- Mobile companion app
- Marketplace de plantillas de escaneo
