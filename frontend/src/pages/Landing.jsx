import { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import {
  Radar, Lock, Terminal, ShieldAlert, ArrowRight, Cpu, Search, Loader2,
  Activity, AlertTriangle, CheckCircle2, Users, Zap, Server, Cloud, Send, FileText,
} from "lucide-react";
import { API, useAuth } from "@/lib/auth";

function AnimatedCounter({ value, label, testId }) {
  const [display, setDisplay] = useState(0);
  const raf = useRef(null);
  useEffect(() => {
    const target = Number(value) || 0;
    const start = display;
    const duration = 1400;
    const t0 = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - t0) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(start + (target - start) * eased));
      if (p < 1) raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => raf.current && cancelAnimationFrame(raf.current);
  }, [value]);
  return (
    <div data-testid={testId} className="border border-white/[0.08] bg-[#0A0A0C] p-6 hover:border-cyan-400/40 transition-colors">
      <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/40 mb-3">{label}</div>
      <div className="font-heading text-4xl sm:text-5xl font-black text-cyan-400 tracking-tight tabular-nums">
        {display.toLocaleString("es-ES")}
      </div>
    </div>
  );
}

function SeverityDot({ level }) {
  const cls = {
    critical: "bg-red-500",
    high: "bg-orange-400",
    medium: "bg-cyan-400",
    low: "bg-white/40",
  }[level] || "bg-white/40";
  return <span className={`inline-block w-2 h-2 rounded-full ${cls}`} />;
}

export default function Landing() {
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get(`${API}/public/stats`).then(r => setStats(r.data)).catch(() => setStats(null));
  }, []);

  const runPublicScan = async (e) => {
    e?.preventDefault?.();
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!d || !d.includes(".")) {
      setError("Introduce un dominio válido (ej: acme.com)");
      return;
    }
    setError(null);
    setResult(null);
    setScanning(true);
    try {
      const r = await axios.get(`${API}/public/takeover-check`, { params: { domain: d } });
      setResult(r.data);
      // Bump the counter locally for instant feedback
      setStats(s => s ? { ...s, scans_this_month: (s.scans_this_month || 0) + 1, public_scans_this_month: (s.public_scans_this_month || 0) + 1 } : s);
    } catch (e) {
      const detail = e?.response?.data?.detail;
      if (e?.response?.status === 429) {
        const wait = detail?.retry_after_seconds || 3600;
        setError(`Límite gratuito alcanzado. Reintenta en ${Math.ceil(wait / 60)} min o crea una cuenta Pro.`);
      } else {
        setError(typeof detail === "string" ? detail : "Error ejecutando el escaneo");
      }
    } finally { setScanning(false); }
  };

  const vulns = (result?.results || []).filter(r => r.vulnerable);
  const suspects = (result?.results || []).filter(r => !r.vulnerable && (r.cname_chain?.length > 0));

  return (
    <div data-testid="landing-page" className="relative min-h-screen bg-[#050505] text-white overflow-hidden grain">
      {/* Grid backdrop + glow */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.06]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,0.4) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />
      <div className="absolute top-[10%] left-1/2 -translate-x-1/2 w-[700px] h-[700px] rounded-full bg-cyan-500/[0.08] blur-[130px] pointer-events-none" />

      <header className="relative z-10 flex items-center justify-between px-6 sm:px-10 py-6 border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 border border-cyan-400/40 flex items-center justify-center">
            <Radar className="w-4 h-4 text-cyan-400" />
          </div>
          <span className="font-heading font-black text-lg tracking-tight">NOCTUA<span className="text-cyan-400">.osint</span></span>
        </div>
        <div className="flex items-center gap-3">
          <Link
            to="/pricing"
            data-testid="landing-nav-pricing"
            className="hidden sm:inline font-mono-data text-xs uppercase tracking-[0.2em] text-white/60 hover:text-cyan-400"
          >
            Pricing
          </Link>
          <Link
            to={user ? "/dashboard" : "/login"}
            data-testid="landing-cta-header"
            className="font-mono-data text-xs uppercase tracking-[0.2em] px-5 py-2.5 border border-white/20 hover:border-cyan-400 hover:text-cyan-400 transition-colors"
          >
            {user ? "Ir al dashboard" : "Iniciar sesión"}
          </Link>
        </div>
      </header>

      <main className="relative z-10 max-w-6xl mx-auto px-6 sm:px-10 pt-20 pb-16">
        {/* HERO */}
        <div className="mb-6 inline-flex items-center gap-2 border border-white/10 px-3 py-1.5">
          <span className="w-1.5 h-1.5 bg-green-400 animate-pulse" />
          <span className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/60">
            Motor OSINT operacional
          </span>
        </div>

        <h1 className="font-heading text-5xl sm:text-6xl lg:text-7xl font-black tracking-tighter leading-[0.95] mb-6">
          ¿Tu dominio es<br/>
          <span className="text-cyan-400">un takeover</span> esperando ocurrir?
        </h1>
        <p className="max-w-2xl text-lg text-white/60 mb-10 leading-relaxed">
          Escanea gratis subdominios abandonados apuntando a servicios vulnerables (S3, GitHub Pages, Heroku, Vercel...).
          Sin registro. Rate limit: 5 escaneos por hora.
        </p>

        {/* PUBLIC SCAN FORM */}
        <form onSubmit={runPublicScan} className="mb-6 border border-cyan-400/30 bg-black/60 p-2 flex items-stretch gap-2 max-w-3xl">
          <div className="flex items-center gap-3 pl-3 pr-2 text-white/40">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="acme.com"
            data-testid="public-scan-input"
            className="flex-1 bg-transparent font-mono-data text-base placeholder:text-white/25 focus:outline-none py-3"
            disabled={scanning}
            autoComplete="off"
          />
          <button
            type="submit"
            disabled={scanning || !domain.trim()}
            data-testid="public-scan-btn"
            className="bg-cyan-400 text-black font-semibold px-6 py-3 hover:bg-cyan-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-2 whitespace-nowrap"
          >
            {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            {scanning ? "Escaneando..." : "Escanear gratis"}
          </button>
        </form>
        {error && (
          <div data-testid="public-scan-error" className="mb-6 border border-red-400/40 bg-red-500/[0.05] p-4 text-sm text-red-300 font-mono-data max-w-3xl">
            {error}
          </div>
        )}

        {/* RESULTS */}
        {result && (
          <div data-testid="public-scan-result" className="mb-16 border border-white/[0.08] bg-[#0A0A0C] max-w-4xl">
            <div className="px-6 py-4 border-b border-white/[0.06] bg-[#101014] flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center gap-3">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span className="font-heading font-bold">{result.domain}</span>
                <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
                  {result.checked_subdomains} subdominios · {result.with_cname} con CNAME
                </span>
              </div>
              <span className="border border-white/[0.15] font-mono-data text-[10px] uppercase tracking-widest px-3 py-1 text-white/60">
                Tier: FREE PUBLIC
              </span>
            </div>

            <div className="p-6 space-y-5">
              {vulns.length > 0 ? (
                <div className="border border-red-400/40 bg-red-500/[0.06] p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                    <span className="font-heading font-bold text-red-300">
                      {vulns.length} takeover(s) detectado(s)
                    </span>
                  </div>
                  <ul className="space-y-2">
                    {vulns.slice(0, 10).map((v, i) => (
                      <li key={i} className="font-mono-data text-sm flex items-center gap-3">
                        <SeverityDot level="critical" />
                        <span className="text-white">{v.subdomain}</span>
                        <span className="text-white/40">→</span>
                        <span className="text-red-300">{v.service || "unknown"}</span>
                        {v.evidence && (
                          <span className="text-white/40 text-xs truncate max-w-[280px]" title={v.evidence}>
                            · {v.evidence}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="border border-green-400/30 bg-green-500/[0.04] p-5 flex items-center gap-3">
                  <CheckCircle2 className="w-5 h-5 text-green-400" />
                  <div>
                    <div className="font-heading font-bold text-green-300">Sin takeovers detectados</div>
                    <div className="text-sm text-white/50 mt-0.5">
                      Este escaneo revisa {result.checked_subdomains} subdominios superficiales. NOCTUA Pro va mucho más profundo.
                    </div>
                  </div>
                </div>
              )}

              {suspects.length > 0 && (
                <details className="border border-white/[0.06] bg-black">
                  <summary className="px-4 py-3 cursor-pointer font-mono-data text-xs uppercase tracking-widest text-white/60 hover:text-cyan-400">
                    {suspects.length} subdominio(s) con CNAME activos (revisar)
                  </summary>
                  <ul className="px-4 pb-3 space-y-1 font-mono-data text-xs text-white/50">
                    {suspects.slice(0, 15).map((s, i) => (
                      <li key={i}>{s.subdomain} → <span className="text-white/40">{(s.cname_chain || []).join(" → ")}</span></li>
                    ))}
                  </ul>
                </details>
              )}

              {/* UPSELL */}
              <div className="border-t border-white/[0.06] pt-5 mt-5">
                <div className="font-heading text-sm font-bold uppercase tracking-wide text-cyan-400 mb-3">
                  Este es solo el 15% de NOCTUA
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-5">
                  {(result.upsell?.features_locked || []).map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm text-white/70">
                      <Lock className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                      <span>{f}</span>
                    </div>
                  ))}
                </div>
                <Link
                  to="/pricing"
                  data-testid="upsell-cta"
                  className="inline-flex items-center gap-2 bg-cyan-400 text-black font-semibold px-6 py-3 hover:bg-cyan-300 transition-colors"
                >
                  Desbloquear NOCTUA Pro <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          </div>
        )}

        {/* LIVE STATS */}
        <section className="mb-24">
          <div className="flex items-center gap-3 mb-6">
            <Activity className="w-4 h-4 text-green-400 animate-pulse" />
            <span className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/60">
              Ranking global · en vivo
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <AnimatedCounter
              value={stats?.scans_this_month}
              label="Escaneos este mes"
              testId="stat-scans-month"
            />
            <AnimatedCounter
              value={stats?.takeovers_detected}
              label="Takeovers detectados"
              testId="stat-takeovers"
            />
            <AnimatedCounter
              value={stats?.total_scans}
              label="Escaneos históricos"
              testId="stat-total"
            />
            <AnimatedCounter
              value={stats?.active_users}
              label="Analistas activos"
              testId="stat-users"
            />
          </div>
        </section>

        {/* CAPACIDADES PRO */}
        <section id="features">
          <div className="mb-8">
            <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/40 mb-2">
              Capacidades NOCTUA Pro
            </div>
            <h2 className="font-heading text-3xl sm:text-4xl font-black tracking-tight">
              Reconocimiento total.<br/>
              <span className="text-cyan-400">Un solo dominio.</span>
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-0 border-t border-l border-white/10">
            {[
              { icon: Terminal, title: "WHOIS + DNS", desc: "Titularidad, registrador, servidores autoritativos y cadena DNS." },
              { icon: Lock, title: "SSL / TLS", desc: "Emisor, validez, SAN, versión de TLS y suites de cifrado." },
              { icon: Server, title: "Puertos + IP", desc: "Escaneo asincrónico. Servicios expuestos y superficie de ataque." },
              { icon: ShieldAlert, title: "IA + Riesgos", desc: "Resumen ejecutivo con Claude 4.5 / GPT-4o / Gemini." },
              { icon: Cloud, title: "Cloud Radar", desc: "Enumera buckets S3, Azure Blobs y GCS abiertos o filtrados." },
              { icon: FileText, title: "Metadatos docs", desc: "Extrae autores, IPs internas y software de PDFs/DOCX públicos." },
              { icon: Cpu, title: "Intelligence Map", desc: "Mapa interactivo React Flow: dominios, IPs, tecnologías y cadenas CNAME." },
              { icon: Send, title: "Alertas Telegram", desc: "Notificación instantánea de cambios: puertos, CNAME, SSL, headers." },
            ].map((f, i) => (
              <div key={i} className="border-r border-b border-white/10 p-6 hover:bg-white/[0.02] hover:border-cyan-400/30 transition-colors">
                <f.icon className="w-5 h-5 text-cyan-400 mb-4" />
                <h3 className="font-heading text-lg font-semibold mb-2">{f.title}</h3>
                <p className="text-sm text-white/50 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>

          <div className="mt-10 flex flex-wrap gap-4">
            <Link
              to={user ? "/dashboard" : "/login"}
              data-testid="landing-cta-primary"
              className="group inline-flex items-center gap-3 bg-cyan-400 text-black font-semibold px-8 py-4 hover:bg-cyan-300 transition-colors"
            >
              {user ? "Ir al dashboard" : "Empezar gratis"}
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link
              to="/pricing"
              className="inline-flex items-center gap-3 border border-white/20 text-white px-8 py-4 hover:border-cyan-400 hover:text-cyan-400 transition-colors font-mono-data text-sm uppercase tracking-widest"
            >
              Ver plan Pro
            </Link>
          </div>
        </section>
      </main>

      <footer className="relative z-10 border-t border-white/5 px-6 sm:px-10 py-6 text-xs text-white/40 font-mono-data tracking-wider flex items-center justify-between flex-wrap gap-3">
        <span>NOCTUA.OSINT — Uso educativo/defensivo. Escanea solo dominios de tu propiedad o autorizados.</span>
        <span className="flex items-center gap-2">
          <Users className="w-3 h-3" /> {stats?.active_users?.toLocaleString?.("es-ES") || 0} analistas
        </span>
      </footer>
    </div>
  );
}
