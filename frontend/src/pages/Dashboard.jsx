import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { Radar, Search, LogOut, History, ShieldCheck, ShieldAlert, ShieldX, Trash2, Loader2, ChevronRight, Sparkles, CalendarClock, Bell, Settings as SettingsIcon, Zap, Skull, Bot, ShoppingBag } from "lucide-react";
import { Link } from "react-router-dom";
import { API, useAuth } from "@/lib/auth";

function ScoreBadge({ label, score }) {
  const color =
    score >= 80 ? "text-green-400 border-green-400/30 bg-green-400/5"
    : score >= 50 ? "text-yellow-400 border-yellow-400/30 bg-yellow-400/5"
    : "text-red-400 border-red-400/30 bg-red-400/5";
  return (
    <div className={`border px-2 py-1 ${color} font-mono-data text-[10px] uppercase tracking-widest`}>
      {label} {score}%
    </div>
  );
}

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [domain, setDomain] = useState("");
  const [extended, setExtended] = useState(false);
  const [aiSummary, setAiSummary] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scans, setScans] = useState([]);
  const [loadingScans, setLoadingScans] = useState(true);

  const loadScans = async () => {
    try {
      const r = await axios.get(`${API}/scans`, { withCredentials: true });
      setScans(r.data);
    } catch (e) {
      toast.error("No se pudo cargar el historial");
    } finally {
      setLoadingScans(false);
    }
  };

  useEffect(() => { loadScans(); }, []);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!domain.trim() || scanning) return;
    setScanning(true);
    try {
      const r = await axios.post(
        `${API}/scan`,
        { domain: domain.trim(), extended_ports: extended, ai_summary: aiSummary },
        { withCredentials: true, timeout: 180000 }
      );
      toast.success(`Escaneo completado para ${r.data.result.domain}`);
      navigate(`/scan/${r.data.scan_id}`);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Error en el escaneo");
    } finally {
      setScanning(false);
    }
  };

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    try {
      await axios.delete(`${API}/scans/${id}`, { withCredentials: true });
      setScans((s) => s.filter((x) => x.scan_id !== id));
      toast.success("Escaneo eliminado");
    } catch {
      toast.error("No se pudo eliminar");
    }
  };

  return (
    <div data-testid="dashboard-page" className="relative min-h-screen bg-[#050505] text-white grain">
      {/* HEADER */}
      <header className="sticky top-0 z-30 backdrop-blur-xl bg-black/60 border-b border-white/10">
        <div className="max-w-7xl mx-auto px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 border border-cyan-400/40 flex items-center justify-center">
              <Radar className="w-4 h-4 text-cyan-400" />
            </div>
            <span className="font-heading font-black text-lg tracking-tight">NOCTUA<span className="text-cyan-400">.osint</span></span>
            {user?.plan === "pro" ? (
              <span data-testid="pro-badge" className="ml-2 inline-flex items-center gap-1 border border-cyan-400/40 bg-cyan-400/10 text-cyan-400 px-2 py-0.5 font-mono-data text-[10px] uppercase tracking-widest">
                <Zap className="w-3 h-3" /> Pro
              </span>
            ) : (
              <Link to="/pricing" data-testid="upgrade-badge" className="ml-2 border border-white/15 hover:border-cyan-400 hover:text-cyan-400 px-2 py-0.5 font-mono-data text-[10px] uppercase tracking-widest transition-colors">
                Free · Upgrade
              </Link>
            )}
          </div>
          <div className="flex items-center gap-2 md:gap-3">
            <Link to="/schedules" data-testid="nav-schedules" className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
              <CalendarClock className="w-3.5 h-3.5" />
              <span className="hidden md:inline font-mono-data text-[10px] uppercase tracking-widest">Programados</span>
            </Link>
            <Link to="/copilot" data-testid="nav-copilot" className="inline-flex items-center gap-2 border border-cyan-400/40 bg-cyan-400/[0.05] px-3 py-2 hover:bg-cyan-400/10 hover:border-cyan-400 transition-colors">
              <Bot className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden md:inline font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">Copilot</span>
            </Link>
            <Link to="/marketplace" data-testid="nav-marketplace" className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
              <ShoppingBag className="w-3.5 h-3.5" />
              <span className="hidden md:inline font-mono-data text-[10px] uppercase tracking-widest">Marketplace</span>
            </Link>
            <Link to="/breaches" data-testid="nav-breaches" className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-red-400 hover:text-red-400 transition-colors">
              <Skull className="w-3.5 h-3.5" />
              <span className="hidden md:inline font-mono-data text-[10px] uppercase tracking-widest">Brechas</span>
            </Link>
            <Link to="/alerts" data-testid="nav-alerts" className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
              <Bell className="w-3.5 h-3.5" />
              <span className="hidden md:inline font-mono-data text-[10px] uppercase tracking-widest">Alertas</span>
            </Link>
            <Link to="/settings" data-testid="nav-settings" className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
              <SettingsIcon className="w-3.5 h-3.5" />
              <span className="hidden md:inline font-mono-data text-[10px] uppercase tracking-widest">Ajustes</span>
            </Link>
            {user?.picture ? (
              <img src={user.picture} alt="" className="w-8 h-8 border border-white/20" />
            ) : (
              <div className="w-8 h-8 bg-white/10 border border-white/20 flex items-center justify-center font-mono-data text-xs">
                {user?.name?.[0]?.toUpperCase() || "U"}
              </div>
            )}
            <div className="hidden xl:block">
              <div data-testid="user-name" className="text-sm font-medium">{user?.name}</div>
              <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">{user?.email}</div>
            </div>
            <button
              onClick={logout}
              data-testid="logout-button"
              className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-red-400 hover:text-red-400 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="font-mono-data text-[10px] uppercase tracking-widest">Salir</span>
            </button>
          </div>
        </div>
      </header>

      <main className="relative max-w-7xl mx-auto px-8 py-12">
        <div className="mb-4 inline-flex items-center gap-2 border border-white/10 px-3 py-1.5">
          <span className="w-1.5 h-1.5 bg-cyan-400 animate-pulse" />
          <span className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/60">Motor listo</span>
        </div>
        <h1 className="font-heading text-4xl sm:text-5xl font-black tracking-tighter mb-3">
          Iniciar reconocimiento
        </h1>
        <p className="text-white/50 mb-8 max-w-2xl">
          Introduce un dominio para desplegar el análisis OSINT completo. Los resultados se archivan en tu historial.
        </p>

        {/* SEARCH BAR */}
        <form onSubmit={handleScan} className="mb-6">
          <div className="neon-focus flex items-center border border-white/15 bg-[#0C0C0E]">
            <div className="pl-5 pr-3 flex items-center gap-3 border-r border-white/10 py-5">
              <Search className="w-5 h-5 text-cyan-400" />
              <span className="font-mono-data text-xs text-white/40 hidden sm:inline">target://</span>
            </div>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              disabled={scanning}
              placeholder="ejemplo.com"
              data-testid="domain-search-input"
              autoFocus
              className="flex-1 bg-transparent px-4 py-5 font-mono-data text-base placeholder:text-white/25 focus:outline-none"
            />
            <button
              type="submit"
              disabled={scanning || !domain.trim()}
              data-testid="scan-submit-button"
              className="bg-cyan-400 text-black font-semibold px-8 py-5 hover:bg-cyan-300 disabled:bg-white/10 disabled:text-white/40 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-2"
            >
              {scanning ? (<><Loader2 className="w-4 h-4 animate-spin" /> Escaneando</>) : "Escanear"}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-6 mt-4 text-sm">
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={extended}
                onChange={(e) => setExtended(e.target.checked)}
                data-testid="extended-ports-toggle"
                className="accent-cyan-400"
              />
              <span className="font-mono-data text-xs uppercase tracking-widest text-white/60">Escaneo extendido de puertos</span>
            </label>
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={aiSummary}
                onChange={(e) => setAiSummary(e.target.checked)}
                data-testid="ai-summary-toggle"
                className="accent-cyan-400"
              />
              <span className="font-mono-data text-xs uppercase tracking-widest text-white/60 inline-flex items-center gap-1">
                <Sparkles className="w-3 h-3" /> Resumen con IA
              </span>
            </label>
          </div>
        </form>

        {scanning && (
          <div data-testid="scanning-indicator" className="relative h-1 bg-white/5 mb-10 overflow-hidden">
            <div className="scan-bar absolute top-0 left-0 h-full w-1/3 bg-gradient-to-r from-transparent via-cyan-400 to-transparent" />
          </div>
        )}

        {/* HISTORY */}
        <section className="mt-14">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <History className="w-4 h-4 text-cyan-400" />
              <h2 className="font-heading text-xl font-bold tracking-tight">Historial de escaneos</h2>
            </div>
            <span data-testid="scans-count" className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/40">
              {scans.length} registros
            </span>
          </div>

          {loadingScans ? (
            <div className="border border-white/10 p-16 text-center text-white/40 font-mono-data text-xs uppercase tracking-widest">Cargando historial...</div>
          ) : scans.length === 0 ? (
            <div data-testid="empty-history" className="border border-dashed border-white/10 p-16 text-center">
              <p className="font-mono-data text-xs uppercase tracking-[0.3em] text-white/30">Aún no hay escaneos</p>
              <p className="text-sm text-white/50 mt-2">Inicia tu primer análisis arriba.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-0 border-t border-l border-white/10">
              {scans.map((s) => (
                <button
                  key={s.scan_id}
                  onClick={() => navigate(`/scan/${s.scan_id}`)}
                  data-testid={`scan-card-${s.scan_id}`}
                  className="group text-left border-r border-b border-white/10 p-5 hover:bg-white/[0.03] transition-colors relative"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <div className="font-mono-data text-cyan-400 text-sm break-all">{s.domain}</div>
                      <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/30 mt-1">
                        {new Date(s.created_at).toLocaleString()}
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-white/30 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
                  </div>
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    <ScoreBadge label="B" score={s.overview?.score_basic ?? 0} />
                    <ScoreBadge label="M" score={s.overview?.score_medium ?? 0} />
                    <ScoreBadge label="A" score={s.overview?.score_advanced ?? 0} />
                  </div>
                  <div className="flex items-center justify-between text-xs text-white/50">
                    <span className="font-mono-data">{s.overview?.ip || "—"}</span>
                    <span className="font-mono-data">{s.overview?.open_ports ?? 0} puertos</span>
                  </div>
                  {(s.tags || []).length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-3">
                      {s.tags.slice(0, 4).map(t => (
                        <span key={t} data-testid={`tag-${t}`}
                          className="font-mono-data text-[9px] uppercase tracking-widest border border-cyan-400/30 text-cyan-400 px-1.5 py-0.5">
                          {t}
                        </span>
                      ))}
                      {s.tags.length > 4 && (
                        <span className="font-mono-data text-[9px] text-white/40">+{s.tags.length - 4}</span>
                      )}
                    </div>
                  )}
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={(e) => handleDelete(s.scan_id, e)}
                    data-testid={`delete-scan-${s.scan_id}`}
                    className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 p-1.5 hover:text-red-400 text-white/40"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
