import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import {
  Radar, ArrowLeft, Skull, Search, AtSign, Globe, Loader2, ShieldAlert, Database,
} from "lucide-react";
import { API, useAuth } from "@/lib/auth";
import IntegrationEmpty from "@/components/IntegrationEmpty";

function _fmt(d) { try { return new Date(d).toLocaleDateString("es-ES", { year:"numeric", month:"short", day:"2-digit" }); } catch { return d; } }

export default function Breaches() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [query, setQuery] = useState("");
  const [type, setType] = useState("email");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  const loadHistory = async () => {
    try {
      const r = await axios.get(`${API}/breaches/history`, { withCredentials: true });
      setHistory(r.data);
    } catch (_) { /* ignore */ }
  };
  useEffect(() => { loadHistory(); }, []);

  const submit = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await axios.post(`${API}/breaches/lookup`,
        { query: query.trim(), type },
        { withCredentials: true, timeout: 30000 },
      );
      setResult(r.data);
      loadHistory();
      if (r.data.total > 0) toast.error(`${r.data.total} filtración(es) encontradas`);
      else toast.success("Sin filtraciones registradas");
    } catch (e2) {
      toast.error(e2?.response?.data?.detail || "Error en la búsqueda");
    } finally {
      setLoading(false);
    }
  };

  const anyConfigured = result && (result.sources?.hibp?.configured || result.sources?.breachdirectory?.configured);
  const total = result?.total || 0;

  return (
    <div data-testid="breaches-page" className="min-h-screen bg-[#050505] text-white grain">
      <header className="sticky top-0 z-30 backdrop-blur-xl bg-black/60 border-b border-white/10">
        <div className="max-w-6xl mx-auto px-8 py-4 flex items-center gap-4">
          <button onClick={() => navigate("/dashboard")} className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
            <ArrowLeft className="w-3.5 h-3.5" />
            <span className="font-mono-data text-[10px] uppercase tracking-widest">Volver</span>
          </button>
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-cyan-400" />
            <span className="font-heading font-black text-lg">NOCTUA<span className="text-cyan-400">.osint</span></span>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-8 py-12">
        <h1 className="font-heading text-3xl sm:text-4xl font-black tracking-tight mb-2 flex items-center gap-3">
          <Skull className="w-7 h-7 text-cyan-400" /> Centro de Búsqueda de Brechas
        </h1>
        <p className="text-white/50 mb-8 max-w-2xl">
          Cruza <span className="text-white/80">Have I Been Pwned</span> + <span className="text-white/80">BreachDirectory</span>.
          Resultados unificados, sin duplicados, ordenados por fecha (más reciente primero).
        </p>

        <form onSubmit={submit} className="border border-white/10 bg-[#0C0C0E] p-6 mb-8">
          <div className="flex gap-3 mb-4 flex-wrap">
            {["email", "domain"].map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setType(t)}
                data-testid={`type-${t}`}
                className={`inline-flex items-center gap-2 border px-4 py-2 font-mono-data text-[10px] uppercase tracking-widest transition-colors ${
                  type === t
                    ? "border-cyan-400 bg-cyan-400/10 text-cyan-400"
                    : "border-white/15 text-white/60 hover:border-white/30"
                }`}
              >
                {t === "email" ? <AtSign className="w-3.5 h-3.5" /> : <Globe className="w-3.5 h-3.5" />}
                {t === "email" ? "Email" : "Dominio"}
              </button>
            ))}
          </div>
          <div className="flex items-center border border-white/15 bg-[#050505]">
            <Search className="w-4 h-4 text-cyan-400 mx-4 flex-shrink-0" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={type === "email" ? "victim@example.com" : "example.com"}
              disabled={loading}
              data-testid="breach-query-input"
              className="flex-1 bg-transparent py-4 font-mono-data text-base placeholder:text-white/25 focus:outline-none"
            />
            <button
              type="submit"
              disabled={loading || !query.trim()}
              data-testid="breach-search-btn"
              className="bg-cyan-400 text-black font-semibold px-6 py-4 hover:bg-cyan-300 disabled:opacity-50 transition-colors inline-flex items-center gap-2"
            >
              {loading ? (<><Loader2 className="w-4 h-4 animate-spin" /> Buscando</>) : "Buscar"}
            </button>
          </div>
        </form>

        {loading && (
          <div className="flex items-center gap-3 text-white/40 py-4">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">Consultando fuentes…</span>
          </div>
        )}

        {result && !loading && (
          <>
            {!anyConfigured && (
              <div className="space-y-3 mb-8">
                <IntegrationEmpty
                  provider="Have I Been Pwned"
                  keyUrl={result.sources.hibp.key_url}
                  description="Base de datos autoritativa de brechas verificadas. Requiere suscripción de pago ($3.95/mes)."
                />
                <IntegrationEmpty
                  provider="BreachDirectory"
                  keyUrl={result.sources.breachdirectory.key_url}
                  freeTier="Tier gratuito RapidAPI"
                  description="Búsqueda cruzada en dumps de credenciales filtradas. Alternativa gratuita."
                />
              </div>
            )}

            {anyConfigured && (
              <div className="flex items-center gap-4 mb-6 flex-wrap">
                <div className="border border-white/10 px-4 py-3">
                  <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Query</div>
                  <div className="font-mono-data text-cyan-400 text-sm">{result.query}</div>
                </div>
                <div className={`border px-4 py-3 ${total > 0 ? "border-red-400/60 bg-red-400/5" : "border-green-400/60 bg-green-400/5"}`}>
                  <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Filtraciones</div>
                  <div className={`font-heading text-2xl font-black ${total > 0 ? "text-red-400" : "text-green-400"}`}>
                    {total}
                  </div>
                </div>
                <div className="border border-white/10 px-4 py-3 flex-1">
                  <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Fuentes activas</div>
                  <div className="font-mono-data text-xs text-white/70 mt-1">
                    {Object.entries(result.sources).filter(([_, v]) => v.configured).map(([k]) => k.toUpperCase()).join(" · ") || "Ninguna"}
                  </div>
                </div>
              </div>
            )}

            {total > 0 && (
              <div className="space-y-3" data-testid="breach-list">
                {result.breaches.map((b, i) => (
                  <article
                    key={i}
                    data-testid={`breach-${i}`}
                    className="border border-white/10 bg-[#0C0C0E] p-5 hover:border-red-400/40 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-4 flex-wrap mb-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <h3 className="font-heading text-lg font-bold">{b.title || b.name}</h3>
                          {b.is_verified && <span className="border border-red-400/60 bg-red-400/10 text-red-400 px-2 py-0.5 font-mono-data text-[9px] uppercase tracking-widest">verificada</span>}
                          {b.is_sensitive && <span className="border border-orange-400/60 bg-orange-400/10 text-orange-400 px-2 py-0.5 font-mono-data text-[9px] uppercase tracking-widest">sensible</span>}
                        </div>
                        <div className="font-mono-data text-xs text-white/50">
                          {b.domain && <>{b.domain} · </>}
                          {b.breach_date && <>Fecha brecha: <span className="text-white/80">{_fmt(b.breach_date)}</span></>}
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Fuente</span>
                        <div className={`font-mono-data text-xs mt-1 ${b.source === "HIBP" ? "text-cyan-400" : "text-orange-400"}`}>
                          {b.source}
                        </div>
                      </div>
                    </div>
                    {b.pwn_count && (
                      <p className="text-sm text-white/60 mb-3">
                        <span className="text-red-400 font-bold">{b.pwn_count.toLocaleString()}</span> cuentas comprometidas.
                      </p>
                    )}
                    {b.description && (
                      <p className="text-sm text-white/60 mb-3" dangerouslySetInnerHTML={{
                        __html: (b.description || "").replace(/<[^>]+>/g, "").slice(0, 400),
                      }} />
                    )}
                    <div className="flex flex-wrap gap-1.5">
                      {(b.data_classes || []).map((c) => (
                        <span key={c} className="font-mono-data text-[10px] border border-white/15 px-2 py-0.5 text-white/70 uppercase tracking-widest">
                          {c}
                        </span>
                      ))}
                    </div>
                    {b.password_masked && (
                      <div className="mt-3 pt-3 border-t border-white/5 flex gap-4 flex-wrap">
                        <div>
                          <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Password (masked)</div>
                          <div className="font-mono-data text-sm text-red-400">{b.password_masked}</div>
                        </div>
                        {b.hash && (
                          <div>
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Hash</div>
                            <div className="font-mono-data text-xs text-white/60 break-all max-w-md">{b.hash}</div>
                          </div>
                        )}
                      </div>
                    )}
                  </article>
                ))}
              </div>
            )}

            {anyConfigured && total === 0 && (
              <div className="border border-green-400/40 bg-green-400/[0.03] p-10 text-center" data-testid="no-breaches">
                <ShieldAlert className="w-10 h-10 text-green-400 mx-auto mb-3" />
                <h3 className="font-heading text-xl font-bold mb-2">Sin filtraciones registradas</h3>
                <p className="text-white/50 text-sm">
                  <span className="font-mono-data">{result.query}</span> no aparece en las fuentes consultadas.
                </p>
              </div>
            )}
          </>
        )}

        {history.length > 0 && (
          <section className="mt-14">
            <div className="flex items-center gap-3 mb-4">
              <Database className="w-4 h-4 text-cyan-400" />
              <h2 className="font-heading text-lg font-bold tracking-tight">Historial de búsquedas</h2>
            </div>
            <div className="border-t border-l border-white/10 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-0">
              {history.map((h, i) => (
                <div key={i} className="border-r border-b border-white/10 p-4">
                  <div className="font-mono-data text-cyan-400 text-sm break-all">{h.query}</div>
                  <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mt-1 flex items-center justify-between">
                    <span>{h.type} · {new Date(h.created_at).toLocaleDateString()}</span>
                    <span className={h.total > 0 ? "text-red-400" : "text-green-400"}>{h.total} hits</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
