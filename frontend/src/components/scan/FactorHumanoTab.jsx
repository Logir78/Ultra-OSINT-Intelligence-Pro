/* "Factor Humano" tab — inline breach lookup (HIBP + BreachDirectory).
 * Extracted verbatim from ScanDetail.jsx (Fase 3). Self-contained: owns its
 * own state and only needs the `domain` prop.
 */
import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  AtSign, Skull, Database, Fingerprint, Search as SearchIcon,
  Loader2, AlertTriangle, ShieldCheck,
} from "lucide-react";
import { API } from "@/lib/auth";
import { MetricCard, Panel } from "@/components/scan/ScanUI";

export default function FactorHumanoTab({ domain }) {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const search = async (target, kind = "email") => {
    setLoading(true); setResult(null);
    try {
      const r = await axios.post(`${API}/breaches/lookup`,
        { query: target, type: kind },
        { withCredentials: true, timeout: 30000 });
      setResult(r.data);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error en la búsqueda");
    } finally { setLoading(false); }
  };

  const quickEmails = ["admin", "info", "contact", "support", "webmaster", "sales"];

  const anyConfigured = result && (result.sources?.hibp?.configured || result.sources?.breachdirectory?.configured);
  const total = result?.total || 0;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard icon={AtSign} label="Emails probados" value={result ? "1" : "0"} tone="accent" />
        <MetricCard icon={Skull} label="Brechas totales" value={total} tone={total > 0 ? "bad" : "good"} />
        <MetricCard icon={Database} label="Fuentes activas"
          value={result ? Object.values(result.sources).filter((s) => s.configured).length : "?"}
          tone={anyConfigured ? "good" : "warn"} sub={anyConfigured ? "HIBP · BREACHDIRECTORY" : "sin API keys"} />
        <MetricCard icon={Fingerprint} label="Dominio" value={domain} tone="neutral" />
      </div>

      <Panel title="Búsqueda de brechas por correo" icon={SearchIcon}>
        <p className="text-sm text-white/60 mb-4">
          Introduce un email asociado al dominio <span className="font-mono-data text-cyan-400">{domain}</span> o cualquier correo.
          Cruzamos <span className="text-white/80">Have I Been Pwned</span> + <span className="text-white/80">BreachDirectory</span>.
        </p>
        <form onSubmit={(e) => { e.preventDefault(); if (email.trim()) search(email.trim()); }}
              className="flex items-center border border-white/[0.08] bg-black">
          <SearchIcon className="w-4 h-4 text-cyan-400 mx-4" />
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={`admin@${domain}`}
            data-testid="factor-humano-input"
            className="flex-1 bg-transparent py-3.5 font-mono-data text-sm placeholder:text-white/25 focus:outline-none"
          />
          <button type="submit" disabled={loading || !email.trim()}
            data-testid="factor-humano-search"
            className="bg-cyan-400 text-black font-semibold px-5 py-3.5 hover:bg-cyan-300 disabled:opacity-50">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Buscar"}
          </button>
        </form>

        <div className="mt-4">
          <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-2">
            Sugerencias rápidas
          </div>
          <div className="flex flex-wrap gap-2">
            {quickEmails.map((prefix) => {
              const q = `${prefix}@${domain}`;
              return (
                <button key={prefix}
                  onClick={() => { setEmail(q); search(q); }}
                  className="font-mono-data text-xs border border-white/[0.08] hover:border-cyan-400 hover:text-cyan-400 px-3 py-1.5 transition-colors">
                  {q}
                </button>
              );
            })}
            <button onClick={() => { setEmail(domain); search(domain, "domain"); }}
              className="font-mono-data text-xs border border-orange-400/40 text-orange-400 hover:bg-orange-400 hover:text-black px-3 py-1.5 transition-colors">
              Buscar dominio completo
            </button>
          </div>
        </div>
      </Panel>

      {loading && (
        <div className="flex items-center gap-3 text-white/40 py-4 px-5 border border-white/[0.06] bg-[#0A0A0C]">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          <span className="font-mono-data text-xs uppercase tracking-widest">Consultando fuentes…</span>
        </div>
      )}

      {result && !loading && !anyConfigured && (
        <Panel title="Integraciones pendientes" icon={AlertTriangle} accent="orange">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(result.sources).map(([k, v]) => (
              <div key={k} className="border border-dashed border-white/[0.15] p-4">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-yellow-400 mb-1">
                  {v.provider}
                </div>
                <a href={v.key_url} target="_blank" rel="noreferrer"
                  className="text-sm text-cyan-400 hover:underline">Obtener API key ↗</a>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {result && !loading && anyConfigured && total === 0 && (
        <Panel title="Sin filtraciones" icon={ShieldCheck} accent="green">
          <p className="text-sm text-white/60">
            <span className="font-mono-data text-cyan-400">{result.query}</span> no aparece en las fuentes consultadas. Buena noticia.
          </p>
        </Panel>
      )}

      {result && !loading && total > 0 && (
        <Panel title={`${total} brechas encontradas`} icon={Skull} accent="red">
          <div className="space-y-3" data-testid="factor-humano-results">
            {result.breaches.map((b, i) => (
              <article key={i} className="border border-white/[0.08] p-4 hover:border-red-400/40 transition-colors">
                <div className="flex items-start justify-between gap-4 flex-wrap mb-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h4 className="font-heading text-base font-bold">{b.title || b.name}</h4>
                      {b.is_verified && <span className="border border-red-400/60 bg-red-400/10 text-red-400 px-2 py-0.5 font-mono-data text-[9px] uppercase tracking-widest">verificada</span>}
                    </div>
                    <div className="font-mono-data text-xs text-white/50 mt-1">
                      {b.domain && <>{b.domain} · </>}
                      {b.breach_date && new Date(b.breach_date).toLocaleDateString()}
                      {b.pwn_count && <> · <span className="text-red-400">{b.pwn_count.toLocaleString()}</span> cuentas</>}
                    </div>
                  </div>
                  <span className={`font-mono-data text-xs ${b.source === "HIBP" ? "text-cyan-400" : "text-orange-400"}`}>
                    {b.source}
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {(b.data_classes || []).slice(0, 12).map((c) => (
                    <span key={c} className="font-mono-data text-[10px] border border-white/[0.15] px-2 py-0.5 text-white/70 uppercase tracking-widest">
                      {c}
                    </span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
