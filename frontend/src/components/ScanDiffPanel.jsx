import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Loader2, GitCompareArrows, ArrowUp, ArrowDown, ArrowRight } from "lucide-react";
import { API } from "@/lib/auth";

export default function ScanDiffPanel({ scanId, domain }) {
  const [history, setHistory] = useState([]);
  const [selectedVs, setSelectedVs] = useState("");
  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    axios.get(`${API}/scans/history/${encodeURIComponent(domain)}`, { withCredentials: true })
      .then(r => setHistory((r.data.scans || []).filter(s => s.scan_id !== scanId)))
      .catch(() => {});
  }, [scanId, domain]);

  const runDiff = async () => {
    setLoading(true);
    setDiff(null);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/diff`,
        { withCredentials: true, params: selectedVs ? { vs: selectedVs } : {} });
      if (r.data.available === false) {
        toast.info(r.data.reason);
      } else {
        setDiff(r.data.diff);
      }
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };

  const sevClass = {
    critical: "border-red-400 bg-red-500/[0.08] text-red-300",
    high: "border-orange-400 bg-orange-500/[0.05] text-orange-300",
    medium: "border-cyan-400 bg-cyan-500/[0.03] text-cyan-300",
    low: "border-white/15 text-white/50",
  };

  return (
    <section data-testid="panel-scan-diff" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <GitCompareArrows className="w-4 h-4 text-cyan-400" />
          <h3 className="font-heading text-sm font-bold uppercase tracking-wide">Time-Travel · Comparativa entre escaneos</h3>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedVs}
            onChange={(e) => setSelectedVs(e.target.value)}
            data-testid="diff-vs-select"
            className="bg-black border border-white/[0.15] px-3 py-1.5 font-mono-data text-xs focus:outline-none focus:border-cyan-400"
          >
            <option value="">vs escaneo anterior (auto)</option>
            {history.map(s => (
              <option key={s.scan_id} value={s.scan_id}>
                {new Date(s.created_at).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" })}
              </option>
            ))}
          </select>
          <button onClick={runDiff} disabled={loading}
            data-testid="run-diff-btn"
            className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5">
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <GitCompareArrows className="w-3 h-3" />}
            Comparar
          </button>
        </div>
      </div>
      <div className="p-5">
        {!diff && !loading && history.length === 0 && (
          <p className="text-sm text-white/50">Aún no hay escaneos previos de este dominio. Ejecuta un nuevo escaneo dentro de unos días para comparar.</p>
        )}
        {!diff && !loading && history.length > 0 && (
          <p className="text-sm text-white/50">Hay {history.length} escaneo(s) anteriores. Selecciona uno y compara.</p>
        )}
        {diff && (
          <div className="space-y-4">
            {!diff.changed ? (
              <div className="text-sm text-green-400/80">Sin cambios detectados entre los dos escaneos.</div>
            ) : (
              <div className={`border p-3 ${sevClass[diff.severity] || sevClass.low}`}>
                <span className="font-mono-data text-[10px] uppercase tracking-widest">Severidad del delta: {diff.severity}</span>
              </div>
            )}

            {(diff.ports?.added?.length > 0 || diff.ports?.removed?.length > 0) && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Puertos</div>
                <div className="flex flex-wrap gap-1.5">
                  {diff.ports.added.map(p => (
                    <span key={`a${p}`} className="font-mono-data text-xs border border-red-400/40 text-red-300 px-2 py-1 inline-flex items-center gap-1">
                      <ArrowUp className="w-3 h-3" /> +{p}
                    </span>
                  ))}
                  {diff.ports.removed.map(p => (
                    <span key={`r${p}`} className="font-mono-data text-xs border border-green-400/30 text-green-400 px-2 py-1 inline-flex items-center gap-1">
                      <ArrowDown className="w-3 h-3" /> −{p}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {(diff.subdomains?.added?.length > 0 || diff.subdomains?.removed?.length > 0) && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Subdominios ({diff.subdomains.prev_count} → {diff.subdomains.current_count})</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 max-h-56 overflow-y-auto">
                  {diff.subdomains.added.map((s, i) => (
                    <div key={`sa${i}`} className="font-mono-data text-xs text-red-300 border border-red-400/20 p-1.5 inline-flex items-center gap-1">
                      <ArrowUp className="w-3 h-3" /> {s}
                    </div>
                  ))}
                  {diff.subdomains.removed.map((s, i) => (
                    <div key={`sr${i}`} className="font-mono-data text-xs text-green-400 border border-green-400/20 p-1.5 inline-flex items-center gap-1">
                      <ArrowDown className="w-3 h-3" /> {s}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {(diff.tech?.changed?.length > 0 || Object.keys(diff.tech?.added || {}).length > 0 || Object.keys(diff.tech?.removed || {}).length > 0) && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Tecnología</div>
                <div className="space-y-1 font-mono-data text-xs">
                  {(diff.tech.changed || []).map((t, i) => (
                    <div key={`tc${i}`} className="flex items-center gap-2 border border-white/[0.05] p-2">
                      <span className="text-white">{t.name}</span>
                      <span className="text-orange-300">{t.from || "∅"}</span>
                      <ArrowRight className="w-3 h-3 text-white/40" />
                      <span className="text-cyan-300">{t.to || "∅"}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {(diff.security_headers?.lost?.length > 0 || diff.security_headers?.gained?.length > 0) && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Cabeceras de seguridad</div>
                <div className="flex flex-wrap gap-1.5">
                  {diff.security_headers.lost.map(h => (
                    <span key={h} className="font-mono-data text-[10px] border border-red-400/40 text-red-300 px-2 py-1">− {h}</span>
                  ))}
                  {diff.security_headers.gained.map(h => (
                    <span key={h} className="font-mono-data text-[10px] border border-green-400/30 text-green-400 px-2 py-1">+ {h}</span>
                  ))}
                </div>
              </div>
            )}

            {diff.ip_change && (
              <div className="font-mono-data text-xs text-orange-300 border border-orange-400/30 p-2 flex items-center gap-2">
                IP cambió: <span className="text-white/70">{diff.ip_change.from}</span>
                <ArrowRight className="w-3 h-3" />
                <span className="text-cyan-300">{diff.ip_change.to}</span>
              </div>
            )}
            {diff.tls_change && (
              <div className="font-mono-data text-xs text-orange-300 border border-orange-400/30 p-2 flex items-center gap-2">
                TLS cambió: <span className="text-white/70">{diff.tls_change.from || "∅"}</span>
                <ArrowRight className="w-3 h-3" />
                <span className="text-cyan-300">{diff.tls_change.to || "∅"}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
