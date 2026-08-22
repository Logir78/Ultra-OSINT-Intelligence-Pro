import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Loader2, FileSearch, Play, AlertTriangle, Copy, Check } from "lucide-react";
import { API } from "@/lib/auth";

const SEVERITY_STYLES = {
  critical: "border-red-400 bg-red-500/[0.06] text-red-300",
  high: "border-orange-400 bg-orange-500/[0.06] text-orange-300",
  medium: "border-cyan-400 bg-cyan-500/[0.04] text-cyan-300",
  low: "border-white/15 text-white/60",
  info: "border-white/10 text-white/50",
};

function Snippet({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-start gap-2 mt-1.5">
      <pre className="flex-1 bg-black/50 font-mono-data text-[11px] text-white/70 p-2 overflow-x-auto whitespace-pre-wrap break-all border border-white/[0.05]">{text}</pre>
      <button
        onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
        className="text-white/40 hover:text-cyan-400 p-1"
      >
        {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
      </button>
    </div>
  );
}

export default function JsMinerPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/js-miner`, { withCredentials: true, timeout: 90000 });
      setData(r.data.js_miner);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error JS Miner"); }
    finally { setLoading(false); }
  };

  const findings = data?.findings || [];
  const bySeverity = ["critical", "high", "medium", "low", "info"].map(sev => ({
    sev, items: findings.filter(f => f.severity === sev),
  })).filter(g => g.items.length > 0);

  return (
    <section data-testid="panel-js-miner" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <FileSearch className="w-4 h-4 text-cyan-400" />
          <h3 className="font-heading text-sm font-bold uppercase tracking-wide">Análisis de código · JS Miner</h3>
        </div>
        <button onClick={run} disabled={loading}
          data-testid="run-js-miner-btn"
          className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
        >
          {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
          {data ? "Reescanear" : "Ejecutar"}
        </button>
      </div>
      <div className="p-5">
        {!data && !loading && (
          <p className="text-sm text-white/50">
            Descarga y analiza los archivos JavaScript del dominio en busca de rutas de API,
            comentarios de developers, JWTs y claves expuestas.
          </p>
        )}
        {loading && (
          <div className="flex items-center gap-3 text-white/60 py-3">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">Analizando JavaScript…</span>
          </div>
        )}
        {data && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{data.js_files_analyzed}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Archivos JS analizados</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{data.total_findings}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Hallazgos totales</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{data.counts_by_severity?.critical || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Críticos</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{data.counts_by_severity?.high || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Altos</div>
              </div>
            </div>

            {findings.length === 0 && (
              <div className="text-sm text-green-400/80">Sin hallazgos sospechosos en el código JS analizado.</div>
            )}

            {bySeverity.map(({ sev, items }) => (
              <div key={sev}>
                <div className={`font-mono-data text-[10px] uppercase tracking-widest mb-2 ${SEVERITY_STYLES[sev]?.split(" ")[2] || "text-white/40"}`}>
                  {sev.toUpperCase()} ({items.length})
                </div>
                <div className="space-y-2">
                  {items.slice(0, 40).map((f, i) => (
                    <div key={i} className={`border p-3 ${SEVERITY_STYLES[sev]}`}>
                      <div className="flex items-center justify-between gap-3 flex-wrap">
                        <div>
                          <span className="font-mono-data text-[10px] uppercase tracking-widest border border-current px-1.5 py-0.5">
                            {f.kind}
                          </span>
                          <span className="ml-2 font-mono-data text-xs break-all">{f.match}</span>
                        </div>
                        <span className="font-mono-data text-[10px] text-white/40 break-all max-w-[280px] truncate" title={f.source}>{f.source}</span>
                      </div>
                      {f.snippet && f.snippet !== f.match && <Snippet text={f.snippet} />}
                    </div>
                  ))}
                  {items.length > 40 && (
                    <div className="text-xs text-white/40 font-mono-data">… y {items.length - 40} más</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
