import { useEffect, useState } from "react";
import axios from "axios";
import { ShieldOff, Loader2, AlertTriangle, Info, ChevronDown } from "lucide-react";
import { API } from "@/lib/auth";

const RISK_STYLE = {
  critical: { border: "border-red-400/60",  bg: "bg-red-400/10",    text: "text-red-400",    label: "CRÍTICO" },
  high:     { border: "border-orange-400/60", bg: "bg-orange-400/10", text: "text-orange-400", label: "ALTO" },
  possibly_vulnerable: { border: "border-yellow-400/40", bg: "bg-yellow-400/5", text: "text-yellow-400", label: "POSIBLE" },
  safe:     { border: "border-green-400/30", bg: "bg-transparent", text: "text-green-400/70", label: "OK" },
};

export default function TakeoverPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showNote, setShowNote] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/takeover`, { withCredentials: true, timeout: 120000 });
        setData(r.data.takeover);
      } catch (_) { /* ignore */ } finally { setLoading(false); }
    })();
  }, [scanId]);

  const vuln = data?.vulnerable_count || 0;

  return (
    <section id="takeover" data-testid="panel-takeover"
      className={`border ${vuln > 0 ? "border-red-400/60 shadow-[0_0_40px_rgba(255,51,85,0.15)]" : "border-white/[0.06]"} bg-[#0A0A0C] mb-5`}>
      <div className={`flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] ${vuln > 0 ? "bg-red-400/[0.08]" : "bg-[#101014]"}`}>
        <div className="flex items-center gap-3">
          <ShieldOff className={`w-4 h-4 ${vuln > 0 ? "text-red-400" : "text-cyan-400"}`} />
          <h3 className="font-heading text-sm font-bold tracking-wide uppercase">
            Subdomain Takeover · Dangling DNS
          </h3>
        </div>
        {data && (
          <div className="flex items-center gap-3">
            {vuln > 0 && (
              <span data-testid="takeover-critical-badge"
                className="inline-flex items-center gap-1.5 border-2 border-red-400 bg-red-400/20 text-red-400 px-3 py-1 font-mono-data text-[10px] uppercase tracking-widest animate-pulse font-bold">
                <AlertTriangle className="w-3.5 h-3.5" /> {vuln} RIESGO CRÍTICO
              </span>
            )}
            <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
              {data.checked} revisados · {data.with_cname} con CNAME
            </span>
          </div>
        )}
      </div>

      <div className="p-5">
        {loading ? (
          <div className="flex items-center gap-3 text-white/40 py-4">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">
              Resolviendo CNAMEs + verificando servicios externos…
            </span>
          </div>
        ) : (
          <>
            {vuln > 0 && (
              <div data-testid="critical-alert" className="mb-5 border-2 border-red-400 bg-red-400/[0.08] p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 animate-pulse" />
                  <div>
                    <h4 className="font-heading text-lg font-black text-red-400 tracking-tight">
                      ALERTA: Posible secuestro de subdominio
                    </h4>
                    <p className="text-sm text-white/80 mt-1">
                      Se detectaron <b>{vuln} subdominios</b> apuntando a servicios externos no reclamados o inexistentes.
                      Un atacante podría reclamar estos servicios y tomar el control.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Technical note — always visible on vulnerable, collapsible when clean */}
            <div className={`border ${vuln > 0 ? "border-orange-400/50" : "border-white/[0.08]"} bg-black/40 mb-5`}>
              <button
                onClick={() => setShowNote((v) => !v)}
                className="w-full flex items-center justify-between gap-3 px-4 py-2.5 hover:bg-white/[0.02]"
                data-testid="takeover-note-toggle"
              >
                <div className="flex items-center gap-2">
                  <Info className={`w-4 h-4 ${vuln > 0 ? "text-orange-400" : "text-cyan-400"}`} />
                  <span className="font-mono-data text-[11px] uppercase tracking-[0.2em] text-white/80">
                    Nota técnica · ¿Qué es un Subdomain Takeover?
                  </span>
                </div>
                <ChevronDown className={`w-4 h-4 text-white/40 transition-transform ${showNote ? "rotate-180" : ""}`} />
              </button>
              {showNote && (
                <div className="px-4 pb-4 pt-1">
                  <p data-testid="takeover-note" className="text-sm text-white/75 leading-relaxed">
                    {data?.explanation}
                  </p>
                </div>
              )}
            </div>

            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="border-b border-white/[0.08] text-left bg-[#101014]">
                  {["Subdominio", "CNAME", "Servicio", "Riesgo", "Evidencia"].map((c) => (
                    <th key={c} className="py-2.5 px-3 font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(data?.results || []).map((r) => {
                  const s = RISK_STYLE[r.risk] || RISK_STYLE.safe;
                  return (
                    <tr key={r.subdomain} data-testid={`takeover-row-${r.subdomain}`}
                        className={`border-b border-white/[0.04] hover:bg-white/[0.02] ${r.vulnerable ? "bg-red-400/[0.04]" : ""}`}>
                      <td className="py-3 px-3 font-mono-data text-sm text-cyan-400 break-all">{r.subdomain}</td>
                      <td className="py-3 px-3 font-mono-data text-[11px] text-white/60 break-all max-w-[220px]">
                        {r.cname_chain.length ? r.cname_chain.join(" → ") : <span className="text-white/25">—</span>}
                      </td>
                      <td className="py-3 px-3 font-mono-data text-xs text-white/70">{r.service || "—"}</td>
                      <td className="py-3 px-3">
                        <span className={`inline-block border px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest ${s.border} ${s.bg} ${s.text} ${r.vulnerable ? "font-bold" : ""}`}>
                          {s.label}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono-data text-[11px] text-white/50 break-words max-w-[240px]">
                        {r.evidence || "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>
    </section>
  );
}
