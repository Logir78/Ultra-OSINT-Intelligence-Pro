import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Loader2, Radar, Play, AlertTriangle } from "lucide-react";
import { API } from "@/lib/auth";

const SEV_CLS = {
  critical: "border-red-400 bg-red-500/[0.08] text-red-300",
  high: "border-orange-400 bg-orange-500/[0.06] text-orange-300",
  info: "border-white/10 text-white/60",
};

export default function ShodanDeepPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/shodan-deep`, { withCredentials: true, timeout: 60000 });
      setData(r.data.shodan_deep);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error Shodan Deep"); }
    finally { setLoading(false); }
  };

  return (
    <section data-testid="panel-shodan-deep" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <Radar className="w-4 h-4 text-cyan-400" />
          <h3 className="font-heading text-sm font-bold uppercase tracking-wide">Shodan Deep Scan · Puertos TCP/UDP completos</h3>
        </div>
        <button onClick={run} disabled={loading}
          data-testid="run-shodan-deep-btn"
          className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
        >
          {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
          {data ? "Reescanear" : "Ejecutar"}
        </button>
      </div>
      <div className="p-5">
        {!data && !loading && (
          <p className="text-sm text-white/50">
            Enumera TODOS los puertos TCP/UDP abiertos en las IPs del dominio, identifica el servicio (Redis, MongoDB, SSH, RDP…) y alerta si hay servicios críticos expuestos sin autenticación.
          </p>
        )}
        {loading && (
          <div className="flex items-center gap-3 text-white/60">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">Consultando Shodan…</span>
          </div>
        )}
        {data && !data.configured && (
          <div className="text-sm text-orange-400/90">Falta la API key de Shodan. Configúrala en Ajustes → API Keys.</div>
        )}
        {data && data.configured && (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{data.hosts?.length || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">IPs analizadas</div>
              </div>
              <div className="border border-cyan-400/30 p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{data.unique_ports?.length || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Puertos únicos</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{data.critical_count || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Alertas críticas</div>
              </div>
            </div>

            {(data.hosts || []).map((h, i) => (
              <div key={i} className="border border-white/[0.06]">
                <div className="px-4 py-2 border-b border-white/[0.06] bg-[#0F0F13] flex items-center justify-between flex-wrap gap-2">
                  <div className="font-mono-data text-sm text-cyan-300">{h.ip}</div>
                  <div className="font-mono-data text-[10px] text-white/40">
                    {h.org || "?"} · {h.country_code || "??"} · {(h.ports || []).length} puertos
                  </div>
                </div>
                <div className="p-3">
                  {(h.services || []).length === 0 && <div className="text-xs text-white/40">Sin datos de servicios en Shodan.</div>}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {(h.services || []).map((s, j) => (
                      <div key={j} className={`border p-2.5 ${SEV_CLS[s.severity] || SEV_CLS.info}`}>
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <div className="font-mono-data text-sm font-bold">
                            {s.port}/{s.transport || "tcp"}
                            {s.service_kind && <span className="ml-2 text-xs uppercase tracking-widest opacity-80">{s.service_kind}</span>}
                          </div>
                          {(s.vulns || []).length > 0 && (
                            <span className="font-mono-data text-[10px] border border-current px-1.5 py-0.5">
                              {s.vulns.length} CVE
                            </span>
                          )}
                        </div>
                        <div className="font-mono-data text-[10px] text-white/50 mt-1">
                          {s.product || "?"} {s.version || ""}
                        </div>
                        {s.unauth_flag && (
                          <div className="mt-2 flex items-start gap-2 text-xs">
                            <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                            <span>{s.unauth_flag}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
