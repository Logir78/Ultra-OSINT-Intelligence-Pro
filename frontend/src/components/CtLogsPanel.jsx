import { useEffect, useState } from "react";
import axios from "axios";
import { Loader2, Fingerprint, History } from "lucide-react";
import { API } from "@/lib/auth";

const SOURCE_STYLE = {
  both: { label: "ACTIVO+CT", cls: "border-green-400/40 text-green-400" },
  dns_only: { label: "SOLO DNS", cls: "border-cyan-400/40 text-cyan-400" },
  ct_only: { label: "HISTÓRICO", cls: "border-orange-400/40 text-orange-400" },
};

export default function CtLogsPanel({ scanId, autoLoad = true }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/ct-logs`, { withCredentials: true, timeout: 30000 });
      setData(r.data.ct_logs);
    } catch (e) { /* silent */ }
    finally { setLoading(false); }
  };

  useEffect(() => { if (autoLoad) run(); /* eslint-disable-next-line */ }, []);

  return (
    <section data-testid="panel-ct-logs" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <History className="w-4 h-4 text-cyan-400" />
          <h3 className="font-heading text-sm font-bold uppercase tracking-wide">Certificate Transparency · Subdominios históricos</h3>
        </div>
        {data && (
          <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/50">
            {data.counts?.combined} totales · {data.counts?.ct_only} solo CT
          </div>
        )}
      </div>
      <div className="p-5">
        {loading && (
          <div className="flex items-center gap-3 text-white/60">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">Consultando crt.sh…</span>
          </div>
        )}
        {data && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-green-400/30 p-3">
                <div className="font-heading text-2xl font-black text-green-400">{data.counts?.active_and_ct || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Activos + CT</div>
              </div>
              <div className="border border-cyan-400/30 p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{data.counts?.dns_only || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Solo DNS</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{data.counts?.ct_only || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Solo histórico</div>
              </div>
            </div>

            {(data.combined_subdomains || []).length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 max-h-[400px] overflow-y-auto">
                {data.combined_subdomains.map((s, i) => {
                  const meta = SOURCE_STYLE[s.source] || SOURCE_STYLE.dns_only;
                  return (
                    <div key={i} className="border border-white/[0.06] bg-black/40 p-2.5 flex items-center gap-2">
                      <span className={`font-mono-data text-[9px] uppercase tracking-widest px-1.5 py-0.5 border ${meta.cls} whitespace-nowrap`}>
                        {meta.label}
                      </span>
                      <span className="font-mono-data text-xs text-white/80 break-all">{s.subdomain}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
