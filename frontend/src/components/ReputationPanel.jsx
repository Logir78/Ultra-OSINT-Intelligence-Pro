import { useEffect, useState } from "react";
import axios from "axios";
import { ShieldAlert, AlertTriangle, Globe2, Loader2 } from "lucide-react";
import { API } from "@/lib/auth";
import IntegrationEmpty from "@/components/IntegrationEmpty";

function scoreBadge(score) {
  if (score >= 75) return { label: "MALICIOSA", cls: "text-red-400 border-red-400/50 bg-red-400/10" };
  if (score >= 25) return { label: "SOSPECHOSA", cls: "text-orange-400 border-orange-400/50 bg-orange-400/10" };
  if (score > 0)   return { label: "REPORTADA", cls: "text-yellow-400 border-yellow-400/40 bg-yellow-400/10" };
  return { label: "LIMPIA", cls: "text-green-400 border-green-400/40 bg-green-400/10" };
}

export default function ReputationPanel({ scanId, onWorstScore }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/reputation`, { withCredentials: true });
        setData(r.data.reputation);
        onWorstScore?.(r.data.reputation?.worst_score || 0);
      } catch (_) { /* ignore */ }
      finally { setLoading(false); }
    })();
  }, [scanId, onWorstScore]);

  return (
    <section id="reputation" data-testid="panel-reputation" className="border border-white/10 bg-[#0C0C0E] p-6 mb-4 scroll-mt-24">
      <div className="flex items-center gap-3 mb-5 pb-4 border-b border-white/5">
        <ShieldAlert className="w-4 h-4 text-cyan-400" />
        <h2 className="font-heading text-lg font-bold tracking-tight">Reputación IP · AbuseIPDB</h2>
        {data?.worst_score >= 25 && (
          <span className="ml-auto inline-flex items-center gap-1.5 border border-red-400/60 bg-red-400/15 text-red-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest animate-pulse">
            <AlertTriangle className="w-3 h-3" /> Actividad maliciosa detectada
          </span>
        )}
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-white/40 py-6">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          <span className="font-mono-data text-xs uppercase tracking-widest">Consultando AbuseIPDB…</span>
        </div>
      ) : !data?.provider?.configured ? (
        <IntegrationEmpty
          provider="AbuseIPDB"
          keyUrl={data?.provider?.key_url}
          freeTier={data?.provider?.free_tier}
          description="Comprueba automáticamente si las IPs del dominio están reportadas por actividad maliciosa (scanning, DDoS, spam, brute-force)."
        />
      ) : (
        <table data-testid="reputation-table" className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-white/10 text-left">
              <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">IP</th>
              <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">Estado</th>
              <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">Score</th>
              <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">Reportes</th>
              <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">ISP</th>
              <th className="py-2 font-mono-data text-[10px] uppercase tracking-widest text-white/50">Último reporte</th>
            </tr>
          </thead>
          <tbody>
            {(data.checks || []).map((c) => {
              const b = scoreBadge(c.abuse_confidence || 0);
              return (
                <tr key={c.ip} data-testid={`reputation-row-${c.ip}`} className="border-b border-white/5">
                  <td className="py-3 pr-3 font-mono-data text-cyan-400 text-sm">
                    <div className="flex items-center gap-2">
                      <Globe2 className="w-3.5 h-3.5 text-white/40" />
                      {c.ip}
                    </div>
                  </td>
                  <td className="py-3 pr-3">
                    <span className={`inline-block border px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest ${b.cls}`}>
                      {b.label}
                    </span>
                  </td>
                  <td className="py-3 pr-3 font-mono-data text-sm font-bold">
                    <span className={c.abuse_confidence >= 25 ? "text-red-400" : "text-white/70"}>
                      {c.abuse_confidence ?? 0}/100
                    </span>
                  </td>
                  <td className="py-3 pr-3 font-mono-data text-sm text-white/70">{c.total_reports ?? 0}</td>
                  <td className="py-3 pr-3 font-mono-data text-xs text-white/60">{c.isp || "—"}</td>
                  <td className="py-3 font-mono-data text-xs text-white/50">{c.last_reported_at ? new Date(c.last_reported_at).toLocaleDateString() : "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
