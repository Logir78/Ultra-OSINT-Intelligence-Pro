import { useEffect, useState } from "react";
import axios from "axios";
import { Bug, Loader2, ShieldOff, ExternalLink } from "lucide-react";
import { API } from "@/lib/auth";
import IntegrationEmpty from "@/components/IntegrationEmpty";

export default function ShodanPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/shodan`, { withCredentials: true });
        setData(r.data.shodan);
      } catch (_) { /* ignore */ }
      finally { setLoading(false); }
    })();
  }, [scanId]);

  const totalVulns = data?.total_vulns || 0;

  return (
    <section id="shodan" data-testid="panel-shodan" className="border border-white/10 bg-[#0C0C0E] p-6 mb-4 scroll-mt-24">
      <div className="flex items-center gap-3 mb-5 pb-4 border-b border-white/5">
        <Bug className="w-4 h-4 text-cyan-400" />
        <h2 className="font-heading text-lg font-bold tracking-tight">Puertos y Vulnerabilidades · Shodan</h2>
        {totalVulns > 0 && (
          <span className="ml-auto inline-flex items-center gap-1.5 border border-red-400/60 bg-red-400/15 text-red-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest">
            <ShieldOff className="w-3 h-3" /> {totalVulns} CVEs detectados
          </span>
        )}
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-white/40 py-6">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          <span className="font-mono-data text-xs uppercase tracking-widest">Consultando Shodan…</span>
        </div>
      ) : !data?.provider?.configured ? (
        <IntegrationEmpty
          provider="Shodan"
          keyUrl={data?.provider?.key_url}
          freeTier={data?.provider?.free_tier}
          description="Recupera puertos abiertos indexados por Shodan (más completo que un scan directo) y correlaciona con CVEs conocidos."
        />
      ) : (
        <div className="space-y-8">
          {(data.hosts || []).map((h) => (
            <div key={h.ip} data-testid={`shodan-host-${h.ip}`} className="border border-white/5">
              <div className="flex items-center justify-between px-4 py-3 bg-white/[0.02] border-b border-white/5">
                <div>
                  <span className="font-mono-data text-cyan-400 text-sm">{h.ip}</span>
                  <span className="ml-3 text-xs text-white/40">{h.org || h.isp || "—"}</span>
                </div>
                {h.vulns?.length > 0 && (
                  <span className="border border-red-400/60 bg-red-400/15 text-red-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest">
                    {h.vulns.length} CVEs
                  </span>
                )}
              </div>

              {!h.found ? (
                <p className="text-white/40 text-sm p-4">
                  {h.error ? <span className="text-red-400 font-mono-data text-xs">{h.error}</span> : "IP no indexada en Shodan."}
                </p>
              ) : (
                <div className="p-4">
                  <div className="flex flex-wrap gap-2 mb-4">
                    {(h.ports || []).map((p) => (
                      <span key={p} className="font-mono-data text-xs border border-green-400/40 text-green-400 px-2 py-1">
                        {p}
                      </span>
                    ))}
                  </div>

                  {(h.services || []).length > 0 && (
                    <table className="w-full text-sm border-collapse mb-4">
                      <thead>
                        <tr className="border-b border-white/10 text-left">
                          <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">Puerto</th>
                          <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">Servicio</th>
                          <th className="py-2 pr-3 font-mono-data text-[10px] uppercase tracking-widest text-white/50">Versión</th>
                          <th className="py-2 font-mono-data text-[10px] uppercase tracking-widest text-white/50">CVEs</th>
                        </tr>
                      </thead>
                      <tbody>
                        {h.services.map((svc, i) => (
                          <tr key={i} className="border-b border-white/5 align-top">
                            <td className="py-2 pr-3 font-mono-data text-green-400 text-sm font-bold">{svc.port}</td>
                            <td className="py-2 pr-3 font-mono-data text-xs text-white/80">{svc.product || svc.transport || "—"}</td>
                            <td className="py-2 pr-3 font-mono-data text-xs text-white/60">{svc.version || "—"}</td>
                            <td className="py-2">
                              <div className="flex flex-wrap gap-1">
                                {(svc.vulns || []).map((v) => (
                                  <a
                                    key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`}
                                    target="_blank" rel="noreferrer"
                                    className="font-mono-data text-[10px] border border-red-400/50 bg-red-400/10 text-red-400 px-1.5 py-0.5 hover:bg-red-400 hover:text-black transition-colors inline-flex items-center gap-1"
                                  >
                                    {v} <ExternalLink className="w-2.5 h-2.5" />
                                  </a>
                                ))}
                                {!svc.vulns?.length && <span className="text-white/30 text-xs">—</span>}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
