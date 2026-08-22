import { useEffect, useState } from "react";
import axios from "axios";
import { FileWarning, Loader2, ExternalLink } from "lucide-react";
import { API } from "@/lib/auth";

export default function PasteMonitorPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/pastes`, { withCredentials: true, timeout: 120000 });
        setData(r.data.pastes);
      } catch (_) { /* ignore */ } finally { setLoading(false); }
    })();
  }, [scanId]);

  const total = data?.total_mentions || 0;

  return (
    <section id="pastes" data-testid="panel-pastes"
      className={`border ${total > 0 ? "border-orange-400/50" : "border-white/[0.06]"} bg-[#0A0A0C] mb-5`}>
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <FileWarning className={`w-4 h-4 ${total > 0 ? "text-orange-400" : "text-cyan-400"}`} />
          <h3 className="font-heading text-sm font-bold tracking-wide uppercase">
            Menciones en paste sites & threat intel
          </h3>
        </div>
        {data && (
          <div className="flex items-center gap-3">
            {total > 0 && (
              <span className="inline-flex items-center gap-1.5 border border-orange-400/60 bg-orange-400/15 text-orange-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest animate-pulse">
                {total} mención(es)
              </span>
            )}
            <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
              {data.queries_run || 0} búsquedas realizadas
            </span>
          </div>
        )}
      </div>

      <div className="p-5">
        {loading ? (
          <div className="flex items-center gap-3 text-white/40 py-4">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">
              Buscando en Pastebin, Ghostbin, Hastebin, GitHub Gist…
            </span>
          </div>
        ) : total === 0 ? (
          <div className="text-center py-4">
            <p data-testid="pastes-empty" className="text-white/60 text-sm">
              <span className="text-green-400 font-mono-data mr-2">✓</span>
              Sin menciones públicas del dominio o sus IPs en paste sites.
            </p>
            <div className="mt-3 flex flex-wrap justify-center gap-1.5">
              {(data?.sites_covered || []).map((s) => (
                <span key={s} className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 border border-white/[0.08] px-2 py-0.5">
                  {s}
                </span>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {data.mentions.map((m, i) => (
              <a key={i} href={m.url} target="_blank" rel="noreferrer"
                 data-testid={`paste-mention-${i}`}
                 className="group block border border-white/[0.08] p-4 hover:border-orange-400/60 hover:bg-white/[0.02] transition-colors">
                <div className="flex items-center justify-between gap-4 mb-2">
                  <span className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-orange-400">
                    {m.source_label}
                  </span>
                  <ExternalLink className="w-3.5 h-3.5 text-white/30 group-hover:text-orange-400 group-hover:translate-x-0.5 transition-all" />
                </div>
                <div className="font-mono-data text-sm text-cyan-400 mb-1 truncate">{m.title || m.url}</div>
                {m.snippet && (
                  <p className="text-xs text-white/60 leading-relaxed">
                    {m.snippet}
                  </p>
                )}
              </a>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
