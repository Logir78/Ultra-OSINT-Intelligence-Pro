import { useEffect, useState } from "react";
import axios from "axios";
import { Cloud, ShieldAlert, Loader2, ExternalLink } from "lucide-react";
import { API } from "@/lib/auth";

const PROVIDER_LABEL = { s3: "AWS S3", azure: "Azure Blob", gcs: "Google Cloud Storage" };

export default function CloudStoragePanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/cloud`, { withCredentials: true, timeout: 90000 });
        setData(r.data.cloud);
      } catch (_) { /* ignore */ } finally { setLoading(false); }
    })();
  }, [scanId]);

  return (
    <section id="cloud" data-testid="panel-cloud" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <Cloud className="w-4 h-4 text-cyan-400" />
          <h3 className="font-heading text-sm font-bold tracking-wide uppercase">
            Cloud Storage · Shadow IT
          </h3>
        </div>
        {data && (
          <div className="flex items-center gap-3">
            {data.public_count > 0 && (
              <span className="inline-flex items-center gap-1.5 border border-red-400/60 bg-red-400/15 text-red-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest animate-pulse">
                <ShieldAlert className="w-3 h-3" /> {data.public_count} públicos
              </span>
            )}
            <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
              {data.candidates_checked} candidatos probados
            </span>
          </div>
        )}
      </div>
      <div className="p-5">
        {loading ? (
          <div className="flex items-center gap-3 text-white/40 py-4">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">
              Enumerando buckets S3 / Azure / GCS…
            </span>
          </div>
        ) : !data?.hits?.length ? (
          <p data-testid="cloud-empty" className="text-white/50 text-sm">
            Ningún bucket / container encontrado con las {data?.candidates_checked ?? 0} permutaciones comunes.
            <span className="block text-white/30 font-mono-data text-xs mt-2 uppercase tracking-widest">
              Enumeración pasiva — solo se probaron nombres derivados del dominio.
            </span>
          </p>
        ) : (
          <>
            <div className="grid grid-cols-3 gap-3 mb-5">
              {["s3", "azure", "gcs"].map((p) => {
                const s = data.provider_summary[p] || { total: 0, public: 0 };
                return (
                  <div key={p} className="border border-white/[0.08] p-3">
                    <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
                      {PROVIDER_LABEL[p]}
                    </div>
                    <div className="mt-1 flex items-baseline gap-2">
                      <span className="font-heading text-2xl font-black">{s.total}</span>
                      {s.public > 0 && (
                        <span className="text-red-400 font-mono-data text-xs uppercase tracking-widest">
                          {s.public} públicos
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="border-b border-white/[0.08] text-left bg-[#101014]">
                  {["Proveedor", "Nombre", "Estado", "Acceso", "Enlace"].map((c) => (
                    <th key={c} className="py-2.5 px-3 font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.hits.map((h, i) => (
                  <tr key={i} data-testid={`cloud-row-${h.name}-${h.provider}`} className="border-b border-white/[0.04] hover:bg-white/[0.02]">
                    <td className="py-3 px-3 font-mono-data text-xs text-white/70">{PROVIDER_LABEL[h.provider]}</td>
                    <td className="py-3 px-3 font-mono-data text-sm text-cyan-400">{h.name}</td>
                    <td className="py-3 px-3">
                      <span className={`font-mono-data text-[10px] px-2 py-1 border ${
                        h.exists
                          ? "border-orange-400/50 bg-orange-400/10 text-orange-400"
                          : "border-white/15 text-white/50"
                      }`}>
                        {h.note || `HTTP ${h.status_code}`}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      {h.public ? (
                        <span className="font-mono-data text-[10px] px-2 py-1 border border-red-400/60 bg-red-400/15 text-red-400 uppercase tracking-widest">
                          Público
                        </span>
                      ) : (
                        <span className="font-mono-data text-[10px] px-2 py-1 border border-green-400/40 text-green-400 uppercase tracking-widest">
                          Restringido
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <a href={h.url} target="_blank" rel="noreferrer" className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 font-mono-data text-xs">
                        Abrir <ExternalLink className="w-3 h-3" />
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </section>
  );
}
