import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Clock, ExternalLink, Archive, Loader2 } from "lucide-react";
import { API } from "@/lib/auth";

function _fmt(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString("es-ES", { year: "numeric", month: "short", day: "2-digit" });
  } catch { return iso; }
}

function _fmtTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
  } catch { return ""; }
}

function SnapshotRow({ snap }) {
  return (
    <a
      href={snap.snapshot_url}
      target="_blank"
      rel="noreferrer"
      data-testid={`wayback-snap-${snap.timestamp}`}
      className="group flex items-center justify-between gap-4 border-b border-white/5 py-3 hover:bg-white/[0.03] transition-colors -mx-3 px-3"
    >
      <div className="flex items-center gap-4 min-w-0">
        <div className="w-14 h-14 border border-white/10 flex flex-col items-center justify-center font-mono-data text-cyan-400 flex-shrink-0">
          <span className="text-[10px] uppercase tracking-widest text-white/40">
            {new Date(snap.date).toLocaleDateString("es-ES", { month: "short" })}
          </span>
          <span className="text-lg font-bold leading-none">
            {new Date(snap.date).getFullYear()}
          </span>
        </div>
        <div className="min-w-0">
          <div className="font-mono-data text-sm text-white/90">{_fmt(snap.date)}</div>
          <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mt-0.5">
            {_fmtTime(snap.date)} · HTTP {snap.status_code || "?"}
          </div>
        </div>
      </div>
      <ExternalLink className="w-4 h-4 text-white/30 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all flex-shrink-0" />
    </a>
  );
}

export default function WaybackTimeline({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/wayback`, {
          withCredentials: true, timeout: 60000,
        });
        setData(r.data.wayback);
      } catch {
        setError(true);
      } finally {
        setLoading(false);
      }
    })();
  }, [scanId]);

  return (
    <section
      id="wayback"
      data-testid="panel-wayback"
      className="border border-white/10 bg-[#0C0C0E] p-6 mb-4 scroll-mt-24"
    >
      <div className="flex items-center gap-3 mb-2">
        <Clock className="w-4 h-4 text-cyan-400" />
        <h2 className="font-heading text-lg font-bold tracking-tight">Cronología del Dominio</h2>
      </div>
      <p className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-6 flex items-center gap-2">
        <Archive className="w-3 h-3" /> Fuente: Wayback Machine · archive.org
      </p>

      {loading ? (
        <div className="flex items-center gap-3 text-white/40 py-8">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          <span className="font-mono-data text-xs uppercase tracking-widest">Consultando archive.org...</span>
        </div>
      ) : error || !data || data.total_returned === 0 ? (
        <p data-testid="wayback-empty" className="text-white/40 text-sm py-8">
          No hay snapshots públicas registradas para este dominio en archive.org.
        </p>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* OLDEST */}
          <div>
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/10">
              <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full" />
              <h3 className="font-heading text-sm font-bold tracking-[0.2em] uppercase text-cyan-400">
                Más antiguas
              </h3>
              <span className="font-mono-data text-[10px] text-white/40 ml-auto">
                {data.oldest.length} snapshots
              </span>
            </div>
            {data.oldest.length === 0 ? (
              <p className="text-white/30 text-sm">—</p>
            ) : (
              data.oldest.map((s) => <SnapshotRow key={s.timestamp} snap={s} />)
            )}
          </div>

          {/* NEWEST */}
          <div>
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/10">
              <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
              <h3 className="font-heading text-sm font-bold tracking-[0.2em] uppercase text-green-400">
                Más recientes
              </h3>
              <span className="font-mono-data text-[10px] text-white/40 ml-auto">
                {data.newest.length} snapshots
              </span>
            </div>
            {data.newest.length === 0 ? (
              <p className="text-white/30 text-sm">—</p>
            ) : (
              data.newest.map((s) => <SnapshotRow key={s.timestamp} snap={s} />)
            )}
          </div>
        </div>
      )}
    </section>
  );
}
