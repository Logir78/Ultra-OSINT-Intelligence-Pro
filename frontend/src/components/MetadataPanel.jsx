import { useEffect, useState } from "react";
import axios from "axios";
import { FileText, Loader2, ExternalLink, User, Zap, AlertTriangle } from "lucide-react";
import { API } from "@/lib/auth";

function _fmt(dstr) {
  if (!dstr) return "—";
  // PDF format: D:20230513142530+00'00'
  const m = dstr.match(/D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/);
  if (m) return `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}`;
  try { return new Date(dstr).toLocaleString("es-ES"); } catch { return dstr; }
}

export default function MetadataPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/metadata`, { withCredentials: true, timeout: 120000 });
        setData(r.data.metadata);
      } catch (_) { /* ignore */ } finally { setLoading(false); }
    })();
  }, [scanId]);

  const totalWarnings = (data?.docs || []).reduce((acc, d) => acc + (d.warnings?.length || 0), 0);

  return (
    <section id="metadata" data-testid="panel-metadata" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <FileText className="w-4 h-4 text-cyan-400" />
          <h3 className="font-heading text-sm font-bold tracking-wide uppercase">
            Metadatos de documentos filtrados
          </h3>
        </div>
        {data && (
          <div className="flex items-center gap-3">
            {totalWarnings > 0 && (
              <span className="inline-flex items-center gap-1.5 border border-orange-400/60 bg-orange-400/15 text-orange-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest">
                <AlertTriangle className="w-3 h-3" /> {totalWarnings} avisos
              </span>
            )}
            <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
              {data.reachable || 0}/{data.found || 0} accesibles
            </span>
          </div>
        )}
      </div>
      <div className="p-5">
        {loading ? (
          <div className="flex items-center gap-3 text-white/40 py-4">
            <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
            <span className="font-mono-data text-xs uppercase tracking-widest">
              Buscando PDF / DOCX / XLSX en DuckDuckGo y extrayendo metadatos…
            </span>
          </div>
        ) : !data || data.found === 0 ? (
          <p data-testid="metadata-empty" className="text-white/50 text-sm">
            No se encontraron documentos indexados para el dominio.
          </p>
        ) : (
          <>
            {(data.unique_authors?.length > 0 || data.unique_software?.length > 0) && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
                <div className="border border-white/[0.08] p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <User className="w-3.5 h-3.5 text-orange-400" />
                    <span className="font-mono-data text-[10px] uppercase tracking-widest text-orange-400">
                      Autores expuestos ({data.unique_authors.length})
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {data.unique_authors.map((a) => (
                      <span key={a} className="font-mono-data text-xs border border-orange-400/40 text-orange-300 px-2 py-0.5">
                        {a}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="border border-white/[0.08] p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">
                      Software identificado ({data.unique_software.length})
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {data.unique_software.slice(0, 10).map((s) => (
                      <span key={s} className="font-mono-data text-xs border border-cyan-400/30 text-cyan-300 px-2 py-0.5">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            <div className="space-y-2">
              {(data.docs || []).map((d, i) => {
                const m = d.metadata || {};
                const isOpen = expanded === i;
                return (
                  <div key={i} data-testid={`metadata-row-${i}`} className="border border-white/[0.06]">
                    <button
                      onClick={() => setExpanded(isOpen ? null : i)}
                      className="w-full flex items-center justify-between gap-4 px-4 py-3 hover:bg-white/[0.02] text-left"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="font-mono-data text-sm text-cyan-400 truncate">{d.filename}</div>
                        <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mt-1 flex flex-wrap gap-x-3 gap-y-1">
                          <span>{d.type?.toUpperCase()}</span>
                          {d.size_bytes && <span>{(d.size_bytes / 1024).toFixed(0)} KB</span>}
                          {m.author && <span className="text-orange-300">✎ {m.author}</span>}
                          {(m.creator || m.producer) && <span>⚙ {m.creator || m.producer}</span>}
                          {d.warnings?.length > 0 && (
                            <span className="text-orange-400 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" /> {d.warnings.length}
                            </span>
                          )}
                        </div>
                      </div>
                      <a href={d.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}
                        className="text-white/50 hover:text-cyan-400 p-1">
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </button>

                    {isOpen && (
                      <div className="border-t border-white/[0.06] p-4 bg-black/40 grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Autor</div>
                            <div className="col-span-2 font-mono-data text-xs text-orange-300">{m.author || "—"}</div>
                          </div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Modificado por</div>
                            <div className="col-span-2 font-mono-data text-xs text-orange-300">{m.last_modified_by || "—"}</div>
                          </div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Title</div>
                            <div className="col-span-2 font-mono-data text-xs text-white/70">{m.title || "—"}</div>
                          </div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Company</div>
                            <div className="col-span-2 font-mono-data text-xs text-white/70">{m.company || "—"}</div>
                          </div>
                        </div>
                        <div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Creator</div>
                            <div className="col-span-2 font-mono-data text-xs text-cyan-300">{m.creator || "—"}</div>
                          </div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Producer</div>
                            <div className="col-span-2 font-mono-data text-xs text-cyan-300">{m.producer || "—"}</div>
                          </div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Creación</div>
                            <div className="col-span-2 font-mono-data text-xs text-white/70">{_fmt(m.creation_date)}</div>
                          </div>
                          <div className="grid grid-cols-3 gap-3 py-1.5 border-b border-white/[0.05]">
                            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Modificación</div>
                            <div className="col-span-2 font-mono-data text-xs text-white/70">{_fmt(m.mod_date)}</div>
                          </div>
                        </div>
                        {d.warnings?.length > 0 && (
                          <div className="col-span-full mt-3 pt-3 border-t border-orange-400/30">
                            {d.warnings.map((w, wi) => (
                              <div key={wi} className="flex items-center gap-2 text-orange-400 text-xs py-1">
                                <AlertTriangle className="w-3.5 h-3.5" />
                                {w}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </section>
  );
}
