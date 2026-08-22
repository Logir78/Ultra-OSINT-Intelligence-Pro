import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { ShieldOff, Loader2, ChevronDown, ChevronUp, Sparkles, Zap } from "lucide-react";
import { API } from "@/lib/auth";

const CAT_COLOR = {
  recon:    "text-cyan-400 border-cyan-400/30",
  payload:  "text-yellow-400 border-yellow-400/30",
  protocol: "text-purple-400 border-purple-400/30",
  traffic:  "text-green-400 border-green-400/30",
  cache:    "text-orange-400 border-orange-400/30",
};

const RISK_COLOR = {
  critical: "text-red-400 border-red-400/40",
  high:     "text-red-400 border-red-400/40",
  medium:   "text-yellow-400 border-yellow-400/40",
  low:      "text-green-400 border-green-400/40",
};

export default function WafBypassPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(true);
  const [useAi, setUseAi] = useState(true);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/waf-bypass`, {
        params: { use_ai: useAi },
        withCredentials: true,
      });
      setData(r.data.waf_bypass);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo al calcular bypass");
    } finally { setLoading(false); }
  };

  return (
    <section data-testid="waf-bypass-panel" className="border border-white/[0.08] bg-[#0A0A0C]">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-5 py-3 bg-[#101014] border-b border-white/[0.06] flex items-center gap-3 hover:bg-[#141419] transition-colors"
      >
        <ShieldOff className="w-4 h-4 text-cyan-400" />
        <h3 className="font-heading text-sm font-bold uppercase tracking-wide flex-1 text-left">
          WAF Bypass Suggestor
          <span className="ml-2 font-mono-data text-[9px] uppercase tracking-widest text-cyan-400 border border-cyan-400/30 px-1.5 py-0.5">
            IA Táctica
          </span>
        </h3>
        {open ? <ChevronUp className="w-4 h-4 text-white/40" /> : <ChevronDown className="w-4 h-4 text-white/40" />}
      </button>

      {open && (
        <div className="p-5 space-y-4">
          {!data && (
            <div>
              <p className="text-sm text-white/60 mb-4 leading-relaxed">
                Analiza los WAFs/CDN detectados en el objetivo y genera un <b className="text-white/90">playbook táctico</b> con
                técnicas de bypass ordenadas por probabilidad de éxito (uso ético · bug bounty autorizado).
              </p>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 cursor-pointer text-xs text-white/70">
                  <input
                    type="checkbox"
                    checked={useAi}
                    onChange={(e) => setUseAi(e.target.checked)}
                    data-testid="waf-bypass-ai-toggle"
                    className="w-3.5 h-3.5 accent-cyan-400"
                  />
                  Resumen táctico con IA
                </label>
                <button
                  onClick={run}
                  disabled={loading}
                  data-testid="waf-bypass-run-btn"
                  className="bg-cyan-400 text-black font-semibold px-5 py-2.5 hover:bg-cyan-300 disabled:opacity-40 transition-colors inline-flex items-center gap-2 font-mono-data text-[10px] uppercase tracking-widest"
                >
                  {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                  Analizar Evasión
                </button>
              </div>
            </div>
          )}

          {data && (
            <div className="space-y-5">
              {/* HEADER RESULT */}
              <div className="flex flex-wrap items-center gap-3">
                {data.waf_detected ? (
                  <span className="font-mono-data text-[10px] uppercase tracking-widest text-yellow-400 border border-yellow-400/40 px-2 py-1">
                    WAF Detectado
                  </span>
                ) : (
                  <span className="font-mono-data text-[10px] uppercase tracking-widest text-green-400 border border-green-400/40 px-2 py-1">
                    Sin WAF · Objetivo Expuesto
                  </span>
                )}
                {data.wafs.map((w) => (
                  <span key={w} className="font-mono-data text-[11px] text-cyan-400 border border-cyan-400/30 px-2 py-0.5">
                    {w}
                  </span>
                ))}
                <button
                  onClick={run}
                  disabled={loading}
                  className="ml-auto font-mono-data text-[9px] uppercase tracking-widest text-white/60 hover:text-cyan-400"
                >
                  {loading ? "..." : "Recalcular"}
                </button>
              </div>

              {/* AI SUMMARY */}
              {data.ai_summary && (
                <div className="border border-cyan-400/25 bg-cyan-400/[0.03] p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-cyan-400">
                      Briefing Táctico · IA
                    </span>
                  </div>
                  <p className="text-sm text-white/80 leading-relaxed whitespace-pre-line">{data.ai_summary}</p>
                </div>
              )}

              {/* PER-WAF PLAYBOOK */}
              {data.playbook.map((entry) => (
                <div key={entry.waf} className="border border-white/[0.08]">
                  <div className="px-4 py-2 bg-[#101014] flex items-center gap-3 border-b border-white/[0.06]">
                    <span className="font-heading text-sm font-bold">{entry.waf}</span>
                    <span className={`font-mono-data text-[9px] uppercase tracking-widest px-2 py-0.5 border ${RISK_COLOR[entry.risk] || "text-white/50 border-white/20"}`}>
                      Riesgo: {entry.risk}
                    </span>
                  </div>
                  {entry.notes.length > 0 && (
                    <div className="px-4 py-3 border-b border-white/[0.06] bg-black/40">
                      {entry.notes.map((n, i) => (
                        <p key={i} className="text-xs text-white/60 leading-relaxed">
                          <span className="text-cyan-400">›</span> {n}
                        </p>
                      ))}
                    </div>
                  )}
                  <div className="divide-y divide-white/[0.05]">
                    {entry.techniques.map((t, i) => (
                      <div key={i} className="px-4 py-3">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`font-mono-data text-[9px] uppercase tracking-widest px-1.5 py-0.5 border ${CAT_COLOR[t.category] || "text-white/50 border-white/20"}`}>
                            {t.category}
                          </span>
                          <span className="font-mono-data text-sm text-white/90">{t.name}</span>
                        </div>
                        <p className="text-xs text-white/60 leading-relaxed pl-1">{t.detail}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {/* GENERIC */}
              <div className="border border-white/[0.05]">
                <div className="px-4 py-2 bg-[#0C0C10] border-b border-white/[0.05]">
                  <span className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50">
                    Técnicas genéricas (siempre aplicables)
                  </span>
                </div>
                <div className="divide-y divide-white/[0.05]">
                  {data.generic.map((t, i) => (
                    <div key={i} className="px-4 py-2.5">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`font-mono-data text-[9px] uppercase tracking-widest px-1.5 py-0.5 border ${CAT_COLOR[t.category] || "text-white/50 border-white/20"}`}>
                          {t.category}
                        </span>
                        <span className="text-xs text-white/85">{t.name}</span>
                      </div>
                      <p className="text-[11px] text-white/50 leading-relaxed pl-1">{t.detail}</p>
                    </div>
                  ))}
                </div>
              </div>

              <p className="text-[10px] text-white/30 font-mono-data uppercase tracking-widest text-center pt-2 border-t border-white/[0.04]">
                ⚠️ Solo para pentest autorizado / bug bounty programs
              </p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
