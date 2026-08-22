import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Sparkles, ShieldCheck, AlertTriangle, ShieldX, Target, Loader2, RefreshCw } from "lucide-react";
import { API } from "@/lib/auth";

const LEVEL_STYLES = {
  green: {
    border: "border-green-400/60",
    glow: "0 0 60px rgba(0,204,102,0.12), inset 0 0 40px rgba(0,204,102,0.03)",
    accent: "text-green-400",
    bg: "from-green-500/[0.04] to-transparent",
    strip: "bg-green-400",
    icon: ShieldCheck,
    label: "CONFIANZA ALTA",
    tone: "text-green-400",
  },
  orange: {
    border: "border-orange-400/60",
    glow: "0 0 60px rgba(255,176,0,0.10), inset 0 0 40px rgba(255,176,0,0.03)",
    accent: "text-orange-400",
    bg: "from-orange-500/[0.04] to-transparent",
    strip: "bg-orange-400",
    icon: AlertTriangle,
    label: "CONFIANZA MEDIA",
    tone: "text-orange-400",
  },
  red: {
    border: "border-red-400/60",
    glow: "0 0 60px rgba(255,51,102,0.14), inset 0 0 40px rgba(255,51,102,0.04)",
    accent: "text-red-400",
    bg: "from-red-500/[0.05] to-transparent",
    strip: "bg-red-400",
    icon: ShieldX,
    label: "CONFIANZA BAJA",
    tone: "text-red-400",
  },
};

export default function IntelSummary({ scanId, domain }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);

  const load = async (force = false) => {
    try {
      const url = `${API}/scans/${scanId}/intel${force ? `?_=${Date.now()}` : ""}`;
      const r = await axios.get(url, { withCredentials: true, timeout: 60000 });
      setData(r.data.intel);
    } catch {
      toast.error("No se pudo generar el resumen de inteligencia");
    } finally {
      setLoading(false);
      setRegenerating(false);
    }
  };

  useEffect(() => { load(); }, [scanId]);

  const downloadPdf = async () => {
    try {
      toast.info("Generando PDF...");
      const r = await axios.get(`${API}/scans/${scanId}/pdf`, {
        withCredentials: true, responseType: "blob", timeout: 60000,
      });
      const url = window.URL.createObjectURL(new Blob([r.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `noctua_${domain}_${scanId}.pdf`;
      document.body.appendChild(a); a.click(); a.remove();
      window.URL.revokeObjectURL(url);
      toast.success("PDF descargado");
    } catch {
      toast.error("No se pudo generar el PDF");
    }
  };

  if (loading) {
    return (
      <section
        data-testid="intel-summary-loading"
        className="border border-cyan-400/30 bg-[#0C0C0E] p-8 mb-8 flex items-center gap-4"
      >
        <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
        <div>
          <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-cyan-400 mb-1">
            Analizando hallazgos
          </div>
          <p className="text-sm text-white/60">
            Claude Sonnet 4.5 está procesando subdominios, tecnologías, historial y postura de seguridad…
          </p>
        </div>
      </section>
    );
  }

  if (!data) return null;

  const level = data.risk_level || "orange";
  const style = LEVEL_STYLES[level] || LEVEL_STYLES.orange;
  const Icon = style.icon;

  return (
    <section
      data-testid="intel-summary"
      className={`relative border-2 ${style.border} bg-gradient-to-b ${style.bg} p-8 mb-10 overflow-hidden`}
      style={{ boxShadow: style.glow }}
    >
      {/* colored top strip */}
      <div className={`absolute top-0 left-0 right-0 h-1 ${style.strip}`} />

      <div className="flex items-start justify-between flex-wrap gap-4 mb-6">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 border-2 ${style.border} flex items-center justify-center`}>
            <Icon className={`w-5 h-5 ${style.accent}`} />
          </div>
          <div>
            <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/50 flex items-center gap-2">
              <Sparkles className="w-3 h-3" /> Resumen de Inteligencia · Claude Sonnet 4.5
            </div>
            <h2 className="font-heading text-xl font-black tracking-tight">
              {domain}
            </h2>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className={`border-2 ${style.border} px-5 py-3 text-center`}>
            <div className="font-mono-data text-[9px] uppercase tracking-[0.25em] text-white/50">
              Nivel de confianza
            </div>
            <div data-testid="intel-confidence" className={`font-heading text-xl font-black ${style.tone} leading-tight mt-1`}>
              {data.confidence?.toUpperCase() || "MEDIA"}
            </div>
          </div>
          <button
            onClick={() => { setRegenerating(true); load(true); }}
            disabled={regenerating}
            data-testid="regen-intel-btn"
            title="Regenerar con IA"
            className="border border-white/15 p-3 hover:border-cyan-400 hover:text-cyan-400 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-4 h-4 ${regenerating ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={downloadPdf}
            data-testid="download-pdf-btn"
            className="bg-cyan-400 text-black font-semibold px-5 py-3 hover:bg-cyan-300 transition-colors inline-flex items-center gap-2"
          >
            <Target className="w-4 h-4" />
            <span className="font-mono-data text-xs uppercase tracking-widest">Exportar PDF</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 1. PERFIL */}
        <div className="border-l-2 border-cyan-400/60 pl-5">
          <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-cyan-400 mb-2">
            01 · Perfil del sitio
          </div>
          <p data-testid="intel-profile" className="text-sm text-white/85 leading-relaxed">
            {data.profile}
          </p>
        </div>

        {/* 2. PUNTOS CRÍTICOS */}
        <div className={`border-l-2 ${style.border.replace("/60", "/80")} pl-5`}>
          <div className={`font-mono-data text-[10px] uppercase tracking-[0.3em] ${style.accent} mb-2`}>
            02 · Puntos críticos
          </div>
          <ul data-testid="intel-risks" className="space-y-3">
            {(data.critical_risks || []).map((r, i) => (
              <li key={i} className="flex gap-3 text-sm text-white/85 leading-relaxed">
                <span className={`font-heading font-black ${style.tone} flex-shrink-0`}>{String(i + 1).padStart(2, "0")}</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* 3. CONCLUSIÓN */}
        <div className="border-l-2 border-white/20 pl-5">
          <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/60 mb-2">
            03 · Conclusión
          </div>
          <div className="space-y-2 font-mono-data text-sm">
            <div className="flex justify-between border-b border-white/10 py-1.5">
              <span className="text-white/50 text-xs uppercase tracking-widest">Antigüedad</span>
              <span className="text-white/90">{data.risk_meta?.age_years != null ? `${data.risk_meta.age_years} años` : "N/D"}</span>
            </div>
            <div className="flex justify-between border-b border-white/10 py-1.5">
              <span className="text-white/50 text-xs uppercase tracking-widest">Score global</span>
              <span className={`${style.tone} font-bold`}>{data.risk_meta?.score_average ?? 0}%</span>
            </div>
            <div className="flex justify-between border-b border-white/10 py-1.5">
              <span className="text-white/50 text-xs uppercase tracking-widest">Protección WAF</span>
              <span className={data.risk_meta?.protected ? "text-green-400" : "text-yellow-400"}>
                {data.risk_meta?.protected ? "Activa" : "No detectada"}
              </span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-white/50 text-xs uppercase tracking-widest">Puertos sensibles</span>
              <span className={data.risk_meta?.exposed_risky_ports?.length ? "text-red-400" : "text-green-400"}>
                {data.risk_meta?.exposed_risky_ports?.length || 0}
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
