/* Shared helpers for the Bug Bounty toolkit tab.
 * Extracted verbatim from BountyTab.jsx (Fase 3): CopyLink, SevBadge,
 * the useRunner hook and the Section wrapper.
 */
import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Loader2, Play, Copy, Check } from "lucide-react";

export function CopyLink({ text }) {
  const [c, setC] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setC(true); setTimeout(() => setC(false), 1500); }}
      className="text-white/40 hover:text-cyan-400 p-1" title="Copiar">
      {c ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

export function SevBadge({ level }) {
  const cls = {
    critical: "border-red-400 text-red-400",
    high: "border-orange-400 text-orange-400",
    medium: "border-cyan-400 text-cyan-400",
    low: "border-white/25 text-white/50",
    info: "border-white/15 text-white/40",
  }[level] || "border-white/15 text-white/40";
  return (
    <span className={`font-mono-data text-[9px] uppercase tracking-widest px-1.5 py-0.5 border ${cls}`}>
      {level}
    </span>
  );
}

export function useRunner(url) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(url, { withCredentials: true, timeout: 90000 });
      setData(r.data);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error");
    } finally { setLoading(false); }
  };
  return { data, loading, run };
}

export function Section({ title, icon: Icon, accent, runner, description, children }) {
  const iconClass = {
    cyan: "text-cyan-400", red: "text-red-400", orange: "text-orange-400",
    purple: "text-purple-400", green: "text-green-400",
  }[accent] || "text-cyan-400";
  return (
    <section className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <Icon className={`w-4 h-4 ${iconClass}`} />
          <h3 className="font-heading text-sm font-bold uppercase tracking-wide">{title}</h3>
        </div>
        <button onClick={runner.run} disabled={runner.loading}
          className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5">
          {runner.loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
          {runner.data ? "Reescanear" : "Ejecutar"}
        </button>
      </div>
      <div className="p-5">
        {!runner.data && !runner.loading && description && (
          <p className="text-sm text-white/50">{description}</p>
        )}
        {children}
      </div>
    </section>
  );
}
