/* Presentational building blocks for the scan detail view.
 * Extracted verbatim from ScanDetail.jsx (Fase 3) so they can be reused
 * and unit-tested independently. Pure components — no data fetching.
 */
import { CheckCircle2, AlertTriangle, XCircle } from "lucide-react";

export function Panel({ title, icon: Icon, children, id, accent = "cyan", right = null }) {
  const accentCls = {
    cyan: "text-cyan-400",
    green: "text-green-400",
    red: "text-red-400",
    orange: "text-orange-400",
  }[accent];
  return (
    <section id={id} data-testid={id ? `panel-${id}` : undefined}
      className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          {Icon && <Icon className={`w-4 h-4 ${accentCls}`} />}
          <h3 className="font-heading text-sm font-bold tracking-wide uppercase">{title}</h3>
        </div>
        {right}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

export function MetricCard({ icon: Icon, label, value, sub, tone = "neutral" }) {
  const toneCls = {
    neutral: "border-white/[0.08] text-white",
    good:    "border-green-400/40 text-green-400",
    warn:    "border-orange-400/40 text-orange-400",
    bad:     "border-red-400/50 text-red-400",
    accent:  "border-cyan-400/40 text-cyan-400",
  }[tone];
  return (
    <div data-testid={`metric-${label.toLowerCase().replace(/\s+/g, "-")}`}
      className={`relative border ${toneCls} bg-[#0A0A0C] p-5 overflow-hidden`}>
      <div className="absolute top-0 right-0 opacity-[0.06]">
        <Icon className="w-24 h-24 -mt-4 -mr-4" />
      </div>
      <div className="relative">
        <div className="flex items-center gap-2 mb-3">
          <Icon className="w-3.5 h-3.5 opacity-70" />
          <span className="font-mono-data text-[10px] uppercase tracking-[0.25em] opacity-60">
            {label}
          </span>
        </div>
        <div className="font-heading text-3xl font-black leading-none">{value}</div>
        {sub && (
          <div className="font-mono-data text-[11px] uppercase tracking-widest opacity-50 mt-2">
            {sub}
          </div>
        )}
      </div>
    </div>
  );
}

export function KV({ label, value }) {
  return (
    <div className="grid grid-cols-3 gap-3 py-2 border-b border-white/[0.05]">
      <div className="font-mono-data text-[11px] uppercase tracking-widest text-white/40">{label}</div>
      <div className="col-span-2 font-mono-data text-sm text-white/85 break-all">{value ?? "—"}</div>
    </div>
  );
}

export function StatusIcon({ status }) {
  if (status === "pass") return <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />;
  if (status === "warn") return <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0" />;
  return <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />;
}

export function SecurityChecks({ items }) {
  if (!items?.length) return <p className="text-white/40 text-sm">Sin resultados</p>;
  return (
    <ul className="space-y-0 border-t border-white/[0.05]">
      {items.map((it, i) => (
        <li key={i} className="flex items-start gap-3 py-3 border-b border-white/[0.05]">
          <StatusIcon status={it.status} />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium">{it.check}</div>
            <div className="font-mono-data text-xs text-white/50 mt-0.5 break-all">{it.detail}</div>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function ScoreCircle({ score, label }) {
  const color = score >= 80 ? "#39FF14" : score >= 50 ? "#FFAA00" : "#FF3355";
  const r = 40;
  const c = 2 * Math.PI * r;
  const off = c - (score / 100) * c;
  return (
    <div className="flex flex-col items-center">
      <div className="relative w-24 h-24">
        <svg className="transform -rotate-90 w-24 h-24">
          <circle cx="48" cy="48" r={r} stroke="rgba(255,255,255,0.06)" strokeWidth="4" fill="none" />
          <circle cx="48" cy="48" r={r} stroke={color} strokeWidth="4" fill="none"
            strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 0.6s ease", filter: `drop-shadow(0 0 8px ${color}88)` }} />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center font-heading font-black text-xl"
             style={{ color, textShadow: `0 0 12px ${color}88` }}>
          {score}
        </div>
      </div>
      <div className="font-mono-data text-[10px] uppercase tracking-[0.2em] text-white/50 mt-2">{label}</div>
    </div>
  );
}
