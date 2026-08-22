import { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  ShieldAlert, Loader2, ChevronDown, ChevronUp, ExternalLink, Bug, Copy,
  Target, ShieldCheck, Zap, Clock, AlertTriangle,
} from "lucide-react";
import { API } from "@/lib/auth";

const SEV_CLR = {
  critical: "text-red-400 border-red-400/40 bg-red-400/[0.05]",
  high:     "text-orange-400 border-orange-400/40 bg-orange-400/[0.05]",
  medium:   "text-yellow-400 border-yellow-400/40 bg-yellow-400/[0.05]",
  low:      "text-green-400 border-green-400/40 bg-green-400/[0.05]",
  expired:  "text-red-400 border-red-400/40 bg-red-400/[0.05]",
  warning:  "text-yellow-400 border-yellow-400/40 bg-yellow-400/[0.05]",
  ok:       "text-green-400 border-green-400/40",
  clean:    "text-green-400 border-green-400/40",
};

function Section({ icon: Icon, title, badge, open, setOpen, children, testid }) {
  return (
    <section data-testid={testid} className="border border-white/[0.08] bg-[#0A0A0C]">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-5 py-3 bg-[#101014] border-b border-white/[0.06] flex items-center gap-3 hover:bg-[#141419] transition-colors"
      >
        <Icon className="w-4 h-4 text-cyan-400" />
        <h3 className="font-heading text-sm font-bold uppercase tracking-wide flex-1 text-left">
          {title}
          {badge && (
            <span className="ml-2 font-mono-data text-[9px] uppercase tracking-widest text-cyan-400 border border-cyan-400/30 px-1.5 py-0.5">
              {badge}
            </span>
          )}
        </h3>
        {open ? <ChevronUp className="w-4 h-4 text-white/40" /> : <ChevronDown className="w-4 h-4 text-white/40" />}
      </button>
      {open && <div className="p-5 space-y-4">{children}</div>}
    </section>
  );
}

// ─── CVE / EPSS / KEV ─────────────────────────────────────
export function CveEnginePanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/cve-correlate`, { withCredentials: true });
        setData(r.data.cve_correlation);
      } catch { /* silent */ }
    })();
  }, [scanId]);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/cve-correlate`, {}, { withCredentials: true });
      setData(r.data.cve_correlation);
      toast.success(`${r.data.cve_correlation.summary.total_cves} CVEs correlacionadas`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo");
    } finally { setLoading(false); }
  };

  return (
    <Section icon={Bug} title="CVE · EPSS · KEV Correlation" badge="Killer"
             open={open} setOpen={setOpen} testid="cve-engine-panel">
      {!data && !loading && (
        <button onClick={run} data-testid="cve-run-btn"
                className="bg-cyan-400 text-black font-semibold px-5 py-2.5 hover:bg-cyan-300 inline-flex items-center gap-2 font-mono-data text-[10px] uppercase tracking-widest">
          <Zap className="w-3.5 h-3.5" /> Analizar CVEs
        </button>
      )}
      {loading && <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />}
      {data && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
            {[
              ["Total CVEs", data.summary.total_cves, "text-white"],
              ["Critical", data.summary.critical, "text-red-400"],
              ["High", data.summary.high, "text-orange-400"],
              ["KEV Hits", data.summary.kev_count, "text-red-400"],
              ["Risk uplift", `+${data.summary.risk_uplift}`, "text-cyan-400"],
            ].map(([label, val, clr]) => (
              <div key={label} className="border border-white/[0.06] p-3">
                <div className={`font-heading text-xl font-black ${clr}`}>{val}</div>
                <div className="font-mono-data text-[9px] uppercase tracking-widest text-white/40 mt-1">{label}</div>
              </div>
            ))}
          </div>
          {data.kev_hits.length > 0 && (
            <div className="border border-red-400/30 bg-red-400/[0.03] p-3">
              <div className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-red-400 mb-2">
                🚨 CISA KEV · Exploitation en el mundo real
              </div>
              {data.kev_hits.slice(0, 6).map((k) => (
                <div key={k.id} className="text-xs text-white/80 py-1 border-b border-white/[0.04] last:border-0">
                  <code className="text-red-400">{k.id}</code> · <b>{k.tech}</b> ·
                  {k.kev?.ransomware && <span className="ml-1 text-red-400">💀 Ransomware</span>}
                  <div className="text-white/50 mt-0.5">{k.description?.slice(0, 200)}</div>
                </div>
              ))}
            </div>
          )}
          {data.top_risky.length > 0 && (
            <div>
              <div className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-2">
                Top 10 riesgos (CVSS × EPSS × KEV)
              </div>
              <div className="space-y-1.5">
                {data.top_risky.slice(0, 10).map((c) => (
                  <div key={c.id} className="flex items-center gap-2 text-xs border border-white/[0.05] p-2">
                    <span className={`font-mono-data text-[9px] uppercase tracking-widest px-1.5 py-0.5 border ${SEV_CLR[c.severity] || "text-white/50 border-white/20"}`}>
                      {c.severity || "?"}
                    </span>
                    <code className="text-cyan-400">{c.id}</code>
                    <span className="text-white/40">·</span>
                    <span className="font-mono-data text-cyan-400">CVSS {c.cvss || "?"}</span>
                    {c.epss?.score && (
                      <>
                        <span className="text-white/40">·</span>
                        <span className="font-mono-data text-yellow-400">
                          EPSS {(c.epss.score * 100).toFixed(1)}%
                        </span>
                      </>
                    )}
                    {c.kev && <span className="font-mono-data text-red-400 border border-red-400/40 px-1">KEV</span>}
                    <span className="text-white/60 flex-1 truncate">{c.description?.slice(0, 100)}</span>
                    <span className="font-mono-data text-[10px] text-white/40">score={c.score}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <button onClick={run} className="font-mono-data text-[9px] uppercase tracking-widest text-white/60 hover:text-cyan-400">
            Recalcular
          </button>
        </>
      )}
    </Section>
  );
}

// ─── TYPOSQUAT HUNTER ─────────────────────────────────────
export function TyposquatPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/typosquat`, { withCredentials: true });
        setData(r.data.typosquat);
      } catch { /* silent */ }
    })();
  }, [scanId]);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/typosquat`, {}, { withCredentials: true });
      setData(r.data.typosquat);
      toast.success(`${r.data.typosquat.registered_count} dominios sospechosos detectados`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo");
    } finally { setLoading(false); }
  };

  return (
    <Section icon={Target} title="Typosquatting / Homograph Hunter" badge="Brand Protection"
             open={open} setOpen={setOpen} testid="typosquat-panel">
      {!data && !loading && (
        <button onClick={run} data-testid="typosquat-run-btn"
                className="bg-cyan-400 text-black font-semibold px-5 py-2.5 hover:bg-cyan-300 inline-flex items-center gap-2 font-mono-data text-[10px] uppercase tracking-widest">
          <Zap className="w-3.5 h-3.5" /> Cazar variantes
        </button>
      )}
      {loading && <div className="text-xs font-mono-data text-white/60"><Loader2 className="w-4 h-4 animate-spin inline mr-2" />Generando y sondeando DNS...</div>}
      {data && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <span className={`font-mono-data text-[10px] uppercase tracking-widest px-2 py-1 border ${SEV_CLR[data.risk_level] || "text-white/50 border-white/20"}`}>
              Riesgo: {data.risk_level}
            </span>
            <span className="font-mono-data text-xs text-white/60">
              {data.variants_generated} variantes generadas · {data.registered_count} registradas
            </span>
            <button onClick={run} className="ml-auto font-mono-data text-[9px] uppercase tracking-widest text-white/60 hover:text-cyan-400">
              Rescan
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-96 overflow-y-auto">
            {data.registered.map((r) => (
              <div key={r.variant} className="border border-white/[0.06] p-2.5 text-xs">
                <div className="flex items-center gap-2 mb-1">
                  <code className="text-cyan-400 flex-1 truncate">{r.variant}</code>
                  <span className={`font-mono-data text-[9px] uppercase tracking-widest px-1.5 py-0.5 border ${
                    r.kind === "homoglyph" ? "text-red-400 border-red-400/40"
                    : r.kind === "tld_swap" ? "text-orange-400 border-orange-400/40"
                    : "text-yellow-400 border-yellow-400/40"
                  }`}>
                    {r.kind}
                  </span>
                </div>
                <div className="font-mono-data text-[10px] text-white/50">
                  IP: <span className="text-white/80">{r.ip || "?"}</span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </Section>
  );
}

// ─── MITRE ATT&CK ────────────────────────────────────────
export function AttackMappingPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/attack-mapping`, { withCredentials: true });
      setData(r.data.attack_mapping);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo");
    } finally { setLoading(false); }
  };

  useEffect(() => { if (open && !data) run(); }, [open]);

  return (
    <Section icon={Target} title="MITRE ATT&CK Mapping" badge="Enterprise"
             open={open} setOpen={setOpen} testid="attack-mapping-panel">
      {loading && <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />}
      {data && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-mono-data text-xs text-white/60">
              <b className="text-cyan-400">{data.coverage}</b> técnicas mapeadas · {data.findings_matched} hallazgos matched
            </span>
            <a href={`${API}/scans/${scanId}/attack-navigator`}
               data-testid="download-navigator-btn"
               className="ml-auto font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 hover:underline inline-flex items-center gap-1">
              <ExternalLink className="w-3 h-3" /> Descargar Navigator layer
            </a>
          </div>
          <div className="space-y-3">
            {data.tactics.map((t) => (
              <div key={t.tactic} className="border border-white/[0.06]">
                <div className="px-3 py-2 bg-[#101014] border-b border-white/[0.06]">
                  <code className="text-cyan-400 font-mono-data text-xs">{t.tactic}</code>
                  <span className="ml-2 font-heading font-bold text-sm">{t.tactic_name}</span>
                </div>
                <div className="divide-y divide-white/[0.05]">
                  {t.techniques.map((tech) => (
                    <div key={tech.id} className="px-3 py-2 flex items-start gap-3">
                      <code className="text-cyan-400 font-mono-data text-xs">{tech.id}</code>
                      <div className="flex-1">
                        <div className="text-sm text-white/90">{tech.name}</div>
                        <div className="text-[11px] text-white/40 mt-0.5">
                          {tech.sources.join(" · ")}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </Section>
  );
}

// ─── CERT EXPIRATION ─────────────────────────────────────
export function CertMonitorPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);

  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/cert-monitor`, {}, { withCredentials: true });
      setData(r.data.cert_monitor);
      toast.success(`${r.data.cert_monitor.hosts_reachable} certificados analizados`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/cert-monitor`, { withCredentials: true });
        setData(r.data.cert_monitor);
      } catch { /* silent */ }
    })();
  }, [scanId]);

  return (
    <Section icon={Clock} title="SSL Cert Expiration Monitor"
             open={open} setOpen={setOpen} testid="cert-monitor-panel">
      {!data && !loading && (
        <button onClick={run} data-testid="cert-run-btn"
                className="bg-cyan-400 text-black font-semibold px-5 py-2.5 hover:bg-cyan-300 inline-flex items-center gap-2 font-mono-data text-[10px] uppercase tracking-widest">
          <Zap className="w-3.5 h-3.5" /> Analizar certificados
        </button>
      )}
      {loading && <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />}
      {data && (
        <>
          <div className="grid grid-cols-4 gap-2">
            {["expired", "critical", "warning", "ok"].map((k) => (
              <div key={k} className={`border p-3 ${SEV_CLR[k]}`}>
                <div className="font-heading text-2xl font-black">{data.counts[k]}</div>
                <div className="font-mono-data text-[9px] uppercase tracking-widest mt-1">{k}</div>
              </div>
            ))}
          </div>
          {["expired", "critical", "warning"].map((k) =>
            data.buckets[k].length > 0 && (
              <div key={k}>
                <div className={`font-mono-data text-[10px] uppercase tracking-[0.25em] mb-2 ${SEV_CLR[k].split(" ")[0]}`}>
                  {k === "expired" ? "🚨 Ya expirados" : k === "critical" ? "⚠️ Expiran en <7 días" : "Expiran en <30 días"}
                </div>
                <div className="space-y-1">
                  {data.buckets[k].map((c) => (
                    <div key={c.host} className="text-xs border border-white/[0.06] p-2 flex items-center gap-3">
                      <code className="text-cyan-400 flex-1 truncate">{c.host}</code>
                      <span className="font-mono-data text-white/60">{c.days_remaining} días</span>
                      <span className="text-white/40 truncate max-w-[200px]">{c.issuer}</span>
                    </div>
                  ))}
                </div>
              </div>
            )
          )}
          <button onClick={run} className="font-mono-data text-[9px] uppercase tracking-widest text-white/60 hover:text-cyan-400">
            Rescan
          </button>
        </>
      )}
    </Section>
  );
}
