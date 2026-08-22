import { useEffect, useMemo, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import {
  Radar, ArrowLeft, Globe, Server, Lock, Network, Wifi, ShieldCheck, ShieldAlert,
  ShieldX, Terminal, Sparkles, CheckCircle2, AlertTriangle, XCircle, Loader2, Map,
  Layers, Shield, Unlock, Clock, Target, User, AtSign, Search as SearchIcon,
  Activity, Bug, Skull, Database, Fingerprint, Cpu, Copy, GitBranch, Brain,
  Tag, Sparkle, Flag,
} from "lucide-react";
import { API, useAuth } from "@/lib/auth";
import ServerMapModal from "@/components/ServerMapModal";
import WaybackTimeline from "@/components/WaybackTimeline";
import IntelSummary from "@/components/IntelSummary";
import ReputationPanel from "@/components/ReputationPanel";
import ShodanPanel from "@/components/ShodanPanel";
import CloudStoragePanel from "@/components/CloudStoragePanel";
import MetadataPanel from "@/components/MetadataPanel";
import WafBypassPanel from "@/components/WafBypassPanel";
import { CveEnginePanel, TyposquatPanel, AttackMappingPanel, CertMonitorPanel } from "@/components/CompetitivePanels";
import IntelligenceMap from "@/components/IntelligenceMap";
import TakeoverPanel from "@/components/TakeoverPanel";
import PasteMonitorPanel from "@/components/PasteMonitorPanel";
import JsMinerPanel from "@/components/JsMinerPanel";
import CtLogsPanel from "@/components/CtLogsPanel";
import ShodanDeepPanel from "@/components/ShodanDeepPanel";
import ScanDiffPanel from "@/components/ScanDiffPanel";
import PredictiveTab from "@/pages/PredictiveTab";
import BountyTab from "@/pages/BountyTab";
import { Panel, MetricCard, KV, SecurityChecks, ScoreCircle } from "@/components/scan/ScanUI";
import FactorHumanoTab from "@/components/scan/FactorHumanoTab";
import EdgeTab from "@/components/edge/EdgeTab";

/* ─────────────────  MAIN PAGE  ───────────────── */

const TABS = [
  { id: "resumen",    label: "Resumen Inteligente",   icon: Target,      hint: "Vista general · IA · Mapa · Riesgos" },
  { id: "infra",      label: "Infraestructura",       icon: Network,     hint: "Subdominios · IPs · Tecnologías · CT Logs" },
  { id: "seguridad",  label: "Seguridad Técnica",     icon: Shield,      hint: "Shodan · Takeover · Cloud · Metadatos" },
  { id: "humano",     label: "Factor Humano",         icon: User,        hint: "Brechas · JS Miner" },
  { id: "mapa",       label: "Mapa de Inteligencia",  icon: GitBranch,   hint: "Grafo de red interactivo" },
  { id: "predict",    label: "Inteligencia Predictiva", icon: Brain,     hint: "Attack Path · Oracle · DNA · Brand · PoC" },
  { id: "bounty",     label: "Bug Bounty Toolkit",    icon: Bug,         hint: "Params · Cloud config · APIs · Rollbacks · Delta" },
  { id: "ventaja",    label: "Ventaja Competitiva",   icon: ShieldCheck, hint: "Explotabilidad · Notarizar · Autopilot · Score · IA" },
];

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const isPro = user?.plan === "pro";
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showMap, setShowMap] = useState(false);
  const [tab, setTab] = useState("resumen");
  const [shodanMeta, setShodanMeta] = useState(null);
  const [repMeta, setRepMeta] = useState(null);
  const [takeoverMeta, setTakeoverMeta] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}`, { withCredentials: true });
        setData(r.data);
      } catch {
        toast.error("No se pudo cargar el escaneo");
      } finally { setLoading(false); }
    })();
  }, [scanId]);

  // Fetch light meta from shodan / reputation / takeover for header badges
  useEffect(() => {
    (async () => {
      try {
        const [sh, rp, tk] = await Promise.all([
          axios.get(`${API}/scans/${scanId}/shodan`, { withCredentials: true }).catch(() => null),
          axios.get(`${API}/scans/${scanId}/reputation`, { withCredentials: true }).catch(() => null),
          axios.get(`${API}/scans/${scanId}/takeover`, { withCredentials: true, timeout: 120000 }).catch(() => null),
        ]);
        setShodanMeta(sh?.data?.shodan || null);
        setRepMeta(rp?.data?.reputation || null);
        setTakeoverMeta(tk?.data?.takeover || null);
      } catch (_) { /* silent - these are enrichments */ }
    })();
  }, [scanId]);

  const downloadPdf = async () => {
    try {
      toast.info("Generando PDF…");
      const r = await axios.get(`${API}/scans/${scanId}/pdf`, {
        withCredentials: true, responseType: "blob", timeout: 60000,
      });
      const url = window.URL.createObjectURL(new Blob([r.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url; a.download = `noctua_${data?.result?.domain}_${scanId}.pdf`;
      document.body.appendChild(a); a.click(); a.remove();
      window.URL.revokeObjectURL(url);
      toast.success("PDF descargado");
    } catch {
      toast.error("Error al generar PDF");
    }
  };

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(data?.result || {}, null, 2));
    toast.success("JSON copiado");
  };

  const r = data?.result;
  const security = r?.security;
  const totalRisk = useMemo(() => {
    if (!security) return 0;
    return Math.round(((security.basic?.score || 0) + (security.medium?.score || 0) + (security.advanced?.score || 0)) / 3);
  }, [security]);

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
      </div>
    );
  }
  if (!r) {
    return <div className="min-h-screen bg-black flex items-center justify-center text-white/50">Escaneo no encontrado</div>;
  }

  const cveCount = shodanMeta?.total_vulns || 0;
  const worstAbuse = repMeta?.worst_score || 0;
  const takeoverCount = takeoverMeta?.vulnerable_count || 0;

  return (
    <div data-testid="scan-detail-page" className="relative min-h-screen bg-black text-white grain">
      {/* ── HEADER (sticky, PDF button always visible) ── */}
      <header className="sticky top-0 z-30 backdrop-blur-xl bg-black/80 border-b border-white/[0.08]">
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4 min-w-0">
            <button
              onClick={() => navigate("/dashboard")}
              data-testid="back-to-dashboard"
              className="inline-flex items-center gap-2 border border-white/[0.08] px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span className="font-mono-data text-[10px] uppercase tracking-widest">Volver</span>
            </button>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
                <span className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-cyan-400">
                  ANÁLISIS ACTIVO
                </span>
              </div>
              <div data-testid="scan-domain-header" className="font-heading text-2xl font-black truncate term-cursor">
                {r.domain}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button onClick={copyJson} title="Copiar JSON" className="border border-white/[0.08] p-2.5 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
              <Copy className="w-4 h-4" />
            </button>
            <button
              onClick={downloadPdf}
              data-testid="header-pdf-btn"
              className="bg-cyan-400 text-black font-semibold px-5 py-2.5 hover:bg-cyan-300 transition-colors inline-flex items-center gap-2 shadow-[0_0_20px_rgba(0,229,255,0.25)]"
            >
              <Target className="w-4 h-4" />
              <span className="font-mono-data text-xs uppercase tracking-widest">Exportar PDF</span>
            </button>
          </div>
        </div>

        {/* ── TAB BAR ── */}
        <nav data-testid="tab-bar" className="max-w-[1600px] mx-auto px-6 flex overflow-x-auto no-scrollbar border-t border-white/[0.04]">
          {TABS.map((t) => {
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                data-testid={`tab-${t.id}`}
                className={`relative flex items-center gap-3 px-5 py-4 whitespace-nowrap transition-colors border-b-2 ${
                  active
                    ? "border-cyan-400 text-white bg-white/[0.02]"
                    : "border-transparent text-white/50 hover:text-white hover:bg-white/[0.01]"
                }`}
              >
                <t.icon className={`w-4 h-4 ${active ? "text-cyan-400" : "text-white/40"}`} />
                <div className="text-left">
                  <div className="font-heading text-sm font-bold tracking-tight">{t.label}</div>
                  <div className="font-mono-data text-[9px] uppercase tracking-widest text-white/40 mt-0.5">
                    {t.hint}
                  </div>
                </div>
                {/* Indicators */}
                {t.id === "seguridad" && (cveCount > 0 || worstAbuse >= 25 || takeoverCount > 0) && (
                  <span className={`ml-2 border px-1.5 py-0.5 font-mono-data text-[9px] uppercase tracking-widest ${
                    takeoverCount > 0
                      ? "border-red-400 bg-red-400/25 text-red-400 animate-pulse font-bold"
                      : "border-red-400/60 bg-red-400/15 text-red-400"
                  }`}>
                    {takeoverCount > 0 ? `${takeoverCount} CRÍTICO` : `${cveCount + (worstAbuse >= 25 ? 1 : 0)} !`}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </header>

      <main className="max-w-[1600px] mx-auto px-6 py-8 relative">
        {/* ═════════ TAB: RESUMEN INTELIGENTE ═════════ */}
        {tab === "resumen" && (
          <div className="space-y-5">
            {/* Critical takeover alert — visible immediately on Resumen */}
            {takeoverCount > 0 && (
              <div data-testid="resumen-takeover-alert"
                className="border-2 border-red-400 bg-red-400/[0.08] p-5 flex items-start gap-4 shadow-[0_0_40px_rgba(255,51,85,0.2)]">
                <ShieldX className="w-7 h-7 text-red-400 flex-shrink-0 animate-pulse" />
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-red-400 font-bold">
                      Riesgo Crítico Detectado
                    </span>
                  </div>
                  <h3 className="font-heading text-xl font-black text-red-400 mb-2">
                    Posible Subdomain Takeover · {takeoverCount} subdominio(s)
                  </h3>
                  <p className="text-sm text-white/80 leading-relaxed">
                    Un secuestro de subdominio ocurre cuando un registro DNS apunta a un servicio externo eliminado.
                    Un atacante puede reclamar ese servicio y tomar el control total del subdominio, permitiéndole
                    realizar ataques de phishing o robo de cookies bajo el nombre de su empresa.
                  </p>
                </div>
                <button
                  onClick={() => setTab("seguridad")}
                  data-testid="goto-takeover-btn"
                  className="border-2 border-red-400 text-red-400 hover:bg-red-400 hover:text-black font-mono-data text-[10px] uppercase tracking-widest px-4 py-2 transition-colors font-bold flex-shrink-0"
                >
                  Ver detalles →
                </button>
              </div>
            )}

            {/* Metric cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard icon={Activity} label="Score Global" value={`${totalRisk}%`}
                tone={totalRisk >= 80 ? "good" : totalRisk >= 50 ? "warn" : "bad"} />
              <MetricCard icon={Globe} label="IP principal" value={r.ip?.ip || "N/A"}
                sub={r.ip?.reverse_dns?.slice(0, 24) || ""} tone="accent" />
              <MetricCard icon={Terminal} label="Puertos abiertos" value={r.ports?.open_ports?.length || 0}
                tone={(r.ports?.open_ports?.length || 0) > 5 ? "warn" : "good"} />
              <MetricCard icon={Network} label="Subdominios" value={r.subdomains?.found?.length || 0}
                tone="accent" sub={`de ${r.subdomains?.total_checked || 0} probados`} />
            </div>

            {/* Intel Summary AI */}
            <IntelSummary scanId={scanId} domain={r.domain} />

            {/* Scores + Map */}
            <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-5">
              <Panel title="Postura de Seguridad" icon={Shield}
                right={
                  <button onClick={() => setShowMap(true)} data-testid="open-map-btn"
                    className="inline-flex items-center gap-2 border border-cyan-400/50 text-cyan-400 px-4 py-1.5 hover:bg-cyan-400 hover:text-black transition-colors">
                    <Map className="w-3.5 h-3.5" />
                    <span className="font-mono-data text-[10px] uppercase tracking-widest">Ver mapa</span>
                  </button>
                }>
                <div className="grid grid-cols-4 gap-6 place-items-center py-4">
                  <ScoreCircle score={security?.basic?.score || 0} label="Básica" />
                  <ScoreCircle score={security?.medium?.score || 0} label="Media" />
                  <ScoreCircle score={security?.advanced?.score || 0} label="Avanzada" />
                  <ScoreCircle score={totalRisk} label="Global" />
                </div>
              </Panel>
              <Panel title="Threat Signals" icon={AlertTriangle}
                accent={cveCount > 0 || worstAbuse >= 25 ? "red" : "green"}>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono-data text-xs text-white/60 uppercase tracking-widest">CVEs (Shodan)</span>
                    <span className={`data-value ${cveCount > 0 ? "!text-red-400" : ""}`}>{cveCount}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono-data text-xs text-white/60 uppercase tracking-widest">Abuse score</span>
                    <span className={`data-value ${worstAbuse >= 25 ? "!text-red-400" : ""}`}>{worstAbuse}/100</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono-data text-xs text-white/60 uppercase tracking-widest">HTTPS</span>
                    <span className="data-value">{r.https_headers?.success ? "OK" : "FAIL"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono-data text-xs text-white/60 uppercase tracking-widest">TLS</span>
                    <span className="data-value">{r.ssl?.tls_version || "N/A"}</span>
                  </div>
                </div>
              </Panel>
            </div>

            <WaybackTimeline scanId={scanId} />
          </div>
        )}

        {/* ═════════ TAB: INFRAESTRUCTURA ═════════ */}
        {tab === "infra" && (
          <div className="space-y-5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard icon={Server} label="IP" value={r.ip?.ip || "—"} tone="accent" />
              <MetricCard icon={Network} label="Subdominios" value={r.subdomains?.found?.length || 0}
                tone="good" sub={`${r.subdomains?.total_checked || 0} probados`} />
              <MetricCard icon={Layers} label="Hosts únicos" value={(r.tech_analysis || []).length}
                sub="fingerprint activo" tone="accent" />
              <MetricCard icon={Shield} label="CDN/WAF"
                value={(r.tech_analysis || []).filter((t) => t.is_protected).length}
                tone="good" sub={`de ${(r.tech_analysis || []).length}`} />
            </div>

            <Panel title="WHOIS" icon={Globe}>
              {r.whois?.success ? (
                <div>{Object.entries(r.whois.data || {}).slice(0, 15).map(([k, v]) => (
                  <KV key={k} label={k.replace(/_/g, " ")} value={Array.isArray(v) ? v.join(", ") : String(v)} />
                ))}</div>
              ) : (<p className="text-red-400 text-sm">Error: {r.whois?.error}</p>)}
            </Panel>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <Panel title="IP + Reverse DNS" icon={Server}>
                <KV label="IP" value={r.ip?.ip} />
                <KV label="Reverse DNS" value={r.ip?.reverse_dns} />
              </Panel>
              <Panel title="Registros DNS" icon={Cpu}>
                {Object.entries(r.dns || {}).filter(([, v]) => v.length).map(([type, records]) => (
                  <div key={type} className="py-1.5 border-b border-white/[0.05]">
                    <div className="flex items-start gap-4">
                      <div className="font-mono-data text-xs text-cyan-400 min-w-[50px]">{type}</div>
                      <div className="flex-1 font-mono-data text-xs text-white/70 break-all">
                        {records.map((rec, i) => <div key={i}>{rec}</div>)}
                      </div>
                    </div>
                  </div>
                ))}
              </Panel>
            </div>

            <Panel title="Subdominios encontrados" icon={Network}>
              {r.subdomains?.found?.length ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-0 border-t border-l border-white/[0.05]">
                  {r.subdomains.found.map((s, i) => (
                    <div key={i} className="border-r border-b border-white/[0.05] p-3">
                      <div className="font-mono-data text-cyan-400 text-sm break-all">{s.subdomain}</div>
                      <div className="font-mono-data text-xs text-white/50 mt-1">{s.ips.join(", ")}</div>
                    </div>
                  ))}
                </div>
              ) : (<p className="text-white/40 text-sm">Ninguno encontrado.</p>)}
            </Panel>

            <CtLogsPanel scanId={scanId} />

            <Panel title="Stack tecnológico por host" icon={Layers}>
              <div className="overflow-x-auto">
                <table data-testid="tech-stack-table" className="w-full border-collapse text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.08] text-left bg-[#101014]">
                      {["Host", "Estado", "Servidor", "CMS/Framework", "Proxy/WAF", "Cabeceras críticas"].map((c) => (
                        <th key={c} className="py-2.5 px-3 font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(r.tech_analysis || []).map((t) => {
                      const missingCsp = (t.missing_critical || []).includes("content-security-policy");
                      const missingHsts = (t.missing_critical || []).includes("strict-transport-security");
                      return (
                        <tr key={t.hostname} data-testid={`tech-row-${t.hostname}`} className="border-b border-white/[0.04] align-top hover:bg-white/[0.02]">
                          <td className="py-3 px-3">
                            <div className="font-mono-data text-cyan-400 text-sm break-all">{t.hostname}</div>
                            {t.ips?.length > 0 && <div className="font-mono-data text-[10px] text-white/40 mt-0.5">{t.ips.join(", ")}</div>}
                          </td>
                          <td className="py-3 px-3">
                            {!t.reachable ? (
                              <span className="inline-flex border border-white/[0.15] px-2 py-1 text-white/40 font-mono-data text-[10px] uppercase tracking-widest">Sin respuesta</span>
                            ) : t.is_protected ? (
                              <span data-testid={`badge-${t.hostname}`} className="inline-flex items-center gap-1.5 border border-green-400/50 bg-green-400/10 text-green-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest">
                                <Shield className="w-3 h-3" /> Protegido
                              </span>
                            ) : (
                              <span data-testid={`badge-${t.hostname}`} className="inline-flex items-center gap-1.5 border border-orange-400/50 bg-orange-400/10 text-orange-400 px-2 py-1 font-mono-data text-[10px] uppercase tracking-widest">
                                <Unlock className="w-3 h-3" /> Directo
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-3 font-mono-data text-xs text-white/80">
                            {t.server || "—"}
                            {t.powered_by && <div className="text-[10px] text-white/40 mt-0.5">{t.powered_by}</div>}
                          </td>
                          <td className="py-3 px-3">
                            <div className="flex flex-wrap gap-1">
                              {[...(t.cms || []), ...(t.frameworks || [])].map((x) => (
                                <span key={x.name} className="font-mono-data text-[10px] border border-cyan-400/30 text-cyan-300 px-1.5 py-0.5">{x.name}</span>
                              ))}
                              {(t.cms?.length || 0) + (t.frameworks?.length || 0) === 0 && <span className="text-white/30 text-xs">—</span>}
                            </div>
                          </td>
                          <td className="py-3 px-3">
                            <div className="flex flex-wrap gap-1">
                              {(t.proxies || []).map((p) => (
                                <span key={p.name} className="font-mono-data text-[10px] border border-green-400/30 text-green-400 px-1.5 py-0.5">{p.name}</span>
                              ))}
                              {!t.proxies?.length && <span className="text-white/30 text-xs">—</span>}
                            </div>
                          </td>
                          <td className="py-3 px-3">
                            <div className="flex flex-wrap gap-1">
                              <span data-testid={`csp-${t.hostname}`}
                                className={`font-mono-data text-[10px] px-1.5 py-0.5 border ${missingCsp ? "border-red-400/60 bg-red-400/15 text-red-400" : "border-green-400/40 text-green-400"}`}>
                                {missingCsp ? "✗ CSP" : "✓ CSP"}
                              </span>
                              <span data-testid={`hsts-${t.hostname}`}
                                className={`font-mono-data text-[10px] px-1.5 py-0.5 border ${missingHsts ? "border-red-400/60 bg-red-400/15 text-red-400" : "border-green-400/40 text-green-400"}`}>
                                {missingHsts ? "✗ HSTS" : "✓ HSTS"}
                              </span>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>
        )}

        {/* ═════════ TAB: SEGURIDAD TÉCNICA ═════════ */}
        {tab === "seguridad" && (
          <div className="space-y-5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard icon={Bug} label="CVEs detectados" value={cveCount}
                tone={cveCount > 0 ? "bad" : "good"} sub="Shodan" />
              <MetricCard icon={ShieldAlert} label="Abuse Score" value={`${worstAbuse}/100`}
                tone={worstAbuse >= 50 ? "bad" : worstAbuse >= 25 ? "warn" : "good"} sub="AbuseIPDB" />
              <MetricCard icon={Lock} label="TLS" value={r.ssl?.tls_version || "N/A"} tone="accent"
                sub={r.ssl?.issuer?.organizationName?.slice(0, 20) || ""} />
              <MetricCard icon={ShieldX} label="Sec. Avanzada" value={`${security?.advanced?.score || 0}%`}
                tone={(security?.advanced?.score || 0) >= 70 ? "good" : (security?.advanced?.score || 0) >= 40 ? "warn" : "bad"} />
            </div>

            <ShodanPanel scanId={scanId} />
            <ShodanDeepPanel scanId={scanId} />
            <CveEnginePanel scanId={scanId} />
            <TyposquatPanel scanId={scanId} />
            <CertMonitorPanel scanId={scanId} />
            <AttackMappingPanel scanId={scanId} />
            <WafBypassPanel scanId={scanId} />
            <TakeoverPanel scanId={scanId} />
            <ReputationPanel scanId={scanId} onWorstScore={(s) => setRepMeta((prev) => ({ ...(prev || {}), worst_score: s }))} />
            <CloudStoragePanel scanId={scanId} />
            <PasteMonitorPanel scanId={scanId} />
            <MetadataPanel scanId={scanId} />

            <Panel title="Certificado SSL / TLS" icon={Lock}>
              {r.ssl?.success ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                  <div>
                    <KV label="Emisor" value={r.ssl.issuer?.organizationName} />
                    <KV label="Sujeto" value={r.ssl.subject?.commonName} />
                    <KV label="Válido desde" value={r.ssl.not_before} />
                    <KV label="Válido hasta" value={r.ssl.not_after} />
                  </div>
                  <div>
                    <KV label="Versión TLS" value={r.ssl.tls_version} />
                    <KV label="Cipher" value={Array.isArray(r.ssl.cipher) ? r.ssl.cipher.join(" · ") : "—"} />
                    <KV label="SAN" value={(r.ssl.san || []).slice(0, 6).join(", ")} />
                  </div>
                </div>
              ) : (<p className="text-red-400 text-sm">SSL no disponible: {r.ssl?.error}</p>)}
            </Panel>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              <Panel title={`Básica · ${security?.basic?.score || 0}%`} icon={ShieldCheck}
                accent={(security?.basic?.score || 0) >= 70 ? "green" : "orange"}>
                <SecurityChecks items={security?.basic?.items} />
              </Panel>
              <Panel title={`Media · ${security?.medium?.score || 0}%`} icon={ShieldAlert}
                accent={(security?.medium?.score || 0) >= 70 ? "green" : "orange"}>
                <SecurityChecks items={security?.medium?.items} />
              </Panel>
              <Panel title={`Avanzada · ${security?.advanced?.score || 0}%`} icon={ShieldX}
                accent={(security?.advanced?.score || 0) >= 70 ? "green" : (security?.advanced?.score || 0) >= 40 ? "orange" : "red"}>
                <SecurityChecks items={security?.advanced?.items} />
              </Panel>
            </div>
          </div>
        )}

        {/* ═════════ TAB: FACTOR HUMANO ═════════ */}
        {tab === "humano" && (
          <div className="space-y-5">
            <FactorHumanoTab domain={r.domain} />
            <JsMinerPanel scanId={scanId} />
          </div>
        )}

        {/* ═════════ TAB: MAPA DE INTELIGENCIA ═════════ */}
        {tab === "mapa" && (
          <div className="space-y-5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard icon={Globe} label="Nodo raíz" value={r.domain} tone="accent" />
              <MetricCard icon={Server} label="IPs únicas"
                value={new Set([r.ip?.ip, ...(r.subdomains?.found || []).flatMap((s) => s.ips || [])].filter(Boolean)).size}
                tone="accent" />
              <MetricCard icon={Network} label="Subdominios" value={r.subdomains?.found?.length || 0} tone="good" />
              <MetricCard icon={Lock} label="SAN en cert" value={r.ssl?.san?.length || 0} tone="warn" />
            </div>
            <IntelligenceMap scan={r} scanId={scanId} />
          </div>
        )}

        {/* ═════════ TAB: INTELIGENCIA PREDICTIVA ═════════ */}
        {tab === "predict" && (
          <PredictiveTab scanId={scanId} domain={r.domain} isPro={isPro} />
        )}

        {/* ═════════ TAB: BUG BOUNTY TOOLKIT ═════════ */}
        {tab === "bounty" && (
          <div className="space-y-5">
            <ScanDiffPanel scanId={scanId} domain={r.domain} />
            <BountyTab scanId={scanId} />
          </div>
        )}

        {tab === "ventaja" && <EdgeTab scanId={scanId} domain={r.domain} />}
      </main>

      {showMap && <ServerMapModal scanId={scanId} onClose={() => setShowMap(false)} />}
    </div>
  );
}
