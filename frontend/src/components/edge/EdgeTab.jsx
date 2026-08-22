/* Ventaja Competitiva — UI para los 6 diferenciadores (Fase frontend).
 * Cada panel llama a los endpoints nuevos del backend. Comparten estado para
 * que trabajen juntos: el veredicto de explotabilidad (#1) y la notarización (#2)
 * alimentan el generador de reportes de bounty (#3).
 */
import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  ShieldCheck, Stamp, Bot, Eye, Gauge, Crosshair, Loader2, Play,
  CheckCircle2, AlertTriangle, HelpCircle, Download, FileText,
} from "lucide-react";
import { API } from "@/lib/auth";
import { Panel } from "@/components/scan/ScanUI";

const VERDICT = {
  verified:    { cls: "text-green-400 border-green-400/50",  label: "Verificado" },
  probable:    { cls: "text-orange-400 border-orange-400/50", label: "Probable" },
  theoretical: { cls: "text-white/50 border-white/20",        label: "Teórico" },
};
const BAND = {
  critical: "text-red-400 border-red-400/50",
  high:     "text-orange-400 border-orange-400/50",
  medium:   "text-cyan-400 border-cyan-400/50",
  low:      "text-white/50 border-white/20",
  noise:    "text-white/30 border-white/10",
};

function Pill({ cls, children }) {
  return (
    <span className={`inline-flex items-center gap-1 font-mono-data text-[10px] uppercase tracking-widest px-2 py-0.5 border ${cls}`}>
      {children}
    </span>
  );
}

function ActionButton({ onClick, loading, children, icon: Icon = Play }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className="inline-flex items-center gap-2 bg-cyan-400 text-black font-semibold px-4 py-2 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[11px] uppercase tracking-widest"
    >
      {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Icon className="w-3.5 h-3.5" />}
      {children}
    </button>
  );
}

/* #1 — Verificación de explotabilidad */
function ExploitabilityCard({ scanId, onResult }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/verify-exploitability`, {}, { withCredentials: true, timeout: 120000 });
      setData(r.data);
      onResult?.(r.data.findings || []);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };
  const s = data?.summary || {};
  return (
    <Panel title="Verificación de explotabilidad" icon={ShieldCheck} accent="green"
      right={<ActionButton onClick={run} loading={loading}>Verificar</ActionButton>}>
      {!data && <p className="text-sm text-white/50">Comprueba (solo lectura) qué hallazgos son realmente explotables.</p>}
      {data && (
        <>
          <div className="flex gap-2 mb-4">
            <Pill cls={VERDICT.verified.cls}>{s.verified || 0} verificados</Pill>
            <Pill cls={VERDICT.probable.cls}>{s.probable || 0} probables</Pill>
            <Pill cls={VERDICT.theoretical.cls}>{s.theoretical || 0} teóricos</Pill>
          </div>
          <div className="space-y-2">
            {(data.findings || []).map((f, i) => (
              <div key={i} className="flex items-center justify-between gap-3 border border-white/[0.06] px-3 py-2">
                <div className="min-w-0">
                  <div className="font-mono-data text-xs text-white/80 truncate">{f.target || f.type}</div>
                  <div className="font-mono-data text-[10px] text-white/40">{f.type} · {f.method}</div>
                </div>
                <Pill cls={(VERDICT[f.verdict] || VERDICT.theoretical).cls}>{(VERDICT[f.verdict] || {}).label || f.verdict}</Pill>
              </div>
            ))}
            {!data.findings?.length && <p className="text-sm text-white/40">Sin hallazgos críticos que verificar.</p>}
          </div>
        </>
      )}
    </Panel>
  );
}

/* #2 — Evidencia notarizada */
function NotarizeCard({ scanId, onNotarized }) {
  const [rec, setRec] = useState(null);
  const [integrity, setIntegrity] = useState(null);
  const [loading, setLoading] = useState(false);
  const notarize = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/notarize`, {}, { withCredentials: true, timeout: 60000 });
      setRec(r.data); setIntegrity(null); onNotarized?.(r.data);
      toast.success("Evidencia notarizada con sello de tiempo");
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };
  const verify = async () => {
    if (!rec) return;
    try {
      const r = await axios.get(`${API}/notary/${rec.notary_id}/verify`, { withCredentials: true });
      setIntegrity(r.data);
    } catch (e) { toast.error("Error verificando"); }
  };
  const bundle = async () => {
    if (!rec) return;
    try {
      const r = await axios.get(`${API}/notary/${rec.notary_id}/bundle`, { withCredentials: true });
      const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `evidence-${rec.notary_id}.json`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { toast.error("Error descargando"); }
  };
  const intact = integrity?.status === "INTACT";
  return (
    <Panel title="Evidencia notarizada (cadena de custodia)" icon={Stamp} accent="cyan"
      right={<ActionButton onClick={notarize} loading={loading} icon={Stamp}>Notarizar</ActionButton>}>
      {!rec && <p className="text-sm text-white/50">Sella los hallazgos con SHA-256 + timestamp RFC3161. Prueba de descubrimiento con fecha.</p>}
      {rec && (
        <div className="space-y-3">
          <div className="font-mono-data text-xs text-white/60 break-all">
            chain: <span className="text-cyan-400">{rec.chain_hash?.slice(0, 40)}…</span>
          </div>
          <div className="font-mono-data text-[11px] text-white/40">
            {rec.total_findings_sealed} hallazgos · RFC3161: {rec.rfc3161?.ok ? "sellado ✓" : "no disponible"}
          </div>
          <div className="flex gap-2 flex-wrap">
            <button onClick={verify} className="font-mono-data text-[11px] uppercase tracking-widest border border-white/15 hover:border-cyan-400 hover:text-cyan-400 px-3 py-1.5">Verificar integridad</button>
            <button onClick={bundle} className="inline-flex items-center gap-1.5 font-mono-data text-[11px] uppercase tracking-widest border border-white/15 hover:border-cyan-400 hover:text-cyan-400 px-3 py-1.5"><Download className="w-3 h-3" /> Bundle</button>
            {integrity && (
              <Pill cls={intact ? "text-green-400 border-green-400/50" : "text-red-400 border-red-400/50"}>
                {intact ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />} {integrity.status}
              </Pill>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}

/* #4 — Autopilot */
function AutopilotCard({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/autopilot`, {}, { withCredentials: true, timeout: 180000 });
      setData(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };
  return (
    <Panel title="Copiloto agéntico · Autopilot" icon={Bot} accent="cyan"
      right={<ActionButton onClick={run} loading={loading} icon={Bot}>Ejecutar Autopilot</ActionButton>}>
      {!data && <p className="text-sm text-white/50">El agente decide qué módulos ejecutar y los encadena, narrando cada decisión.</p>}
      {data && (
        <div className="space-y-2">
          <div className="font-mono-data text-[11px] text-white/40 mb-2">{data.steps_run} pasos autónomos</div>
          {(data.trace || []).map((t) => (
            <div key={t.step} className="border-l-2 border-cyan-400/40 pl-3 py-1">
              <div className="font-mono-data text-xs text-cyan-400">{t.step}. {t.module}</div>
              <div className="text-xs text-white/60">{t.reason}</div>
              <div className="font-mono-data text-[10px] text-white/40">→ {t.outcome}</div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* #5 — IA caja de cristal */
function GlassboxCard({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/explain`, { withCredentials: true, timeout: 120000 });
      setData(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };
  return (
    <Panel title="IA caja de cristal (explicable)" icon={Eye} accent="cyan"
      right={<ActionButton onClick={run} loading={loading} icon={Eye}>Explicar</ActionButton>}>
      {!data && <p className="text-sm text-white/50">Cada conclusión enlaza su evidencia y se autovalida contra los datos reales.</p>}
      {data && (
        <>
          <div className="mb-3"><Pill cls="text-cyan-400 border-cyan-400/50">Fiabilidad {data.trust_score}% · {data.grounded}/{data.total} fundamentadas</Pill></div>
          <div className="space-y-2">
            {(data.conclusions || []).map((c, i) => (
              <div key={i} className="border border-white/[0.06] px-3 py-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="text-sm text-white/85">{c.claim}</div>
                  {c.grounded
                    ? <Pill cls="text-green-400 border-green-400/50"><CheckCircle2 className="w-3 h-3" /> fundada</Pill>
                    : <Pill cls="text-red-400 border-red-400/50"><HelpCircle className="w-3 h-3" /> sin fundar</Pill>}
                </div>
                <div className="font-mono-data text-[10px] text-white/40 mt-1">
                  confianza {Math.round((c.confidence || 0) * 100)}% · evidencia: {(c.evidence || []).join(", ") || "—"}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </Panel>
  );
}

/* #6 — Score de explotabilidad real */
function ScoreCard({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const run = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/exploit-score`, { withCredentials: true, timeout: 60000 });
      setData(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };
  return (
    <Panel title="Score de explotabilidad real" icon={Gauge} accent="orange"
      right={<ActionButton onClick={run} loading={loading} icon={Gauge}>Calcular</ActionButton>}>
      {!data && <p className="text-sm text-white/50">Prioriza por riesgo alcanzable (no CVSS crudo): severidad × veredicto × alcanzabilidad − honeypot.</p>}
      {data && (
        <div className="space-y-2">
          {data.noise_reduction && (
            <div className="font-mono-data text-[11px] text-white/40 mb-2">
              Reducción de ruido: {data.noise_reduction.flagged_by_severity} marcados por severidad → {data.noise_reduction.real_priority} prioridad real
            </div>
          )}
          {(data.findings || []).map((f, i) => (
            <div key={i} className="flex items-center justify-between gap-3 border border-white/[0.06] px-3 py-2">
              <div className="min-w-0">
                <div className="font-mono-data text-xs text-white/80 truncate">{f.target || f.type}</div>
                <div className="font-mono-data text-[10px] text-white/40">{f.type} · {f.verdict}{f.cvss ? ` · CVSS ${f.cvss}` : ""}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-heading font-black text-lg">{f.real_score}</span>
                <Pill cls={BAND[f.band] || BAND.noise}>{f.band}</Pill>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* #3 — Bug Bounty: scope + reporte */
function BountyProCard({ scanId, exploitFindings, notaryId }) {
  const [scopeText, setScopeText] = useState("");
  const [scopeRes, setScopeRes] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const checkScope = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/scope-check`, { scope_text: scopeText }, { withCredentials: true });
      setScopeRes(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };
  const genReport = async (finding) => {
    try {
      const r = await axios.post(`${API}/scans/${scanId}/bounty-report`,
        { finding, platform: "hackerone", include_notarization: !!notaryId },
        { withCredentials: true });
      setReport(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
  };
  const copyReport = () => {
    if (report?.markdown) { navigator.clipboard.writeText(report.markdown); toast.success("Reporte copiado"); }
  };

  return (
    <Panel title="Bug Bounty · Scope + Reporte" icon={Crosshair} accent="red">
      <div className="space-y-4">
        <div>
          <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-2">Scope del programa (uno por línea · <code>!fuera</code>)</div>
          <textarea
            value={scopeText}
            onChange={(e) => setScopeText(e.target.value)}
            placeholder={"*.target.com\napi.target.com\n!staging.target.com"}
            rows={3}
            className="w-full bg-black border border-white/[0.08] font-mono-data text-xs p-3 focus:outline-none focus:border-cyan-400"
          />
          <div className="mt-2"><ActionButton onClick={checkScope} loading={loading} icon={Crosshair}>Clasificar activos</ActionButton></div>
        </div>
        {scopeRes && (
          <div className="flex gap-2 flex-wrap">
            <Pill cls="text-green-400 border-green-400/50">{scopeRes.counts.in_scope} in-scope</Pill>
            <Pill cls="text-red-400 border-red-400/50">{scopeRes.counts.out_of_scope} out-of-scope</Pill>
            <Pill cls="text-white/50 border-white/20">{scopeRes.counts.unknown} unknown</Pill>
          </div>
        )}
        <div>
          <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-2">Generar reporte (usa los hallazgos verificados en #1)</div>
          {(exploitFindings || []).length === 0 && <p className="text-xs text-white/40">Ejecuta "Verificar explotabilidad" arriba para tener hallazgos.</p>}
          <div className="flex gap-2 flex-wrap">
            {(exploitFindings || []).map((f, i) => (
              <button key={i} onClick={() => genReport(f)}
                className="inline-flex items-center gap-1.5 font-mono-data text-[11px] border border-white/15 hover:border-cyan-400 hover:text-cyan-400 px-3 py-1.5">
                <FileText className="w-3 h-3" /> {f.target || f.type}
              </button>
            ))}
          </div>
        </div>
        {report && (
          <div className="border border-white/[0.08] bg-black">
            <div className="flex items-center justify-between px-3 py-2 border-b border-white/[0.06]">
              <span className="font-mono-data text-[11px] text-white/60">{report.title}</span>
              <button onClick={copyReport} className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 hover:underline">Copiar MD</button>
            </div>
            <pre className="text-[11px] text-white/70 p-3 overflow-x-auto whitespace-pre-wrap max-h-72">{report.markdown}</pre>
          </div>
        )}
      </div>
    </Panel>
  );
}

export default function EdgeTab({ scanId }) {
  const [exploitFindings, setExploitFindings] = useState([]);
  const [notary, setNotary] = useState(null);
  return (
    <div className="space-y-5">
      <div className="border border-cyan-400/30 bg-cyan-400/[0.04] px-5 py-3">
        <p className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-cyan-400">Ventaja competitiva</p>
        <p className="text-sm text-white/60 mt-1">No solo lo encuentra — lo prueba, sella la evidencia y te da el reporte. Lo que la competencia no tiene.</p>
      </div>
      <ExploitabilityCard scanId={scanId} onResult={setExploitFindings} />
      <ScoreCard scanId={scanId} />
      <NotarizeCard scanId={scanId} onNotarized={setNotary} />
      <BountyProCard scanId={scanId} exploitFindings={exploitFindings} notaryId={notary?.notary_id} />
      <AutopilotCard scanId={scanId} />
      <GlassboxCard scanId={scanId} />
    </div>
  );
}
