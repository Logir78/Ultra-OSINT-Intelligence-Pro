import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  Loader2, Brain, Target, ShieldAlert, Zap, Sparkles, Skull, Copy, Check,
  FileCode2, AlertTriangle, Fingerprint, Globe2, Play, RefreshCw, Lock,
} from "lucide-react";
import { API } from "@/lib/auth";

function SectionCard({ title, icon: Icon, accent = "cyan", right = null, children }) {
  const colorMap = { cyan: "text-cyan-400", red: "text-red-400", orange: "text-orange-400", green: "text-green-400", purple: "text-purple-400" };
  return (
    <section className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <Icon className={`w-4 h-4 ${colorMap[accent]}`} />
          <h3 className="font-heading text-sm font-bold tracking-wide uppercase">{title}</h3>
        </div>
        {right}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

function StepBadge({ step, plain, technical, asset, outcome }) {
  return (
    <div className="flex items-stretch gap-3 mb-3">
      <div className="w-12 flex-shrink-0 bg-cyan-400/10 border border-cyan-400/30 flex items-center justify-center">
        <span className="font-heading font-black text-2xl text-cyan-400">{step}</span>
      </div>
      <div className="flex-1 border border-white/[0.06] bg-black/40 p-4">
        <div className="font-heading text-sm text-white leading-snug mb-1.5">{plain}</div>
        {technical && technical !== plain && (
          <div className="font-mono-data text-[11px] text-white/40 mb-1.5">{technical}</div>
        )}
        {asset && (
          <div className="font-mono-data text-[10px] text-cyan-400 uppercase tracking-widest mb-1">
            Utiliza: <span className="text-white/70 normal-case tracking-normal">{asset}</span>
          </div>
        )}
        {outcome && (
          <div className="font-mono-data text-[10px] text-orange-400 uppercase tracking-widest">
            → {outcome}
          </div>
        )}
      </div>
    </div>
  );
}

function CopyButton({ text, label = "Copiar" }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="inline-flex items-center gap-1.5 border border-white/[0.15] px-3 py-1.5 hover:border-cyan-400 hover:text-cyan-400 font-mono-data text-[10px] uppercase tracking-widest"
    >
      {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />} {copied ? "Copiado" : label}
    </button>
  );
}

export default function PredictiveTab({ scanId, domain, isPro }) {
  // Attack Path
  const [personas, setPersonas] = useState([]);
  const [selectedPersona, setSelectedPersona] = useState("none");
  const [ap, setAp] = useState(null);
  const [apLoading, setApLoading] = useState(false);

  // Oracle
  const [oracle, setOracle] = useState(null);
  const [oracleLoading, setOracleLoading] = useState(false);

  // DNA Fingerprint
  const [dna, setDna] = useState(null);
  const [dnaLoading, setDnaLoading] = useState(false);

  // Brand Guardian
  const [brand, setBrand] = useState(null);
  const [brandLoading, setBrandLoading] = useState(false);

  // PoC
  const [poc, setPoc] = useState(null);
  const [pocLoading, setPocLoading] = useState(false);

  // Phishing Sim
  const [phish, setPhish] = useState(null);
  const [phishLoading, setPhishLoading] = useState(false);

  useEffect(() => {
    axios.get(`${API}/apt-personas`, { withCredentials: true })
      .then(r => setPersonas(r.data.personas || []))
      .catch(() => {});
  }, []);

  const runAttackPath = async (persona = "none", regenerate = false) => {
    setApLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/attack-path`,
        { apt_persona: persona, regenerate },
        { withCredentials: true, timeout: 120000 });
      setAp(r.data.attack_path);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error generando ruta de ataque"); }
    finally { setApLoading(false); }
  };

  const runOracle = async () => {
    setOracleLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/risk-oracle`,
        { withCredentials: true, timeout: 90000 });
      setOracle(r.data.risk_oracle);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error consultando oráculo"); }
    finally { setOracleLoading(false); }
  };

  const runDna = async () => {
    setDnaLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/dna`,
        { withCredentials: true, timeout: 60000 });
      setDna(r.data.dna);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error DNA"); }
    finally { setDnaLoading(false); }
  };

  const runBrand = async () => {
    setBrandLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/brand-guardian`,
        { withCredentials: true, timeout: 120000 });
      setBrand(r.data.brand_guardian);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error Guardián de Marca"); }
    finally { setBrandLoading(false); }
  };

  const runPoc = async () => {
    setPocLoading(true);
    try {
      const r = await axios.get(`${API}/scans/${scanId}/poc`,
        { withCredentials: true, timeout: 90000 });
      setPoc(r.data.poc);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error PoC"); }
    finally { setPocLoading(false); }
  };

  const runPhish = async () => {
    if (!isPro) { toast.error("Función Pro. Actualiza para desbloquear."); return; }
    setPhishLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/phishing-sim`, {},
        { withCredentials: true, timeout: 90000 });
      setPhish(r.data.phishing_sim);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error simulador phishing"); }
    finally { setPhishLoading(false); }
  };

  const urgencyColor = {
    critical: "border-red-400 bg-red-500/[0.08] text-red-400",
    high: "border-orange-400 bg-orange-500/[0.08] text-orange-400",
    medium: "border-cyan-400 bg-cyan-500/[0.06] text-cyan-400",
    low: "border-white/20 text-white/60",
  };
  const oracleColor = (p) => p >= 60 ? "bg-red-500" : p >= 30 ? "bg-orange-400" : "bg-green-500";

  return (
    <div data-testid="predictive-tab" className="space-y-5">
      {/* Header intro */}
      <div className="border border-purple-400/30 bg-gradient-to-r from-purple-500/[0.06] to-cyan-500/[0.04] p-5">
        <div className="flex items-center gap-3 mb-2">
          <Brain className="w-5 h-5 text-purple-400" />
          <h2 className="font-heading text-xl font-black">Inteligencia Predictiva</h2>
        </div>
        <p className="text-sm text-white/60 leading-relaxed">
          La IA analiza TODOS los hallazgos previos y proyecta el futuro: probabilidad de brecha,
          camino exacto que seguiría un atacante, activos hermanos que revelan al mismo dueño,
          clones de marca y simulaciones autorizadas.
        </p>
      </div>

      {/* ATTACK PATH */}
      <SectionCard title="Estratega de Intrusión · Ruta de ataque" icon={Target} accent="red"
        right={
          <div className="flex items-center gap-2">
            <select
              value={selectedPersona}
              onChange={(e) => { setSelectedPersona(e.target.value); }}
              data-testid="apt-persona-select"
              className="bg-black border border-white/[0.15] px-3 py-1.5 font-mono-data text-xs focus:outline-none focus:border-cyan-400"
            >
              {personas.map(p => <option key={p.id} value={p.id}>{p.id}</option>)}
            </select>
            <button
              onClick={() => runAttackPath(selectedPersona, ap != null)}
              disabled={apLoading}
              data-testid="run-attack-path-btn"
              className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
            >
              {apLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : (ap ? <RefreshCw className="w-3 h-3" /> : <Play className="w-3 h-3" />)}
              {ap ? "Regenerar" : "Ejecutar"}
            </button>
          </div>
        }
      >
        {!ap && !apLoading && (
          <p className="text-sm text-white/50">
            Encadena los hallazgos en una narrativa paso-a-paso. Elige un perfil de adversario para
            que la IA analice desde la perspectiva de ese grupo.
          </p>
        )}
        {ap && (
          <div className="space-y-4">
            <div className="border-l-4 border-cyan-400 pl-4 py-1">
              <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-1">
                Resumen ejecutivo (lenguaje no técnico)
              </div>
              <p className="text-base text-white leading-relaxed italic">
                “{ap.executive_summary}”
              </p>
            </div>

            {ap.attack_chain?.length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-3">
                  Cadena de intrusión ({ap.attack_chain.length} pasos)
                </div>
                {ap.attack_chain.map((s) => (
                  <StepBadge key={s.step} {...s} plain={s.action_plain} technical={s.action_technical} asset={s.asset_used} outcome={s.outcome} />
                ))}
              </div>
            )}

            {ap.final_impact && (
              <div className={`border-2 ${urgencyColor[ap.urgency] || urgencyColor.medium} p-4 flex items-start gap-3`}>
                <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="font-mono-data text-[10px] uppercase tracking-widest mb-1">
                    Impacto final · Urgencia {ap.urgency?.toUpperCase()} · TTC: {ap.estimated_time_to_compromise}
                  </div>
                  <p className="text-sm text-white/90 leading-relaxed">{ap.final_impact}</p>
                </div>
              </div>
            )}

            {ap.mitigation_priorities?.length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-green-400 mb-2">
                  Acciones que rompen la cadena
                </div>
                <ol className="space-y-1.5">
                  {ap.mitigation_priorities.map((m, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-white/80">
                      <span className="font-heading text-green-400 font-black">{i + 1}.</span>
                      <span>{m}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )}
      </SectionCard>

      {/* RISK ORACLE */}
      <SectionCard title="Oráculo de Riesgos · Probabilidad de brecha 90 días" icon={Sparkles} accent="orange"
        right={
          <button onClick={runOracle} disabled={oracleLoading}
            data-testid="run-oracle-btn"
            className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
          >
            {oracleLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            {oracle ? "Recalcular" : "Consultar"}
          </button>
        }
      >
        {!oracle && !oracleLoading && (
          <p className="text-sm text-white/50">Calcula la probabilidad de que este dominio sufra una brecha a corto plazo.</p>
        )}
        {oracle && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-[240px_1fr] gap-4 items-center">
              <div className="border border-white/[0.08] bg-black p-5">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-2">Probabilidad</div>
                <div className="font-heading text-6xl font-black text-white tabular-nums">
                  {oracle.probability_percent}<span className="text-2xl text-white/40">%</span>
                </div>
                <div className="w-full h-1.5 bg-white/10 mt-3">
                  <div className={`h-full ${oracleColor(oracle.probability_percent)}`} style={{ width: `${oracle.probability_percent}%` }} />
                </div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mt-2">
                  Baseline: {oracle.baseline_percent}% · Confianza: {oracle.confidence}
                </div>
              </div>
              <div>
                <div className="text-base italic text-white/90 leading-relaxed mb-4">“{oracle.verdict}”</div>
                <ul className="space-y-1.5">
                  {(oracle.top_risk_factors || []).map((f, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-white/80">
                      <ShieldAlert className="w-3.5 h-3.5 text-orange-400 flex-shrink-0 mt-0.5" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}
      </SectionCard>

      {/* DNA FINGERPRINT */}
      <SectionCard title="ADN Digital · Activos hermanos del mismo dueño" icon={Fingerprint} accent="cyan"
        right={
          <button onClick={runDna} disabled={dnaLoading}
            data-testid="run-dna-btn"
            className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
          >
            {dnaLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            {dna ? "Regenerar" : "Ejecutar"}
          </button>
        }
      >
        {!dna && !dnaLoading && (
          <p className="text-sm text-white/50">Genera un hash único de la infraestructura y busca otros activos que compartan la misma firma.</p>
        )}
        {dna && (
          <div className="space-y-3">
            <div className="font-mono-data text-xs text-cyan-400">Fingerprint: <span className="text-white">{dna.fingerprint}</span></div>
            <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
              Señales usadas: {(dna.signals_used || []).join(" · ") || "solo componentes locales"}
            </div>
            <div className="text-sm text-white/60">
              {dna.sibling_count} activo(s) hermano(s) detectados
            </div>
            {dna.siblings?.length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 max-h-72 overflow-y-auto">
                {dna.siblings.map((s, i) => (
                  <div key={i} className="border border-white/[0.06] bg-black/40 p-2.5 font-mono-data text-xs">
                    <div className="text-cyan-300 break-all">{s.asset}</div>
                    <div className="text-white/40 text-[10px] uppercase tracking-widest mt-1">
                      {s.signal} · {s.kind}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </SectionCard>

      {/* BRAND GUARDIAN */}
      <SectionCard title="Guardián de Marca · Clones y typosquats" icon={Globe2} accent="purple"
        right={
          <button onClick={runBrand} disabled={brandLoading}
            data-testid="run-brand-btn"
            className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
          >
            {brandLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            {brand ? "Reescanear" : "Ejecutar"}
          </button>
        }
      >
        {!brand && !brandLoading && (
          <p className="text-sm text-white/50">Genera variantes de typosquatting y detecta si alguna se está usando para phishing.</p>
        )}
        {brand && (
          <div className="space-y-3">
            {brand.brand_at_risk && (
              <div className="border-2 border-red-400 bg-red-500/[0.08] p-4 text-red-300">
                <div className="font-heading font-bold flex items-center gap-2 mb-1">
                  <AlertTriangle className="w-4 h-4" /> Suplantación de Marca Detectada
                </div>
                <p className="text-sm text-white/90">{brand.impersonation_verdict}</p>
              </div>
            )}
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{brand.variants_tested}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Variantes probadas</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{brand.clones_detected}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Clones</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{brand.suspicious_count}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Sospechosos</div>
              </div>
            </div>
            {(brand.clones || []).length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-red-400 mb-2">Clones detectados</div>
                <ul className="space-y-1 font-mono-data text-xs">
                  {brand.clones.map((c, i) => (
                    <li key={i} className="flex items-center gap-2 border border-red-400/20 p-2">
                      <span className="text-red-300">{c.host}</span>
                      <span className="text-white/40">→ {c.ip}</span>
                      {c.reason && <span className="text-white/50 text-[10px] ml-auto">{c.reason}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </SectionCard>

      {/* POC GENERATOR */}
      <SectionCard title="Generador de PoC · Prueba segura por vulnerabilidad" icon={FileCode2} accent="green"
        right={
          <button onClick={runPoc} disabled={pocLoading}
            data-testid="run-poc-btn"
            className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
          >
            {pocLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            {poc ? "Regenerar" : "Ejecutar"}
          </button>
        }
      >
        {!poc && !pocLoading && (
          <p className="text-sm text-white/50">Genera scripts Python/curl seguros y no destructivos que prueban cada fallo crítico detectado.</p>
        )}
        {poc && (
          <div className="space-y-3">
            <div className="text-xs text-white/50 font-mono-data">
              {poc.vulns_analyzed} vulnerabilidad(es) analizadas · {(poc.pocs || []).length} PoC generados
            </div>
            {poc.message && <p className="text-sm text-green-400/80">{poc.message}</p>}
            {(poc.pocs || []).map((p, i) => (
              <div key={i} className="border border-white/[0.06] bg-black/40">
                <div className="flex items-center justify-between px-4 py-2 border-b border-white/[0.06] bg-[#0F0F13]">
                  <div>
                    <div className="font-heading font-bold text-sm">{p.title}</div>
                    <div className="font-mono-data text-[10px] text-white/50 mt-0.5">
                      <span className={`px-1.5 py-0.5 border ${p.severity === "critical" ? "border-red-400 text-red-400" : "border-orange-400 text-orange-400"}`}>{p.severity}</span> · {p.vuln_kind} · {p.target}
                    </div>
                  </div>
                  <CopyButton text={p.poc_code} />
                </div>
                <div className="p-3">
                  <p className="text-xs text-white/70 mb-2">{p.explanation_plain}</p>
                  <pre className="bg-black text-cyan-300 font-mono-data text-xs p-3 overflow-x-auto whitespace-pre-wrap border border-white/[0.05]">{p.poc_code}</pre>
                  {p.remediation && (
                    <div className="mt-2 text-xs text-green-400/80">
                      <span className="font-mono-data uppercase tracking-widest text-[10px]">Fix:</span> {p.remediation}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {poc.disclaimer && (
              <div className="border border-white/10 bg-white/[0.02] p-3 text-[11px] text-white/50 font-mono-data leading-relaxed">
                {poc.disclaimer}
              </div>
            )}
          </div>
        )}
      </SectionCard>

      {/* PHISHING SIM */}
      <SectionCard title="Simulador de Phishing · Solo red-team autorizado" icon={Skull} accent="red"
        right={
          isPro ? (
            <button onClick={runPhish} disabled={phishLoading}
              data-testid="run-phish-btn"
              className="bg-red-500 text-white font-semibold px-4 py-1.5 hover:bg-red-400 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5"
            >
              {phishLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
              {phish ? "Regenerar" : "Generar simulación"}
            </button>
          ) : (
            <div className="inline-flex items-center gap-2 border border-white/[0.15] px-3 py-1.5 font-mono-data text-[10px] uppercase tracking-widest text-white/60">
              <Lock className="w-3 h-3" /> Pro
            </div>
          )
        }
      >
        {!phish && (
          <p className="text-sm text-white/50">
            Genera plantilla de correo + página objetivo para ejercicios de red-team con autorización escrita.
            {!isPro && <span className="text-cyan-400"> Requiere plan Pro.</span>}
          </p>
        )}
        {phish && (
          <div className="space-y-3">
            <div className="border-2 border-red-400 bg-red-500/[0.08] p-3">
              <div className="font-mono-data text-[10px] uppercase tracking-widest text-red-400 font-bold mb-1">
                AVISO LEGAL OBLIGATORIO
              </div>
              <p className="text-xs text-white/80 leading-relaxed">{phish.disclaimer}</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="border border-white/[0.06] p-4">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Escenario</div>
                <div className="font-heading font-bold text-sm mb-1">{phish.scenario_name}</div>
                <div className="text-xs text-white/60">Target: {phish.target_role}</div>
              </div>
              <div className="border border-white/[0.06] p-4">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Página a clonar</div>
                <div className="font-heading font-bold text-sm mb-1">{phish.clone_target?.page_type}</div>
                <div className="font-mono-data text-xs text-white/60 break-all">{phish.clone_target?.url_suggestion}</div>
              </div>
            </div>
            <div className="border border-white/[0.06]">
              <div className="flex items-center justify-between px-4 py-2 border-b border-white/[0.06] bg-[#0F0F13]">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">Plantilla email</div>
                <CopyButton text={`Subject: ${phish.email?.subject}\nFrom: ${phish.email?.from_display}\n\n${phish.email?.body_text}`} />
              </div>
              <div className="p-4 space-y-2 text-sm">
                <div><span className="text-white/40 font-mono-data text-xs uppercase tracking-widest">Subject:</span> {phish.email?.subject}</div>
                <div><span className="text-white/40 font-mono-data text-xs uppercase tracking-widest">From:</span> {phish.email?.from_display}</div>
                <div className="mt-3 whitespace-pre-wrap text-white/80 border-l-2 border-cyan-400/30 pl-3 py-1">
                  {phish.email?.body_text}
                </div>
              </div>
            </div>
            {phish.psychological_triggers?.length > 0 && (
              <div className="text-xs text-white/60">
                <span className="font-mono-data uppercase tracking-widest text-[10px] text-orange-400">Palancas: </span>
                {phish.psychological_triggers.join(" · ")}
              </div>
            )}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
