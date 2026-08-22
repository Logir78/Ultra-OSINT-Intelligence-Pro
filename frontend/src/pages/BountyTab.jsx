import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  Loader2, Search, Play, Bug, FileWarning, Server as ServerIcon,
  Copy, Check, ShieldAlert, Network, ExternalLink, Flag, AlertTriangle,
  KeyRound, Package, Workflow, Users, Github, Bot,
  Fingerprint as FingerprintIcon, EyeOff, ShieldCheck, Skull, Sparkles, Building2, Code2,
} from "lucide-react";
import { API } from "@/lib/auth";
import { CopyLink, SevBadge, useRunner, Section } from "@/components/bounty/BountyUI";

export default function BountyTab({ scanId }) {
  const pm = useRunner(`${API}/scans/${scanId}/param-miner`);
  const cc = useRunner(`${API}/scans/${scanId}/cloud-config`);
  const apiA = useRunner(`${API}/scans/${scanId}/api-audit`);
  const vt = useRunner(`${API}/scans/${scanId}/version-track`);
  const corr = useRunner(`${API}/scans/${scanId}/correlate`);
  const idor = useRunner(`${API}/scans/${scanId}/idor`);
  const supply = useRunner(`${API}/scans/${scanId}/supply-chain`);
  const logic = useRunner(`${API}/scans/${scanId}/logic-flow`);
  const revip = useRunner(`${API}/scans/${scanId}/reverse-ip`);
  const gh = useRunner(`${API}/scans/${scanId}/github-miner`);
  const bot = useRunner(`${API}/scans/${scanId}/bot-resistance`);
  const jarm = useRunner(`${API}/scans/${scanId}/jarm`);
  const honey = useRunner(`${API}/scans/${scanId}/honeypot`);
  const evid = useRunner(`${API}/scans/${scanId}/evidence-seal`);
  const sleep = useRunner(`${API}/scans/${scanId}/sleeping-infra`);
  const orgmap = useRunner(`${API}/scans/${scanId}/org-map`);
  const devp = useRunner(`${API}/scans/${scanId}/dev-profile`);

  const pmData = pm.data?.param_miner;
  const ccData = cc.data?.cloud_config;
  const apiData = apiA.data?.api_audit;
  const vtData = vt.data?.version_track;
  const corrData = corr.data?.correlation;
  const idorData = idor.data?.idor;
  const supplyData = supply.data?.supply_chain;
  const logicData = logic.data?.logic_flow;
  const revipData = revip.data?.reverse_ip;
  const ghData = gh.data?.github_miner;
  const botData = bot.data?.bot_resistance;
  const jarmData = jarm.data?.jarm;
  const honeyData = honey.data?.honeypot;
  const evidData = evid.data?.evidence;
  const sleepData = sleep.data?.sleeping_infra;
  const orgData = orgmap.data?.org_map;
  const devData = devp.data?.dev_profile;

  return (
    <div data-testid="bounty-tab" className="space-y-5">
      <div className="border border-orange-400/30 bg-gradient-to-r from-orange-500/[0.06] to-red-500/[0.03] p-5">
        <div className="flex items-center gap-3 mb-2">
          <Bug className="w-5 h-5 text-orange-400" />
          <h2 className="font-heading text-xl font-black">Bug Bounty Toolkit</h2>
        </div>
        <p className="text-sm text-white/60 leading-relaxed">
          Arsenal para cazadores de vulnerabilidades: descubrimiento pasivo de parámetros ocultos,
          fugas de configuración, endpoints de API, correlación global de amenazas y detección de
          rollbacks de versiones vulnerables.
        </p>
      </div>

      {/* PARAM MINER */}
      <Section title="Parameter Miner · Parámetros ocultos" icon={Search} accent="cyan" runner={pm}
        description="Analiza JS/HTML del dominio para inferir nombres de parámetros ocultos (?admin=, ?debug=) susceptibles a inyecciones.">
        {pmData && (
          <div className="space-y-3">
            <div className="grid grid-cols-4 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{pmData.total_discovered}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Total</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{pmData.counts_by_priority?.critical || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Críticos</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{pmData.counts_by_priority?.high || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Altos</div>
              </div>
              <div className="border border-cyan-400/30 p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{pmData.counts_by_priority?.medium || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Medios</div>
              </div>
            </div>
            <div className="max-h-[420px] overflow-y-auto space-y-1">
              {(pmData.candidates || []).map((c, i) => (
                <div key={i} className="flex items-center gap-2 border border-white/[0.05] p-2 font-mono-data text-xs">
                  <SevBadge level={c.priority} />
                  <span className="text-cyan-300 min-w-[120px]">{c.name}</span>
                  <span className="text-white/40 text-[10px]">{c.sources.join(",")}</span>
                  <a href={c.candidate_url} target="_blank" rel="noreferrer"
                    className="ml-auto text-white/40 hover:text-cyan-400 truncate max-w-[350px] inline-flex items-center gap-1">
                    {c.candidate_url} <ExternalLink className="w-3 h-3 flex-shrink-0" />
                  </a>
                  <CopyLink text={c.candidate_url} />
                </div>
              ))}
            </div>
            {pmData.note && (
              <div className="text-[11px] text-white/40 font-mono-data italic">{pmData.note}</div>
            )}
          </div>
        )}
      </Section>

      {/* CLOUD CONFIG HUNTER */}
      <Section title="Cloud & Dev Config Hunter · Ficheros peligrosos expuestos" icon={FileWarning} accent="red" runner={cc}
        description="Prueba rutas típicas de configuración expuesta por error (.env, .git/config, docker-compose.yml, wp-config.php.bak, dumps SQL, claves privadas…).">
        {ccData && (
          <div className="space-y-3">
            <div className="grid grid-cols-4 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{ccData.total_findings}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Hallazgos</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{ccData.counts_by_severity?.critical || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Críticos</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{ccData.counts_by_severity?.high || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Altos</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white/60">{ccData.targets_probed}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Targets probados</div>
              </div>
            </div>
            {(ccData.findings || []).length === 0 && (
              <div className="text-sm text-green-400/80">Sin ficheros de configuración expuestos detectados.</div>
            )}
            {(ccData.findings || []).map((f, i) => (
              <div key={i} className="border border-white/[0.06] p-3">
                <div className="flex items-center justify-between gap-2 mb-1 flex-wrap">
                  <div className="flex items-center gap-2">
                    <SevBadge level={f.severity} />
                    <span className="font-mono-data text-sm text-cyan-300">{f.path}</span>
                    {f.confirmed && <span className="font-mono-data text-[10px] text-green-400 border border-green-400/30 px-1.5">✓ CONFIRMADO</span>}
                  </div>
                  <a href={f.url} target="_blank" rel="noreferrer" className="text-white/40 hover:text-cyan-400 font-mono-data text-[10px] break-all inline-flex items-center gap-1">
                    {f.url} <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <div className="text-xs text-white/70">{f.description}</div>
                {f.content_preview && (
                  <pre className="mt-2 bg-black text-white/60 font-mono-data text-[11px] p-2 overflow-x-auto whitespace-pre-wrap border border-white/[0.05]">{f.content_preview}</pre>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* API AUDITOR */}
      <Section title="API Auditor · Endpoints y versiones" icon={ServerIcon} accent="cyan" runner={apiA}
        description="Descubre bases /api/v1..v3/, GraphQL introspection, y endpoints sensibles (/admin, /debug, /swagger).">
        {apiData && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{apiData.active_bases_count}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">API bases activas</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{apiData.counts_by_severity?.critical || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Endpoints críticos</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{apiData.findings_total}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Total hallazgos</div>
              </div>
            </div>
            {apiData.graphql && (
              <div className="border border-purple-400/30 bg-purple-500/[0.05] p-3">
                <div className="font-mono-data text-xs font-bold text-purple-300 mb-1">GraphQL detectado</div>
                <div className="text-xs text-white/70">
                  {apiData.graphql.introspection_enabled ? "⚠️ Introspection HABILITADA — schema completo accesible" : "Introspection deshabilitada"}
                </div>
              </div>
            )}
            {(apiData.findings || []).slice(0, 40).map((f, i) => (
              <div key={i} className="flex items-center gap-2 border border-white/[0.05] p-2 font-mono-data text-xs">
                <SevBadge level={f.severity} />
                <span className={f.status === 200 ? "text-green-400" : f.status === 401 || f.status === 403 ? "text-orange-400" : "text-white/50"}>{f.status}</span>
                <span className="text-cyan-300 break-all flex-1">{f.url.replace(/^https?:\/\/[^/]+/, "")}</span>
                <span className="text-white/40 text-[10px] max-w-[240px] truncate">{f.reason}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* VERSION TRACKING */}
      <Section title="Version Tracker · Detector de rollbacks vulnerables" icon={ShieldAlert} accent="orange" runner={vt}
        description="Compara las versiones detectadas ahora con los escaneos anteriores del mismo dominio. Alerta si un producto volvió a una versión inferior (posible rollback vulnerable).">
        {vtData && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{vtData.tracked_products}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Productos rastreados</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{vtData.downgrades?.length || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Rollbacks detectados</div>
              </div>
              <div className="border border-green-400/30 p-3">
                <div className="font-heading text-2xl font-black text-green-400">{vtData.upgrades?.length || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Upgrades</div>
              </div>
            </div>
            {vtData.note && <p className="text-xs text-white/50">{vtData.note}</p>}
            {(vtData.downgrades || []).length > 0 ? (
              <div className="space-y-2">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-red-400">Rollbacks</div>
                {vtData.downgrades.map((d, i) => (
                  <div key={i} className="border border-red-400/40 bg-red-500/[0.06] p-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      <AlertTriangle className="w-4 h-4 text-red-400" />
                      <span className="font-heading font-bold">{d.product}</span>
                      <span className="font-mono-data text-xs text-orange-300">{d.previous_version}</span>
                      <span className="text-white/40">→</span>
                      <span className="font-mono-data text-xs text-red-300">{d.current_version}</span>
                    </div>
                    <div className="text-xs text-white/60 mt-1">{d.note}</div>
                  </div>
                ))}
              </div>
            ) : vtData.history_scans > 0 ? (
              <div className="text-sm text-green-400/80">Sin rollbacks detectados en {vtData.history_scans} escaneo(s) anteriores.</div>
            ) : null}
          </div>
        )}
      </Section>

      {/* GLOBAL CORRELATION */}
      <Section title="Grafo Global de Amenazas · Vecinos sospechosos" icon={Network} accent="purple" runner={corr}
        description="Busca patrones comunes con otros dominios analizados en la plataforma (misma IP, mismo certificado). Alerta si alguno fue marcado como fraude por otro analista.">
        {corrData && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{corrData.total_correlations}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Correlaciones</div>
              </div>
              <div className={`border p-3 ${corrData.flagged_neighbours_count > 0 ? "border-red-400/40" : "border-white/[0.06]"}`}>
                <div className={`font-heading text-2xl font-black ${corrData.flagged_neighbours_count > 0 ? "text-red-400" : "text-white/60"}`}>
                  {corrData.flagged_neighbours_count}
                </div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Vecinos marcados</div>
              </div>
            </div>
            {corrData.risk_note && (
              <div className={`border p-3 ${corrData.flagged_neighbours_count > 0 ? "border-red-400 bg-red-500/[0.06] text-red-300" : "border-green-400/30 bg-green-500/[0.03] text-green-400"}`}>
                <div className="text-sm">{corrData.risk_note}</div>
              </div>
            )}
            {(corrData.correlations || []).length > 0 && (
              <div className="space-y-1 max-h-72 overflow-y-auto">
                {corrData.correlations.map((c, i) => (
                  <div key={i} className="flex items-center gap-2 border border-white/[0.05] p-2 font-mono-data text-xs">
                    {c.flagged_by_someone ? <Flag className="w-3 h-3 text-red-400 flex-shrink-0" /> : <span className="w-3 h-3 flex-shrink-0" />}
                    <span className="text-cyan-300 flex-1 break-all">{c.asset}</span>
                    <span className="text-white/40 text-[10px] uppercase tracking-widest">{c.signal}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Section>

      {/* IDOR ANALYZER */}
      <Section title="IDOR Analyzer · Enumeración de IDs (BOLA)" icon={KeyRound} accent="orange" runner={idor}
        description="Mapea endpoints con IDs numéricos y UUIDs; sugiere valores de fuzz para probar acceso no autorizado a datos de otros usuarios.">
        {idorData && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{idorData.endpoints_analyzed}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Endpoints analizados</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{idorData.total_id_patterns}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Patrones IDOR</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{idorData.counts_by_risk?.critical || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Críticos</div>
              </div>
            </div>
            {idorData.ai_recommendations?.overall_verdict && (
              <div className="border-l-4 border-orange-400 pl-4 py-2">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-orange-400 mb-1">Veredicto IA</div>
                <p className="text-sm text-white/90 italic">&ldquo;{idorData.ai_recommendations.overall_verdict}&rdquo;</p>
              </div>
            )}
            {(idorData.ai_recommendations?.top_targets || []).length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Top targets (IA)</div>
                {idorData.ai_recommendations.top_targets.map((t, i) => (
                  <div key={i} className="border border-orange-400/30 bg-orange-500/[0.04] p-3 mb-2">
                    <div className="font-mono-data text-xs text-cyan-300 break-all">{t.endpoint}</div>
                    <div className="text-xs text-white/70 mt-1">{t.why_dangerous}</div>
                    <div className="text-xs text-white/50 mt-1"><span className="text-cyan-400">Prueba:</span> {t.test_strategy}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="space-y-1 max-h-72 overflow-y-auto">
              {(idorData.findings || []).slice(0, 30).map((f, i) => (
                <div key={i} className="border border-white/[0.05] p-2 font-mono-data text-xs">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SevBadge level={f.risk} />
                    <span className="text-cyan-300">{f.id_type}</span>
                    <span className="text-white/40 flex-1 truncate">{f.endpoint}</span>
                  </div>
                  <div className="text-[11px] text-white/50 mt-1">{f.reason}</div>
                  {f.fuzz_urls?.length > 0 && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-[10px] text-cyan-400 uppercase tracking-widest">
                        {f.fuzz_urls.length} fuzz URLs
                      </summary>
                      <div className="mt-1 space-y-0.5">
                        {f.fuzz_urls.map((u, j) => (
                          <div key={j} className="flex items-center gap-1 text-[11px] text-white/60">
                            <span className="break-all flex-1">{u}</span>
                            <CopyLink text={u} />
                          </div>
                        ))}
                      </div>
                    </details>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* LOGIC FLOW ANALYZER */}
      <Section title="Detective de Lógica · Bypass de flujos críticos" icon={Workflow} accent="purple" runner={logic}
        description="La IA mapea flujos de negocio (login, checkout, reset password) y sugiere rutas de bypass autorizadas para pruebas.">
        {logicData && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{logicData.flows_detected}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Flujos detectados</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{(logicData.bypass_scenarios || []).length}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Escenarios IA</div>
              </div>
            </div>
            {logicData.overall_verdict && (
              <div className="border-l-4 border-purple-400 pl-4 py-1 italic text-sm text-white/90">
                &ldquo;{logicData.overall_verdict}&rdquo;
              </div>
            )}
            {logicData.note && <p className="text-sm text-white/50">{logicData.note}</p>}
            <div className="space-y-2">
              {(logicData.bypass_scenarios || []).map((s, i) => (
                <div key={i} className="border border-orange-400/30 bg-orange-500/[0.04] p-3">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <SevBadge level={s.risk} />
                    <span className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">{s.flow}</span>
                    <span className="font-mono-data text-[10px] uppercase tracking-widest text-purple-400">{s.vulnerability_class}</span>
                  </div>
                  <div className="text-sm text-white/90 font-heading">{s.hypothetical_bypass}</div>
                  <div className="text-xs text-white/60 mt-1"><span className="text-cyan-400">Impacto:</span> {s.impact_plain}</div>
                  {(s.test_steps || []).length > 0 && (
                    <ol className="mt-2 space-y-0.5 text-xs text-white/70 list-decimal list-inside">
                      {s.test_steps.map((step, j) => <li key={j}>{step}</li>)}
                    </ol>
                  )}
                  {s.expected_indicator && (
                    <div className="text-[11px] text-green-400 mt-1"><span className="uppercase tracking-widest">Indicador esperado:</span> {s.expected_indicator}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* REVERSE IP / NEIGHBORS */}
      <Section title="Vecindad de Red · Dominios que comparten IP/ASN" icon={Users} accent="cyan" runner={revip}
        description="Encuentra otros dominios en la misma IP y explora el rango ASN. A menudo revela entornos de desarrollo o subsidiarias sin firewall.">
        {revipData && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{revipData.reverse_ip_count}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Vecinos IP</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{revipData.interesting_count || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Interesantes (dev/staging/…)</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-mono-data text-sm text-cyan-300 truncate">{revipData.asn?.name || revipData.ip || "—"}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">ASN / red</div>
              </div>
            </div>
            {revipData.note && <p className="text-sm text-white/50">{revipData.note}</p>}
            {revipData.asn?.start_address && (
              <div className="font-mono-data text-xs text-white/60">
                Rango: <span className="text-cyan-300">{revipData.asn.start_address} → {revipData.asn.end_address}</span>
                {revipData.asn.country && <span className="ml-2 text-white/40">{revipData.asn.country}</span>}
              </div>
            )}
            {(revipData.interesting_neighbors || []).length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-orange-400 mb-2">
                  Vecinos con palabras clave sospechosas
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
                  {revipData.interesting_neighbors.map((n, i) => (
                    <a key={i} href={`https://${n}`} target="_blank" rel="noreferrer"
                      className="font-mono-data text-xs text-orange-300 hover:text-cyan-400 border border-orange-400/20 p-1.5 inline-flex items-center gap-1">
                      {n} <ExternalLink className="w-3 h-3" />
                    </a>
                  ))}
                </div>
              </div>
            )}
            {(revipData.reverse_ip_domains || []).length > 0 && (
              <details>
                <summary className="cursor-pointer text-xs text-cyan-400 uppercase tracking-widest font-mono-data">
                  Ver todos los vecinos ({revipData.reverse_ip_domains.length})
                </summary>
                <div className="mt-2 grid grid-cols-1 md:grid-cols-3 gap-1 max-h-64 overflow-y-auto">
                  {revipData.reverse_ip_domains.map((n, i) => (
                    <div key={i} className="font-mono-data text-[11px] text-white/60 border border-white/[0.05] p-1">{n}</div>
                  ))}
                </div>
              </details>
            )}
          </div>
        )}
      </Section>

      {/* GITHUB MINER */}
      <Section title="GitHub Miner · Fugas en repositorios públicos" icon={Github} accent="green" runner={gh}
        description="Busca menciones del dominio en código público de GitHub. Requiere GitHub Personal Access Token (Ajustes → API Keys → github).">
        {ghData && !ghData.configured && (
          <div className="border border-orange-400/40 bg-orange-500/[0.06] p-3 text-sm text-orange-300">
            {ghData.note}
          </div>
        )}
        {ghData && ghData.configured && ghData.error && (
          <div className="text-sm text-red-400">Error: {ghData.error}</div>
        )}
        {ghData && ghData.configured && !ghData.error && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{ghData.total_hits}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Repos que mencionan</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{ghData.secret_hits_count || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Secretos detectados</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{(ghData.results || []).filter(r => r.query?.includes(".env")).length}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">.env expuestos</div>
              </div>
            </div>
            {(ghData.secret_hits || []).length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-red-400 mb-2">Secretos filtrados</div>
                {ghData.secret_hits.map((s, i) => (
                  <div key={i} className="border border-red-400/40 bg-red-500/[0.06] p-3 mb-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SevBadge level="critical" />
                      <span className="font-mono-data text-xs text-cyan-300">{s.kind}</span>
                      <span className="font-mono-data text-xs text-white/80">{s.repository}/{s.path}</span>
                    </div>
                    <div className="font-mono-data text-xs text-red-300 mt-1 break-all">{s.match}</div>
                    <a href={s.html_url} target="_blank" rel="noreferrer" className="text-xs text-cyan-400 hover:underline mt-1 inline-flex items-center gap-1">
                      Ver en GitHub <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                ))}
              </div>
            )}
            <div className="max-h-72 overflow-y-auto space-y-1">
              {(ghData.results || []).slice(0, 40).map((r, i) => (
                <a key={i} href={r.html_url} target="_blank" rel="noreferrer"
                  className="block border border-white/[0.05] p-2 hover:border-cyan-400/40">
                  <div className="flex items-center gap-2 font-mono-data text-xs flex-wrap">
                    <span className="text-cyan-300">{r.repository}</span>
                    <span className="text-white/40 truncate">{r.path}</span>
                    {r.repo_stars > 0 && <span className="text-orange-400 ml-auto">★ {r.repo_stars}</span>}
                  </div>
                  {r.snippet && <div className="text-[11px] text-white/50 mt-1 truncate">{r.snippet}</div>}
                </a>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* BOT RESISTANCE */}
      <Section title="Resistencia a Bots · Captcha + rate-limit en login" icon={Bot} accent="orange" runner={bot}
        description="Evalúa si el sitio tiene protecciones (reCAPTCHA, hCaptcha, Turnstile, rate-limit) suficientes para resistir credential-stuffing y fuerza bruta.">
        {botData && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className={`border p-3 ${botData.score >= 70 ? "border-green-400/30" : botData.score >= 40 ? "border-orange-400/30" : "border-red-400/30"}`}>
                <div className={`font-heading text-3xl font-black tabular-nums ${botData.score >= 70 ? "text-green-400" : botData.score >= 40 ? "text-orange-400" : "text-red-400"}`}>
                  {botData.score}<span className="text-lg text-white/40">/100</span>
                </div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Score protección</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{botData.captchas_count}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Captchas detectados</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-mono-data text-sm text-cyan-300">{botData.waf_hint || "—"}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">WAF detectado</div>
              </div>
            </div>
            <div className={`border p-3 ${botData.risk === "critical" || botData.risk === "high" ? "border-red-400 bg-red-500/[0.06] text-red-300" : botData.risk === "medium" ? "border-orange-400 bg-orange-500/[0.04] text-orange-300" : "border-green-400/30 bg-green-500/[0.03] text-green-400"}`}>
              <div className="flex items-center gap-2 mb-1">
                <SevBadge level={botData.risk === "critical" ? "critical" : botData.risk === "high" ? "high" : botData.risk === "medium" ? "medium" : "low"} />
                <span className="font-mono-data text-[10px] uppercase tracking-widest">Veredicto</span>
              </div>
              <p className="text-sm">{botData.verdict}</p>
            </div>
            {(botData.captchas_detected || []).length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400 mb-2">Protecciones detectadas</div>
                <div className="flex flex-wrap gap-1.5">
                  {botData.captchas_detected.map(c => (
                    <span key={c} className="font-mono-data text-[10px] border border-green-400/40 text-green-400 px-2 py-1">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {botData.login_page && (
              <div className="border border-white/[0.06] p-3">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-1">Login detectado</div>
                <div className="font-mono-data text-xs text-cyan-300 break-all">{botData.login_page.url}</div>
                <div className="text-xs text-white/60 mt-1">
                  {botData.login_page.has_password_input ? "✓ Campo password" : "✗ Sin password"} ·
                  Captchas en login: <span className="text-cyan-400">{botData.login_page.captchas_on_login?.join(", ") || "ninguno"}</span>
                </div>
              </div>
            )}
            {botData.rate_limit?.tested && (
              <div className="border border-white/[0.06] p-3">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-1">
                  Rate-limit ({botData.rate_limit.sample_size} peticiones simultáneas)
                </div>
                <div className="text-xs text-white/70 font-mono-data">
                  {botData.rate_limit.rate_limited_seen ? (
                    <span className="text-green-400">✓ 429 devuelto — hay rate-limit</span>
                  ) : botData.rate_limit.challenge_seen ? (
                    <span className="text-orange-400">⚠ Challenge (403) devuelto</span>
                  ) : (
                    <span className="text-red-400">✗ Sin rate-limit efectivo detectado</span>
                  )}
                </div>
                <div className="font-mono-data text-[10px] text-white/40 mt-1">
                  Códigos: {(botData.rate_limit.statuses || []).join(", ")}
                </div>
              </div>
            )}
          </div>
        )}
      </Section>

      {/* SUPPLY CHAIN */}
      <Section title="Supply Chain · CVEs en librerías detectadas" icon={Package} accent="red" runner={supply}
        description="Cruza las versiones de librerías detectadas con OSV.dev (base pública de CVEs). Alerta si alguna tiene exploit conocido.">
        {supplyData && (
          <div className="space-y-3">
            <div className="grid grid-cols-4 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{supplyData.libraries_analyzed}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Libs analizadas</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{supplyData.libraries_with_vulns || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Con CVE</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{supplyData.total_vulnerabilities}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Vulnerabilidades</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{supplyData.counts_by_severity?.critical || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Críticas</div>
              </div>
            </div>
            {supplyData.note && <p className="text-sm text-white/50">{supplyData.note}</p>}
            {(supplyData.vulnerable_libraries || []).map((lib, i) => (
              <div key={i} className="border border-white/[0.06]">
                <div className="px-4 py-2 border-b border-white/[0.06] bg-[#0F0F13] flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <SevBadge level={lib.worst_severity} />
                    <span className="font-heading font-bold text-sm">{lib.name}</span>
                    <span className="font-mono-data text-xs text-orange-300">@{lib.version}</span>
                    <span className="font-mono-data text-[10px] text-white/40">{lib.ecosystem}</span>
                  </div>
                  <span className="font-mono-data text-[10px] text-white/60">{lib.vuln_count} CVE(s)</span>
                </div>
                <div className="p-3 space-y-2">
                  {(lib.vulnerabilities || []).slice(0, 5).map((v, j) => (
                    <div key={j} className="border-l-2 border-red-400/40 pl-3 py-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <SevBadge level={v.severity} />
                        <span className="font-mono-data text-xs text-cyan-300">{v.id}</span>
                        {v.cves?.map(c => (
                          <span key={c} className="font-mono-data text-[10px] border border-orange-400/40 text-orange-300 px-1.5">{c}</span>
                        ))}
                        {v.cvss_score !== null && v.cvss_score !== undefined && (
                          <span className="font-mono-data text-[10px] text-white/60">CVSS {v.cvss_score}</span>
                        )}
                      </div>
                      <div className="text-xs text-white/70 mt-1">{v.summary}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* ═══ PROJECT GENESIS ═══ */}
      <div className="border-2 border-purple-400/40 bg-gradient-to-r from-purple-500/[0.08] via-cyan-500/[0.04] to-purple-500/[0.06] p-5 mb-5">
        <div className="flex items-center gap-3 mb-2">
          <EyeOff className="w-5 h-5 text-purple-400" />
          <h2 className="font-heading text-xl font-black">Project Genesis · Sigilo + Análisis avanzado</h2>
        </div>
        <p className="text-sm text-white/60 leading-relaxed">
          Motor sigiloso (rotación de User-Agents + timing orgánico), huella JARM del servidor TLS,
          detección de honeypots, sellado de evidencias con hash criptográfico y perfilado
          IA del equipo objetivo.
        </p>
      </div>

      {/* STEALTH STATUS */}
      <StealthStatusPanel />

      {/* JARM */}
      <Section title="JARM Fingerprint · Huella TLS única del servidor" icon={FingerprintIcon} accent="cyan" runner={jarm}
        description="Genera un hash único basado en cómo el servidor negocia TLS. Persiste aunque el objetivo cambie de IP o dominio.">
        {jarmData && (
          <div className="space-y-2">
            <div className="border border-white/[0.06] p-3 font-mono-data text-xs text-cyan-300 break-all">
              {jarmData.jarm_fingerprint}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{jarmData.handshakes_successful}/{jarmData.handshakes_attempted}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">TLS handshakes exitosos</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-mono-data text-xs text-cyan-300">{(jarmData.observed_tls_versions || []).join(", ") || "—"}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Versiones TLS</div>
              </div>
            </div>
            <p className="text-xs text-white/50">{jarmData.note}</p>
          </div>
        )}
      </Section>

      {/* HONEYPOT */}
      <Section title="Detector de Honeypots · Trampas antes de proceder" icon={Skull} accent="red" runner={honey}
        description="Evalúa señales de que el objetivo es un servidor trampa (banners conocidos, puertos ilógicos abiertos, cabeceras canary).">
        {honeyData && (
          <div className="space-y-3">
            <div className={`border-2 p-3 flex items-center gap-3 ${honeyData.risk === "critical" ? "border-red-400 bg-red-500/[0.08]" : honeyData.risk === "high" ? "border-orange-400 bg-orange-500/[0.06]" : "border-green-400/30 bg-green-500/[0.03]"}`}>
              <AlertTriangle className={`w-5 h-5 ${honeyData.risk === "critical" ? "text-red-400" : honeyData.risk === "high" ? "text-orange-400" : "text-green-400"}`} />
              <div>
                <div className="font-heading font-bold">{honeyData.verdict}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/50 mt-1">
                  Suspicion score: {honeyData.suspicion_score}/100 · Risk: {honeyData.risk}
                </div>
              </div>
            </div>
            {(honeyData.signals_detected || []).length > 0 && (
              <div className="space-y-1">
                {honeyData.signals_detected.map((s, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <SevBadge level={s.severity} />
                    <div>
                      <div className="text-white font-mono-data">{s.signal}</div>
                      <div className="text-white/60">{s.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Section>

      {/* EVIDENCE SEALING */}
      <Section title="Sellado de Evidencias · Cadena de Custodia" icon={ShieldCheck} accent="green" runner={evid}
        description="Genera hashes SHA-256 con timestamp UTC para cada hallazgo crítico. Adecuado para reportes legales o auditorías oficiales.">
        {evidData && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-white">{evidData.total_findings_sealed}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Hallazgos sellados</div>
              </div>
              <div className="border border-green-400/30 p-3">
                <div className="font-mono-data text-xs text-green-400 break-all">{evidData.chain_hash?.slice(0, 32)}…</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Chain hash</div>
              </div>
            </div>
            <p className="text-xs text-white/60">{evidData.custody_note}</p>
            <TimestampButton scanId={scanId} chainHash={evidData.chain_hash} existing={evidData.rfc3161_timestamp} />
            {(evidData.sealed_findings || []).length > 0 && (
              <div className="max-h-72 overflow-y-auto space-y-1">
                {evidData.sealed_findings.map((f, i) => (
                  <div key={i} className="border border-green-400/20 p-2 font-mono-data text-xs">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SevBadge level={f.finding.severity || "high"} />
                      <span className="text-cyan-300">{f.finding.type}</span>
                      <span className="text-white/40 text-[10px]">{f.sealed_at}</span>
                    </div>
                    <div className="text-white/50 text-[10px] mt-1 break-all">SHA-256: {f.sha256}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Section>

      {/* SLEEPING INFRA */}
      <Section title="Infraestructura Durmiente · Objetivos prioritarios" icon={AlertTriangle} accent="orange" runner={sleep}
        description="Identifica subdominios con nombres marketing/legacy/dev, certificados >1 año y tech obsoleta — típicos activos con menor monitorización.">
        {sleepData && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{sleepData.total_findings}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Hallazgos</div>
              </div>
              <div className="border border-red-400/30 p-3">
                <div className="font-heading text-2xl font-black text-red-400">{sleepData.counts_by_severity?.high || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Altos</div>
              </div>
              <div className="border border-orange-400/30 p-3">
                <div className="font-heading text-2xl font-black text-orange-400">{sleepData.counts_by_severity?.medium || 0}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Medios</div>
              </div>
            </div>
            {(sleepData.findings || []).map((f, i) => (
              <div key={i} className="border border-white/[0.06] p-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <SevBadge level={f.severity} />
                  <span className="font-mono-data text-xs text-cyan-300">{f.type}</span>
                  <span className="text-sm text-white/80">{f.asset}</span>
                </div>
                <div className="text-xs text-white/60 mt-1">{f.reason}</div>
              </div>
            ))}
            {sleepData.note && <p className="text-[11px] text-white/50 italic">{sleepData.note}</p>}
          </div>
        )}
      </Section>

      {/* ORGANIZATIONAL MAP */}
      <Section title="Mapeo Organizacional · Personas clave & exposición humana" icon={Building2} accent="purple" runner={orgmap}
        description="IA infiere personal clave, roles y perfiles con alta exposición a partir de WHOIS, autores de documentos, breaches y GitHub.">
        {orgData && (
          <div className="space-y-3">
            <div className="border border-white/[0.06] p-3">
              <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mb-1">Organización</div>
              <div className="font-heading font-bold">{orgData.organization_name || "Sin identificar"}</div>
              <div className="font-mono-data text-[10px] text-cyan-400 mt-1">Tipo: {orgData.org_type}</div>
            </div>
            {orgData.attack_surface_summary && (
              <p className="text-sm text-white/80 italic border-l-2 border-purple-400 pl-3">&ldquo;{orgData.attack_surface_summary}&rdquo;</p>
            )}
            {(orgData.key_people || []).length > 0 && (
              <div className="space-y-1">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-cyan-400">Personas clave ({orgData.key_people.length})</div>
                {orgData.key_people.map((p, i) => (
                  <div key={i} className="border border-white/[0.06] p-2 text-xs">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SevBadge level={p.social_exposure === "high" ? "critical" : p.social_exposure === "medium" ? "high" : "low"} />
                      <span className="font-mono-data text-cyan-300">{p.handle_or_name}</span>
                      <span className="text-white/70">— {p.inferred_role}</span>
                      <span className="text-white/40 text-[10px] uppercase tracking-widest ml-auto">{p.signal_source}</span>
                    </div>
                    {p.notes && <div className="text-white/50 text-[11px] mt-1">{p.notes}</div>}
                  </div>
                ))}
              </div>
            )}
            {(orgData.high_exposure_targets || []).length > 0 && (
              <div className="border border-red-400/30 bg-red-500/[0.04] p-3">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-red-400 mb-1">Alta exposición (prioritarios social eng)</div>
                <div className="flex flex-wrap gap-1">
                  {orgData.high_exposure_targets.map((t, i) => (
                    <span key={i} className="font-mono-data text-xs border border-red-400/40 text-red-300 px-2 py-1">{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Section>

      {/* DEV STYLE PROFILE */}
      <Section title="Perfilador de Estilo de Desarrollo" icon={Code2} accent="cyan" runner={devp}
        description="IA analiza calidad del código y madurez del equipo para estimar la probabilidad de encontrar bugs lógicos básicos.">
        {devData && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className={`border p-3 ${devData.maturity_score >= 75 ? "border-green-400/30" : devData.maturity_score >= 50 ? "border-cyan-400/30" : devData.maturity_score >= 25 ? "border-orange-400/30" : "border-red-400/30"}`}>
                <div className={`font-heading text-3xl font-black tabular-nums ${devData.maturity_score >= 75 ? "text-green-400" : devData.maturity_score >= 50 ? "text-cyan-400" : devData.maturity_score >= 25 ? "text-orange-400" : "text-red-400"}`}>
                  {devData.maturity_score}<span className="text-lg text-white/40">/100</span>
                </div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Madurez · {devData.maturity_label}</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-mono-data text-sm text-cyan-300">{devData.logic_bug_probability}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Probabilidad bugs lógicos</div>
              </div>
              <div className="border border-white/[0.06] p-3 text-xs text-white/70">
                {devData.team_profile}
              </div>
            </div>
            {devData.bug_hunting_verdict && (
              <p className="text-sm text-white/90 italic border-l-2 border-cyan-400 pl-3">&ldquo;{devData.bug_hunting_verdict}&rdquo;</p>
            )}
            {(devData.recommended_focus_areas || []).length > 0 && (
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-green-400 mb-1">Áreas de enfoque recomendadas</div>
                <ul className="space-y-1 text-sm text-white/80">
                  {devData.recommended_focus_areas.map((a, i) => (
                    <li key={i} className="flex items-start gap-2"><Sparkles className="w-3 h-3 text-cyan-400 mt-1 flex-shrink-0" />{a}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </Section>
    </div>
  );
}

function TimestampButton({ scanId, chainHash, existing }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(existing || null);
  const stamp = async () => {
    setLoading(true);
    try {
      const r = await axios.post(`${API}/scans/${scanId}/evidence-seal/timestamp`, {},
        { withCredentials: true, timeout: 20000 });
      setResult(r.data.rfc3161);
      if (r.data.rfc3161?.ok) toast.success("Timestamp RFC3161 obtenido de FreeTSA");
      else toast.error(`Error: ${r.data.rfc3161?.error || "sin respuesta"}`);
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
    finally { setLoading(false); }
  };
  if (!chainHash) return null;
  return (
    <div className="border border-green-400/20 p-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <div className="font-mono-data text-[10px] uppercase tracking-widest text-green-400">Timestamp RFC3161 certificado</div>
          <div className="text-xs text-white/60 mt-0.5">
            {result?.ok
              ? `Certificado por ${result.authority} · ${result.tsr_size_bytes} bytes de firma`
              : "Solicita un timestamp firmado a FreeTSA.org para valor legal ante tribunales"}
          </div>
        </div>
        <button onClick={stamp} disabled={loading}
          data-testid="rfc3161-timestamp-btn"
          className="bg-green-400 text-black font-semibold px-4 py-1.5 hover:bg-green-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5">
          {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldCheck className="w-3 h-3" />}
          {result?.ok ? "Renovar timestamp" : "Certificar timestamp"}
        </button>
      </div>
      {result?.ok && result.tsr_base64 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-[10px] text-green-400 uppercase tracking-widest font-mono-data">
            Ver TSR base64 (para verificación con openssl ts)
          </summary>
          <pre className="mt-1 bg-black font-mono-data text-[10px] text-white/60 p-2 overflow-x-auto whitespace-pre-wrap break-all border border-white/[0.05] max-h-32">{result.tsr_base64.slice(0, 800)}{result.tsr_base64.length > 800 ? "…" : ""}</pre>
          <div className="text-[10px] text-white/40 mt-1">{result.verification_note}</div>
        </details>
      )}
      {result && !result.ok && (
        <div className="mt-2 text-xs text-red-400">Error: {result.error}</div>
      )}
    </div>
  );
}

function StealthStatusPanel() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const load = async () => {
    setLoading(true);
    try {
      const r = await axios.get(`${API}/stealth/status`, { withCredentials: true });
      setStatus(r.data);
    } catch (e) { toast.error("Error"); }
    finally { setLoading(false); }
  };
  return (
    <section data-testid="panel-stealth" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <div className="flex items-center gap-3">
          <EyeOff className="w-4 h-4 text-purple-400" />
          <h3 className="font-heading text-sm font-bold uppercase tracking-wide">Módulo Sigilo · Estado</h3>
        </div>
        <button onClick={load} disabled={loading}
          data-testid="stealth-status-btn"
          className="bg-cyan-400 text-black font-semibold px-4 py-1.5 hover:bg-cyan-300 disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5">
          {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
          Consultar
        </button>
      </div>
      <div className="p-5">
        {status ? (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
              <span className="text-green-400 font-mono-data uppercase tracking-widest text-xs">SIGILO ACTIVO</span>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{status.pool_sizes?.user_agents}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">User-Agents</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{status.pool_sizes?.languages}</div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Accept-Language</div>
              </div>
              <div className="border border-white/[0.06] p-3">
                <div className="font-heading text-2xl font-black text-cyan-400">{status.default_delay_ms?.min}-{status.default_delay_ms?.max}<span className="text-lg text-white/40">ms</span></div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Jitter entre peticiones</div>
              </div>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(status.features || []).map(f => (
                <span key={f} className="font-mono-data text-[10px] border border-purple-400/30 text-purple-300 px-2 py-1">{f}</span>
              ))}
            </div>
            <p className="text-xs text-white/50">{status.note}</p>
          </div>
        ) : (
          <p className="text-sm text-white/50">Consulta la configuración del motor sigiloso.</p>
        )}
      </div>
    </section>
  );
}

