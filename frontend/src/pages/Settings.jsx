import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Link, useNavigate } from "react-router-dom";
import {
  Radar, ArrowLeft, Key, Slack, Save, Zap, Loader2, CheckCircle2, XCircle,
  Cpu, Sparkles, Sliders, Eye, EyeOff, ExternalLink, Send, Brain, StickyNote,
  ShieldAlert, Clock, Globe, Mail, Rocket, Trash2, Webhook,
} from "lucide-react";
import { API, useAuth } from "@/lib/auth";
import { PROVIDERS, AI_PROVIDERS, AI_MODES } from "@/constants/settingsData";
import { TestBadge, KeyInput } from "@/components/settings/SettingsUI";

export default function Settings() {
  const { user, checkAuth } = useAuth();
  const navigate = useNavigate();

  const [webhook, setWebhook] = useState("");
  const [tgToken, setTgToken] = useState("");
  const [tgChat, setTgChat] = useState("");
  const [tgTokenSet, setTgTokenSet] = useState(false);
  const [tgTokenMasked, setTgTokenMasked] = useState("");
  const [tgTesting, setTgTesting] = useState(false);
  const [tgTest, setTgTest] = useState(null);
  const [savingTg, setSavingTg] = useState(false);
  const [loading, setLoading] = useState(true);
  // Preferences
  const [riskThreshold, setRiskThreshold] = useState(50);
  const [notes, setNotes] = useState("");
  const [savingPrefs, setSavingPrefs] = useState(false);
  // Security log (admin-only)
  const [isAdmin, setIsAdmin] = useState(false);
  const [whitelistInfo, setWhitelistInfo] = useState(null);
  const [securityLog, setSecurityLog] = useState(null);
  const [loadingLog, setLoadingLog] = useState(false);
  const [savingApi, setSavingApi] = useState(false);
  const [savingAi, setSavingAi] = useState(false);

  // API keys state
  const [keys, setKeys] = useState({ shodan: "", abuseipdb: "", hibp: "", rapidapi: "" });
  const [keysSet, setKeysSet] = useState({});         // { shodan: true, ... }
  const [changed, setChanged] = useState({});          // track which fields changed
  const [tests, setTests] = useState({});              // per-provider test result
  const [testing, setTesting] = useState({});          // per-provider testing bool

  // AI config
  const [aiProvider, setAiProvider] = useState("emergent");
  const [aiMode, setAiMode] = useState("precision");
  const [aiKey, setAiKey] = useState("");
  const [aiKeyChanged, setAiKeyChanged] = useState(false);
  const [aiTest, setAiTest] = useState(null);
  const [aiTesting, setAiTesting] = useState(false);
  const [aiKeySet, setAiKeySet] = useState(false);

  // Email (Resend) config
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [emailAddress, setEmailAddress] = useState("");
  const [resendConfigured, setResendConfigured] = useState(false);
  const [savingEmail, setSavingEmail] = useState(false);
  const [emailTesting, setEmailTesting] = useState(false);

  // Telegram webhook status
  const [webhookInfo, setWebhookInfo] = useState(null);
  const [webhookBusy, setWebhookBusy] = useState(false);

  // Claude tier
  const [claudeTiers, setClaudeTiers] = useState([]);
  const [claudeActive, setClaudeActive] = useState("balanced");
  const [savingClaude, setSavingClaude] = useState(false);

  // Ollama config
  const [ollamaUrl, setOllamaUrl] = useState("");
  const [ollamaModel, setOllamaModel] = useState("");
  const [ollamaUrlChanged, setOllamaUrlChanged] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [s, w, tg, prefs, em, cl] = await Promise.all([
          axios.get(`${API}/settings/keys`, { withCredentials: true }),
          axios.get(`${API}/settings/slack`, { withCredentials: true }),
          axios.get(`${API}/settings/telegram`, { withCredentials: true }),
          axios.get(`${API}/settings/preferences`, { withCredentials: true }),
          axios.get(`${API}/settings/email`, { withCredentials: true }),
          axios.get(`${API}/settings/claude`, { withCredentials: true }),
        ]);
        const setMap = {};
        Object.entries(s.data.api_keys).forEach(([p, v]) => { setMap[p] = v.set; });
        setKeysSet(setMap);
        setAiProvider(s.data.ai_config.provider || "emergent");
        setAiMode(s.data.ai_config.mode || "precision");
        setAiKeySet(!!s.data.ai_config.key_set);
        setOllamaUrl(s.data.ai_config.ollama_url || "");
        setOllamaModel(s.data.ai_config.ollama_model || "");
        setOllamaUrlChanged(false);
        setWebhook(w.data.webhook_url || "");
        setTgTokenSet(!!tg.data.bot_token_set);
        setTgTokenMasked(tg.data.bot_token_masked || "");
        setTgChat(tg.data.chat_id || "");
        setRiskThreshold(prefs.data.risk_threshold ?? 50);
        setNotes(prefs.data.notes || "");
        setEmailEnabled(!!em.data.enabled);
        setEmailAddress(em.data.address || "");
        setResendConfigured(!!em.data.resend_configured);
        setClaudeTiers(cl.data.tiers || []);
        setClaudeActive(cl.data.active || "balanced");
        // Check if current user is admin
        try {
          const wl = await axios.get(`${API}/settings/access-whitelist`, { withCredentials: true });
          setWhitelistInfo(wl.data);
          setIsAdmin(!!wl.data.you_are_admin);
        } catch { /* silent */ }
      } catch (_) { /* ignore */ } finally { setLoading(false); }
    })();
  }, []);

  const isPro = user?.plan === "pro";

  const runTest = async (provider) => {
    if (!keys[provider]) {
      toast.error("Introduce la key antes de probar");
      return false;
    }
    setTesting((t) => ({ ...t, [provider]: true }));
    setTests((t) => ({ ...t, [provider]: null }));
    try {
      const r = await axios.post(`${API}/settings/test-key`, { provider, key: keys[provider] }, { withCredentials: true });
      setTests((t) => ({ ...t, [provider]: r.data }));
      return r.data.ok;
    } catch (e) {
      setTests((t) => ({ ...t, [provider]: { ok: false, detail: e?.response?.data?.detail || "Error" } }));
      return false;
    } finally {
      setTesting((t) => ({ ...t, [provider]: false }));
    }
  };

  const saveApiKeys = async () => {
    // Test any changed key first
    for (const p of PROVIDERS.map((x) => x.id)) {
      if (changed[p] && keys[p]) {
        const ok = await runTest(p);
        if (!ok) {
          toast.error(`La key de ${p} no pasó el test. No se guarda.`);
          return;
        }
      }
    }
    setSavingApi(true);
    try {
      const payload = { api_keys: {} };
      for (const p of PROVIDERS.map((x) => x.id)) {
        if (keys[p]) {
          payload.api_keys[p] = keys[p];
          payload.api_keys[`${p}_changed`] = !!changed[p];
        }
      }
      await axios.post(`${API}/settings/keys`, payload, { withCredentials: true });
      toast.success("API keys guardadas");
      setChanged({});
      const setMap = {};
      Object.keys(payload.api_keys).forEach((k) => { if (!k.endsWith("_changed")) setMap[k] = true; });
      setKeysSet((prev) => ({ ...prev, ...setMap }));
      // Clear the actual key inputs — server has them, we don't need them in memory
      setKeys({ shodan: "", abuseipdb: "", hibp: "", rapidapi: "" });
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error al guardar");
    } finally { setSavingApi(false); }
  };

  const runAiTest = async () => {
    if (aiProvider === "emergent") { setAiTest({ ok: true, detail: "Motor Emergent activo" }); return true; }
    // For Ollama, the "key" is the base URL
    const probeKey = aiProvider === "ollama" ? ollamaUrl : aiKey;
    if (!probeKey) {
      toast.error(aiProvider === "ollama"
        ? "Introduce la URL pública de Ollama antes de probar"
        : "Introduce la key AI antes de probar");
      return false;
    }
    setAiTesting(true);
    setAiTest(null);
    try {
      const r = await axios.post(`${API}/settings/test-key`,
        { provider: `ai:${aiProvider}`, key: probeKey },
        { withCredentials: true });
      setAiTest(r.data);
      return r.data.ok;
    } catch (e) {
      setAiTest({ ok: false, detail: e?.response?.data?.detail || "Error" });
      return false;
    } finally { setAiTesting(false); }
  };

  const saveAi = async () => {
    // Auto-test on save for non-emergent providers when credentials changed
    if (aiProvider === "ollama") {
      if (!ollamaUrl) { toast.error("Falta la URL pública de Ollama"); return; }
      if (!ollamaModel) { toast.error("Especifica un modelo (ej: llama3.1)"); return; }
      if (ollamaUrlChanged) {
        const ok = await runAiTest();
        if (!ok) { toast.error("La URL de Ollama no responde. No se guarda."); return; }
      }
    } else if (aiProvider !== "emergent" && (aiKeyChanged || !aiKeySet) && aiKey) {
      const ok = await runAiTest();
      if (!ok) { toast.error("La key AI no pasó el test. No se guarda."); return; }
    }
    setSavingAi(true);
    try {
      await axios.post(`${API}/settings/ai`,
        { provider: aiProvider, mode: aiMode, key: aiKey, key_changed: aiKeyChanged,
          ollama_url: ollamaUrl, ollama_model: ollamaModel },
        { withCredentials: true });
      toast.success("Motor de IA guardado");
      setAiKeyChanged(false);
      setAiKey("");
      setOllamaUrlChanged(false);
      if (aiProvider !== "emergent" && aiProvider !== "ollama") setAiKeySet(true);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error al guardar IA");
    } finally { setSavingAi(false); }
  };

  const saveSlack = async () => {
    try {
      await axios.post(`${API}/settings/slack`, { webhook_url: webhook }, { withCredentials: true });
      toast.success("Slack webhook guardado");
    } catch (e) { toast.error(e?.response?.data?.detail || "Error"); }
  };

  const testTelegram = async () => {
    if (!tgChat || (!tgToken && !tgTokenSet)) {
      toast.error("Introduce Bot Token y Chat ID antes de probar");
      return false;
    }
    setTgTesting(true);
    setTgTest(null);
    try {
      const r = await axios.post(`${API}/settings/telegram/test`, {
        bot_token: tgToken || "", chat_id: tgChat || "",
      }, { withCredentials: true });
      setTgTest(r.data);
      if (r.data.ok) toast.success("Mensaje de prueba enviado a Telegram");
      return r.data.ok;
    } catch (e) {
      const msg = e?.response?.data?.detail || "Error";
      setTgTest({ ok: false, detail: msg });
      toast.error(msg);
      return false;
    } finally {
      setTgTesting(false);
    }
  };

  const saveTelegram = async () => {
    setSavingTg(true);
    try {
      // If both empty, clear stored credentials
      await axios.post(`${API}/settings/telegram`, {
        bot_token: tgToken || null,
        chat_id: tgChat || null,
      }, { withCredentials: true });
      // Reload state
      const r = await axios.get(`${API}/settings/telegram`, { withCredentials: true });
      setTgTokenSet(!!r.data.bot_token_set);
      setTgTokenMasked(r.data.bot_token_masked || "");
      setTgChat(r.data.chat_id || "");
      setTgToken("");
      toast.success(tgToken || tgChat ? "Telegram guardado" : "Telegram limpiado");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error al guardar Telegram");
    } finally { setSavingTg(false); }
  };

  const savePrefs = async () => {
    setSavingPrefs(true);
    try {
      await axios.post(`${API}/settings/preferences`,
        { risk_threshold: riskThreshold, notes },
        { withCredentials: true });
      toast.success("Preferencias guardadas");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error al guardar preferencias");
    } finally { setSavingPrefs(false); }
  };

  // ─── EMAIL (Resend) ────────────────────────────────────────────────
  const saveEmail = async () => {
    setSavingEmail(true);
    try {
      const r = await axios.post(`${API}/settings/email`,
        { enabled: emailEnabled, address: emailAddress || null },
        { withCredentials: true });
      setEmailAddress(r.data.address || "");
      toast.success(emailEnabled ? "Notificaciones email activadas" : "Notificaciones email desactivadas");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error al guardar email");
    } finally { setSavingEmail(false); }
  };

  const testEmail = async () => {
    setEmailTesting(true);
    try {
      const r = await axios.post(`${API}/settings/email/test`, {}, { withCredentials: true });
      toast.success(`Email de prueba enviado a ${r.data.sent_to}`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo al enviar email");
    } finally { setEmailTesting(false); }
  };

  // ─── TELEGRAM WEBHOOK ──────────────────────────────────────────────
  const loadWebhookStatus = async () => {
    try {
      const r = await axios.get(`${API}/telegram/webhook/status`, { withCredentials: true });
      setWebhookInfo(r.data);
    } catch { /* silent */ }
  };

  const setupWebhook = async () => {
    setWebhookBusy(true);
    try {
      const r = await axios.post(`${API}/telegram/webhook/setup`, {}, { withCredentials: true });
      toast.success("Webhook registrado en Telegram");
      setWebhookInfo({ ...(webhookInfo || {}), configured: true, url: r.data.webhook_url });
      await loadWebhookStatus();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo al registrar webhook");
    } finally { setWebhookBusy(false); }
  };

  const deleteWebhook = async () => {
    setWebhookBusy(true);
    try {
      await axios.post(`${API}/telegram/webhook/delete`, {}, { withCredentials: true });
      toast.success("Webhook eliminado");
      await loadWebhookStatus();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo al eliminar webhook");
    } finally { setWebhookBusy(false); }
  };

  const sendWelcome = async () => {
    setWebhookBusy(true);
    try {
      await axios.post(`${API}/telegram/send-welcome`, {}, { withCredentials: true });
      toast.success("Bienvenida enviada a tu Chat ID");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo al enviar bienvenida");
    } finally { setWebhookBusy(false); }
  };

  // ─── CLAUDE TIER ──────────────────────────────────────────────────
  const saveClaudeTier = async (tier) => {
    setSavingClaude(true);
    try {
      await axios.post(`${API}/settings/claude`, { tier }, { withCredentials: true });
      setClaudeActive(tier);
      const label = claudeTiers.find((t) => t.id === tier)?.label || tier;
      toast.success(`Modelo Claude actualizado: ${label}`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo al guardar el modelo");
    } finally { setSavingClaude(false); }
  };

  // Load webhook status when admin visits
  useEffect(() => {
    if (isAdmin) loadWebhookStatus();
  }, [isAdmin]);

  const loadSecurityLog = async () => {
    setLoadingLog(true);
    try {
      const r = await axios.get(`${API}/settings/security-log`, { withCredentials: true });
      setSecurityLog(r.data);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "No autorizado");
    } finally { setLoadingLog(false); }
  };

  return (
    <div data-testid="settings-page" className="min-h-screen bg-black text-white grain">
      <header className="sticky top-0 z-30 backdrop-blur-xl bg-black/80 border-b border-white/[0.08]">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-4">
          <button onClick={() => navigate("/dashboard")} className="inline-flex items-center gap-2 border border-white/[0.08] px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
            <ArrowLeft className="w-3.5 h-3.5" />
            <span className="font-mono-data text-[10px] uppercase tracking-widest">Volver</span>
          </button>
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-cyan-400" />
            <span className="font-heading font-black text-lg">NOCTUA<span className="text-cyan-400">.osint</span></span>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-12">
        <h1 className="font-heading text-3xl sm:text-4xl font-black tracking-tight mb-2">Configuración</h1>
        <p className="text-white/50 mb-10">Cuenta, plan, integraciones y motor de IA.</p>

        {/* PLAN */}
        <section className="border border-white/[0.08] bg-[#0A0A0C] mb-6">
          <div className="px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex items-center gap-3">
            <Zap className="w-4 h-4 text-cyan-400" />
            <h2 className="font-heading text-sm font-bold uppercase tracking-wide">Plan</h2>
          </div>
          <div className="p-5 flex items-center justify-between">
            <div>
              <div data-testid="current-plan" className="font-mono-data text-2xl font-bold text-cyan-400 uppercase">{isPro ? "Pro" : "Free"}</div>
              <div className="text-sm text-white/50 mt-1">
                {isPro ? "Escaneos programados y alertas activados." : "Actualiza a Pro para monitoreo continuo."}
              </div>
            </div>
            <Link to="/pricing" data-testid="manage-plan-link" className="border border-white/[0.15] px-5 py-2.5 hover:border-cyan-400 hover:text-cyan-400 transition-colors font-mono-data text-xs uppercase tracking-widest">
              {isPro ? "Gestionar" : "Actualizar a Pro"}
            </Link>
          </div>
        </section>

        {/* PREFERENCIAS IA */}
        <section data-testid="preferences-section" className="border border-white/[0.08] bg-[#0A0A0C] mb-6">
          <div className="px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex items-center gap-3">
            <Brain className="w-4 h-4 text-cyan-400" />
            <h2 className="font-heading text-sm font-bold uppercase tracking-wide">Memoria de Preferencias IA</h2>
          </div>
          <div className="p-5 space-y-5">
            <div>
              <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-2 block">
                Umbral de riesgo aceptable — <span className="text-cyan-400">{riskThreshold}%</span>
              </label>
              <input
                type="range" min="0" max="100" step="5"
                value={riskThreshold}
                onChange={(e) => setRiskThreshold(Number(e.target.value))}
                data-testid="risk-threshold-input"
                className="w-full accent-cyan-400"
              />
              <div className="flex justify-between font-mono-data text-[10px] text-white/40 mt-1">
                <span>Tolerante · 0%</span><span>Estricto · 100%</span>
              </div>
            </div>
            <div>
              <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-2 block flex items-center gap-2">
                <StickyNote className="w-3 h-3" /> Notas personalizadas para la IA
              </label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value.slice(0, 2000))}
                data-testid="notes-input"
                rows={4}
                placeholder="Ej: 'Somos un banco regulado por PCI-DSS. Priorizar exposiciones que afecten datos de tarjeta.'"
                className="w-full bg-black border border-white/[0.08] px-4 py-2.5 font-mono-data text-sm placeholder:text-white/25 focus:outline-none focus:border-cyan-400 resize-y"
              />
              <div className="font-mono-data text-[10px] text-white/40 mt-1">
                {notes.length}/2000 · Se incluye como contexto en cada análisis IA.
              </div>
            </div>
            <button
              onClick={savePrefs} disabled={savingPrefs}
              data-testid="save-prefs-btn"
              className="bg-cyan-400 text-black font-semibold px-6 py-2.5 hover:bg-cyan-300 disabled:opacity-40 transition-colors inline-flex items-center gap-2"
            >
              {savingPrefs ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              Guardar preferencias
            </button>
          </div>
        </section>

        {/* SECURITY LOG (Admin-only, hidden section) */}
        {isAdmin && (
          <section data-testid="security-log-section" className="border-2 border-red-400/30 bg-[#0A0A0C] mb-6">
            <div className="px-5 py-3 border-b border-red-400/20 bg-gradient-to-r from-red-500/[0.06] to-transparent flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <h2 className="font-heading text-sm font-bold uppercase tracking-wide text-red-300">
                  Registro de Seguridad · Solo administrador
                </h2>
              </div>
              <button onClick={loadSecurityLog} disabled={loadingLog}
                data-testid="load-security-log-btn"
                className="border border-red-400/40 text-red-300 px-4 py-1.5 hover:bg-red-500/[0.06] disabled:opacity-40 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-1.5">
                {loadingLog ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldAlert className="w-3 h-3" />}
                {securityLog ? "Refrescar" : "Cargar registro"}
              </button>
            </div>
            <div className="p-5">
              {whitelistInfo && (
                <div className="mb-4 text-xs text-white/60 font-mono-data">
                  Whitelist activo: <span className={whitelistInfo.enabled ? "text-green-400" : "text-orange-400"}>{whitelistInfo.enabled ? "SÍ" : "NO"}</span>
                  {whitelistInfo.enabled && (
                    <> · <span className="text-cyan-400">{whitelistInfo.authorized_count}</span> correo(s) autorizado(s) · Admin: <span className="text-cyan-400">{whitelistInfo.admin_email}</span></>
                  )}
                </div>
              )}
              {securityLog ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-3 gap-3">
                    <div className="border border-white/[0.06] p-3">
                      <div className="font-heading text-2xl font-black text-red-400">{securityLog.total_attempts}</div>
                      <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Intentos rechazados</div>
                    </div>
                    <div className="border border-white/[0.06] p-3">
                      <div className="font-heading text-2xl font-black text-orange-400">{securityLog.unique_rejected_emails}</div>
                      <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">Emails únicos</div>
                    </div>
                    <div className="border border-white/[0.06] p-3">
                      <div className="font-heading text-2xl font-black text-cyan-400">{securityLog.unique_rejected_ips}</div>
                      <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">IPs únicas</div>
                    </div>
                  </div>
                  <p className="text-xs text-white/50">{securityLog.note}</p>
                  <div className="max-h-96 overflow-y-auto">
                    <table className="w-full text-xs font-mono-data">
                      <thead className="text-white/40 border-b border-white/10">
                        <tr>
                          <th className="text-left py-2 pr-3">Cuándo</th>
                          <th className="text-left py-2 pr-3">Email</th>
                          <th className="text-left py-2 pr-3">IP</th>
                          <th className="text-left py-2">Motivo</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(securityLog.attempts || []).map((a, i) => (
                          <tr key={i} className="border-b border-white/[0.04] hover:bg-white/[0.02]">
                            <td className="py-2 pr-3 text-white/60"><Clock className="w-3 h-3 inline mr-1 text-white/30" />{new Date(a.attempted_at).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "medium" })}</td>
                            <td className="py-2 pr-3 text-red-300 break-all">{a.email}</td>
                            <td className="py-2 pr-3 text-cyan-300"><Globe className="w-3 h-3 inline mr-1 text-white/30" />{a.ip}</td>
                            <td className="py-2 text-white/50">{a.reason}</td>
                          </tr>
                        ))}
                        {(securityLog.attempts || []).length === 0 && (
                          <tr><td colSpan="4" className="py-4 text-center text-green-400/80">Sin intentos registrados. La whitelist está intacta.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  <p className="text-[11px] text-white/40 italic">
                    Los rechazos también generan un mensaje en Telegram si tienes bot + chat_id configurados arriba.
                  </p>
                </div>
              ) : (
                <p className="text-sm text-white/50">
                  Pulsa &ldquo;Cargar registro&rdquo; para ver los intentos de acceso rechazados por la lista blanca.
                </p>
              )}
            </div>
          </section>
        )}

        {/* API KEYS */}
        <section className="border border-white/[0.08] bg-[#0A0A0C] mb-6">
          <div className="px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex items-center gap-3">
            <Key className="w-4 h-4 text-cyan-400" />
            <h2 className="font-heading text-sm font-bold uppercase tracking-wide">API Keys de integraciones</h2>
          </div>
          <div className="p-5 space-y-5">
            <p className="text-sm text-white/50">
              Pega tus keys y pulsa <span className="text-cyan-400">Probar</span>. Solo se guardan las que pasen el test.
              Las keys se almacenan en tu perfil (no en variables de entorno).
            </p>
            {PROVIDERS.map((p) => (
              <div key={p.id} data-testid={`key-row-${p.id}`} className="border border-white/[0.06] p-4">
                <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                  <div>
                    <div className="font-heading text-sm font-bold flex items-center gap-2">
                      {p.label}
                      {keysSet[p.id] && !changed[p.id] && (
                        <span className="border border-green-400/40 text-green-400 px-2 py-0.5 font-mono-data text-[9px] uppercase tracking-widest">Guardada</span>
                      )}
                    </div>
                    <a href={p.url} target="_blank" rel="noreferrer" className="text-xs text-white/40 hover:text-cyan-400 inline-flex items-center gap-1 mt-0.5">
                      {p.hint} <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <TestBadge result={tests[p.id]} testing={testing[p.id]} />
                </div>
                <div className="flex items-stretch gap-2">
                  <div className="flex-1">
                    <KeyInput
                      value={keys[p.id]}
                      onChange={(e) => { setKeys((k) => ({ ...k, [p.id]: e.target.value })); setChanged((c) => ({ ...c, [p.id]: true })); setTests((t) => ({ ...t, [p.id]: null })); }}
                      placeholder={keysSet[p.id] ? "•••••• (deja vacío para mantener la guardada)" : "Pega tu API key aquí"}
                      testId={`input-${p.id}`}
                    />
                  </div>
                  <button
                    onClick={() => runTest(p.id)}
                    disabled={!keys[p.id] || testing[p.id]}
                    data-testid={`test-${p.id}`}
                    className="border border-white/[0.15] px-4 hover:border-cyan-400 hover:text-cyan-400 transition-colors font-mono-data text-[10px] uppercase tracking-widest disabled:opacity-40 whitespace-nowrap"
                  >
                    Probar
                  </button>
                </div>
              </div>
            ))}
            <button
              onClick={saveApiKeys}
              disabled={savingApi}
              data-testid="save-keys-btn"
              className="bg-cyan-400 text-black font-semibold px-6 py-3 hover:bg-cyan-300 transition-colors inline-flex items-center gap-2 disabled:opacity-50"
            >
              {savingApi ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              Guardar keys
            </button>
          </div>
        </section>

        {/* AI ENGINE */}
        <section className="border border-cyan-400/40 bg-gradient-to-b from-cyan-500/[0.02] to-transparent mb-6">
          <div className="px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex items-center gap-3">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h2 className="font-heading text-sm font-bold uppercase tracking-wide">Motor de IA Personalizado</h2>
          </div>
          <div className="p-5 space-y-6">
            {/* Provider */}
            <div>
              <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-3 block">
                Proveedor de IA
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {AI_PROVIDERS.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => { setAiProvider(p.id); setAiTest(null); }}
                    data-testid={`ai-provider-${p.id}`}
                    className={`text-left border p-3 transition-colors ${
                      aiProvider === p.id
                        ? "border-cyan-400 bg-cyan-400/10"
                        : "border-white/[0.08] hover:border-white/25"
                    }`}
                  >
                    <div className="font-heading font-bold text-sm">{p.label}</div>
                    <div className="text-xs text-white/40 mt-1">{p.info}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Custom key (openai/anthropic/gemini) */}
            {aiProvider !== "emergent" && aiProvider !== "ollama" && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50">
                    API Key {AI_PROVIDERS.find((x) => x.id === aiProvider)?.label}
                  </label>
                  <TestBadge result={aiTest} testing={aiTesting} />
                </div>
                <div className="flex items-stretch gap-2">
                  <div className="flex-1">
                    <KeyInput
                      value={aiKey}
                      onChange={(e) => { setAiKey(e.target.value); setAiKeyChanged(true); setAiTest(null); }}
                      placeholder={aiKeySet ? "•••••• (guardada — deja vacío para mantener)" : "Pega tu API key AI"}
                      testId="input-ai-key"
                    />
                  </div>
                  <button
                    onClick={runAiTest}
                    disabled={!aiKey || aiTesting}
                    data-testid="test-ai-btn"
                    className="border border-white/[0.15] px-4 hover:border-cyan-400 hover:text-cyan-400 transition-colors font-mono-data text-[10px] uppercase tracking-widest disabled:opacity-40 whitespace-nowrap"
                  >
                    Probar
                  </button>
                </div>
              </div>
            )}

            {/* Ollama · URL + model */}
            {aiProvider === "ollama" && (
              <div data-testid="ollama-config" className="space-y-4">
                <div className="border border-cyan-400/20 bg-cyan-400/[0.03] p-3 text-xs text-white/60 leading-relaxed">
                  <div className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-cyan-400 mb-2">
                    ⚠️ Ollama en cloud
                  </div>
                  Como NOCTUA corre en servidores, tu Ollama debe estar accesible desde Internet.
                  Opciones rápidas:
                  <div className="mt-2 font-mono-data text-[11px] space-y-0.5 text-white/70">
                    <div>• <code className="text-cyan-400">ngrok http 11434</code></div>
                    <div>• <code className="text-cyan-400">cloudflared tunnel --url http://localhost:11434</code></div>
                    <div>• Instancia Ollama en VPS/cloud</div>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50">
                      URL pública de Ollama
                    </label>
                    <TestBadge result={aiTest} testing={aiTesting} />
                  </div>
                  <div className="flex items-stretch gap-2">
                    <input
                      type="text"
                      value={ollamaUrl}
                      onChange={(e) => { setOllamaUrl(e.target.value); setOllamaUrlChanged(true); setAiTest(null); }}
                      placeholder="https://xxxxx.ngrok-free.app"
                      data-testid="input-ollama-url"
                      className="flex-1 bg-black border border-white/[0.08] px-4 py-2.5 font-mono-data text-sm placeholder:text-white/25 focus:outline-none focus:border-cyan-400"
                    />
                    <button
                      onClick={runAiTest}
                      disabled={!ollamaUrl || aiTesting}
                      data-testid="test-ollama-btn"
                      className="border border-white/[0.15] px-4 hover:border-cyan-400 hover:text-cyan-400 transition-colors font-mono-data text-[10px] uppercase tracking-widest disabled:opacity-40 whitespace-nowrap"
                    >
                      Probar conexión
                    </button>
                  </div>
                </div>

                <div>
                  <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-2 block">
                    Modelo Ollama
                  </label>
                  <input
                    type="text"
                    value={ollamaModel}
                    onChange={(e) => setOllamaModel(e.target.value)}
                    placeholder="llama3.1"
                    data-testid="input-ollama-model"
                    className="w-full bg-black border border-white/[0.08] px-4 py-2.5 font-mono-data text-sm placeholder:text-white/25 focus:outline-none focus:border-cyan-400"
                    list="ollama-model-suggestions"
                  />
                  <datalist id="ollama-model-suggestions">
                    <option value="llama3.1" />
                    <option value="llama3.2" />
                    <option value="mistral" />
                    <option value="mixtral" />
                    <option value="phi3" />
                    <option value="qwen2.5" />
                    <option value="deepseek-r1" />
                    <option value="gemma2" />
                  </datalist>
                  <p className="text-[11px] text-white/40 mt-1">
                    Debe estar descargado en tu Ollama: <code>ollama pull {ollamaModel || "llama3.1"}</code>
                  </p>
                </div>

                {aiTest?.usage?.models?.length > 0 && (
                  <div className="border border-white/[0.06] bg-black/40 p-3">
                    <div className="font-mono-data text-[9px] uppercase tracking-[0.25em] text-white/40 mb-1.5">
                      Modelos detectados en tu Ollama
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {aiTest.usage.models.map((m) => (
                        <button
                          key={m}
                          onClick={() => setOllamaModel(m)}
                          className="font-mono-data text-[10px] text-cyan-400 border border-cyan-400/30 hover:bg-cyan-400/10 px-2 py-0.5"
                        >
                          {m}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Analysis Mode */}
            <div>
              <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-3 block flex items-center gap-2">
                <Sliders className="w-3 h-3" /> Modo de Análisis
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {AI_MODES.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setAiMode(m.id)}
                    data-testid={`ai-mode-${m.id}`}
                    className={`text-left border p-4 transition-colors ${
                      aiMode === m.id
                        ? "border-cyan-400 bg-cyan-400/[0.06]"
                        : "border-white/[0.08] hover:border-white/25"
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Sparkles className={`w-4 h-4 ${aiMode === m.id ? "text-cyan-400" : "text-white/40"}`} />
                      <div className="font-heading font-bold text-sm">{m.label}</div>
                      <span className="ml-auto font-mono-data text-[10px] text-white/40">T={m.temp}</span>
                    </div>
                    <div className="text-xs text-white/60 leading-relaxed">{m.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Claude Model Tier */}
            {(aiProvider === "emergent" || aiProvider === "anthropic") && claudeTiers.length > 0 && (
              <div data-testid="claude-tier-section">
                <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-3 block flex items-center gap-2">
                  <Brain className="w-3 h-3 text-cyan-400" /> Modelo Claude · Tier de razonamiento
                </label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {claudeTiers.map((t) => (
                    <button
                      key={t.id}
                      onClick={() => saveClaudeTier(t.id)}
                      disabled={savingClaude}
                      data-testid={`claude-tier-${t.id}`}
                      className={`text-left border p-4 transition-colors disabled:opacity-40 relative ${
                        claudeActive === t.id
                          ? "border-cyan-400 bg-cyan-400/[0.06]"
                          : "border-white/[0.08] hover:border-white/25"
                      }`}
                    >
                      {claudeActive === t.id && (
                        <span className="absolute top-2 right-2 font-mono-data text-[9px] uppercase tracking-widest text-cyan-400 border border-cyan-400/40 px-1.5 py-0.5">
                          ACTIVO
                        </span>
                      )}
                      <div className="font-heading font-bold text-sm mb-1">{t.label}</div>
                      <code className="font-mono-data text-[10px] text-cyan-400/70 block mb-2">{t.model}</code>
                      <div className="text-xs text-white/60 leading-relaxed">{t.desc}</div>
                    </button>
                  ))}
                </div>
                <p className="text-xs text-white/40 mt-2 font-mono-data">
                  El tier se aplica cuando el proveedor activo es <b className="text-white/70">Emergent</b> o <b className="text-white/70">Anthropic</b>.
                </p>
              </div>
            )}

            <button
              onClick={saveAi}
              disabled={savingAi}
              data-testid="save-ai-btn"
              className="bg-cyan-400 text-black font-semibold px-6 py-3 hover:bg-cyan-300 transition-colors inline-flex items-center gap-2 disabled:opacity-50"
            >
              {savingAi ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              Guardar motor de IA
            </button>
          </div>
        </section>

        {/* SLACK */}
        <section className="border border-white/[0.08] bg-[#0A0A0C] mb-6">
          <div className="px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex items-center gap-3">
            <Slack className="w-4 h-4 text-cyan-400" />
            <h2 className="font-heading text-sm font-bold uppercase tracking-wide">Webhook de Slack (Pro)</h2>
          </div>
          <div className="p-5">
            <input
              type="text" value={webhook} onChange={(e) => setWebhook(e.target.value)}
              disabled={!isPro}
              placeholder="https://hooks.slack.com/services/T.../B.../..."
              data-testid="slack-webhook-input"
              className="w-full bg-black border border-white/[0.15] px-4 py-3 font-mono-data text-sm placeholder:text-white/25 focus:outline-none focus:border-cyan-400 disabled:opacity-50 mb-4"
            />
            <button
              onClick={saveSlack}
              disabled={!isPro}
              data-testid="save-slack-btn"
              className="bg-cyan-400 text-black font-semibold px-6 py-3 hover:bg-cyan-300 disabled:opacity-40 transition-colors inline-flex items-center gap-2"
            >
              <Save className="w-4 h-4" /> Guardar Slack
            </button>
          </div>
        </section>

        {/* TELEGRAM */}
        <section data-testid="telegram-section" className="border border-white/[0.08] bg-[#0A0A0C]">
          <div className="px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex items-center gap-3">
            <Send className="w-4 h-4 text-cyan-400" />
            <h2 className="font-heading text-sm font-bold uppercase tracking-wide">Alertas Telegram (Pro)</h2>
            <TestBadge result={tgTest} testing={tgTesting} />
          </div>
          <div className="p-5 space-y-4">
            <p className="text-sm text-white/50">
              Recibe alertas en tiempo real de cambios en tu infraestructura directamente en Telegram.
              Crea un bot con{" "}
              <a href="https://t.me/BotFather" target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline inline-flex items-center gap-1">
                @BotFather <ExternalLink className="w-3 h-3" />
              </a>{" "}
              y obtén tu Chat ID en{" "}
              <a href="https://t.me/userinfobot" target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline inline-flex items-center gap-1">
                @userinfobot <ExternalLink className="w-3 h-3" />
              </a>.
            </p>

            <div>
              <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-2 block">
                Bot Token {tgTokenSet && !tgToken && (
                  <span className="ml-2 border border-green-400/40 text-green-400 px-2 py-0.5 font-mono-data text-[9px] uppercase tracking-widest">
                    Guardado · {tgTokenMasked}
                  </span>
                )}
              </label>
              <KeyInput
                value={tgToken}
                onChange={(e) => { setTgToken(e.target.value); setTgTest(null); }}
                placeholder={tgTokenSet ? "•••••• (deja vacío para mantener el guardado)" : "123456789:ABCdefGhIJKlmNoPQRsTUVwxyz"}
                testId="telegram-token-input"
                disabled={!isPro}
              />
            </div>

            <div>
              <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-2 block">
                Chat ID
              </label>
              <input
                type="text"
                value={tgChat}
                onChange={(e) => { setTgChat(e.target.value); setTgTest(null); }}
                disabled={!isPro}
                placeholder="123456789 o -100123456789 para grupos"
                data-testid="telegram-chat-input"
                className="w-full bg-black border border-white/[0.08] px-4 py-2.5 font-mono-data text-sm placeholder:text-white/25 focus:outline-none focus:border-cyan-400 disabled:opacity-50"
              />
            </div>

            <div className="flex flex-wrap gap-3 pt-2">
              <button
                onClick={testTelegram}
                disabled={!isPro || tgTesting || (!tgChat) || (!tgToken && !tgTokenSet)}
                data-testid="test-telegram-btn"
                className="border border-white/[0.15] px-5 py-2.5 hover:border-cyan-400 hover:text-cyan-400 disabled:opacity-40 transition-colors font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-2"
              >
                {tgTesting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                Enviar prueba
              </button>
              <button
                onClick={saveTelegram}
                disabled={!isPro || savingTg}
                data-testid="save-telegram-btn"
                className="bg-cyan-400 text-black font-semibold px-6 py-2.5 hover:bg-cyan-300 disabled:opacity-40 transition-colors inline-flex items-center gap-2"
              >
                {savingTg ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                Guardar Telegram
              </button>
              {tgTokenSet && (
                <button
                  onClick={() => { setTgToken(""); setTgChat(""); setTimeout(saveTelegram, 0); }}
                  disabled={!isPro || savingTg}
                  data-testid="clear-telegram-btn"
                  className="border border-red-400/30 text-red-400 px-4 py-2.5 hover:border-red-400 disabled:opacity-40 transition-colors font-mono-data text-[10px] uppercase tracking-widest"
                >
                  Limpiar
                </button>
              )}
            </div>

            {/* BOT WEBHOOK (admin only) */}
            {isAdmin && (
              <div data-testid="telegram-webhook-block" className="mt-6 pt-5 border-t border-white/[0.08] space-y-3">
                <div className="flex items-center gap-2">
                  <Webhook className="w-4 h-4 text-cyan-400" />
                  <h3 className="font-mono-data text-[11px] uppercase tracking-[0.25em] text-white/80">
                    Bot Webhook · Auto-respuesta /start
                  </h3>
                </div>
                <p className="text-xs text-white/50 leading-relaxed">
                  Activa el webhook para que tu bot responda automáticamente al comando <code className="text-cyan-400">/start</code> con
                  la bienvenida de <b>PROJECT GENESIS</b>. Los chats no autorizados reciben su <b>Chat ID</b> para poder registrarse.
                </p>

                <div className="border border-cyan-400/20 bg-cyan-400/[0.03] p-3">
                  <div className="font-mono-data text-[9px] uppercase tracking-[0.25em] text-cyan-400 mb-2">
                    Comandos operativos disponibles
                  </div>
                  <div className="space-y-1.5 font-mono-data text-[11px]">
                    <div><code className="text-cyan-400">/start</code> <span className="text-white/50">— Bienvenida Project Genesis</span></div>
                    <div><code className="text-cyan-400">/scan example.com</code> <span className="text-white/50">— Lanza escaneo OSINT + resumen</span></div>
                    <div><code className="text-cyan-400">/scans</code> <span className="text-white/50">— Últimos 5 escaneos con links</span></div>
                    <div><code className="text-cyan-400">/pricing</code> <span className="text-white/50">— Enlace de suscripción Pro (Stripe)</span></div>
                    <div><code className="text-cyan-400">/status</code> <span className="text-white/50">— Ping del nodo</span></div>
                    <div><code className="text-cyan-400">/help</code> <span className="text-white/50">— Menú completo</span></div>
                  </div>
                </div>

                {webhookInfo && (
                  <div className="bg-black/40 border border-white/[0.06] px-3 py-2 font-mono-data text-[11px] space-y-1">
                    <div className="flex gap-2 items-center">
                      <span className="text-white/40">Estado:</span>
                      {webhookInfo.configured
                        ? <span className="text-green-400">● ACTIVO</span>
                        : <span className="text-white/40">○ INACTIVO</span>}
                    </div>
                    {webhookInfo.url && (
                      <div className="text-white/60 break-all">
                        <span className="text-white/40">URL:</span> {webhookInfo.url}
                      </div>
                    )}
                    {webhookInfo.pending_update_count > 0 && (
                      <div className="text-yellow-400">
                        Pendientes: {webhookInfo.pending_update_count}
                      </div>
                    )}
                    {webhookInfo.last_error_message && (
                      <div className="text-red-400">
                        Último error: {webhookInfo.last_error_message}
                      </div>
                    )}
                  </div>
                )}

                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={setupWebhook}
                    disabled={webhookBusy || !tgTokenSet}
                    data-testid="setup-webhook-btn"
                    className="border border-cyan-400/40 text-cyan-400 hover:bg-cyan-400/10 disabled:opacity-40 transition-colors px-4 py-2 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-2"
                  >
                    {webhookBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
                    {webhookInfo?.configured ? "Re-registrar Webhook" : "Activar Webhook"}
                  </button>
                  <button
                    onClick={sendWelcome}
                    disabled={webhookBusy || !tgTokenSet || !tgChat}
                    data-testid="send-welcome-btn"
                    className="border border-white/[0.15] hover:border-cyan-400 hover:text-cyan-400 disabled:opacity-40 transition-colors px-4 py-2 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-2"
                  >
                    <Send className="w-3.5 h-3.5" />
                    Enviar Bienvenida Ahora
                  </button>
                  {webhookInfo?.configured && (
                    <button
                      onClick={deleteWebhook}
                      disabled={webhookBusy}
                      data-testid="delete-webhook-btn"
                      className="border border-red-400/30 text-red-400 hover:border-red-400 disabled:opacity-40 transition-colors px-4 py-2 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-2"
                    >
                      <Trash2 className="w-3.5 h-3.5" /> Desactivar
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* EMAIL NOTIFICATIONS (RESEND) */}
        <section data-testid="email-section" className="border border-white/[0.08] bg-[#0A0A0C] mt-6">
          <div className="px-5 py-3 border-b border-white/[0.06] bg-[#101014] flex items-center gap-3">
            <Mail className="w-4 h-4 text-cyan-400" />
            <h2 className="font-heading text-sm font-bold uppercase tracking-wide">Notificaciones Email</h2>
            {resendConfigured
              ? <span className="ml-auto font-mono-data text-[9px] uppercase tracking-widest text-green-400 border border-green-400/30 px-2 py-0.5">Resend · Online</span>
              : <span className="ml-auto font-mono-data text-[9px] uppercase tracking-widest text-yellow-400 border border-yellow-400/30 px-2 py-0.5">Resend · No configurado</span>}
          </div>
          <div className="p-5 space-y-4">
            <p className="text-sm text-white/50">
              Recibe alertas por email (además de Telegram) cuando se detecten <b className="text-white/80">cambios críticos</b>,
              se complete un escaneo, o se registren <b className="text-white/80">intentos de acceso bloqueados</b>.
            </p>

            <div>
              <label className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/50 mb-2 block">
                Dirección de destino
              </label>
              <input
                type="email"
                value={emailAddress}
                onChange={(e) => setEmailAddress(e.target.value)}
                placeholder="tu@correo.com"
                data-testid="email-address-input"
                disabled={!resendConfigured}
                className="w-full bg-black border border-white/[0.08] px-4 py-2.5 font-mono-data text-sm placeholder:text-white/25 focus:outline-none focus:border-cyan-400 disabled:opacity-50"
              />
            </div>

            <label className="flex items-center gap-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={emailEnabled}
                onChange={(e) => setEmailEnabled(e.target.checked)}
                disabled={!resendConfigured}
                data-testid="email-enabled-toggle"
                className="w-4 h-4 accent-cyan-400"
              />
              <span className="text-sm text-white/80">Activar notificaciones por email</span>
            </label>

            <div className="flex flex-wrap gap-3 pt-2">
              <button
                onClick={saveEmail}
                disabled={savingEmail || !resendConfigured}
                data-testid="save-email-btn"
                className="bg-cyan-400 text-black font-semibold px-6 py-2.5 hover:bg-cyan-300 disabled:opacity-40 transition-colors inline-flex items-center gap-2"
              >
                {savingEmail ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                Guardar
              </button>
              <button
                onClick={testEmail}
                disabled={emailTesting || !resendConfigured || !emailAddress}
                data-testid="test-email-btn"
                className="border border-white/[0.15] hover:border-cyan-400 hover:text-cyan-400 disabled:opacity-40 transition-colors px-5 py-2.5 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-2"
              >
                {emailTesting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                Enviar email de prueba
              </button>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
