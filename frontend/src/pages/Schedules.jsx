import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Link, useNavigate } from "react-router-dom";
import { CalendarClock, Plus, Trash2, Play, Pause, ArrowLeft, Radar, Zap } from "lucide-react";
import { API, useAuth } from "@/lib/auth";

const ALL_ALERTS = [
  { id: "new_ports", label: "Nuevos puertos" },
  { id: "new_subdomains", label: "Nuevos subdominios" },
  { id: "ssl_expiry", label: "SSL <30 días" },
  { id: "ip_change", label: "Cambio de IP" },
  { id: "security_headers", label: "Cabeceras perdidas" },
];

export default function Schedules() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const isPro = user?.plan === "pro";
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [domain, setDomain] = useState("");
  const [frequency, setFrequency] = useState("daily");
  const [customHours, setCustomHours] = useState(12);
  const [extended, setExtended] = useState(false);
  const [alertTypes, setAlertTypes] = useState(ALL_ALERTS.map((a) => a.id));
  const [creating, setCreating] = useState(false);

  const load = async () => {
    try {
      const r = await axios.get(`${API}/schedules`, { withCredentials: true });
      setSchedules(r.data);
    } catch {
      toast.error("No se pudieron cargar los schedules");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { if (isPro) load(); else setLoading(false); }, [isPro]);

  const toggleAlert = (id) => {
    setAlertTypes((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]);
  };

  const create = async (e) => {
    e.preventDefault();
    if (!domain.trim()) return;
    setCreating(true);
    try {
      await axios.post(
        `${API}/schedules`,
        {
          domain: domain.trim(),
          frequency,
          custom_hours: frequency === "custom" ? customHours : null,
          extended_ports: extended,
          alert_types: alertTypes,
        },
        { withCredentials: true },
      );
      toast.success("Escaneo programado creado (arrancará en 1 minuto)");
      setDomain(""); setShowForm(false);
      load();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error al crear");
    } finally {
      setCreating(false);
    }
  };

  const remove = async (id) => {
    if (!confirm("¿Eliminar este escaneo programado?")) return;
    try {
      await axios.delete(`${API}/schedules/${id}`, { withCredentials: true });
      setSchedules((s) => s.filter((x) => x.schedule_id !== id));
      toast.success("Eliminado");
    } catch { toast.error("Error"); }
  };

  const toggle = async (id) => {
    try {
      const r = await axios.patch(`${API}/schedules/${id}`, {}, { withCredentials: true });
      setSchedules((prev) => prev.map((s) => s.schedule_id === id ? r.data : s));
    } catch { toast.error("Error"); }
  };

  return (
    <div data-testid="schedules-page" className="min-h-screen bg-[#050505] text-white grain">
      <header className="sticky top-0 z-30 backdrop-blur-xl bg-black/60 border-b border-white/10">
        <div className="max-w-6xl mx-auto px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button onClick={() => navigate("/dashboard")} className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" />
              <span className="font-mono-data text-[10px] uppercase tracking-widest">Volver</span>
            </button>
            <div className="flex items-center gap-2">
              <Radar className="w-4 h-4 text-cyan-400" />
              <span className="font-heading font-black text-lg">NOCTUA<span className="text-cyan-400">.osint</span></span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-8 py-12">
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="font-heading text-3xl font-black tracking-tight mb-2 flex items-center gap-3">
              <CalendarClock className="w-6 h-6 text-cyan-400" /> Escaneos programados
            </h1>
            <p className="text-white/50">Monitorea tus dominios de forma continua y recibe alertas por cambios.</p>
          </div>
          {isPro && (
            <button
              onClick={() => setShowForm((v) => !v)}
              data-testid="new-schedule-btn"
              className="bg-cyan-400 text-black font-semibold px-5 py-3 hover:bg-cyan-300 transition-colors inline-flex items-center gap-2"
            >
              <Plus className="w-4 h-4" /> Nuevo
            </button>
          )}
        </div>

        {!isPro ? (
          <div className="border border-cyan-400/30 bg-cyan-500/[0.03] p-10 text-center">
            <Zap className="w-8 h-8 text-cyan-400 mx-auto mb-4" />
            <h2 className="font-heading text-xl font-bold mb-2">Función Pro</h2>
            <p className="text-white/60 mb-6 max-w-md mx-auto">
              Los escaneos programados requieren plan Pro. $9/mes, cancela cuando quieras.
            </p>
            <Link
              to="/pricing"
              data-testid="upgrade-cta-schedules"
              className="inline-block bg-cyan-400 text-black font-semibold px-6 py-3 hover:bg-cyan-300 transition-colors"
            >
              Actualizar a Pro
            </Link>
          </div>
        ) : (
          <>
            {showForm && (
              <form onSubmit={create} data-testid="schedule-form" className="border border-white/10 bg-[#0C0C0E] p-6 mb-8">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="font-mono-data text-[10px] uppercase tracking-widest text-white/50 mb-2 block">Dominio</label>
                    <input
                      type="text"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder="ejemplo.com"
                      required
                      data-testid="schedule-domain-input"
                      className="w-full bg-[#050505] border border-white/15 px-4 py-3 font-mono-data text-sm focus:outline-none focus:border-cyan-400"
                    />
                  </div>
                  <div>
                    <label className="font-mono-data text-[10px] uppercase tracking-widest text-white/50 mb-2 block">Frecuencia</label>
                    <select
                      value={frequency}
                      onChange={(e) => setFrequency(e.target.value)}
                      data-testid="schedule-frequency-select"
                      className="w-full bg-[#050505] border border-white/15 px-4 py-3 font-mono-data text-sm focus:outline-none focus:border-cyan-400"
                    >
                      <option value="daily">Diario (24 h)</option>
                      <option value="weekly">Semanal (7 días)</option>
                      <option value="monthly">Mensual (30 días)</option>
                      <option value="custom">Custom (horas)</option>
                    </select>
                  </div>
                  {frequency === "custom" && (
                    <div>
                      <label className="font-mono-data text-[10px] uppercase tracking-widest text-white/50 mb-2 block">Cada X horas</label>
                      <input
                        type="number" min="1" max="8760"
                        value={customHours}
                        onChange={(e) => setCustomHours(parseInt(e.target.value) || 1)}
                        className="w-full bg-[#050505] border border-white/15 px-4 py-3 font-mono-data text-sm focus:outline-none focus:border-cyan-400"
                      />
                    </div>
                  )}
                </div>

                <div className="mt-6">
                  <label className="font-mono-data text-[10px] uppercase tracking-widest text-white/50 mb-3 block">Alertas a detectar</label>
                  <div className="flex flex-wrap gap-3">
                    {ALL_ALERTS.map((a) => (
                      <label key={a.id} className="inline-flex items-center gap-2 border border-white/10 px-3 py-2 cursor-pointer hover:border-white/30 transition-colors">
                        <input
                          type="checkbox"
                          checked={alertTypes.includes(a.id)}
                          onChange={() => toggleAlert(a.id)}
                          className="accent-cyan-400"
                        />
                        <span className="font-mono-data text-xs uppercase tracking-widest">{a.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <label className="inline-flex items-center gap-2 mt-5 cursor-pointer">
                  <input type="checkbox" checked={extended} onChange={(e) => setExtended(e.target.checked)} className="accent-cyan-400" />
                  <span className="font-mono-data text-xs uppercase tracking-widest text-white/60">Escaneo extendido de puertos</span>
                </label>

                <div className="mt-8 flex gap-3">
                  <button
                    type="submit"
                    disabled={creating}
                    data-testid="submit-schedule-btn"
                    className="bg-cyan-400 text-black font-semibold px-6 py-3 hover:bg-cyan-300 disabled:opacity-50 transition-colors"
                  >
                    {creating ? "Creando..." : "Crear programación"}
                  </button>
                  <button type="button" onClick={() => setShowForm(false)} className="border border-white/15 px-6 py-3 hover:border-white/30 font-mono-data text-xs uppercase tracking-widest">
                    Cancelar
                  </button>
                </div>
              </form>
            )}

            {loading ? (
              <div className="text-white/40 font-mono-data text-xs uppercase tracking-widest">Cargando...</div>
            ) : schedules.length === 0 ? (
              <div className="border border-dashed border-white/10 p-16 text-center">
                <p className="font-mono-data text-xs uppercase tracking-[0.3em] text-white/30">Aún no hay programaciones</p>
                <p className="text-sm text-white/50 mt-2">Crea la primera arriba.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 border-t border-l border-white/10">
                {schedules.map((s) => (
                  <div key={s.schedule_id} data-testid={`schedule-${s.schedule_id}`} className="border-r border-b border-white/10 p-5">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="font-mono-data text-cyan-400 text-base break-all">{s.domain}</div>
                        <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/40 mt-1">
                          {s.frequency === "custom" ? `Cada ${s.custom_hours}h` : s.frequency}
                          {" · "}
                          {s.enabled ? <span className="text-green-400">Activo</span> : <span className="text-white/40">Pausado</span>}
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => toggle(s.schedule_id)} data-testid={`toggle-${s.schedule_id}`} className="border border-white/15 p-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
                          {s.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                        </button>
                        <button onClick={() => remove(s.schedule_id)} data-testid={`delete-${s.schedule_id}`} className="border border-white/15 p-2 hover:border-red-400 hover:text-red-400 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1.5 mb-3">
                      {(s.alert_types || []).map((t) => (
                        <span key={t} className="font-mono-data text-[10px] uppercase tracking-widest text-white/50 border border-white/10 px-2 py-0.5">{t}</span>
                      ))}
                    </div>
                    <div className="font-mono-data text-[10px] uppercase tracking-widest text-white/30">
                      Próximo: {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "—"} · Último: {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "nunca"}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
