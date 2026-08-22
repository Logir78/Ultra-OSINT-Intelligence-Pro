import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { useNavigate } from "react-router-dom";
import { Bell, ArrowLeft, Radar, ChevronRight } from "lucide-react";
import { API, useAuth } from "@/lib/auth";

const sevColor = {
  critical: "text-red-400 border-red-400/40 bg-red-400/5",
  high:     "text-yellow-400 border-yellow-400/40 bg-yellow-400/5",
  medium:   "text-cyan-400 border-cyan-400/40 bg-cyan-400/5",
  low:      "text-white/60 border-white/20 bg-white/5",
};

export default function Alerts() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const isPro = user?.plan === "pro";

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/alerts`, { withCredentials: true });
        setItems(r.data);
      } catch {
        toast.error("No se pudieron cargar las alertas");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const markRead = async (id) => {
    try {
      await axios.post(`${API}/alerts/${id}/read`, {}, { withCredentials: true });
      setItems((s) => s.map((a) => a.alert_id === id ? { ...a, read: true } : a));
    } catch (_) { /* ignore */ }
  };

  return (
    <div data-testid="alerts-page" className="min-h-screen bg-[#050505] text-white grain">
      <header className="sticky top-0 z-30 backdrop-blur-xl bg-black/60 border-b border-white/10">
        <div className="max-w-5xl mx-auto px-8 py-4 flex items-center justify-between">
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

      <main className="max-w-5xl mx-auto px-8 py-12">
        <h1 className="font-heading text-3xl font-black tracking-tight mb-2 flex items-center gap-3">
          <Bell className="w-6 h-6 text-cyan-400" /> Alertas
        </h1>
        <p className="text-white/50 mb-10">Cambios detectados por tus escaneos programados.</p>

        {!isPro ? (
          <div className="border border-white/10 p-10 text-center text-white/50">
            Las alertas se generan a partir de escaneos programados (plan Pro).
          </div>
        ) : loading ? (
          <div className="text-white/40 font-mono-data text-xs uppercase tracking-widest">Cargando...</div>
        ) : items.length === 0 ? (
          <div data-testid="empty-alerts" className="border border-dashed border-white/10 p-16 text-center">
            <p className="font-mono-data text-xs uppercase tracking-[0.3em] text-white/30">No hay alertas todavía</p>
            <p className="text-sm text-white/50 mt-2">Aparecerán aquí tras el 2º escaneo programado de cada dominio.</p>
          </div>
        ) : (
          <div className="border-t border-l border-white/10">
            {items.map((a) => (
              <div
                key={a.alert_id}
                data-testid={`alert-${a.alert_id}`}
                className={`border-r border-b border-white/10 p-5 flex items-start justify-between gap-4 ${a.read ? "opacity-60" : ""}`}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`border px-2 py-0.5 font-mono-data text-[10px] uppercase tracking-widest ${sevColor[a.severity] || sevColor.low}`}>
                      {a.severity}
                    </span>
                    <span className="font-mono-data text-cyan-400 text-xs">{a.domain}</span>
                    <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/30">
                      {new Date(a.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="text-sm text-white/80">{a.title}</div>
                </div>
                <div className="flex items-center gap-2">
                  {!a.read && (
                    <button onClick={() => markRead(a.alert_id)} data-testid={`mark-read-${a.alert_id}`} className="font-mono-data text-[10px] uppercase tracking-widest border border-white/15 px-3 py-1.5 hover:border-cyan-400 hover:text-cyan-400 transition-colors">
                      Marcar leído
                    </button>
                  )}
                  {a.scan_id && (
                    <button onClick={() => navigate(`/scan/${a.scan_id}`)} className="p-2 hover:text-cyan-400 transition-colors">
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
