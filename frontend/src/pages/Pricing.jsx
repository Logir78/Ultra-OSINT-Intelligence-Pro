import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { Radar, ArrowLeft, Check, Zap, Loader2 } from "lucide-react";
import { API, useAuth } from "@/lib/auth";

export default function Pricing() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const startCheckout = async () => {
    if (!user) { navigate("/login"); return; }
    setLoading(true);
    try {
      const r = await axios.post(
        `${API}/payments/checkout`,
        { lookup_key: "pro_monthly", origin_url: window.location.origin },
        { withCredentials: true },
      );
      window.location.href = r.data.checkout_url;
    } catch (e) {
      toast.error(e?.response?.data?.detail || "No se pudo iniciar el pago");
      setLoading(false);
    }
  };

  const cancel = async () => {
    if (!confirm("¿Cancelar tu suscripción Pro?")) return;
    try {
      await axios.post(`${API}/payments/cancel`, {}, { withCredentials: true });
      toast.success("Suscripción cancelada");
      window.location.reload();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Error al cancelar");
    }
  };

  const isPro = user?.plan === "pro";

  const freeFeatures = [
    "Escaneos OSINT ilimitados on-demand",
    "WHOIS, DNS, SSL, subdominios, cabeceras",
    "Puertos comunes + extendidos",
    "Resumen IA con Claude Sonnet 4.5",
    "Historial completo en tu cuenta",
  ];
  const proFeatures = [
    "Todo lo del plan Free",
    "Escaneos programados (diario/semanal/mensual/custom)",
    "Alertas automáticas: puertos, subdominios, SSL, IP, cabeceras",
    "Notificaciones por Slack (tu webhook)",
    "Bandeja de alertas priorizadas por severidad",
    "Diff automático entre escaneos consecutivos",
  ];

  return (
    <div data-testid="pricing-page" className="min-h-screen bg-[#050505] text-white grain">
      <header className="sticky top-0 z-30 backdrop-blur-xl bg-black/60 border-b border-white/10">
        <div className="max-w-6xl mx-auto px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate(user ? "/dashboard" : "/")}
              data-testid="back-btn"
              className="inline-flex items-center gap-2 border border-white/15 px-3 py-2 hover:border-cyan-400 hover:text-cyan-400 transition-colors"
            >
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

      <main className="max-w-6xl mx-auto px-8 py-16">
        <div className="mb-4 inline-flex items-center gap-2 border border-white/10 px-3 py-1.5">
          <span className="w-1.5 h-1.5 bg-cyan-400 animate-pulse" />
          <span className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/60">Planes</span>
        </div>
        <h1 className="font-heading text-4xl sm:text-5xl font-black tracking-tighter mb-4">
          Escanea, monitoriza, <span className="text-cyan-400">reacciona.</span>
        </h1>
        <p className="text-white/50 mb-12 max-w-2xl">
          Del reconocimiento único al monitoreo continuo. Detecta cambios de superficie en tus dominios antes que un atacante.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-0 border-t border-l border-white/10">
          {/* FREE */}
          <div className="border-r border-b border-white/10 p-10">
            <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-white/40 mb-3">Free</div>
            <div className="flex items-baseline gap-2 mb-2">
              <span className="font-heading text-5xl font-black">$0</span>
              <span className="text-white/40 text-sm">/mes</span>
            </div>
            <p className="text-white/50 text-sm mb-8">Ideal para análisis puntuales y pruebas.</p>
            <ul className="space-y-3 mb-8">
              {freeFeatures.map((f, i) => (
                <li key={i} className="flex items-start gap-3 text-sm">
                  <Check className="w-4 h-4 text-white/50 flex-shrink-0 mt-0.5" />
                  <span className="text-white/70">{f}</span>
                </li>
              ))}
            </ul>
            <div className="border border-white/10 text-center py-3 font-mono-data text-xs uppercase tracking-widest text-white/40">
              {isPro ? "Plan anterior" : "Tu plan actual"}
            </div>
          </div>

          {/* PRO */}
          <div className="border-r border-b border-cyan-400/40 bg-gradient-to-b from-cyan-500/[0.04] to-transparent p-10 relative"
               style={{ boxShadow: "0 0 60px rgba(0,229,255,0.06)" }}>
            <div className="absolute top-0 right-0 bg-cyan-400 text-black font-mono-data text-[10px] uppercase tracking-[0.2em] px-3 py-1">
              Recomendado
            </div>
            <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-cyan-400 mb-3 flex items-center gap-2">
              <Zap className="w-3 h-3" /> Pro
            </div>
            <div className="flex items-baseline gap-2 mb-2">
              <span className="font-heading text-5xl font-black">$9</span>
              <span className="text-white/40 text-sm">/mes</span>
            </div>
            <p className="text-white/60 text-sm mb-8">Vigilancia continua de tu superficie de ataque.</p>
            <ul className="space-y-3 mb-8">
              {proFeatures.map((f, i) => (
                <li key={i} className="flex items-start gap-3 text-sm">
                  <Check className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span className="text-white/80">{f}</span>
                </li>
              ))}
            </ul>
            {isPro ? (
              <button
                onClick={cancel}
                data-testid="cancel-pro-btn"
                className="w-full border border-white/15 text-white py-4 hover:border-red-400 hover:text-red-400 transition-colors font-mono-data text-xs uppercase tracking-widest"
              >
                Cancelar suscripción
              </button>
            ) : (
              <button
                onClick={startCheckout}
                disabled={loading}
                data-testid="upgrade-pro-btn"
                className="w-full bg-cyan-400 text-black font-semibold py-4 hover:bg-cyan-300 disabled:opacity-60 transition-colors inline-flex items-center justify-center gap-2"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {loading ? "Redirigiendo a Stripe..." : "Activar Pro — $9/mes"}
              </button>
            )}
            <p className="mt-4 font-mono-data text-[10px] uppercase tracking-widest text-white/30 text-center">
              Stripe · Cancela cuando quieras
            </p>
          </div>
        </div>

        <div className="mt-12 text-xs text-white/40 font-mono-data">
          Pago procesado por Stripe (modo test). Tarjeta demo: <span className="text-cyan-400">4242 4242 4242 4242</span> — cualquier fecha futura, cualquier CVC.
        </div>
      </main>
    </div>
  );
}
