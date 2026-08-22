import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { CheckCircle2, XCircle, Loader2, ArrowRight } from "lucide-react";
import { API, useAuth } from "@/lib/auth";

export default function PaymentSuccess() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { checkAuth } = useAuth();
  const sessionId = params.get("session_id");
  const [status, setStatus] = useState("polling");
  const [attempts, setAttempts] = useState(0);

  useEffect(() => {
    if (!sessionId) { setStatus("error"); return; }
    let cancelled = false;
    let n = 0;

    const poll = async () => {
      if (cancelled) return;
      n++;
      setAttempts(n);
      try {
        const r = await axios.get(`${API}/payments/status/${sessionId}`);
        if (r.data.payment_status === "paid") {
          await checkAuth();
          setStatus("paid");
          return;
        }
        if (r.data.payment_status === "failed" || r.data.payment_status === "expired") {
          setStatus("failed");
          return;
        }
      } catch {
        // ignore transient
      }
      if (n >= 15) { setStatus("timeout"); return; }
      setTimeout(poll, 2000);
    };
    poll();
    return () => { cancelled = true; };
  }, [sessionId, checkAuth]);

  return (
    <div data-testid="payment-success-page" className="min-h-screen bg-[#050505] text-white grain flex items-center justify-center px-6">
      <div className="max-w-md w-full border border-white/10 bg-[#0C0C0E] p-10 text-center">
        {status === "polling" && (
          <>
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin mx-auto mb-6" />
            <h1 className="font-heading text-2xl font-black mb-2">Confirmando tu pago…</h1>
            <p className="text-white/50 text-sm">Intento {attempts} de 15</p>
          </>
        )}
        {status === "paid" && (
          <>
            <CheckCircle2 className="w-12 h-12 text-green-400 mx-auto mb-6" />
            <h1 data-testid="payment-success-title" className="font-heading text-3xl font-black mb-3">¡Bienvenido a Pro!</h1>
            <p className="text-white/60 text-sm mb-8">
              Tu suscripción está activa. Ya puedes crear escaneos programados y configurar Slack.
            </p>
            <button
              onClick={() => navigate("/dashboard")}
              data-testid="go-dashboard-btn"
              className="w-full bg-cyan-400 text-black font-semibold py-3 hover:bg-cyan-300 transition-colors inline-flex items-center justify-center gap-2"
            >
              Ir al dashboard <ArrowRight className="w-4 h-4" />
            </button>
          </>
        )}
        {(status === "failed" || status === "error" || status === "timeout") && (
          <>
            <XCircle className="w-12 h-12 text-red-400 mx-auto mb-6" />
            <h1 className="font-heading text-2xl font-black mb-3">Pago no confirmado</h1>
            <p className="text-white/50 text-sm mb-8">
              {status === "timeout" ? "Se agotó el tiempo de espera. Verifica en unos minutos." : "Algo salió mal con el pago."}
            </p>
            <button
              onClick={() => navigate("/pricing")}
              className="w-full border border-white/15 py-3 hover:border-cyan-400 hover:text-cyan-400 transition-colors font-mono-data text-xs uppercase tracking-widest"
            >
              Volver a planes
            </button>
          </>
        )}
      </div>
    </div>
  );
}
