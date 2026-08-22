import { useNavigate } from "react-router-dom";
import { XCircle } from "lucide-react";

export default function PaymentCancel() {
  const navigate = useNavigate();
  return (
    <div data-testid="payment-cancel-page" className="min-h-screen bg-[#050505] text-white grain flex items-center justify-center px-6">
      <div className="max-w-md w-full border border-white/10 bg-[#0C0C0E] p-10 text-center">
        <XCircle className="w-12 h-12 text-yellow-400 mx-auto mb-6" />
        <h1 className="font-heading text-2xl font-black mb-3">Pago cancelado</h1>
        <p className="text-white/50 text-sm mb-8">No se realizó ningún cargo. Puedes reintentar cuando quieras.</p>
        <button
          onClick={() => navigate("/pricing")}
          className="w-full bg-cyan-400 text-black font-semibold py-3 hover:bg-cyan-300 transition-colors"
        >
          Volver a planes
        </button>
      </div>
    </div>
  );
}
