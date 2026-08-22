import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { ArrowLeft, ShoppingBag, Check, Loader2, Zap } from "lucide-react";
import { API } from "@/lib/auth";

export default function Marketplace() {
  const [products, setProducts] = useState([]);
  const [plan, setPlan] = useState("free");
  const [unlocks, setUnlocks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [buying, setBuying] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/marketplace/products`, { withCredentials: true });
        setProducts(r.data.products);
        setPlan(r.data.plan);
        setUnlocks(r.data.unlocks || []);
      } catch (e) {
        toast.error("Fallo al cargar productos");
      } finally { setLoading(false); }
    })();
  }, []);

  const buy = async (product_id) => {
    setBuying(product_id);
    try {
      const r = await axios.post(`${API}/marketplace/checkout`,
        { product_id }, { withCredentials: true });
      window.location.href = r.data.url;
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Fallo checkout");
      setBuying(null);
    }
  };

  return (
    <div data-testid="marketplace-page" className="min-h-screen bg-[#050505] text-white grain">
      <header className="border-b border-white/[0.06] bg-[#0A0A0C]">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-4">
          <Link to="/dashboard" data-testid="back-btn"
                className="text-white/50 hover:text-cyan-400 transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <ShoppingBag className="w-5 h-5 text-cyan-400" />
          <div>
            <h1 className="font-heading font-bold text-lg tracking-tight">
              NOCTUA <span className="text-cyan-400">Marketplace</span>
            </h1>
            <p className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
              Módulos à-la-carte · pago único
            </p>
          </div>
          <div className="ml-auto font-mono-data text-[10px] uppercase tracking-widest text-white/50">
            Plan actual: <span className="text-cyan-400">{plan}</span>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        {plan === "pro" && (
          <div className="border border-cyan-400/40 bg-cyan-400/[0.05] p-4 mb-6">
            <p className="text-sm">
              🎉 Tienes el <b>plan Pro</b>. Todos los módulos están desbloqueados por defecto.
              Los pagos aquí son opcionales (soporta al equipo).
            </p>
          </div>
        )}
        {loading && <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {products.map((p) => {
            const isUnlocked = p.unlocked || unlocks.includes(p.modules_unlocked[0]);
            return (
              <div key={p.id} data-testid={`product-${p.id}`}
                   className={`border p-5 ${
                     isUnlocked
                       ? "border-cyan-400/40 bg-cyan-400/[0.03]"
                       : "border-white/[0.08] bg-[#0A0A0C]"
                   }`}>
                <div className="flex items-start justify-between mb-3">
                  <h3 className="font-heading font-bold text-lg">{p.name}</h3>
                  {isUnlocked ? (
                    <span className="font-mono-data text-[9px] uppercase tracking-widest text-cyan-400 border border-cyan-400/40 px-2 py-1 inline-flex items-center gap-1">
                      <Check className="w-3 h-3" /> Desbloqueado
                    </span>
                  ) : (
                    <span className="font-heading text-2xl font-black text-cyan-400">
                      ${p.price_usd}
                    </span>
                  )}
                </div>
                <p className="text-sm text-white/60 mb-4 leading-relaxed">{p.description}</p>
                {!isUnlocked && (
                  <button onClick={() => buy(p.id)} disabled={buying === p.id}
                          data-testid={`buy-${p.id}`}
                          className="w-full bg-cyan-400 text-black font-semibold px-4 py-2.5 hover:bg-cyan-300 disabled:opacity-40 transition-colors inline-flex items-center justify-center gap-2 font-mono-data text-[10px] uppercase tracking-widest">
                    {buying === p.id
                      ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      : <Zap className="w-3.5 h-3.5" />}
                    Comprar ${p.price_usd}
                  </button>
                )}
              </div>
            );
          })}
        </div>
        <p className="font-mono-data text-[10px] uppercase tracking-widest text-white/30 text-center mt-8">
          Pagos seguros vía Stripe · Un único pago sin renovación · Acceso permanente
        </p>
      </main>
    </div>
  );
}
