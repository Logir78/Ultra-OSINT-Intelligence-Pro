import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { Radar, LogIn, ShieldAlert, Mail, Lock, User as UserIcon, Loader2 } from "lucide-react";
import { API, useAuth } from "@/lib/auth";

// REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
export default function Login() {
  const { user, loading, checkAuth } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const privateMode = params.get("private") === "1";
  const blockedEmail = params.get("email") || "";

  // Native email/password auth (backend: /api/auth/login · /api/auth/register)
  const [mode, setMode] = useState("login"); // "login" | "register"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && user) navigate("/dashboard", { replace: true });
  }, [user, loading, navigate]);

  const handleGoogle = () => {
    const redirectUrl = window.location.origin + "/dashboard";
    window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
  };

  const handleNativeSubmit = async (e) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    try {
      const url = mode === "login" ? `${API}/auth/login` : `${API}/auth/register`;
      const body = mode === "login"
        ? { email: email.trim(), password }
        : { email: email.trim(), password, name: name.trim() };
      await axios.post(url, body, { withCredentials: true });
      await checkAuth();
      navigate("/dashboard", { replace: true });
    } catch (err) {
      const detail = err?.response?.data?.detail;
      toast.error(typeof detail === "string" ? detail : "No se pudo completar la operación");
    } finally {
      setBusy(false);
    }
  };

  const isRegister = mode === "register";

  return (
    <div data-testid="login-page" className="relative min-h-screen bg-[#050505] text-white grain overflow-hidden flex items-center justify-center">
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.08]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,0.4) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] rounded-full bg-cyan-500/10 blur-[120px] pointer-events-none" />

      <div className="relative z-10 w-full max-w-md px-6">
        <div className="flex items-center justify-center gap-3 mb-10">
          <div className="w-10 h-10 border border-cyan-400/40 flex items-center justify-center">
            <Radar className="w-5 h-5 text-cyan-400" />
          </div>
          <span className="font-heading font-black text-xl tracking-tight">NOCTUA<span className="text-cyan-400">.osint</span></span>
        </div>

        <div className="border border-white/10 bg-[#0C0C0E] p-10">
          {privateMode && (
            <div data-testid="private-access-banner" className="mb-6 border-2 border-red-400 bg-red-500/[0.08] p-4">
              <div className="flex items-center gap-2 mb-2">
                <ShieldAlert className="w-5 h-5 text-red-400" />
                <span className="font-heading font-bold text-red-300">ACCESO PRIVADO</span>
              </div>
              <p className="text-sm text-white/80 leading-relaxed">
                Esta instancia de NOCTUA está en modo Acceso Privado. Tu correo
                <span className="text-cyan-400 font-mono-data"> {blockedEmail || "—"} </span>
                no está en la lista blanca. El intento ha sido registrado.
              </p>
            </div>
          )}

          {/* Login / Register toggle */}
          <div className="flex mb-8 border border-white/10">
            <button
              type="button"
              onClick={() => setMode("login")}
              data-testid="tab-login"
              className={`flex-1 py-2.5 font-mono-data text-[11px] uppercase tracking-[0.2em] transition-colors ${!isRegister ? "bg-cyan-400 text-black font-semibold" : "text-white/50 hover:text-white"}`}
            >
              Entrar
            </button>
            <button
              type="button"
              onClick={() => setMode("register")}
              data-testid="tab-register"
              className={`flex-1 py-2.5 font-mono-data text-[11px] uppercase tracking-[0.2em] transition-colors ${isRegister ? "bg-cyan-400 text-black font-semibold" : "text-white/50 hover:text-white"}`}
            >
              Crear cuenta
            </button>
          </div>

          <div className="mb-6">
            <h1 className="font-heading text-2xl font-black tracking-tight mb-2">
              {isRegister ? "Crea tu cuenta" : "Autentica tu identidad"}
            </h1>
            <p className="text-sm text-white/50 leading-relaxed">
              {isRegister
                ? "Regístrate con tu correo para acceder al motor de reconocimiento."
                : "Inicia sesión para acceder al motor y a tu historial de escaneos."}
            </p>
          </div>

          <form onSubmit={handleNativeSubmit} className="space-y-3">
            {isRegister && (
              <div className="flex items-center border border-white/[0.08] bg-black">
                <UserIcon className="w-4 h-4 text-cyan-400 mx-3.5" />
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Nombre"
                  required
                  data-testid="login-name"
                  className="flex-1 bg-transparent py-3 font-mono-data text-sm placeholder:text-white/25 focus:outline-none"
                />
              </div>
            )}
            <div className="flex items-center border border-white/[0.08] bg-black">
              <Mail className="w-4 h-4 text-cyan-400 mx-3.5" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="tu@correo.com"
                required
                autoComplete="email"
                data-testid="login-email"
                className="flex-1 bg-transparent py-3 font-mono-data text-sm placeholder:text-white/25 focus:outline-none"
              />
            </div>
            <div className="flex items-center border border-white/[0.08] bg-black">
              <Lock className="w-4 h-4 text-cyan-400 mx-3.5" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isRegister ? "Contraseña (mín. 8 caracteres)" : "Contraseña"}
                required
                minLength={isRegister ? 8 : undefined}
                autoComplete={isRegister ? "new-password" : "current-password"}
                data-testid="login-password"
                className="flex-1 bg-transparent py-3 font-mono-data text-sm placeholder:text-white/25 focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={busy}
              data-testid="native-submit"
              className="w-full inline-flex items-center justify-center gap-2 bg-cyan-400 text-black font-semibold px-6 py-3.5 hover:bg-cyan-300 disabled:opacity-50 transition-colors"
            >
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <LogIn className="w-4 h-4" />}
              {isRegister ? "Crear cuenta" : "Entrar"}
            </button>
          </form>

          <div className="flex items-center gap-3 my-6">
            <div className="flex-1 h-px bg-white/10" />
            <span className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/30">o</span>
            <div className="flex-1 h-px bg-white/10" />
          </div>

          <button
            onClick={handleGoogle}
            data-testid="google-login-button"
            className="group w-full inline-flex items-center justify-center gap-3 bg-white text-black font-semibold px-6 py-3.5 hover:bg-white/90 transition-colors"
          >
            <LogIn className="w-4 h-4" />
            Continuar con Google
          </button>

          <div className="mt-8 pt-6 border-t border-white/5">
            <p className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-white/30 text-center">
              Sesión segura · Cookie httpOnly · 7 días
            </p>
          </div>
        </div>

        <p className="text-center text-xs text-white/30 mt-6">
          Al continuar, aceptas usar la herramienta solo sobre dominios autorizados.
        </p>
      </div>
    </div>
  );
}
