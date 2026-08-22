import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Link, useNavigate } from "react-router-dom";
import { Bot, Send, Loader2, ArrowLeft, Sparkles, Plus, History, User } from "lucide-react";
import ReactMarkdown from "react-markdown";
import { API, useAuth } from "@/lib/auth";

const SUGGESTIONS = [
  "Resume mis escaneos más recientes y dime qué debería mirar primero",
  "¿Qué CVEs del catálogo KEV de CISA tengo activas en mis dominios?",
  "Lista los typosquats registrados con IP y clasifica los más peligrosos",
  "Compara los cambios entre los últimos dos escaneos del mismo dominio",
  "Genera un informe ejecutivo de 3 puntos sobre mis activos",
];

export default function Copilot() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [showSessions, setShowSessions] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (!user) navigate("/login");
  }, [user, navigate]);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/copilot/sessions`, { withCredentials: true });
        setSessions(r.data.sessions || []);
      } catch { /* silent */ }
    })();
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const loadSession = async (sid) => {
    try {
      const r = await axios.get(`${API}/copilot/history`,
        { params: { session_id: sid }, withCredentials: true });
      setSessionId(sid);
      setMessages(r.data.messages || []);
      setShowSessions(false);
    } catch (e) {
      toast.error("Fallo al cargar sesión");
    }
  };

  const newChat = () => {
    setSessionId(null);
    setMessages([]);
    setShowSessions(false);
  };

  const send = async (text) => {
    const msg = (text ?? input).trim();
    if (!msg || sending) return;
    setInput("");
    const now = new Date().toISOString();
    setMessages((m) => [...m, { role: "user", content: msg, at: now }]);
    setSending(true);
    try {
      const r = await axios.post(`${API}/copilot/chat`,
        { message: msg, session_id: sessionId },
        { withCredentials: true });
      setSessionId(r.data.session_id);
      setMessages((m) => [...m, { role: "assistant", content: r.data.answer,
                                    model: r.data.model, at: new Date().toISOString() }]);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Copilot no respondió");
      setMessages((m) => [...m, { role: "assistant",
                                    content: "❌ Error: " + (e?.response?.data?.detail || "sin respuesta"),
                                    at: new Date().toISOString() }]);
    } finally { setSending(false); }
  };

  return (
    <div data-testid="copilot-page" className="min-h-screen bg-[#050505] text-white grain">
      <header className="border-b border-white/[0.06] bg-[#0A0A0C] sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-4">
          <Link to="/dashboard" data-testid="back-btn"
                className="text-white/50 hover:text-cyan-400 transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div className="flex items-center gap-2 flex-1">
            <div className="w-8 h-8 border border-cyan-400/40 flex items-center justify-center bg-cyan-400/[0.05]">
              <Bot className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h1 className="font-heading font-bold text-lg tracking-tight">
                NOCTUA <span className="text-cyan-400">Copilot</span>
              </h1>
              <p className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
                Analista IA · acceso a tus escaneos
              </p>
            </div>
          </div>
          <button onClick={newChat} data-testid="new-chat-btn"
                  className="border border-white/[0.15] hover:border-cyan-400 hover:text-cyan-400 px-3 py-1.5 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-2">
            <Plus className="w-3 h-3" /> Nuevo
          </button>
          <button onClick={() => setShowSessions(!showSessions)} data-testid="sessions-btn"
                  className="border border-white/[0.15] hover:border-cyan-400 hover:text-cyan-400 px-3 py-1.5 font-mono-data text-[10px] uppercase tracking-widest inline-flex items-center gap-2">
            <History className="w-3 h-3" /> Historial
          </button>
        </div>
        {showSessions && (
          <div className="max-w-5xl mx-auto px-6 pb-4 space-y-1.5">
            {sessions.length === 0 && (
              <p className="text-xs text-white/40 font-mono-data">Aún no tienes conversaciones guardadas.</p>
            )}
            {sessions.map((s) => (
              <button key={s.session_id} onClick={() => loadSession(s.session_id)}
                      data-testid={`session-${s.session_id}`}
                      className="w-full text-left border border-white/[0.06] hover:border-cyan-400/40 bg-black/40 p-3 transition-colors">
                <div className="font-mono-data text-[10px] text-cyan-400 mb-0.5">
                  {new Date(s.last_at).toLocaleString()} · {s.count} msgs
                </div>
                <div className="text-xs text-white/70 truncate">{s.preview}</div>
              </button>
            ))}
          </div>
        )}
      </header>

      <main className="max-w-5xl mx-auto px-6 py-6">
        <div ref={scrollRef} className="space-y-4 mb-6 min-h-[50vh] max-h-[65vh] overflow-y-auto">
          {messages.length === 0 && !sending && (
            <div data-testid="copilot-welcome" className="border border-cyan-400/20 bg-cyan-400/[0.02] p-6">
              <div className="flex items-center gap-2 mb-4">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span className="font-mono-data text-[10px] uppercase tracking-[0.25em] text-cyan-400">Empieza aquí</span>
              </div>
              <p className="text-sm text-white/80 mb-4 leading-relaxed">
                Hola {user?.name?.split(" ")[0]}. Puedo analizar tus escaneos, correlacionar CVEs, comparar cambios,
                y generar informes ejecutivos. Pregúntame en lenguaje natural.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {SUGGESTIONS.map((s, i) => (
                  <button key={i} onClick={() => send(s)}
                          data-testid={`suggestion-${i}`}
                          className="text-left border border-white/[0.08] hover:border-cyan-400 bg-black/40 p-3 text-xs text-white/70 hover:text-white transition-colors">
                    → {s}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((m, i) => (
            <div key={i} data-testid={`msg-${m.role}-${i}`}
                 className={`flex gap-3 ${m.role === "user" ? "justify-end" : ""}`}>
              {m.role === "assistant" && (
                <div className="w-7 h-7 border border-cyan-400/40 flex items-center justify-center bg-cyan-400/[0.05] flex-shrink-0">
                  <Bot className="w-3.5 h-3.5 text-cyan-400" />
                </div>
              )}
              <div className={`max-w-[80%] p-4 ${
                m.role === "user"
                  ? "bg-cyan-400/[0.06] border border-cyan-400/25"
                  : "bg-[#0C0C0E] border border-white/[0.06]"
              }`}>
                <div className="prose prose-invert prose-sm max-w-none prose-p:my-2 prose-headings:mt-3 prose-headings:mb-1 prose-code:text-cyan-400 prose-code:bg-black/40 prose-code:px-1 prose-code:rounded-none prose-code:before:content-none prose-code:after:content-none prose-table:my-2 prose-td:border prose-td:border-white/10 prose-td:px-2 prose-td:py-1 prose-th:border prose-th:border-white/10 prose-th:px-2 prose-th:py-1 prose-th:bg-black/40">
                  <ReactMarkdown>{m.content}</ReactMarkdown>
                </div>
                {m.model && (
                  <div className="font-mono-data text-[9px] uppercase tracking-widest text-white/30 mt-2 pt-2 border-t border-white/[0.05]">
                    {m.model}
                  </div>
                )}
              </div>
              {m.role === "user" && (
                <div className="w-7 h-7 border border-white/10 flex items-center justify-center bg-white/[0.03] flex-shrink-0">
                  <User className="w-3.5 h-3.5 text-white/60" />
                </div>
              )}
            </div>
          ))}

          {sending && (
            <div className="flex gap-3">
              <div className="w-7 h-7 border border-cyan-400/40 flex items-center justify-center bg-cyan-400/[0.05] flex-shrink-0">
                <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
              </div>
              <div className="bg-[#0C0C0E] border border-white/[0.06] p-4 font-mono-data text-xs text-white/50">
                Analizando tus datos...
              </div>
            </div>
          )}
        </div>

        <div className="border border-white/[0.08] bg-[#0A0A0C] p-3">
          <div className="flex items-end gap-3">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
              }}
              placeholder="Pregunta al Copilot..."
              rows={2}
              data-testid="copilot-input"
              className="flex-1 bg-transparent border-none focus:outline-none text-sm resize-none placeholder:text-white/25"
            />
            <button onClick={() => send()} disabled={sending || !input.trim()}
                    data-testid="copilot-send-btn"
                    className="bg-cyan-400 text-black font-semibold px-5 py-2.5 hover:bg-cyan-300 disabled:opacity-40 transition-colors inline-flex items-center gap-2">
              {sending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Enviar
            </button>
          </div>
          <p className="font-mono-data text-[9px] uppercase tracking-widest text-white/30 mt-2">
            Enter para enviar · Shift+Enter para salto de línea · Copilot ve solo tus escaneos
          </p>
        </div>
      </main>
    </div>
  );
}
