import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { API, useAuth } from "@/lib/auth";
import Loader from "@/components/Loader";

// REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
export default function AuthCallback() {
  const navigate = useNavigate();
  const { setUser } = useAuth();
  const hasProcessed = useRef(false);

  useEffect(() => {
    if (hasProcessed.current) return;
    hasProcessed.current = true;

    const hash = window.location.hash || "";
    const m = hash.match(/session_id=([^&]+)/);
    if (!m) { navigate("/login"); return; }
    const sessionId = m[1];

    (async () => {
      try {
        const r = await axios.post(
          `${API}/auth/session`,
          { session_id: sessionId },
          { withCredentials: true }
        );
        setUser(r.data);
        window.history.replaceState(null, "", "/dashboard");
        navigate("/dashboard", { replace: true, state: { user: r.data } });
      } catch (e) {
        const detail = e?.response?.data?.detail;
        if (e?.response?.status === 403 && detail?.error === "private_access") {
          navigate(`/login?private=1&email=${encodeURIComponent(detail.email || "")}`,
                   { replace: true });
        } else {
          navigate("/login", { replace: true });
        }
      }
    })();
  }, [navigate, setUser]);

  return <Loader label="Autenticando..." />;
}
