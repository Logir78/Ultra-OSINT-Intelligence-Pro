import { useAuth } from "@/lib/auth";
import { Navigate } from "react-router-dom";
import Loader from "@/components/Loader";

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <Loader label="Verificando sesión..." />;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}
