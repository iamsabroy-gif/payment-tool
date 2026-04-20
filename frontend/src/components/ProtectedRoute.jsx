import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export default function ProtectedRoute({ children }) {
    const { user, loading } = useAuth();
    if (loading) {
        return (
            <div className="h-screen flex items-center justify-center text-xs tracking-widest uppercase text-gray-500">
                Authenticating…
            </div>
        );
    }
    if (!user) return <Navigate to="/login" replace />;
    return children;
}
