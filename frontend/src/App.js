import "./App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { Toaster } from "sonner";
import ProtectedRoute from "./components/ProtectedRoute";
import AppShell from "./components/AppShell";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Builder from "./pages/Builder";
import Templates from "./pages/Templates";
import Logs from "./pages/Logs";
import Pricing from "./pages/Pricing";
import CheckoutReturn from "./pages/CheckoutReturn";

function PublicOnly({ children }) {
    const { user, loading } = useAuth();
    if (loading) return null;
    if (user) return <Navigate to="/app" replace />;
    return children;
}

function App() {
    return (
        <div className="App">
            <AuthProvider>
                <BrowserRouter>
                    <Toaster position="bottom-right" theme="light" toastOptions={{ className: "rounded-none" }} />
                    <Routes>
                        <Route path="/" element={<Landing />} />
                        <Route path="/login" element={<PublicOnly><Login /></PublicOnly>} />
                        <Route path="/register" element={<PublicOnly><Register /></PublicOnly>} />
                        <Route path="/billing/return" element={<CheckoutReturn />} />
                        <Route
                            path="/app"
                            element={
                                <ProtectedRoute>
                                    <AppShell />
                                </ProtectedRoute>
                            }
                        >
                            <Route index element={<Dashboard />} />
                            <Route path="builder" element={<Builder />} />
                            <Route path="templates" element={<Templates />} />
                            <Route path="logs" element={<Logs />} />
                            <Route path="pricing" element={<Pricing />} />
                        </Route>
                        <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                </BrowserRouter>
            </AuthProvider>
        </div>
    );
}

export default App;
