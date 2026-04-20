import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { apiErr } from "../lib/api";
import { Lightning } from "@phosphor-icons/react";

export default function Login() {
    const { login } = useAuth();
    const nav = useNavigate();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [err, setErr] = useState("");
    const [loading, setLoading] = useState(false);

    const submit = async (e) => {
        e.preventDefault();
        setErr("");
        setLoading(true);
        try {
            await login(email, password);
            nav("/app", { replace: true });
        } catch (e) {
            setErr(apiErr(e));
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen grid grid-cols-1 lg:grid-cols-2">
            <div className="hidden lg:flex grid-bg border-r border-[#E5E7EB] items-end p-10">
                <div className="max-w-md">
                    <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight mb-10" data-testid="login-logo">
                        <Lightning weight="fill" size={18} className="text-[#002FA7]" /> ISO-8583 LAB
                    </Link>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563] mb-4">Access · v1.0</div>
                    <h2 className="text-4xl font-semibold tracking-tight leading-tight">Sign in to the bench.</h2>
                    <p className="mt-4 text-sm text-[#4B5563] leading-relaxed">
                        Your builders, captured logs and saved templates are waiting. All traffic is isolated per account.
                    </p>
                </div>
            </div>
            <div className="flex items-center justify-center p-10">
                <form onSubmit={submit} className="w-full max-w-sm space-y-5" data-testid="login-form">
                    <div>
                        <div className="text-[11px] tracking-[0.2em] uppercase text-[#002FA7]">01 · Sign In</div>
                        <h1 className="text-2xl font-semibold tracking-tight mt-2">Welcome back</h1>
                    </div>
                    {err && (
                        <div className="border border-[#E11D48] bg-[#FEF2F2] text-[#E11D48] text-xs px-3 py-2" data-testid="login-error">
                            {err}
                        </div>
                    )}
                    <div className="space-y-1">
                        <label className="text-[11px] uppercase tracking-widest text-[#4B5563]">Email</label>
                        <input
                            data-testid="login-email-input"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                            className="w-full h-10 px-3 border border-gray-300 font-mono text-sm focus:border-[#002FA7]"
                        />
                    </div>
                    <div className="space-y-1">
                        <label className="text-[11px] uppercase tracking-widest text-[#4B5563]">Password</label>
                        <input
                            data-testid="login-password-input"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="w-full h-10 px-3 border border-gray-300 font-mono text-sm focus:border-[#002FA7]"
                        />
                    </div>
                    <button
                        data-testid="login-submit-btn"
                        disabled={loading}
                        className="w-full h-10 bg-[#002FA7] text-white text-sm font-medium hover:bg-[#002080] disabled:opacity-50"
                    >
                        {loading ? "Authenticating…" : "Sign in"}
                    </button>
                    <div className="text-xs text-[#4B5563]">
                        No account? <Link to="/register" className="text-[#002FA7] hover:underline" data-testid="login-to-register-link">Create one</Link>
                    </div>
                </form>
            </div>
        </div>
    );
}
