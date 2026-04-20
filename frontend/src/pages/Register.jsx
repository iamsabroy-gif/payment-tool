import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { apiErr } from "../lib/api";
import { Lightning } from "@phosphor-icons/react";

export default function Register() {
    const { register } = useAuth();
    const nav = useNavigate();
    const [form, setForm] = useState({ email: "", password: "", name: "" });
    const [err, setErr] = useState("");
    const [loading, setLoading] = useState(false);

    const submit = async (e) => {
        e.preventDefault();
        setErr("");
        setLoading(true);
        try {
            await register(form.email, form.password, form.name);
            nav("/app", { replace: true });
        } catch (e) {
            setErr(apiErr(e));
        } finally {
            setLoading(false);
        }
    };

    const onChange = (k) => (e) => setForm({ ...form, [k]: e.target.value });

    return (
        <div className="min-h-screen grid grid-cols-1 lg:grid-cols-2">
            <div className="hidden lg:flex grid-bg border-r border-[#E5E7EB] items-end p-10">
                <div className="max-w-md">
                    <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight mb-10" data-testid="register-logo">
                        <Lightning weight="fill" size={18} className="text-[#002FA7]" /> ISO-8583 LAB
                    </Link>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563] mb-4">Create · Account</div>
                    <h2 className="text-4xl font-semibold tracking-tight leading-tight">Provision your workbench.</h2>
                    <p className="mt-4 text-sm text-[#4B5563] leading-relaxed">
                        Free tier includes 50 captured logs and 10 saved templates. Upgrade to Pro anytime for unlimited capture.
                    </p>
                </div>
            </div>
            <div className="flex items-center justify-center p-10">
                <form onSubmit={submit} className="w-full max-w-sm space-y-5" data-testid="register-form">
                    <div>
                        <div className="text-[11px] tracking-[0.2em] uppercase text-[#002FA7]">02 · Register</div>
                        <h1 className="text-2xl font-semibold tracking-tight mt-2">Create your account</h1>
                    </div>
                    {err && (
                        <div className="border border-[#E11D48] bg-[#FEF2F2] text-[#E11D48] text-xs px-3 py-2" data-testid="register-error">
                            {err}
                        </div>
                    )}
                    <div className="space-y-1">
                        <label className="text-[11px] uppercase tracking-widest text-[#4B5563]">Name</label>
                        <input data-testid="register-name-input" value={form.name} onChange={onChange("name")} className="w-full h-10 px-3 border border-gray-300 font-mono text-sm focus:border-[#002FA7]" />
                    </div>
                    <div className="space-y-1">
                        <label className="text-[11px] uppercase tracking-widest text-[#4B5563]">Email</label>
                        <input data-testid="register-email-input" type="email" value={form.email} onChange={onChange("email")} required className="w-full h-10 px-3 border border-gray-300 font-mono text-sm focus:border-[#002FA7]" />
                    </div>
                    <div className="space-y-1">
                        <label className="text-[11px] uppercase tracking-widest text-[#4B5563]">Password <span className="text-[#9CA3AF]">(8+ characters)</span></label>
                        <input data-testid="register-password-input" type="password" value={form.password} onChange={onChange("password")} minLength={8} required className="w-full h-10 px-3 border border-gray-300 font-mono text-sm focus:border-[#002FA7]" />
                    </div>
                    <button data-testid="register-submit-btn" disabled={loading} className="w-full h-10 bg-[#002FA7] text-white text-sm font-medium hover:bg-[#002080] disabled:opacity-50">
                        {loading ? "Provisioning…" : "Create account"}
                    </button>
                    <div className="text-xs text-[#4B5563]">
                        Have an account? <Link to="/login" className="text-[#002FA7] hover:underline" data-testid="register-to-login-link">Sign in</Link>
                    </div>
                </form>
            </div>
        </div>
    );
}
