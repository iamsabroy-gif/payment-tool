import { useState } from "react";
import { api, apiErr } from "../lib/api";
import { useAuth } from "../contexts/AuthContext";
import { toast } from "sonner";
import { Check, CreditCard } from "@phosphor-icons/react";

const FEATURES_FREE = [
    "ISO-8583 Message Builder (128 fields)",
    "VISA, Mastercard, AMEX and RuPay specs",
    "50 transaction logs",
    "10 saved templates",
    "Built-in simulator",
];
const FEATURES_PRO = [
    "Everything in Free",
    "Unlimited transaction logs",
    "Unlimited saved templates",
    "Custom external endpoint URL",
    "Priority support",
];

export default function Pricing() {
    const { user, refresh } = useAuth();
    const [loading, setLoading] = useState(false);

    const upgrade = async () => {
        setLoading(true);
        try {
            const origin = window.location.origin;
            const { data } = await api.post("/billing/checkout", { origin_url: origin });
            window.location.href = data.url;
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setLoading(false);
        }
    };

    const isPro = user?.plan === "pro";

    return (
        <div className="p-6 space-y-8" data-testid="pricing-page">
            <header>
                <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">05 · Billing</div>
                <h1 className="text-3xl font-semibold tracking-tight mt-1">Pricing</h1>
                <p className="text-sm text-[#4B5563] mt-2 max-w-xl">
                    Free tier covers day-to-day testing. Upgrade to Pro when you need unlimited capture and templates.
                </p>
            </header>

            <section className="grid grid-cols-1 md:grid-cols-2 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                <Tier
                    title="Free"
                    price="$0"
                    subtitle="For exploring specs & lightweight testing"
                    features={FEATURES_FREE}
                    cta={
                        <div className="h-10 border border-gray-300 text-[#4B5563] text-sm flex items-center justify-center" data-testid="tier-free-current">
                            Current tier
                        </div>
                    }
                    dim={isPro}
                />
                <Tier
                    title="Pro"
                    price="$29"
                    subtitle="Per month · cancel anytime"
                    features={FEATURES_PRO}
                    highlight
                    cta={
                        isPro ? (
                            <div className="h-10 bg-[#16A34A] text-white text-sm flex items-center justify-center gap-2" data-testid="tier-pro-active">
                                <Check weight="bold" size={14} /> Active
                            </div>
                        ) : (
                            <button
                                onClick={upgrade}
                                disabled={loading}
                                data-testid="upgrade-pro-btn"
                                className="h-10 bg-[#002FA7] text-white text-sm flex items-center justify-center gap-2 hover:bg-[#002080] disabled:opacity-50"
                            >
                                <CreditCard size={14} /> {loading ? "Redirecting…" : "Upgrade to Pro"}
                            </button>
                        )
                    }
                />
            </section>
        </div>
    );
}

const Tier = ({ title, price, subtitle, features, cta, highlight, dim }) => (
    <div className={`bg-white p-6 ${dim ? "opacity-75" : ""}`}>
        <div className="flex items-baseline justify-between">
            <div className="text-lg font-semibold">{title}</div>
            {highlight && <span className="text-[10px] uppercase tracking-widest border border-[#002FA7] text-[#002FA7] px-1.5 py-0.5">Recommended</span>}
        </div>
        <div className="mt-4 flex items-baseline gap-1">
            <span className="text-4xl font-semibold font-mono">{price}</span>
            {title === "Pro" && <span className="text-xs text-[#4B5563]">/ mo</span>}
        </div>
        <div className="text-xs text-[#4B5563] mt-1">{subtitle}</div>
        <ul className="mt-5 space-y-2 text-sm">
            {features.map((f, i) => (
                <li key={i} className="flex items-start gap-2">
                    <Check size={14} weight="bold" className="text-[#16A34A] mt-0.5 shrink-0" />
                    <span>{f}</span>
                </li>
            ))}
        </ul>
        <div className="mt-6">{cta}</div>
    </div>
);
