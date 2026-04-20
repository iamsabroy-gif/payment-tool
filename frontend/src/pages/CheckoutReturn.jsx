import { useEffect, useState } from "react";
import { useSearchParams, Link, useNavigate } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import { useAuth } from "../contexts/AuthContext";
import { CheckCircle, XCircle, Spinner } from "@phosphor-icons/react";

export default function CheckoutReturn() {
    const [params] = useSearchParams();
    const sessionId = params.get("session_id");
    const { refresh } = useAuth();
    const nav = useNavigate();
    const [status, setStatus] = useState("polling");
    const [err, setErr] = useState("");

    useEffect(() => {
        if (!sessionId) {
            setStatus("error");
            setErr("No session id provided");
            return;
        }
        let attempts = 0;
        const maxAttempts = 8;

        const poll = async () => {
            attempts += 1;
            try {
                const { data } = await api.get(`/billing/status/${sessionId}`);
                if (data.payment_status === "paid") {
                    setStatus("paid");
                    await refresh();
                    return;
                }
                if (data.status === "expired") {
                    setStatus("expired");
                    return;
                }
                if (attempts < maxAttempts) {
                    setTimeout(poll, 2000);
                } else {
                    setStatus("timeout");
                }
            } catch (e) {
                setErr(apiErr(e));
                setStatus("error");
            }
        };
        poll();
    }, [sessionId, refresh]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-white p-6">
            <div className="w-full max-w-md border border-[#E5E7EB] p-10 text-center" data-testid="checkout-return-card">
                {status === "polling" && (
                    <>
                        <Spinner size={32} className="mx-auto text-[#002FA7] animate-spin" />
                        <div className="mt-5 text-[11px] uppercase tracking-widest text-[#4B5563]">Confirming payment</div>
                        <div className="mt-2 text-lg font-semibold">Hold tight — checking with Stripe…</div>
                    </>
                )}
                {status === "paid" && (
                    <>
                        <CheckCircle size={32} weight="fill" className="mx-auto text-[#16A34A]" />
                        <div className="mt-5 text-[11px] uppercase tracking-widest text-[#4B5563]">Welcome aboard</div>
                        <div className="mt-2 text-xl font-semibold">You're on Pro.</div>
                        <div className="mt-2 text-sm text-[#4B5563]">Unlimited transaction logs and templates are unlocked.</div>
                        <button onClick={() => nav("/app")} data-testid="return-to-dashboard-btn" className="mt-6 h-10 px-5 bg-[#002FA7] text-white text-sm hover:bg-[#002080]">
                            Go to dashboard
                        </button>
                    </>
                )}
                {(status === "expired" || status === "timeout" || status === "error") && (
                    <>
                        <XCircle size={32} weight="fill" className="mx-auto text-[#E11D48]" />
                        <div className="mt-5 text-[11px] uppercase tracking-widest text-[#4B5563]">Payment not completed</div>
                        <div className="mt-2 text-lg font-semibold">
                            {status === "expired" ? "Session expired" : status === "timeout" ? "Still processing" : "Something went wrong"}
                        </div>
                        {err && <div className="mt-2 text-xs text-[#E11D48]">{err}</div>}
                        <Link to="/app/pricing" data-testid="return-retry-btn" className="inline-block mt-6 h-10 px-5 bg-[#002FA7] text-white text-sm hover:bg-[#002080] leading-10">
                            Back to pricing
                        </Link>
                    </>
                )}
            </div>
        </div>
    );
}
