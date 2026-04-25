import { useEffect, useState } from "react";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import { LockKey, X, ArrowRight } from "@phosphor-icons/react";

export default function PinHelperModal({ open, onClose, onApply, defaultPan }) {
    const [options, setOptions] = useState({ formats: ["ISO-0", "ISO-1", "ISO-3"], algorithms: ["3DES", "AES"] });
    const [pin, setPin] = useState("");
    const [pan, setPan] = useState(defaultPan || "");
    const [keyHex, setKeyHex] = useState("0123456789ABCDEFFEDCBA9876543210");
    const [format, setFormat] = useState("ISO-0");
    const [algorithm, setAlgorithm] = useState("3DES");
    const [result, setResult] = useState(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        if (!open) return;
        api.get("/pin/options").then((r) => setOptions(r.data)).catch(() => {});
        setPan(defaultPan || "");
        setPin("");
        setResult(null);
    }, [open, defaultPan]);

    if (!open) return null;

    const compute = async (e) => {
        e?.preventDefault();
        setBusy(true);
        try {
            const { data } = await api.post("/pin/encrypt", {
                pin, pan, key_hex: keyHex, format, algorithm,
            });
            setResult(data);
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setBusy(false);
        }
    };

    const apply = () => {
        if (!result) return;
        onApply?.(result.encrypted_block_hex);
        toast.success("F52 populated with encrypted PIN block");
        onClose?.();
    };

    const needsPan = format === "ISO-0" || format === "ISO-3";

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4 overflow-y-auto" onClick={onClose} data-testid="pin-helper-modal">
            <form
                onSubmit={compute}
                onClick={(e) => e.stopPropagation()}
                className="bg-white w-full max-w-xl border border-[#E5E7EB] flex flex-col max-h-[92vh] shadow-xl"
            >
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7] flex items-center gap-1">
                            <LockKey size={12} weight="fill" /> F52 · PIN encryption
                        </div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">PIN block helper</h2>
                        <p className="text-[11px] text-[#4B5563] mt-1">
                            Builds an ISO 9564 PIN block and encrypts it under your test PIN-encryption key.
                            Use HSM-backed keys for production traffic.
                        </p>
                    </div>
                    <button type="button" onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1">
                        <X size={16} />
                    </button>
                </div>

                <div className="px-6 py-5 space-y-4 overflow-y-auto flex-1">
                    <div className="grid grid-cols-2 gap-3">
                        <Field label="PIN format">
                            <select data-testid="pin-format-select" value={format} onChange={(e) => setFormat(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
                                {options.formats.map((f) => (<option key={f} value={f}>{f}</option>))}
                            </select>
                        </Field>
                        <Field label="Algorithm">
                            <select data-testid="pin-algo-select" value={algorithm} onChange={(e) => setAlgorithm(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
                                {options.algorithms.map((a) => (<option key={a} value={a}>{a}</option>))}
                            </select>
                        </Field>
                    </div>
                    <Field label="PIN (4–12 digits)">
                        <input data-testid="pin-input" type="password" inputMode="numeric" maxLength={12} value={pin} onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))} required className="w-full h-9 border border-gray-300 px-2 text-sm font-mono focus:border-[#002FA7]" />
                    </Field>
                    {needsPan && (
                        <Field label={`PAN ${defaultPan ? "(prefilled from F2)" : "(used to derive PAN block)"}`}>
                            <input data-testid="pin-pan-input" inputMode="numeric" value={pan} onChange={(e) => setPan(e.target.value.replace(/\D/g, ""))} required className="w-full h-9 border border-gray-300 px-2 text-sm font-mono focus:border-[#002FA7]" />
                        </Field>
                    )}
                    <Field label={`Key (hex · ${algorithm === "3DES" ? "16/32/48 chars" : "32/48/64 chars"})`}>
                        <input
                            data-testid="pin-key-input"
                            value={keyHex}
                            onChange={(e) => setKeyHex(e.target.value.toUpperCase())}
                            className="w-full h-9 border border-gray-300 px-2 text-sm font-mono focus:border-[#002FA7]"
                        />
                    </Field>

                    {result && (
                        <div className="border border-[#E5E7EB] bg-[#F9FAFB] p-3 space-y-2 text-xs" data-testid="pin-result">
                            <Row label="Clear block" value={result.clear_block_hex} mono />
                            <Row label="Encrypted block" value={result.encrypted_block_hex} mono accent />
                            {result.key_kcv && <Row label="Key KCV" value={result.key_kcv} mono />}
                            <div className="text-[10px] uppercase tracking-widest text-[#4B5563] pt-1 border-t border-[#E5E7EB]">
                                {result.format} · {result.algorithm}
                            </div>
                        </div>
                    )}
                </div>

                <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3 sticky bottom-0">
                    <button type="button" onClick={onClose} data-testid="pin-cancel-btn" className="flex-1 h-11 border border-gray-300 bg-white text-sm font-medium text-[#4B5563] hover:bg-gray-50">
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={busy || !pin || (needsPan && !pan)}
                        data-testid="pin-compute-btn"
                        className="flex-1 h-11 border border-[#002FA7] text-[#002FA7] text-sm font-semibold hover:bg-[#F3F4F6] disabled:opacity-50"
                    >
                        {busy ? "Computing…" : "Compute"}
                    </button>
                    <button
                        type="button"
                        onClick={apply}
                        disabled={!result}
                        data-testid="pin-apply-btn"
                        className="flex-[1.4] h-11 bg-[#002FA7] text-white text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#002080] disabled:opacity-50"
                    >
                        Use as F52 <ArrowRight size={14} weight="bold" />
                    </button>
                </div>
            </form>
        </div>
    );
}

const Field = ({ label, children }) => (
    <label className="block">
        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">{label}</div>
        {children}
    </label>
);

const Row = ({ label, value, mono, accent }) => (
    <div className="grid grid-cols-12 gap-2 items-baseline">
        <div className="col-span-3 text-[10px] uppercase tracking-widest text-[#4B5563]">{label}</div>
        <div className={`col-span-9 break-all ${mono ? "font-mono" : ""} ${accent ? "text-[#002FA7] font-semibold" : ""}`}>{value}</div>
    </div>
);
