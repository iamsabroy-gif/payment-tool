import { useState } from "react";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import { Key, X, Copy, ArrowRight, ShieldCheck, Hash, CheckCircle, XCircle } from "@phosphor-icons/react";

const TABS = [
    { id: "kcv",  label: "KCV match" },
    { id: "cvv",  label: "CVV (CVK)" },
    { id: "pvv",  label: "PVV (PVK)" },
    { id: "arqc", label: "ARQC (MDK)" },
    { id: "arpc", label: "ARPC (issuer)" },
];

export default function KeyToolsModal({ open, onClose, builderState, onInsertField }) {
    const [tab, setTab] = useState("kcv");

    if (!open) return null;

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4 overflow-y-auto" onClick={onClose} data-testid="key-tools-modal">
            <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-3xl border border-[#E5E7EB] flex flex-col max-h-[92vh] shadow-xl">
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7] flex items-center gap-1">
                            <Key size={12} weight="fill" /> Key tools
                        </div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">Crypto helpers</h2>
                        <p className="text-[11px] text-[#4B5563] mt-1">
                            KCV verification, CVV under CVK, PVV under PVK, ARQC under MDK — generate or verify. Software-only — use HSMs in production.
                        </p>
                    </div>
                    <button onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1"><X size={16} /></button>
                </div>

                <div className="flex border-b border-[#E5E7EB]">
                    {TABS.map((t) => (
                        <button
                            key={t.id}
                            onClick={() => setTab(t.id)}
                            data-testid={`key-tab-${t.id}`}
                            className={`flex-1 h-11 text-xs font-medium tracking-wide transition-colors border-b-2 ${
                                tab === t.id ? "border-[#002FA7] text-[#002FA7] bg-[#F3F4F6]" : "border-transparent text-[#4B5563] hover:bg-gray-50"
                            }`}
                        >
                            {t.label}
                        </button>
                    ))}
                </div>

                <div className="px-6 py-5 overflow-y-auto flex-1 space-y-4">
                    {tab === "kcv"  && <KcvTab />}
                    {tab === "cvv"  && <CvvTab builderState={builderState} onInsertField={onInsertField} onClose={onClose} />}
                    {tab === "pvv"  && <PvvTab builderState={builderState} />}
                    {tab === "arqc" && <ArqcTab builderState={builderState} onInsertField={onInsertField} onClose={onClose} />}
                    {tab === "arpc" && <ArpcTab onInsertField={onInsertField} onClose={onClose} />}
                </div>
            </div>
        </div>
    );
}

// ----------------------------- KCV --------------------------------------
function KcvTab() {
    const [keyA, setKeyA] = useState("");
    const [keyB, setKeyB] = useState("");
    const [algo, setAlgo] = useState("3DES");
    const [a, setA] = useState(null);
    const [b, setB] = useState(null);

    const compute = async (which) => {
        const key = which === "a" ? keyA : keyB;
        if (!key) return;
        try {
            const { data } = await api.post("/keys/kcv", { key_hex: key, algorithm: algo });
            (which === "a" ? setA : setB)(data.kcv);
        } catch (e) { toast.error(apiErr(e)); }
    };

    const match = a && b && a === b;

    return (
        <>
            <p className="text-xs text-[#4B5563]">Compute the Key Check Value (encrypt all-zero block, take first 3 bytes). Compare two KCVs to confirm both ends share the same key.</p>
            <Field label="Algorithm">
                <select data-testid="kcv-algo-select" value={algo} onChange={(e) => setAlgo(e.target.value)} className="w-40 h-9 border border-gray-300 px-2 text-sm bg-white">
                    <option value="3DES">3DES</option>
                    <option value="AES">AES</option>
                </select>
            </Field>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <KcvSlot label="Key A" testid="kcv-a" keyHex={keyA} setKey={setKeyA} kcv={a} onCompute={() => compute("a")} />
                <KcvSlot label="Key B" testid="kcv-b" keyHex={keyB} setKey={setKeyB} kcv={b} onCompute={() => compute("b")} />
            </div>
            {a && b && (
                <div className={`border px-4 py-3 text-sm flex items-center gap-2 ${match ? "border-[#16A34A] bg-[#F0FDF4] text-[#16A34A]" : "border-[#E11D48] bg-[#FEF2F2] text-[#E11D48]"}`} data-testid="kcv-match">
                    <ShieldCheck size={16} weight="fill" />
                    {match ? "KCVs match — both sides hold the same key." : "KCVs do not match — keys differ."}
                </div>
            )}
        </>
    );
}

const KcvSlot = ({ label, testid, keyHex, setKey, kcv, onCompute }) => (
    <div className="space-y-2 border border-[#E5E7EB] p-3">
        <Field label={label}>
            <input data-testid={`${testid}-key-input`} value={keyHex} onChange={(e) => setKey(e.target.value.toUpperCase())} placeholder="hex" className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
        </Field>
        <button onClick={onCompute} data-testid={`${testid}-compute-btn`} className="h-9 px-4 border border-[#002FA7] text-[#002FA7] text-xs font-semibold hover:bg-[#F3F4F6]">Compute KCV</button>
        {kcv && <ResultLine label="KCV" value={kcv} testid={`${testid}-kcv`} />}
    </div>
);

// ----------------------------- CVV --------------------------------------
function CvvTab({ builderState, onInsertField, onClose }) {
    const [pan, setPan] = useState(builderState?.values?.[2] || "");
    const [expiry, setExpiry] = useState(builderState?.values?.[14] || "");
    const [svc, setSvc] = useState("101");
    const [cvkA, setCvkA] = useState("0123456789ABCDEF");
    const [cvkB, setCvkB] = useState("FEDCBA9876543210");
    const [mode, setMode] = useState("generate");
    const [cvvIn, setCvvIn] = useState("");
    const [t2Pvki, setT2Pvki] = useState("0");
    const [t2Pvv, setT2Pvv] = useState("0000");
    const [res, setRes] = useState(null);
    const [verdict, setVerdict] = useState(null);
    const [busy, setBusy] = useState(false);

    const compute = async () => {
        setBusy(true);
        try {
            const body = { pan, expiry, service_code: svc, cvk_a_hex: cvkA, cvk_b_hex: cvkB };
            if (mode === "verify") {
                const { data } = await api.post("/keys/cvv/verify", { ...body, cvv: cvvIn });
                setVerdict(data);
            } else {
                const { data } = await api.post("/keys/cvv", body);
                setRes(data);
            }
        } catch (e) { toast.error(apiErr(e)); }
        finally { setBusy(false); }
    };

    const buildTrack2 = () => {
        if (!res) return;
        // Visa discretionary data layout: PVKI(1) || PVV(4) || CVV(3) || filler
        const t2 = `${pan}D${expiry}${svc}${(t2Pvki || "0").slice(0, 1)}${(t2Pvv || "0000").padEnd(4, "0").slice(0, 4)}${res.cvv}000`;
        onInsertField?.(35, t2);
        toast.success("F35 track2 populated");
        onClose?.();
    };

    return (
        <>
            <p className="text-xs text-[#4B5563]">CVV1 (track) when service code is from track data, CVV2 when 000, iCVV when 999. Algorithm: IBM 4731 / ANSI X9.</p>
            <div className="grid grid-cols-3 gap-3">
                <Field label="PAN"><input data-testid="cvv-pan" value={pan} onChange={(e) => setPan(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                <Field label="Expiry (YYMM)"><input data-testid="cvv-expiry" value={expiry} maxLength={4} onChange={(e) => setExpiry(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                <Field label="Service code"><input data-testid="cvv-svc" value={svc} maxLength={3} onChange={(e) => setSvc(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
                <Field label="CVK_A (8 bytes hex)"><input data-testid="cvv-cvka" value={cvkA} onChange={(e) => setCvkA(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                <Field label="CVK_B (8 bytes hex)"><input data-testid="cvv-cvkb" value={cvkB} onChange={(e) => setCvkB(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
            </div>
            <ModeToggle mode={mode} setMode={(m) => { setMode(m); setVerdict(null); }} testid="cvv-mode" />
            {mode === "verify" && (
                <Field label="CVV to verify (3 digits)">
                    <input data-testid="cvv-verify-input" value={cvvIn} maxLength={3} onChange={(e) => setCvvIn(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                </Field>
            )}
            <button onClick={compute} disabled={busy || (mode === "verify" && cvvIn.length !== 3)} data-testid="cvv-compute-btn" className="h-9 px-4 border border-[#002FA7] text-[#002FA7] text-xs font-semibold hover:bg-[#F3F4F6] disabled:opacity-50">
                {busy ? "Working…" : mode === "verify" ? "Verify CVV" : "Compute CVV"}
            </button>
            {mode === "verify" && <Verdict data={verdict} what="CVV" kcvLabel="CVK KCV" kcv={verdict?.cvk_kcv} testid="cvv-verdict" />}
            {mode === "generate" && res && (
                <div className="border border-[#E5E7EB] bg-[#F9FAFB] p-3 space-y-2 text-xs" data-testid="cvv-result">
                    <ResultLine label="CVV" value={res.cvv} accent testid="cvv-value" />
                    <ResultLine label="CVK KCV" value={res.cvk_kcv} testid="cvv-kcv" />
                    <div className="grid grid-cols-2 gap-3">
                        <Field label="Track 2 PVKI (optional)"><input data-testid="cvv-t2-pvki" value={t2Pvki} maxLength={1} onChange={(e) => setT2Pvki(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                        <Field label="Track 2 PVV (optional)"><input data-testid="cvv-t2-pvv" value={t2Pvv} maxLength={4} onChange={(e) => setT2Pvv(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                    </div>
                    <button onClick={buildTrack2} data-testid="cvv-build-track2" className="h-9 px-4 bg-[#002FA7] text-white text-xs font-semibold hover:bg-[#002080] flex items-center gap-2">
                        Build track2 → insert into F35 <ArrowRight size={12} weight="bold" />
                    </button>
                </div>
            )}
        </>
    );
}

// ----------------------------- PVV --------------------------------------
function PvvTab({ builderState }) {
    const [pan, setPan] = useState(builderState?.values?.[2] || "");
    const [pin, setPin] = useState("");
    const [pvki, setPvki] = useState("1");
    const [pvkA, setPvkA] = useState("0123456789ABCDEF");
    const [pvkB, setPvkB] = useState("FEDCBA9876543210");
    const [mode, setMode] = useState("generate");
    const [pvvIn, setPvvIn] = useState("");
    const [source, setSource] = useState("clear"); // clear | block
    const [block, setBlock] = useState(builderState?.values?.[52] || "");
    const [pek, setPek] = useState("");
    const [pinFormat, setPinFormat] = useState("ISO-0");
    const [pinAlgo, setPinAlgo] = useState("3DES");
    const [res, setRes] = useState(null);
    const [verdict, setVerdict] = useState(null);
    const [busy, setBusy] = useState(false);

    const compute = async () => {
        setBusy(true);
        try {
            if (mode === "verify") {
                const body = { pan, pvki, pvv: pvvIn, pvk_a_hex: pvkA, pvk_b_hex: pvkB };
                Object.assign(body, source === "block"
                    ? { pin_block_hex: block, pek_hex: pek, pin_format: pinFormat, pin_algorithm: pinAlgo }
                    : { pin });
                const { data } = await api.post("/keys/pvv/verify", body);
                setVerdict(data);
            } else {
                const { data } = await api.post("/keys/pvv", {
                    pan, pin, pvki, pvk_a_hex: pvkA, pvk_b_hex: pvkB,
                });
                setRes(data);
            }
        } catch (e) { toast.error(apiErr(e)); }
        finally { setBusy(false); }
    };
    const showClearPin = mode === "generate" || source === "clear";

    return (
        <>
            <p className="text-xs text-[#4B5563]">VISA PVV: encrypt (PAN[11] || PVKI || PIN[4]) under PVK pair, take first 4 decimal digits.</p>
            <div className="grid grid-cols-3 gap-3">
                <Field label="PAN"><input data-testid="pvv-pan" value={pan} onChange={(e) => setPan(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                {showClearPin ? (
                    <Field label="PIN (4 digits)"><input data-testid="pvv-pin" type="password" inputMode="numeric" maxLength={4} value={pin} onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                ) : <div />}
                <Field label="PVKI (1 digit)"><input data-testid="pvv-pvki" value={pvki} maxLength={1} onChange={(e) => setPvki(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
                <Field label="PVK_A (8 bytes hex)"><input data-testid="pvv-pvka" value={pvkA} onChange={(e) => setPvkA(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                <Field label="PVK_B (8 bytes hex)"><input data-testid="pvv-pvkb" value={pvkB} onChange={(e) => setPvkB(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
            </div>
            <ModeToggle mode={mode} setMode={(m) => { setMode(m); setVerdict(null); }} testid="pvv-mode" />
            {mode === "verify" && (
                <>
                    <div className="grid grid-cols-2 gap-3">
                        <Field label="PVV to verify (4 digits)">
                            <input data-testid="pvv-verify-input" value={pvvIn} maxLength={4} onChange={(e) => setPvvIn(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                        </Field>
                        <Field label="PIN from">
                            <select data-testid="pvv-source-select" value={source} onChange={(e) => setSource(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
                                <option value="clear">Clear PIN</option>
                                <option value="block">Encrypted PIN block (F52)</option>
                            </select>
                        </Field>
                    </div>
                    {source === "block" && (
                        <div className="grid grid-cols-2 gap-3">
                            <Field label="PIN block (hex)"><input data-testid="pvv-block" value={block} onChange={(e) => setBlock(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                            <Field label="PEK / ZPK (hex)"><input data-testid="pvv-pek" value={pek} onChange={(e) => setPek(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                            <Field label="PIN block format">
                                <select data-testid="pvv-format-select" value={pinFormat} onChange={(e) => setPinFormat(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
                                    <option>ISO-0</option><option>ISO-1</option><option>ISO-3</option>
                                </select>
                            </Field>
                            <Field label="Algorithm">
                                <select data-testid="pvv-algo-select" value={pinAlgo} onChange={(e) => setPinAlgo(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
                                    <option>3DES</option><option>AES</option>
                                </select>
                            </Field>
                        </div>
                    )}
                </>
            )}
            <button onClick={compute} disabled={busy || (mode === "verify" && pvvIn.length !== 4)} data-testid="pvv-compute-btn" className="h-9 px-4 border border-[#002FA7] text-[#002FA7] text-xs font-semibold hover:bg-[#F3F4F6] disabled:opacity-50">
                {busy ? "Working…" : mode === "verify" ? "Verify PIN against PVV" : "Compute PVV"}
            </button>
            {mode === "verify" && <Verdict data={verdict} what="PIN / PVV" kcvLabel="PVK KCV" kcv={verdict?.pvk_kcv} testid="pvv-verdict" />}
            {mode === "generate" && res && (
                <div className="border border-[#E5E7EB] bg-[#F9FAFB] p-3 space-y-2 text-xs" data-testid="pvv-result">
                    <ResultLine label="PVV" value={res.pvv} accent testid="pvv-value" />
                    <ResultLine label="PVKI" value={res.pvki} />
                    <ResultLine label="PVK KCV" value={res.pvk_kcv} testid="pvv-kcv" />
                </div>
            )}
        </>
    );
}

// ----------------------------- ARQC -------------------------------------
function ArqcTab({ builderState, onInsertField, onClose }) {
    const [mdk, setMdk] = useState("0123456789ABCDEFFEDCBA9876543210");
    const [pan, setPan] = useState(builderState?.values?.[2] || "");
    const [psn, setPsn] = useState("00");
    const [cvn, setCvn] = useState("CVN10");
    const [atc, setAtc] = useState("0001");
    const [cdol, setCdol] = useState("");
    const [mode, setMode] = useState("generate");
    const [arqcIn, setArqcIn] = useState("");
    const [res, setRes] = useState(null);
    const [verdict, setVerdict] = useState(null);
    const [busy, setBusy] = useState(false);

    const compute = async () => {
        setBusy(true);
        try {
            const body = { mdk_hex: mdk, pan, psn, cdol_hex: cdol, cvn, atc_hex: cvn === "CVN10" ? null : atc };
            if (mode === "verify") {
                const { data } = await api.post("/keys/arqc/verify", { ...body, arqc_hex: arqcIn });
                setVerdict(data);
            } else {
                const { data } = await api.post("/keys/arqc", body);
                setRes(data);
            }
        } catch (e) { toast.error(apiErr(e)); }
        finally { setBusy(false); }
    };

    const insertF55 = () => {
        if (!res) return;
        onInsertField?.(55, res.f55_tlv_hex);
        toast.success("F55 populated with 9F26 ARQC TLV");
        onClose?.();
    };

    return (
        <>
            <p className="text-xs text-[#4B5563]">
                CVN10: ICC MK (Option A) is the MAC key, Visa zero padding.
                CVN18: ICC MK (Option B) → session key from ATC, EMV 0x80 padding; include the IAD (9F10) at the end of the CDOL data.
                AES: AES ICC MK → session key → AES-CMAC.
            </p>
            <div className="grid grid-cols-1 gap-3">
                <Field label={cvn === "AES" ? "MDK (16/24/32 bytes hex)" : "MDK (16 or 24 bytes hex)"}><input data-testid="arqc-mdk" value={mdk} onChange={(e) => setMdk(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                <div className="grid grid-cols-3 gap-3">
                    <Field label="PAN"><input data-testid="arqc-pan" value={pan} onChange={(e) => setPan(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                    <Field label="PSN"><input data-testid="arqc-psn" value={psn} maxLength={2} onChange={(e) => setPsn(e.target.value.replace(/\D/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" /></Field>
                    <Field label="CVN">
                        <select data-testid="arqc-cvn-select" value={cvn} onChange={(e) => setCvn(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
                            <option value="CVN10">Visa CVN10</option>
                            <option value="CVN18">Visa CVN18</option>
                            <option value="AES">AES</option>
                        </select>
                    </Field>
                </div>
                {cvn !== "CVN10" && (
                    <Field label="ATC (9F36, 2 bytes hex)">
                        <input data-testid="arqc-atc" value={atc} maxLength={4} onChange={(e) => setAtc(e.target.value.toUpperCase().replace(/[^0-9A-F]/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                    </Field>
                )}
                <Field label="CDOL data (hex; concatenation per CDOL1)">
                    <textarea
                        data-testid="arqc-cdol"
                        rows={3}
                        value={cdol}
                        onChange={(e) => setCdol(e.target.value.toUpperCase())}
                        placeholder="e.g. 0000000012500000000000084000000084000000000000840221250000123456000000"
                        className="w-full border border-gray-300 px-2 py-1.5 text-xs font-mono focus:border-[#002FA7]"
                    />
                </Field>
            </div>
            <ModeToggle mode={mode} setMode={(m) => { setMode(m); setVerdict(null); }} testid="arqc-mode" />
            {mode === "verify" && (
                <Field label="ARQC to verify (9F26, 8 bytes hex)">
                    <input data-testid="arqc-verify-input" value={arqcIn} maxLength={16} onChange={(e) => setArqcIn(e.target.value.toUpperCase().replace(/[^0-9A-F]/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                </Field>
            )}
            <button onClick={compute} disabled={busy || (mode === "verify" && arqcIn.length !== 16)} data-testid="arqc-compute-btn" className="h-9 px-4 border border-[#002FA7] text-[#002FA7] text-xs font-semibold hover:bg-[#F3F4F6] disabled:opacity-50">
                {busy ? "Working…" : mode === "verify" ? "Verify ARQC" : "Compute ARQC"}
            </button>
            {mode === "verify" && (
                <Verdict data={verdict} what="ARQC" kcvLabel="Session key KCV" kcv={verdict?.session_key_kcv} testid="arqc-verdict">
                    {verdict?.valid && verdict.session_key_hex && (
                        <ResultLine label="Session key (for ARPC)" value={verdict.session_key_hex} testid="arqc-verdict-sk" />
                    )}
                </Verdict>
            )}
            {mode === "generate" && res && (
                <div className="border border-[#E5E7EB] bg-[#F9FAFB] p-3 space-y-2 text-xs" data-testid="arqc-result">
                    <ResultLine label="MDK KCV"     value={res.mdk_kcv} testid="arqc-mdk-kcv" />
                    <ResultLine label="ICC MK"      value={res.icc_mk_hex} testid="arqc-icc-mk" />
                    <ResultLine label="ICC MK KCV"  value={res.icc_mk_kcv} testid="arqc-icc-kcv" />
                    {res.session_key_hex !== res.icc_mk_hex && (
                        <ResultLine label="Session key" value={res.session_key_hex} testid="arqc-sk" />
                    )}
                    <ResultLine label="ARQC"        value={res.arqc_hex} accent testid="arqc-value" />
                    <ResultLine label="F55 TLV"     value={res.f55_tlv_hex} testid="arqc-f55-tlv" />
                    <button onClick={insertF55} data-testid="arqc-insert-f55" className="h-9 px-4 bg-[#002FA7] text-white text-xs font-semibold hover:bg-[#002080] flex items-center gap-2">
                        Insert as F55 (9F26 ARQC) <ArrowRight size={12} weight="bold" />
                    </button>
                </div>
            )}
        </>
    );
}

// ----------------------------- ARPC ------------------------------------
function ArpcTab({ onInsertField, onClose }) {
    const [sk, setSk] = useState("0123456789ABCDEFFEDCBA9876543210");
    const [arqc, setArqc] = useState("");
    const [arc, setArc] = useState("3030");
    const [algo, setAlgo] = useState("3DES");
    const [method, setMethod] = useState(1);
    const [csu, setCsu] = useState("00000000");
    const [pad, setPad] = useState("");
    const [res, setRes] = useState(null);
    const [busy, setBusy] = useState(false);

    const compute = async () => {
        setBusy(true);
        try {
            const { data } = await api.post("/keys/arpc", method === 2
                ? { sk_hex: sk, arqc_hex: arqc, algorithm: "3DES", method: 2, csu_hex: csu, pad_hex: pad }
                : { sk_hex: sk, arqc_hex: arqc, arc_hex: arc, algorithm: algo, method: 1 });
            setRes(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setBusy(false); }
    };

    const insertF55 = () => {
        if (!res) return;
        onInsertField?.(55, res.f55_tlv_hex);
        toast.success(method === 2 ? "F55 populated with 91 IAD (ARPC || CSU)" : "F55 populated with 91 IAD (ARPC || ARC)");
        onClose?.();
    };

    return (
        <>
            <p className="text-xs text-[#4B5563]">
                Method 1 (Visa CVN10, M/Chip): <code className="font-mono">encrypt(SK, ARQC XOR (ARC || 00…))</code>, tag 91 = ARPC || ARC.
                Method 2 (Visa CVN18): <code className="font-mono">MAC(SK, ARQC || CSU || PAD)</code>, 4 bytes, tag 91 = ARPC || CSU || PAD.
                Paste the session key (SK_AC); the ARQC tab shows it for CVN18.
            </p>
            <div className="grid grid-cols-4 gap-3">
                <Field label="Method">
                    <select data-testid="arpc-method-select" value={method} onChange={(e) => { const m = Number(e.target.value); setMethod(m); if (m === 2) setAlgo("3DES"); }} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
                        <option value={1}>Method 1</option>
                        <option value={2}>Method 2</option>
                    </select>
                </Field>
                <Field label="Algorithm">
                    <select data-testid="arpc-algo-select" value={algo} disabled={method === 2} onChange={(e) => setAlgo(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white disabled:bg-gray-100">
                        <option value="3DES">3DES</option>
                        <option value="AES">AES</option>
                    </select>
                </Field>
                <div className="col-span-2">
                    <Field label="Session Key (SK_AC, 16/24/32 bytes hex)">
                        <input data-testid="arpc-sk" value={sk} onChange={(e) => setSk(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                    </Field>
                </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
                <Field label="ARQC (8 bytes hex for 3DES)">
                    <input data-testid="arpc-arqc" value={arqc} onChange={(e) => setArqc(e.target.value.toUpperCase())} placeholder="e.g. 1A2B3C4D5E6F7081" className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                </Field>
                {method === 1 ? (
                    <Field label="ARC (2 bytes hex; '3030' = '00' approved)">
                        <input data-testid="arpc-arc" value={arc} maxLength={4} onChange={(e) => setArc(e.target.value.toUpperCase())} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                    </Field>
                ) : (
                    <Field label="CSU (4 bytes hex, Card Status Update)">
                        <input data-testid="arpc-csu" value={csu} maxLength={8} onChange={(e) => setCsu(e.target.value.toUpperCase().replace(/[^0-9A-F]/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                    </Field>
                )}
            </div>
            {method === 2 && (
                <Field label="Proprietary Auth Data (optional, 0-8 bytes hex)">
                    <input data-testid="arpc-pad" value={pad} maxLength={16} onChange={(e) => setPad(e.target.value.toUpperCase().replace(/[^0-9A-F]/g, ""))} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                </Field>
            )}
            <button onClick={compute} disabled={busy || !arqc} data-testid="arpc-compute-btn" className="h-9 px-4 border border-[#002FA7] text-[#002FA7] text-xs font-semibold hover:bg-[#F3F4F6] disabled:opacity-50">
                {busy ? "Computing…" : "Compute ARPC"}
            </button>
            {res && (
                <div className="border border-[#E5E7EB] bg-[#F9FAFB] p-3 space-y-2 text-xs" data-testid="arpc-result">
                    <ResultLine label="ARPC"        value={res.arpc_hex}        accent testid="arpc-value" />
                    {res.arc_hex && <ResultLine label="ARC" value={res.arc_hex} testid="arpc-arc-out" />}
                    {res.csu_hex && <ResultLine label="CSU" value={res.csu_hex} testid="arpc-csu-out" />}
                    <ResultLine label="SK KCV"      value={res.session_key_kcv}        testid="arpc-sk-kcv" />
                    <ResultLine label="F55 TLV"     value={res.f55_tlv_hex}            testid="arpc-f55-tlv" />
                    <button onClick={insertF55} data-testid="arpc-insert-f55" className="h-9 px-4 bg-[#002FA7] text-white text-xs font-semibold hover:bg-[#002080] flex items-center gap-2">
                        Insert as F55 (91 IAD) <ArrowRight size={12} weight="bold" />
                    </button>
                </div>
            )}
        </>
    );
}

// ----------------------------- shared ------------------------------------
const ModeToggle = ({ mode, setMode, testid }) => (
    <div className="inline-flex border border-gray-300" data-testid={testid}>
        {["generate", "verify"].map((m) => (
            <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                data-testid={`${testid}-${m}`}
                className={`h-8 px-4 text-xs font-semibold capitalize ${mode === m ? "bg-[#002FA7] text-white" : "text-[#4B5563] hover:bg-gray-50"}`}
            >
                {m}
            </button>
        ))}
    </div>
);

const Verdict = ({ data, what, kcvLabel, kcv, testid, children }) => {
    if (!data) return null;
    const ok = data.valid === true;
    return (
        <div className={`border p-3 space-y-2 text-xs ${ok ? "border-[#16A34A] bg-[#F0FDF4]" : "border-[#E11D48] bg-[#FFF1F2]"}`} data-testid={testid}>
            <div className={`flex items-center gap-2 font-semibold ${ok ? "text-[#16A34A]" : "text-[#E11D48]"}`}>
                {ok ? <CheckCircle size={14} weight="fill" /> : <XCircle size={14} weight="fill" />}
                {what} {ok ? "verified" : "does not match"}
            </div>
            {kcv && <ResultLine label={kcvLabel} value={kcv} />}
            {children}
        </div>
    );
};

const Field = ({ label, children }) => (
    <label className="block">
        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">{label}</div>
        {children}
    </label>
);

const ResultLine = ({ label, value, accent, testid }) => {
    const copy = () => {
        navigator.clipboard?.writeText(value || "");
        toast.success(`Copied ${label}`);
    };
    return (
        <div className="grid grid-cols-12 gap-2 items-center">
            <div className="col-span-3 text-[10px] uppercase tracking-widest text-[#4B5563]">{label}</div>
            <div className={`col-span-8 break-all font-mono ${accent ? "text-[#002FA7] font-semibold text-sm" : ""}`} data-testid={testid}>{value}</div>
            <button onClick={copy} className="col-span-1 text-[#9CA3AF] hover:text-[#002FA7] p-1" title="Copy">
                <Copy size={13} />
            </button>
        </div>
    );
};
