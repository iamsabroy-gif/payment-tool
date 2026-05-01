import { useEffect, useState, useCallback, useRef } from "react";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import {
    Key, Plus, Trash, PencilSimple, X, FloppyDisk, Copy, ShieldCheck,
} from "@phosphor-icons/react";

// Live KCV computation (debounced) — calls /api/keys/kcv on the fly while typing.
function useLiveKcv(hex, algorithm = "3DES") {
    const [kcv, setKcv] = useState(null);
    const [computing, setComputing] = useState(false);
    const tref = useRef(null);
    useEffect(() => {
        if (tref.current) clearTimeout(tref.current);
        const cleaned = (hex || "").replace(/[\s-]/g, "");
        if (!cleaned) { setKcv(null); return; }
        if (!/^[0-9a-fA-F]+$/.test(cleaned) || cleaned.length % 2 !== 0 || cleaned.length < 16) {
            setKcv(null); return;
        }
        setComputing(true);
        tref.current = setTimeout(async () => {
            try {
                const { data } = await api.post("/keys/kcv", { key_hex: cleaned, algorithm });
                setKcv(data.kcv);
            } catch { setKcv(null); }
            finally { setComputing(false); }
        }, 250);
        return () => tref.current && clearTimeout(tref.current);
    }, [hex, algorithm]);
    return { kcv, computing };
}

const KCV_ALGOS = ["3DES", "AES"];

const EMPTY = {
    name: "", description: "",
    mdk_hex: "", cvk_a_hex: "", cvk_b_hex: "",
    pvk_a_hex: "", pvk_b_hex: "", pvki: "1",
    extras: {},
};

export default function KeyVault() {
    const [items, setItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [editor, setEditor] = useState(null); // { mode:'create'|'edit', keyset }

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const { data } = await api.get("/user-keys");
            setItems(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setLoading(false); }
    }, []);
    useEffect(() => { load(); }, [load]);

    const del = async (k) => {
        if (!confirm(`Delete key set "${k.name}"? This cannot be undone.`)) return;
        try {
            await api.delete(`/user-keys/${k.id}`);
            setItems((prev) => prev.filter((x) => x.id !== k.id));
            toast.success("Key set deleted");
        } catch (e) { toast.error(apiErr(e)); }
    };

    return (
        <div className="p-6 space-y-6" data-testid="keyvault-page">
            <header className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">09 · Vault</div>
                    <h1 className="text-3xl font-semibold tracking-tight mt-1">Key Vault</h1>
                    <p className="text-sm text-[#4B5563] mt-2 max-w-2xl">
                        Save EMV / VISA cryptographic keys (MDK, CVK_A/B, PVK_A/B, PVKI and any custom aliases)
                        and let the platform compute their <strong>KCV</strong> as you type — so you can spot
                        a transposed nibble before it hits a host.
                    </p>
                </div>
                <button
                    onClick={() => setEditor({ mode: "create", keyset: { ...EMPTY } })}
                    data-testid="keys-new-btn"
                    className="h-10 px-4 bg-[#002FA7] text-white text-sm font-semibold flex items-center gap-2 hover:bg-[#002080]"
                >
                    <Plus size={13} weight="bold" /> New key set
                </button>
            </header>

            {loading ? (
                <div className="text-xs uppercase tracking-widest text-gray-500">Loading…</div>
            ) : items.length === 0 ? (
                <div className="border border-[#E5E7EB] p-16 text-center" data-testid="keys-empty">
                    <Key size={28} className="text-[#9CA3AF] mx-auto" />
                    <div className="text-sm text-[#4B5563] mt-3">
                        No saved key sets yet. Click <strong>New key set</strong> to add MDK / CVK / PVK with auto-KCV.
                    </div>
                </div>
            ) : (
                <section className="grid grid-cols-1 lg:grid-cols-2 gap-4" data-testid="keys-list">
                    {items.map((k) => (
                        <KeyCard
                            key={k.id}
                            ks={k}
                            onEdit={() => setEditor({ mode: "edit", keyset: { ...EMPTY, ...k } })}
                            onDelete={() => del(k)}
                        />
                    ))}
                </section>
            )}

            {editor && (
                <KeySetEditor
                    keyset={editor.keyset}
                    mode={editor.mode}
                    onClose={() => setEditor(null)}
                    onSaved={(updated) => {
                        setItems((prev) => {
                            const ix = prev.findIndex((x) => x.id === updated.id);
                            if (ix === -1) return [updated, ...prev];
                            const next = [...prev]; next[ix] = updated; return next;
                        });
                        setEditor(null);
                        toast.success(editor.mode === "create" ? "Key set created" : "Key set updated");
                    }}
                />
            )}
        </div>
    );
}

// --------------------------------------------------------------------------
function KeyCard({ ks, onEdit, onDelete }) {
    const copy = async (label, val) => {
        if (!val) return;
        await navigator.clipboard.writeText(val);
        toast.success(`${label} copied`);
    };
    const rows = [
        { label: "MDK",   key: "mdk_hex",   kcv: ks.kcv?.MDK },
        { label: "CVK_A", key: "cvk_a_hex", kcv: ks.kcv?.CVK_A },
        { label: "CVK_B", key: "cvk_b_hex", kcv: ks.kcv?.CVK_B },
        { label: "PVK_A", key: "pvk_a_hex", kcv: ks.kcv?.PVK_A },
        { label: "PVK_B", key: "pvk_b_hex", kcv: ks.kcv?.PVK_B },
    ];
    const extras = Object.entries(ks.extras || {});

    return (
        <article className="border border-[#E5E7EB] bg-white p-5 flex flex-col" data-testid={`key-card-${ks.id}`}>
            <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                    <div className="text-[10px] uppercase tracking-widest text-[#002FA7] flex items-center gap-1">
                        <ShieldCheck size={11} weight="fill" /> Key set
                    </div>
                    <div className="text-base font-semibold mt-1 truncate">{ks.name}</div>
                    {ks.description && <div className="text-xs text-[#4B5563] mt-0.5">{ks.description}</div>}
                </div>
                <div className="flex gap-1 shrink-0">
                    <button onClick={onEdit} data-testid={`key-edit-${ks.id}`} className="h-8 px-2 border border-gray-300 text-xs hover:bg-gray-50 flex items-center gap-1"><PencilSimple size={11} /> Edit</button>
                    <button onClick={onDelete} data-testid={`key-delete-${ks.id}`} className="h-8 px-2 border border-gray-300 text-[#E11D48] hover:bg-[#FEF2F2]"><Trash size={11} /></button>
                </div>
            </div>
            <div className="mt-4 divide-y divide-[#F3F4F6] border-t border-[#F3F4F6]" data-testid={`key-rows-${ks.id}`}>
                {rows.map((r) => (
                    <div key={r.key} className="py-2 flex items-center justify-between gap-3 text-xs">
                        <span className="font-mono uppercase tracking-widest text-[#4B5563] w-16 shrink-0">{r.label}</span>
                        <span className={`font-mono truncate flex-1 ${ks[r.key] ? "text-[#111827]" : "text-[#9CA3AF]"}`}>
                            {ks[r.key] ? maskHex(ks[r.key]) : "(empty)"}
                        </span>
                        <KcvBadge kcv={r.kcv} testid={`key-kcv-${ks.id}-${r.label}`} />
                        {ks[r.key] && (
                            <button onClick={() => copy(r.label, ks[r.key])} title="Copy plain hex" className="text-[#9CA3AF] hover:text-[#002FA7] p-0.5"><Copy size={11} /></button>
                        )}
                    </div>
                ))}
                {ks.pvki && (
                    <div className="py-2 flex items-center justify-between gap-3 text-xs">
                        <span className="font-mono uppercase tracking-widest text-[#4B5563] w-16 shrink-0">PVKI</span>
                        <span className="font-mono text-[#111827] flex-1">{ks.pvki}</span>
                        <span className="w-16" />
                    </div>
                )}
                {extras.map(([alias, val]) => (
                    <div key={alias} className="py-2 flex items-center justify-between gap-3 text-xs">
                        <span className="font-mono uppercase tracking-widest text-[#4B5563] w-16 shrink-0">{alias}</span>
                        <span className={`font-mono truncate flex-1 ${val ? "text-[#111827]" : "text-[#9CA3AF]"}`}>{val ? maskHex(val) : "(empty)"}</span>
                        <KcvBadge kcv={ks.extras_kcv?.[alias]} testid={`key-kcv-${ks.id}-${alias}`} />
                        {val && <button onClick={() => copy(alias, val)} className="text-[#9CA3AF] hover:text-[#002FA7] p-0.5"><Copy size={11} /></button>}
                    </div>
                ))}
            </div>
        </article>
    );
}

const maskHex = (h) => {
    if (!h) return "";
    if (h.length <= 8) return h;
    return `${h.slice(0, 4)}…${h.slice(-4)}  ·  ${h.length / 2}B`;
};

function KcvBadge({ kcv, testid }) {
    return (
        <span
            data-testid={testid}
            className={`inline-flex items-center justify-center font-mono text-[10px] tracking-widest px-2 h-6 ${kcv ? "bg-[#111827] text-[#22C55E]" : "bg-[#F3F4F6] text-[#9CA3AF]"}`}
            style={{ minWidth: 84 }}
        >
            KCV {kcv || "······"}
        </span>
    );
}

// --------------------------------------------------------------------------
function KeySetEditor({ keyset, mode, onClose, onSaved }) {
    const [form, setForm] = useState(() => ({ ...EMPTY, ...keyset, extras: { ...(keyset.extras || {}) } }));
    const [saving, setSaving] = useState(false);
    const [newAlias, setNewAlias] = useState("");

    const save = async () => {
        if (!form.name.trim()) { toast.error("Name is required"); return; }
        setSaving(true);
        try {
            const url = mode === "create" ? "/user-keys" : `/user-keys/${keyset.id}`;
            const { data } = await api({
                method: mode === "create" ? "POST" : "PUT",
                url,
                data: form,
            });
            onSaved(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setSaving(false); }
    };

    const addExtra = () => {
        const a = newAlias.trim().toUpperCase().replace(/[^A-Z0-9_]/g, "_");
        if (!a) { toast.error("Alias required"); return; }
        if (form.extras[a] !== undefined) { toast.error("Alias already exists"); return; }
        setForm({ ...form, extras: { ...form.extras, [a]: "" } });
        setNewAlias("");
    };
    const removeExtra = (a) => {
        const next = { ...form.extras }; delete next[a];
        setForm({ ...form, extras: next });
    };

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose} data-testid="keyset-editor-modal">
            <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-3xl border border-[#E5E7EB] shadow-xl flex flex-col max-h-[92vh]">
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">Key set editor</div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">{mode === "create" ? "New key set" : `Edit ${keyset.name}`}</h2>
                    </div>
                    <button onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1"><X size={16} /></button>
                </div>

                <div className="px-6 py-5 space-y-5 overflow-y-auto flex-1">
                    <div className="grid grid-cols-12 gap-3">
                        <Field label="Name" cls="col-span-12 md:col-span-6">
                            <input data-testid="keyset-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="VISA Production" className="w-full h-9 border border-gray-300 px-2 text-sm" />
                        </Field>
                        <Field label="Description" cls="col-span-12 md:col-span-6">
                            <input data-testid="keyset-description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Optional notes" className="w-full h-9 border border-gray-300 px-2 text-sm" />
                        </Field>
                    </div>

                    <KeyInput
                        label="MDK — Issuer Master Derivation Key (EMV)"
                        hint="32 hex (16 bytes) for double-length TDES MDK. Used to derive the ICC Application Master Key (Option A) for ARQC validation. Try sandbox /iso8583/derive_icc_mk."
                        value={form.mdk_hex}
                        algorithm="3DES"
                        onChange={(v) => setForm({ ...form, mdk_hex: v })}
                        testid="keyset-mdk"
                    />

                    <div className="grid grid-cols-2 gap-4">
                        <KeyInput
                            label="CVK_A — VISA CVV/CVC1 Key A"
                            hint="16 hex (8 bytes single-DES half)"
                            value={form.cvk_a_hex}
                            onChange={(v) => setForm({ ...form, cvk_a_hex: v })}
                            testid="keyset-cvka"
                        />
                        <KeyInput
                            label="CVK_B — VISA CVV/CVC1 Key B"
                            hint="16 hex (8 bytes single-DES half)"
                            value={form.cvk_b_hex}
                            onChange={(v) => setForm({ ...form, cvk_b_hex: v })}
                            testid="keyset-cvkb"
                        />
                    </div>

                    <div className="grid grid-cols-12 gap-4">
                        <div className="col-span-12 md:col-span-5">
                            <KeyInput
                                label="PVK_A — VISA PVV Key A"
                                hint="16 hex"
                                value={form.pvk_a_hex}
                                onChange={(v) => setForm({ ...form, pvk_a_hex: v })}
                                testid="keyset-pvka"
                            />
                        </div>
                        <div className="col-span-12 md:col-span-5">
                            <KeyInput
                                label="PVK_B — VISA PVV Key B"
                                hint="16 hex"
                                value={form.pvk_b_hex}
                                onChange={(v) => setForm({ ...form, pvk_b_hex: v })}
                                testid="keyset-pvkb"
                            />
                        </div>
                        <div className="col-span-12 md:col-span-2">
                            <Field label="PVKI" hint="PVV Key Indicator (1 digit)">
                                <input
                                    data-testid="keyset-pvki"
                                    value={form.pvki}
                                    onChange={(e) => setForm({ ...form, pvki: e.target.value.replace(/\D/g, "").slice(0, 1) })}
                                    maxLength={1}
                                    className="w-full h-9 border border-gray-300 px-2 text-sm font-mono"
                                />
                            </Field>
                        </div>
                    </div>

                    {/* Extras */}
                    <div>
                        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-2">Custom keys (ZPK / TMK / ZMK / etc.)</div>
                        <div className="space-y-2" data-testid="keyset-extras">
                            {Object.entries(form.extras).map(([alias, val]) => (
                                <div key={alias} className="grid grid-cols-12 gap-2 items-end">
                                    <div className="col-span-3 font-mono text-xs uppercase text-[#4B5563] pb-2">{alias}</div>
                                    <div className="col-span-8">
                                        <KeyInput
                                            label={null}
                                            hint=""
                                            value={val}
                                            onChange={(v) => setForm({ ...form, extras: { ...form.extras, [alias]: v } })}
                                            testid={`keyset-extra-${alias}`}
                                            placeholder="hex (8/16/24/32 bytes)"
                                        />
                                    </div>
                                    <button onClick={() => removeExtra(alias)} className="col-span-1 h-9 text-[#9CA3AF] hover:text-[#E11D48] flex items-center justify-center" data-testid={`keyset-extra-remove-${alias}`}><Trash size={12} /></button>
                                </div>
                            ))}
                        </div>
                        <div className="mt-2 flex items-center gap-2">
                            <input
                                value={newAlias}
                                onChange={(e) => setNewAlias(e.target.value)}
                                placeholder="Alias (e.g. ZPK)"
                                data-testid="keyset-extra-alias-input"
                                className="h-9 border border-gray-300 px-2 text-sm font-mono w-48 uppercase"
                            />
                            <button onClick={addExtra} data-testid="keyset-extra-add-btn" className="h-9 px-3 border border-[#002FA7] text-[#002FA7] text-xs font-medium hover:bg-[#F3F4F6] flex items-center gap-1">
                                <Plus size={12} /> Add custom key
                            </button>
                        </div>
                    </div>
                </div>

                <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3">
                    <button onClick={onClose} disabled={saving} className="flex-1 h-10 border border-gray-300 bg-white text-sm">Cancel</button>
                    <button onClick={save} disabled={saving} data-testid="keyset-save-btn" className="flex-[2] h-10 bg-[#002FA7] text-white text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#002080] disabled:opacity-50">
                        <FloppyDisk size={14} weight="bold" /> {saving ? "Saving…" : (mode === "create" ? "Create key set" : "Save changes")}
                    </button>
                </div>
            </div>
        </div>
    );
}

// --------------------------------------------------------------------------
function KeyInput({ label, hint, value, onChange, algorithm = "3DES", testid, placeholder }) {
    const { kcv } = useLiveKcv(value, algorithm);
    return (
        <div>
            {label !== null && (
                <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">{label}</div>
            )}
            <div className="relative">
                <input
                    data-testid={testid}
                    value={value || ""}
                    onChange={(e) => onChange(e.target.value.toUpperCase().replace(/[^0-9A-F]/g, ""))}
                    placeholder={placeholder || "32 hex (16 bytes) for double-length TDES MDK"}
                    className="w-full h-12 border border-gray-300 pl-3 pr-32 text-sm font-mono focus:border-[#002FA7]"
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2">
                    <KcvBadge kcv={kcv} testid={testid && `${testid}-kcv`} />
                </div>
            </div>
            {hint && <div className="text-[10px] text-[#9CA3AF] mt-1">{hint}</div>}
        </div>
    );
}

const Field = ({ label, hint, cls = "", children }) => (
    <label className={`block ${cls}`}>
        {label && <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">{label}</div>}
        {children}
        {hint && <div className="text-[10px] text-[#9CA3AF] mt-0.5">{hint}</div>}
    </label>
);
