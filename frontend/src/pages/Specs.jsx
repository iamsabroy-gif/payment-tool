import { useEffect, useState, useCallback } from "react";
import { api, apiErr, API_BASE } from "../lib/api";
import { toast } from "sonner";
import {
    BookOpen, Trash, PencilSimple, FloppyDisk, Plus, X, Upload,
    DownloadSimple, FileText, Code,
} from "@phosphor-icons/react";

const FORMATS = ["n", "an", "ans", "b", "z"];
const LENGTH_TYPES = ["fixed", "LLVAR", "LLLVAR"];
const AN_CHARSETS = ["ascii", "ebcdic"];
const LEN_PREFIX_ENCS = ["ascii", "bcd"];
const BITMAP_ENCS = ["ascii_hex", "binary"];
const MTI_ENCS = ["ascii", "bcd"];

const EMPTY_FIELD = { name: "", format: "ans", length_type: "fixed", max_length: 0 };

export default function Specs() {
    const [items, setItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [editor, setEditor] = useState(null);   // null | { mode: 'create' | 'edit', spec }
    const [importer, setImporter] = useState(false);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const { data } = await api.get("/user-specs");
            setItems(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setLoading(false); }
    }, []);
    useEffect(() => { load(); }, [load]);

    const del = async (s) => {
        if (!confirm(`Delete spec "${s.name}"? Templates that reference it will keep their data but lose validation.`)) return;
        try {
            await api.delete(`/user-specs/${s.id}`);
            setItems((prev) => prev.filter((x) => x.id !== s.id));
            toast.success("Spec deleted");
        } catch (e) { toast.error(apiErr(e)); }
    };

    return (
        <div className="p-6 space-y-6" data-testid="specs-page">
            <header className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">08 · Spec library</div>
                    <h1 className="text-3xl font-semibold tracking-tight mt-1">Custom Network Specs</h1>
                    <p className="text-sm text-[#4B5563] mt-2 max-w-2xl">
                        Drop your own ISO-8583 dialect — per-field encoding, length type, max length, and which
                        DEs are mandatory per MTI. The Builder uses these hints to flag missing required fields,
                        validate values inline, and encode the message correctly when you Send.
                    </p>
                </div>
                <div className="flex gap-2">
                    <a
                        href={`${API_BASE}/user-specs/template`}
                        data-testid="specs-download-template"
                        className="h-10 px-4 border border-gray-300 text-sm flex items-center gap-2 hover:bg-gray-50"
                    >
                        <DownloadSimple size={13} /> CSV template
                    </a>
                    <button
                        onClick={() => setImporter(true)}
                        data-testid="specs-import-btn"
                        className="h-10 px-4 border border-[#002FA7] text-[#002FA7] text-sm font-semibold flex items-center gap-2 hover:bg-[#F3F4F6]"
                    >
                        <Upload size={13} weight="bold" /> Import
                    </button>
                    <button
                        onClick={() => setEditor({ mode: "create", spec: blankSpec() })}
                        data-testid="specs-new-btn"
                        className="h-10 px-4 bg-[#002FA7] text-white text-sm font-semibold flex items-center gap-2 hover:bg-[#002080]"
                    >
                        <Plus size={13} weight="bold" /> New spec
                    </button>
                </div>
            </header>

            {loading ? (
                <div className="text-xs uppercase tracking-widest text-gray-500">Loading…</div>
            ) : items.length === 0 ? (
                <div className="border border-[#E5E7EB] p-16 text-center">
                    <BookOpen size={28} className="text-[#9CA3AF] mx-auto" />
                    <div className="text-sm text-[#4B5563] mt-3">No custom specs yet. <strong>Import</strong> a CSV / JSON or create one from scratch.</div>
                </div>
            ) : (
                <section className="border border-[#E5E7EB] divide-y divide-[#E5E7EB]" data-testid="specs-list">
                    {items.map((s) => {
                        const fcount = Object.keys(s.fields || {}).length;
                        const mtis = Object.keys(s.mandatory_per_mti || {});
                        return (
                            <article key={s.id} className="p-5 grid grid-cols-12 gap-4 items-start" data-testid={`spec-row-${s.id}`}>
                                <div className="col-span-12 md:col-span-5">
                                    <div className="text-base font-medium">{s.name}</div>
                                    <div className="text-[10px] font-mono text-[#002FA7] mt-0.5">{s.network_id}</div>
                                    {s.description && <div className="text-xs text-[#4B5563] mt-1">{s.description}</div>}
                                </div>
                                <div className="col-span-12 md:col-span-4 text-[10px] uppercase tracking-widest text-[#4B5563] flex flex-wrap gap-1">
                                    <span className="border border-gray-300 px-1.5 py-0.5">MTI {s.mti_encoding}</span>
                                    <span className="border border-gray-300 px-1.5 py-0.5">Bitmap {s.bitmap_encoding}</span>
                                    <span className="border border-gray-300 px-1.5 py-0.5">an {s.default_an_charset}</span>
                                    <span className="border border-gray-300 px-1.5 py-0.5">L {s.length_prefix_encoding}</span>
                                    <span className="border border-[#002FA7] text-[#002FA7] px-1.5 py-0.5">{fcount} field{fcount === 1 ? "" : "s"}</span>
                                    {mtis.length > 0 && <span className="border border-[#16A34A] text-[#16A34A] px-1.5 py-0.5">{mtis.length} mandatory MTI{mtis.length === 1 ? "" : "s"}</span>}
                                </div>
                                <div className="col-span-12 md:col-span-3 flex justify-end gap-2 flex-wrap">
                                    <button onClick={() => setEditor({ mode: "edit", spec: s })} data-testid={`spec-edit-${s.id}`} className="h-9 px-3 border border-gray-300 text-xs hover:bg-gray-50 flex items-center gap-1">
                                        <PencilSimple size={12} /> Edit
                                    </button>
                                    <button onClick={() => del(s)} data-testid={`spec-delete-${s.id}`} className="h-9 px-2 border border-gray-300 text-[#E11D48] hover:bg-[#FEF2F2]">
                                        <Trash size={12} />
                                    </button>
                                </div>
                            </article>
                        );
                    })}
                </section>
            )}

            {editor && (
                <SpecEditor
                    spec={editor.spec}
                    mode={editor.mode}
                    onClose={() => setEditor(null)}
                    onSaved={(updated) => {
                        setItems((prev) => {
                            const ix = prev.findIndex((x) => x.id === updated.id);
                            if (ix === -1) return [updated, ...prev];
                            const next = [...prev]; next[ix] = updated; return next;
                        });
                        setEditor(null);
                        toast.success(editor.mode === "create" ? "Spec created" : "Spec updated");
                    }}
                />
            )}
            {importer && (
                <ImportModal
                    onClose={() => setImporter(false)}
                    onImported={(created) => {
                        setItems((prev) => [created, ...prev]);
                        setImporter(false);
                        toast.success(`Imported "${created.name}"`);
                    }}
                />
            )}
        </div>
    );
}

const blankSpec = () => ({
    network_id: "",
    name: "",
    description: "",
    mti_encoding: "ascii",
    bitmap_encoding: "ascii_hex",
    default_an_charset: "ascii",
    length_prefix_encoding: "ascii",
    fields: {},
    mandatory_per_mti: {},
});

// ----------------------------- Editor ---------------------------------------
function SpecEditor({ spec, mode, onClose, onSaved }) {
    const [form, setForm] = useState(() => ({ ...blankSpec(), ...spec }));
    const [saving, setSaving] = useState(false);
    const [tab, setTab] = useState("fields");
    const [newFieldNum, setNewFieldNum] = useState("");
    const [newMti, setNewMti] = useState("");

    const fieldNums = Object.keys(form.fields || {}).map(Number).sort((a, b) => a - b);

    const addField = () => {
        const n = parseInt(newFieldNum, 10);
        if (!n || n < 1 || n > 128) { toast.error("Field number must be 1–128"); return; }
        if (form.fields[n]) { toast.error("Field already in spec"); return; }
        setForm({ ...form, fields: { ...form.fields, [n]: { ...EMPTY_FIELD } } });
        setNewFieldNum("");
    };
    const updateField = (f, patch) => {
        setForm({ ...form, fields: { ...form.fields, [f]: { ...form.fields[f], ...patch } } });
    };
    const removeField = (f) => {
        const next = { ...form.fields }; delete next[f];
        // also remove from any mandatory list
        const nm = {};
        for (const [mti, list] of Object.entries(form.mandatory_per_mti || {})) {
            const filtered = list.filter((x) => x !== f);
            if (filtered.length) nm[mti] = filtered;
        }
        setForm({ ...form, fields: next, mandatory_per_mti: nm });
    };

    const addMti = () => {
        const m = (newMti || "").trim();
        if (!/^\d{4}$/.test(m)) { toast.error("MTI must be 4 digits"); return; }
        if (form.mandatory_per_mti[m]) { toast.error("MTI already exists"); return; }
        setForm({ ...form, mandatory_per_mti: { ...form.mandatory_per_mti, [m]: [] } });
        setNewMti("");
    };
    const toggleMandatory = (mti, fnum) => {
        const list = form.mandatory_per_mti[mti] || [];
        const next = list.includes(fnum) ? list.filter((x) => x !== fnum) : [...list, fnum];
        setForm({ ...form, mandatory_per_mti: { ...form.mandatory_per_mti, [mti]: next.sort((a, b) => a - b) } });
    };
    const removeMti = (mti) => {
        const nm = { ...form.mandatory_per_mti }; delete nm[mti];
        setForm({ ...form, mandatory_per_mti: nm });
    };

    const save = async () => {
        if (!form.name.trim()) { toast.error("Name is required"); return; }
        if (!form.network_id.trim()) { toast.error("Network ID is required"); return; }
        if (fieldNums.length === 0) { toast.error("Add at least one field"); return; }
        const payload = {
            ...form,
            fields: Object.fromEntries(
                Object.entries(form.fields).map(([k, v]) => [k, { ...v, max_length: Number(v.max_length) || 0 }])
            ),
        };
        setSaving(true);
        try {
            const url = mode === "create" ? "/user-specs" : `/user-specs/${spec.id}`;
            const { data } = await api({ method: mode === "create" ? "POST" : "PUT", url, data: payload });
            onSaved(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setSaving(false); }
    };

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose} data-testid="spec-editor-modal">
            <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-4xl border border-[#E5E7EB] shadow-xl flex flex-col max-h-[92vh]">
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">Spec editor</div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">{mode === "create" ? "New custom spec" : `Edit ${spec.name}`}</h2>
                    </div>
                    <button onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1"><X size={16} /></button>
                </div>

                {/* Header form */}
                <div className="px-6 py-4 border-b border-[#E5E7EB] grid grid-cols-12 gap-3">
                    <Field label="Network ID (slug)" hint="will be saved as user:&lt;slug&gt;" cls="col-span-12 md:col-span-4">
                        <input data-testid="spec-network-id" value={form.network_id} disabled={mode === "edit"} onChange={(e) => setForm({ ...form, network_id: e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, "") })} placeholder="acme-bank" className="w-full h-9 border border-gray-300 px-2 text-sm font-mono disabled:bg-gray-100" />
                    </Field>
                    <Field label="Name" cls="col-span-12 md:col-span-5">
                        <input data-testid="spec-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="ACME Bank Sandbox" className="w-full h-9 border border-gray-300 px-2 text-sm" />
                    </Field>
                    <Field label="Description" cls="col-span-12 md:col-span-3">
                        <input data-testid="spec-description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="w-full h-9 border border-gray-300 px-2 text-sm" />
                    </Field>
                    <SelectField label="MTI encoding" value={form.mti_encoding} options={MTI_ENCS} onChange={(v) => setForm({ ...form, mti_encoding: v })} testid="spec-mti-enc" />
                    <SelectField label="Bitmap encoding" value={form.bitmap_encoding} options={BITMAP_ENCS} onChange={(v) => setForm({ ...form, bitmap_encoding: v })} testid="spec-bitmap-enc" />
                    <SelectField label="AN charset" value={form.default_an_charset} options={AN_CHARSETS} onChange={(v) => setForm({ ...form, default_an_charset: v })} testid="spec-an-charset" />
                    <SelectField label="Length prefix" value={form.length_prefix_encoding} options={LEN_PREFIX_ENCS} onChange={(v) => setForm({ ...form, length_prefix_encoding: v })} testid="spec-len-prefix" />
                </div>

                {/* Tabs */}
                <div className="flex border-b border-[#E5E7EB]">
                    <TabBtn active={tab === "fields"} onClick={() => setTab("fields")} testid="spec-tab-fields">Fields ({fieldNums.length})</TabBtn>
                    <TabBtn active={tab === "mandatory"} onClick={() => setTab("mandatory")} testid="spec-tab-mandatory">Mandatory per MTI ({Object.keys(form.mandatory_per_mti).length})</TabBtn>
                </div>

                <div className="overflow-y-auto flex-1 px-6 py-4">
                    {tab === "fields" ? (
                        <>
                            <div className="flex items-center gap-2 mb-3">
                                <input
                                    data-testid="spec-new-field-num"
                                    type="number" min={1} max={128}
                                    value={newFieldNum} onChange={(e) => setNewFieldNum(e.target.value)}
                                    placeholder="DE #"
                                    className="w-24 h-9 border border-gray-300 px-2 text-sm font-mono"
                                />
                                <button onClick={addField} data-testid="spec-add-field" className="h-9 px-3 border border-[#002FA7] text-[#002FA7] text-xs font-medium hover:bg-[#F3F4F6] flex items-center gap-1">
                                    <Plus size={12} /> Add field
                                </button>
                            </div>
                            <div className="border border-[#E5E7EB] divide-y divide-[#E5E7EB]" data-testid="spec-fields-list">
                                {fieldNums.length === 0 && <div className="p-6 text-center text-sm text-[#9CA3AF]">No fields yet — add at least one above.</div>}
                                {fieldNums.map((f) => (
                                    <div key={f} className="grid grid-cols-12 gap-2 px-3 py-2 items-center" data-testid={`spec-field-row-${f}`}>
                                        <div className="col-span-1 font-mono text-sm text-[#002FA7]">{String(f).padStart(3, "0")}</div>
                                        <input value={form.fields[f].name} onChange={(e) => updateField(f, { name: e.target.value })} className="col-span-4 h-9 border border-gray-300 px-2 text-sm" placeholder="Name" data-testid={`spec-field-name-${f}`} />
                                        <select value={form.fields[f].format} onChange={(e) => updateField(f, { format: e.target.value })} className="col-span-2 h-9 border border-gray-300 px-2 text-sm bg-white" data-testid={`spec-field-format-${f}`}>
                                            {FORMATS.map((x) => <option key={x} value={x}>{x}</option>)}
                                        </select>
                                        <select value={form.fields[f].length_type} onChange={(e) => updateField(f, { length_type: e.target.value })} className="col-span-2 h-9 border border-gray-300 px-2 text-sm bg-white" data-testid={`spec-field-ltype-${f}`}>
                                            {LENGTH_TYPES.map((x) => <option key={x} value={x}>{x}</option>)}
                                        </select>
                                        <input type="number" min={1} max={999} value={form.fields[f].max_length} onChange={(e) => updateField(f, { max_length: e.target.value })} className="col-span-2 h-9 border border-gray-300 px-2 text-sm font-mono" placeholder="max" data-testid={`spec-field-max-${f}`} />
                                        <button onClick={() => removeField(f)} className="col-span-1 text-[#9CA3AF] hover:text-[#E11D48] p-1" data-testid={`spec-field-remove-${f}`}><Trash size={12} /></button>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <>
                            <div className="flex items-center gap-2 mb-3">
                                <input
                                    data-testid="spec-new-mti"
                                    value={newMti} maxLength={4}
                                    onChange={(e) => setNewMti(e.target.value.replace(/\D/g, ""))}
                                    placeholder="MTI (e.g. 0200)"
                                    className="w-32 h-9 border border-gray-300 px-2 text-sm font-mono"
                                />
                                <button onClick={addMti} data-testid="spec-add-mti" className="h-9 px-3 border border-[#002FA7] text-[#002FA7] text-xs font-medium hover:bg-[#F3F4F6] flex items-center gap-1">
                                    <Plus size={12} /> Add MTI
                                </button>
                                {fieldNums.length === 0 && <span className="text-[11px] text-[#9CA3AF]">Define some fields first.</span>}
                            </div>
                            <div className="space-y-3" data-testid="spec-mti-list">
                                {Object.entries(form.mandatory_per_mti).map(([mti, list]) => (
                                    <div key={mti} className="border border-[#E5E7EB] p-3" data-testid={`spec-mti-${mti}`}>
                                        <div className="flex items-center justify-between mb-2">
                                            <div className="text-sm font-mono font-semibold">{mti}</div>
                                            <button onClick={() => removeMti(mti)} className="text-[#9CA3AF] hover:text-[#E11D48] p-1"><Trash size={12} /></button>
                                        </div>
                                        <div className="flex flex-wrap gap-1">
                                            {fieldNums.map((f) => {
                                                const on = list.includes(f);
                                                return (
                                                    <button
                                                        key={f}
                                                        onClick={() => toggleMandatory(mti, f)}
                                                        data-testid={`spec-mti-${mti}-de-${f}`}
                                                        className={`text-[10px] font-mono px-2 py-0.5 border ${on ? "border-[#E11D48] bg-[#FEF2F2] text-[#E11D48]" : "border-gray-300 text-[#4B5563] hover:bg-gray-50"}`}
                                                    >
                                                        {String(f).padStart(3, "0")}{on ? " ✓" : ""}
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </>
                    )}
                </div>

                <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3">
                    <button onClick={onClose} className="flex-1 h-10 border border-gray-300 bg-white text-sm">Cancel</button>
                    <button onClick={save} disabled={saving} data-testid="spec-save-btn" className="flex-[2] h-10 bg-[#002FA7] text-white text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#002080] disabled:opacity-50">
                        <FloppyDisk size={14} weight="bold" /> {saving ? "Saving…" : (mode === "create" ? "Create spec" : "Save changes")}
                    </button>
                </div>
            </div>
        </div>
    );
}

// ----------------------------- Importer -------------------------------------
function ImportModal({ onClose, onImported }) {
    const [tab, setTab] = useState("csv");
    const [networkId, setNetworkId] = useState("");
    const [name, setName] = useState("");
    const [description, setDescription] = useState("");
    const [mtiEnc, setMtiEnc] = useState("ascii");
    const [bitmapEnc, setBitmapEnc] = useState("ascii_hex");
    const [anCharset, setAnCharset] = useState("ascii");
    const [lenPrefixEnc, setLenPrefixEnc] = useState("ascii");
    const [csvText, setCsvText] = useState("");
    const [jsonText, setJsonText] = useState("");
    const [submitting, setSubmitting] = useState(false);

    const onFile = async (e, mode) => {
        const file = e.target.files?.[0];
        if (!file) return;
        const text = await file.text();
        if (mode === "csv") setCsvText(text); else setJsonText(text);
        if (!name) setName(file.name.replace(/\.(csv|json)$/i, ""));
        toast.success(`Loaded ${file.name}`);
    };

    const submit = async () => {
        if (!networkId.trim() || !name.trim()) { toast.error("network_id and name are required"); return; }
        setSubmitting(true);
        try {
            const body = {
                network_id: networkId.trim(),
                name: name.trim(),
                description,
                mti_encoding: mtiEnc,
                bitmap_encoding: bitmapEnc,
                default_an_charset: anCharset,
                length_prefix_encoding: lenPrefixEnc,
            };
            if (tab === "csv") {
                if (!csvText.trim()) { toast.error("CSV body is empty"); setSubmitting(false); return; }
                body.csv_text = csvText;
            } else {
                if (!jsonText.trim()) { toast.error("JSON body is empty"); setSubmitting(false); return; }
                try { body.payload = JSON.parse(jsonText); }
                catch (e) { toast.error("JSON parse error: " + e.message); setSubmitting(false); return; }
            }
            const { data } = await api.post("/user-specs/import", body);
            onImported(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setSubmitting(false); }
    };

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose} data-testid="spec-import-modal">
            <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-2xl border border-[#E5E7EB] shadow-xl flex flex-col max-h-[92vh]">
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">Import spec</div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">Upload CSV or JSON</h2>
                    </div>
                    <button onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1"><X size={16} /></button>
                </div>

                <div className="px-6 py-4 grid grid-cols-12 gap-3 border-b border-[#E5E7EB]">
                    <Field label="Network ID (slug)" cls="col-span-12 md:col-span-4">
                        <input data-testid="import-network-id" value={networkId} onChange={(e) => setNetworkId(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, ""))} placeholder="acme-bank" className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                    </Field>
                    <Field label="Display name" cls="col-span-12 md:col-span-4">
                        <input data-testid="import-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ACME Bank Sandbox" className="w-full h-9 border border-gray-300 px-2 text-sm" />
                    </Field>
                    <Field label="Description" cls="col-span-12 md:col-span-4">
                        <input data-testid="import-description" value={description} onChange={(e) => setDescription(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm" />
                    </Field>
                    <SelectField label="MTI encoding" value={mtiEnc} options={MTI_ENCS} onChange={setMtiEnc} testid="import-mti-enc" />
                    <SelectField label="Bitmap encoding" value={bitmapEnc} options={BITMAP_ENCS} onChange={setBitmapEnc} testid="import-bitmap-enc" />
                    <SelectField label="AN charset" value={anCharset} options={AN_CHARSETS} onChange={setAnCharset} testid="import-an-charset" />
                    <SelectField label="Length prefix" value={lenPrefixEnc} options={LEN_PREFIX_ENCS} onChange={setLenPrefixEnc} testid="import-len-prefix" />
                </div>

                <div className="flex border-b border-[#E5E7EB]">
                    <TabBtn active={tab === "csv"} onClick={() => setTab("csv")} testid="import-tab-csv"><FileText size={12} className="inline mr-1" /> CSV</TabBtn>
                    <TabBtn active={tab === "json"} onClick={() => setTab("json")} testid="import-tab-json"><Code size={12} className="inline mr-1" /> JSON</TabBtn>
                </div>

                <div className="px-6 py-4 overflow-y-auto flex-1 space-y-3">
                    <input type="file" accept={tab === "csv" ? ".csv" : ".json"} onChange={(e) => onFile(e, tab)} data-testid={`import-file-${tab}`} className="text-xs" />
                    {tab === "csv" ? (
                        <>
                            <div className="text-[11px] text-[#4B5563]">
                                Expected header: <code className="font-mono">field,name,format,length_type,max_length,encoding,length_encoding</code>.
                                Get a starter from the <strong>CSV template</strong> button on the page header.
                            </div>
                            <textarea
                                data-testid="import-csv-text"
                                value={csvText}
                                onChange={(e) => setCsvText(e.target.value)}
                                rows={12}
                                placeholder="field,name,format,length_type,max_length,encoding,length_encoding
2,PAN,n,LLVAR,19,ascii,ascii
..."
                                className="w-full border border-gray-300 px-2 py-1.5 text-[11px] font-mono"
                            />
                        </>
                    ) : (
                        <>
                            <div className="text-[11px] text-[#4B5563]">
                                Same shape returned by <code className="font-mono">GET /api/user-specs/&lt;id&gt;</code>: optional encoding fields, plus
                                <code className="font-mono"> fields: {`{"<num>": {name, format, length_type, max_length}}`}</code> and
                                <code className="font-mono"> mandatory_per_mti: {`{"0200": [...]}`}</code>.
                            </div>
                            <textarea
                                data-testid="import-json-text"
                                value={jsonText}
                                onChange={(e) => setJsonText(e.target.value)}
                                rows={12}
                                placeholder='{"fields": {"2": {"name":"PAN","format":"n","length_type":"LLVAR","max_length":19}}}'
                                className="w-full border border-gray-300 px-2 py-1.5 text-[11px] font-mono"
                            />
                        </>
                    )}
                </div>

                <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3">
                    <button onClick={onClose} className="flex-1 h-10 border border-gray-300 bg-white text-sm">Cancel</button>
                    <button onClick={submit} disabled={submitting} data-testid="import-submit" className="flex-[2] h-10 bg-[#002FA7] text-white text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#002080] disabled:opacity-50">
                        <Upload size={14} weight="bold" /> {submitting ? "Importing…" : "Import spec"}
                    </button>
                </div>
            </div>
        </div>
    );
}

// ----------------------------- shared ---------------------------------------
const Field = ({ label, hint, cls = "", children }) => (
    <label className={`block ${cls}`}>
        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">{label}</div>
        {children}
        {hint && <div className="text-[10px] text-[#9CA3AF] mt-0.5">{hint}</div>}
    </label>
);

const SelectField = ({ label, value, options, onChange, testid }) => (
    <Field label={label} cls="col-span-6 md:col-span-3">
        <select value={value} onChange={(e) => onChange(e.target.value)} data-testid={testid} className="w-full h-9 border border-gray-300 px-2 text-sm bg-white">
            {options.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
    </Field>
);

const TabBtn = ({ active, onClick, testid, children }) => (
    <button
        onClick={onClick}
        data-testid={testid}
        className={`flex-1 h-10 text-xs font-medium tracking-wide transition-colors border-b-2 ${active ? "border-[#002FA7] text-[#002FA7] bg-[#F3F4F6]" : "border-transparent text-[#4B5563] hover:bg-gray-50"}`}
    >
        {children}
    </button>
);
