import { useEffect, useState } from "react";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import { Plug, Trash, PencilSimple, Plus, LockKey, LockKeyOpen, FloppyDisk } from "@phosphor-icons/react";

const LENGTH_HEADERS = [
    { value: "2_byte", label: "2-byte big-endian", help: "Most common (ISO8583 over TCP)" },
    { value: "4_byte", label: "4-byte big-endian", help: "Some legacy hosts" },
    { value: "ascii_4", label: "ASCII 4-digit", help: "e.g. '0128' then payload" },
    { value: "none", label: "None (raw stream)", help: "Server closes socket to end message" },
];

const EMPTY = {
    name: "",
    host: "",
    port: 8583,
    length_header: "2_byte",
    use_tls: false,
    timeout_sec: 10,
    description: "",
};

export default function Connections() {
    const [items, setItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [editing, setEditing] = useState(null); // null | {...} | "new"
    const [form, setForm] = useState(EMPTY);
    const [saving, setSaving] = useState(false);

    const load = () => {
        setLoading(true);
        api.get("/connections").then((r) => setItems(r.data)).finally(() => setLoading(false));
    };
    useEffect(load, []);

    const openNew = () => { setEditing("new"); setForm(EMPTY); };
    const openEdit = (c) => { setEditing(c); setForm({ ...c }); };
    const close = () => { setEditing(null); setForm(EMPTY); };

    const save = async (e) => {
        e.preventDefault();
        setSaving(true);
        try {
            const payload = { ...form, port: Number(form.port), timeout_sec: Number(form.timeout_sec) };
            if (editing === "new") {
                const { data } = await api.post("/connections", payload);
                setItems((prev) => [data, ...prev]);
                toast.success("Connection profile created");
            } else {
                const { data } = await api.put(`/connections/${editing.id}`, payload);
                setItems((prev) => prev.map((x) => (x.id === data.id ? data : x)));
                toast.success("Connection profile updated");
            }
            close();
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setSaving(false);
        }
    };

    const del = async (c) => {
        if (!confirm(`Delete "${c.name}"?`)) return;
        try {
            await api.delete(`/connections/${c.id}`);
            setItems((prev) => prev.filter((x) => x.id !== c.id));
            toast.success("Deleted");
        } catch (e) {
            toast.error(apiErr(e));
        }
    };

    return (
        <div className="p-6 space-y-6" data-testid="connections-page">
            <header className="flex items-center justify-between">
                <div>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">06 · Endpoints</div>
                    <h1 className="text-3xl font-semibold tracking-tight mt-1">Connection Profiles</h1>
                    <p className="text-sm text-[#4B5563] mt-2 max-w-2xl">
                        Save CBS / switch host details once. The Builder will open a raw TCP socket (optionally TLS), frame the encoded
                        ISO-8583 bytes with your chosen length header, send, and capture the response into your logs.
                    </p>
                </div>
                <button onClick={openNew} data-testid="new-connection-btn" className="h-9 px-4 bg-[#002FA7] text-white text-sm flex items-center gap-2 hover:bg-[#002080]">
                    <Plus size={14} /> New profile
                </button>
            </header>

            {loading ? (
                <div className="text-xs uppercase tracking-widest text-gray-500">Loading…</div>
            ) : items.length === 0 ? (
                <div className="border border-[#E5E7EB] p-16 text-center">
                    <Plug size={28} className="text-[#9CA3AF] mx-auto" />
                    <div className="text-sm text-[#4B5563] mt-3">No endpoints yet. Create one to send live traffic to your CBS host.</div>
                </div>
            ) : (
                <section className="border border-[#E5E7EB] divide-y divide-[#E5E7EB]" data-testid="connections-list">
                    {items.map((c) => (
                        <article key={c.id} className="p-5 grid grid-cols-12 gap-4 items-center" data-testid={`connection-row-${c.id}`}>
                            <div className="col-span-12 md:col-span-4">
                                <div className="text-base font-medium flex items-center gap-2">
                                    {c.use_tls ? <LockKey size={14} className="text-[#16A34A]" /> : <LockKeyOpen size={14} className="text-[#9CA3AF]" />}
                                    {c.name}
                                </div>
                                {c.description && <div className="text-xs text-[#4B5563] mt-0.5">{c.description}</div>}
                            </div>
                            <div className="col-span-6 md:col-span-3 font-mono text-xs text-[#111827]">{c.host}:{c.port}</div>
                            <div className="col-span-6 md:col-span-3 text-[10px] uppercase tracking-widest text-[#4B5563]">
                                <span className="border border-gray-300 px-1.5 py-0.5 mr-1">{c.length_header}</span>
                                <span className="border border-gray-300 px-1.5 py-0.5">{c.timeout_sec}s timeout</span>
                            </div>
                            <div className="col-span-12 md:col-span-2 flex gap-2 md:justify-end">
                                <button data-testid={`connection-edit-${c.id}`} onClick={() => openEdit(c)} className="h-8 px-3 border border-gray-300 text-xs hover:bg-gray-50 flex items-center gap-1">
                                    <PencilSimple size={12} /> Edit
                                </button>
                                <button data-testid={`connection-delete-${c.id}`} onClick={() => del(c)} className="h-8 px-2 border border-gray-300 text-[#E11D48] hover:bg-[#FEF2F2]">
                                    <Trash size={12} />
                                </button>
                            </div>
                        </article>
                    ))}
                </section>
            )}

            {editing && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4 overflow-y-auto" onClick={close} data-testid="connection-modal">
                    <form
                        onClick={(e) => e.stopPropagation()}
                        onSubmit={save}
                        className="bg-white w-full max-w-lg border border-[#E5E7EB] flex flex-col max-h-[92vh] shadow-xl"
                    >
                        <div className="px-6 py-5 border-b border-[#E5E7EB]">
                            <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">Endpoint config</div>
                            <h2 className="text-xl font-semibold tracking-tight mt-1">
                                {editing === "new" ? "New connection profile" : "Edit profile"}
                            </h2>
                        </div>

                        <div className="px-6 py-5 space-y-4 overflow-y-auto flex-1">
                            <Field label="Name">
                                <input data-testid="connection-name-input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required className="w-full h-9 border border-gray-300 px-2 text-sm focus:border-[#002FA7]" />
                            </Field>
                            <div className="grid grid-cols-3 gap-3">
                                <div className="col-span-2">
                                    <Field label="Host (IP or DNS)">
                                        <input data-testid="connection-host-input" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.12.5" required className="w-full h-9 border border-gray-300 px-2 text-sm font-mono focus:border-[#002FA7]" />
                                    </Field>
                                </div>
                                <Field label="Port">
                                    <input data-testid="connection-port-input" type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} required className="w-full h-9 border border-gray-300 px-2 text-sm font-mono focus:border-[#002FA7]" />
                                </Field>
                            </div>

                            <Field label="Length header framing">
                                <div className="grid grid-cols-1 gap-1">
                                    {LENGTH_HEADERS.map((lh) => (
                                        <label key={lh.value} className={`border px-3 py-2 cursor-pointer flex items-center gap-3 transition-colors ${form.length_header === lh.value ? "border-[#002FA7] bg-[#F3F4F6]" : "border-gray-300 hover:bg-gray-50"}`}>
                                            <input type="radio" name="length_header" value={lh.value} checked={form.length_header === lh.value} onChange={() => setForm({ ...form, length_header: lh.value })} data-testid={`connection-lh-${lh.value}`} />
                                            <div>
                                                <div className="text-sm">{lh.label}</div>
                                                <div className="text-[11px] text-[#4B5563]">{lh.help}</div>
                                            </div>
                                        </label>
                                    ))}
                                </div>
                            </Field>

                            <div className="grid grid-cols-2 gap-3">
                                <Field label="Timeout (sec)">
                                    <input data-testid="connection-timeout-input" type="number" min={1} max={120} value={form.timeout_sec} onChange={(e) => setForm({ ...form, timeout_sec: e.target.value })} className="w-full h-9 border border-gray-300 px-2 text-sm font-mono" />
                                </Field>
                                <label className="flex flex-col">
                                    <span className="text-[10px] uppercase tracking-widest text-[#4B5563]">TLS</span>
                                    <div className="mt-1 flex items-center gap-2 h-9 border border-gray-300 px-3">
                                        <input data-testid="connection-tls-checkbox" type="checkbox" checked={form.use_tls} onChange={(e) => setForm({ ...form, use_tls: e.target.checked })} />
                                        <span className="text-sm">{form.use_tls ? "Encrypted (TLS)" : "Plain TCP"}</span>
                                    </div>
                                </label>
                            </div>

                            <Field label="Description">
                                <input data-testid="connection-desc-input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="e.g. UAT CBS · RuPay switch" className="w-full h-9 border border-gray-300 px-2 text-sm focus:border-[#002FA7]" />
                            </Field>
                        </div>

                        <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3 sticky bottom-0">
                            <button
                                type="button"
                                onClick={close}
                                data-testid="connection-cancel-btn"
                                className="flex-1 h-11 border border-gray-300 bg-white text-sm font-medium text-[#4B5563] hover:bg-gray-50 hover:border-gray-400 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                data-testid="connection-save-btn"
                                disabled={saving}
                                className="flex-[2] h-11 bg-[#002FA7] text-white text-sm font-semibold tracking-wide flex items-center justify-center gap-2 hover:bg-[#002080] active:bg-[#001A66] transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                            >
                                <FloppyDisk size={16} weight="bold" />
                                {saving ? "Saving…" : editing === "new" ? "Create profile" : "Save changes"}
                            </button>
                        </div>
                    </form>
                </div>
            )}
        </div>
    );
}

const Field = ({ label, children }) => (
    <label className="block">
        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">{label}</div>
        {children}
    </label>
);
