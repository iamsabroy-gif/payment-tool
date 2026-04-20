import { useEffect, useState, useCallback, useRef } from "react";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import {
    Plug,
    Trash,
    PencilSimple,
    Plus,
    LockKey,
    LockKeyOpen,
    FloppyDisk,
    Play,
    Stop,
    Heartbeat,
    CircleNotch,
} from "@phosphor-icons/react";

const LENGTH_HEADERS = [
    { value: "2_byte", label: "2-byte big-endian", help: "Most common (ISO-8583 over TCP)" },
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
    auto_heartbeat: false,
    heartbeat_interval_sec: 30,
    description: "",
};

export default function Connections() {
    const [items, setItems] = useState([]);
    const [statusMap, setStatusMap] = useState({}); // {id: {state, last_heartbeat_at, ...}}
    const [loading, setLoading] = useState(true);
    const [editing, setEditing] = useState(null);
    const [form, setForm] = useState(EMPTY);
    const [saving, setSaving] = useState(false);
    const [busyId, setBusyId] = useState(null); // connect/disconnect in flight

    const pollRef = useRef(null);

    const refreshStatuses = useCallback(async (ids) => {
        const list = ids ?? items.map((x) => x.id);
        if (list.length === 0) return;
        const results = await Promise.all(
            list.map((id) => api.get(`/connections/${id}/status`).then((r) => [id, r.data]).catch(() => [id, { state: "idle" }]))
        );
        setStatusMap((prev) => {
            const next = { ...prev };
            results.forEach(([id, s]) => { next[id] = s; });
            return next;
        });
    }, [items]);

    const load = () => {
        setLoading(true);
        api.get("/connections")
            .then((r) => {
                setItems(r.data);
                return refreshStatuses(r.data.map((x) => x.id));
            })
            .finally(() => setLoading(false));
    };
    useEffect(load, []);  // eslint-disable-line react-hooks/exhaustive-deps

    // Poll status every 5s
    useEffect(() => {
        if (items.length === 0) return;
        pollRef.current = setInterval(() => { refreshStatuses(); }, 5000);
        return () => clearInterval(pollRef.current);
    }, [items, refreshStatuses]);

    const openNew = () => { setEditing("new"); setForm(EMPTY); };
    const openEdit = (c) => { setEditing(c); setForm({ ...EMPTY, ...c }); };
    const close = () => { setEditing(null); setForm(EMPTY); };

    const save = async (e) => {
        e.preventDefault();
        setSaving(true);
        try {
            const payload = {
                ...form,
                port: Number(form.port),
                timeout_sec: Number(form.timeout_sec),
                heartbeat_interval_sec: Number(form.heartbeat_interval_sec),
            };
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

    const doConnect = async (c) => {
        setBusyId(c.id);
        try {
            const { data } = await api.post(`/connections/${c.id}/connect`);
            setStatusMap((prev) => ({ ...prev, [c.id]: data }));
            toast.success(`Connected to ${c.host}:${c.port}`);
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setBusyId(null);
        }
    };

    const doDisconnect = async (c) => {
        setBusyId(c.id);
        try {
            await api.post(`/connections/${c.id}/disconnect`);
            setStatusMap((prev) => ({ ...prev, [c.id]: { state: "idle" } }));
            toast.success("Disconnected");
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setBusyId(null);
        }
    };

    return (
        <div className="p-6 space-y-6" data-testid="connections-page">
            <header className="flex items-center justify-between">
                <div>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">06 · Endpoints</div>
                    <h1 className="text-3xl font-semibold tracking-tight mt-1">Connection Profiles</h1>
                    <p className="text-sm text-[#4B5563] mt-2 max-w-2xl">
                        Save a CBS / switch host once. Click <strong>Connect</strong> to open a persistent TCP socket; transactions from
                        the Builder will reuse it. Enable <strong>auto-heartbeat</strong> to fire a 0800 echo every N seconds and keep the line open.
                    </p>
                </div>
                <button onClick={openNew} data-testid="new-connection-btn" className="h-10 px-5 bg-[#002FA7] text-white text-sm font-semibold flex items-center gap-2 hover:bg-[#002080] transition-colors shadow-sm">
                    <Plus size={14} weight="bold" /> New profile
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
                    {items.map((c) => {
                        const st = statusMap[c.id] || { state: "idle" };
                        const isUp = st.state === "connected";
                        const busy = busyId === c.id;
                        return (
                            <article key={c.id} className="p-5 grid grid-cols-12 gap-4 items-center" data-testid={`connection-row-${c.id}`}>
                                <div className="col-span-12 md:col-span-4">
                                    <div className="flex items-center gap-3">
                                        <StatusDot connected={isUp} testid={`connection-status-${c.id}`} />
                                        <div>
                                            <div className="text-base font-medium flex items-center gap-2">
                                                {c.use_tls ? <LockKey size={13} className="text-[#16A34A]" /> : <LockKeyOpen size={13} className="text-[#9CA3AF]" />}
                                                {c.name}
                                            </div>
                                            {c.description && <div className="text-xs text-[#4B5563] mt-0.5">{c.description}</div>}
                                            {isUp && st.last_heartbeat_at && (
                                                <div className="text-[10px] text-[#16A34A] mt-0.5 flex items-center gap-1">
                                                    <Heartbeat size={10} weight="fill" /> last echo {fmtAgo(st.last_heartbeat_at)}
                                                </div>
                                            )}
                                            {!isUp && st.last_error && (
                                                <div className="text-[10px] text-[#E11D48] mt-0.5 truncate max-w-sm">{st.last_error}</div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                                <div className="col-span-6 md:col-span-3 font-mono text-xs text-[#111827]">{c.host}:{c.port}</div>
                                <div className="col-span-6 md:col-span-2 text-[10px] uppercase tracking-widest text-[#4B5563] flex flex-wrap gap-1">
                                    <span className="border border-gray-300 px-1.5 py-0.5">{c.length_header}</span>
                                    {c.auto_heartbeat && <span className="border border-[#16A34A] text-[#16A34A] px-1.5 py-0.5 flex items-center gap-1"><Heartbeat size={10} weight="fill" /> {c.heartbeat_interval_sec}s</span>}
                                </div>
                                <div className="col-span-12 md:col-span-3 flex gap-2 md:justify-end flex-wrap">
                                    {isUp ? (
                                        <button
                                            data-testid={`connection-disconnect-${c.id}`}
                                            disabled={busy}
                                            onClick={() => doDisconnect(c)}
                                            className="h-9 px-3 border border-[#E11D48] text-[#E11D48] text-xs font-medium hover:bg-[#FEF2F2] flex items-center gap-1 disabled:opacity-50"
                                        >
                                            {busy ? <CircleNotch size={12} className="animate-spin" /> : <Stop size={12} weight="fill" />}
                                            Disconnect
                                        </button>
                                    ) : (
                                        <button
                                            data-testid={`connection-connect-${c.id}`}
                                            disabled={busy}
                                            onClick={() => doConnect(c)}
                                            className="h-9 px-3 bg-[#16A34A] text-white text-xs font-semibold hover:bg-[#15803D] flex items-center gap-1 disabled:opacity-50"
                                        >
                                            {busy ? <CircleNotch size={12} className="animate-spin" /> : <Play size={12} weight="fill" />}
                                            Connect
                                        </button>
                                    )}
                                    <button data-testid={`connection-edit-${c.id}`} onClick={() => openEdit(c)} className="h-9 px-3 border border-gray-300 text-xs hover:bg-gray-50 flex items-center gap-1">
                                        <PencilSimple size={12} /> Edit
                                    </button>
                                    <button data-testid={`connection-delete-${c.id}`} onClick={() => del(c)} className="h-9 px-2 border border-gray-300 text-[#E11D48] hover:bg-[#FEF2F2]">
                                        <Trash size={12} />
                                    </button>
                                </div>
                            </article>
                        );
                    })}
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

                            <div className="border border-[#E5E7EB] p-3 bg-[#F9FAFB]">
                                <label className="flex items-start gap-3 cursor-pointer">
                                    <input
                                        data-testid="connection-heartbeat-checkbox"
                                        type="checkbox"
                                        checked={form.auto_heartbeat}
                                        onChange={(e) => setForm({ ...form, auto_heartbeat: e.target.checked })}
                                        className="mt-0.5"
                                    />
                                    <div className="flex-1">
                                        <div className="text-sm font-medium flex items-center gap-2">
                                            <Heartbeat size={14} className="text-[#E11D48]" weight="fill" /> Auto-heartbeat (0800 echo)
                                        </div>
                                        <div className="text-[11px] text-[#4B5563] mt-0.5">
                                            Send a network-management keep-alive over the same socket at a fixed interval. Stops if the echo fails.
                                        </div>
                                    </div>
                                </label>
                                {form.auto_heartbeat && (
                                    <div className="mt-3 grid grid-cols-3 gap-3 items-end">
                                        <Field label="Interval (sec)">
                                            <input
                                                data-testid="connection-heartbeat-interval-input"
                                                type="number"
                                                min={5}
                                                max={3600}
                                                value={form.heartbeat_interval_sec}
                                                onChange={(e) => setForm({ ...form, heartbeat_interval_sec: e.target.value })}
                                                className="w-full h-9 border border-gray-300 px-2 text-sm font-mono"
                                            />
                                        </Field>
                                        <div className="col-span-2 text-[11px] text-[#4B5563] leading-relaxed">
                                            Typical: 30–60s. Echo uses MTI 0800, F70=301.
                                        </div>
                                    </div>
                                )}
                            </div>

                            <Field label="Description">
                                <input data-testid="connection-desc-input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="e.g. UAT CBS · RuPay switch" className="w-full h-9 border border-gray-300 px-2 text-sm focus:border-[#002FA7]" />
                            </Field>
                        </div>

                        <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3 sticky bottom-0">
                            <button type="button" onClick={close} data-testid="connection-cancel-btn" className="flex-1 h-11 border border-gray-300 bg-white text-sm font-medium text-[#4B5563] hover:bg-gray-50 hover:border-gray-400 transition-colors">
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

const StatusDot = ({ connected, testid }) => (
    <span
        data-testid={testid}
        title={connected ? "Connected" : "Disconnected"}
        className={`inline-block w-2.5 h-2.5 rounded-full shrink-0 ${
            connected ? "bg-[#16A34A] shadow-[0_0_0_3px_rgba(22,163,74,0.18)] animate-pulse" : "bg-[#9CA3AF]"
        }`}
    />
);

function fmtAgo(iso) {
    if (!iso) return "";
    const then = new Date(iso).getTime();
    const diff = Math.max(0, (Date.now() - then) / 1000);
    if (diff < 60) return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    return `${Math.round(diff / 3600)}h ago`;
}
