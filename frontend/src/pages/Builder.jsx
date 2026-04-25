import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import { FloppyDisk, PaperPlaneTilt, ArrowsClockwise, CheckCircle, XCircle, LockKey, Key } from "@phosphor-icons/react";
import PinHelperModal from "../components/PinHelperModal";
import KeyToolsModal from "../components/KeyToolsModal";

const COMMON_MTIS = [
    { code: "0100", label: "Authorization Request" },
    { code: "0110", label: "Authorization Response" },
    { code: "0200", label: "Financial Request" },
    { code: "0210", label: "Financial Response" },
    { code: "0220", label: "Financial Advice" },
    { code: "0400", label: "Reversal Request" },
    { code: "0410", label: "Reversal Response" },
    { code: "0800", label: "Network Management Request" },
    { code: "0810", label: "Network Management Response" },
];

export default function Builder() {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const [specs, setSpecs] = useState([]);
    const [networkId, setNetworkId] = useState("visa");
    const [fields, setFields] = useState([]);
    const [mti, setMti] = useState("0200");
    const [active, setActive] = useState(new Set());
    const [values, setValues] = useState({});
    const [preview, setPreview] = useState(null);
    const [saving, setSaving] = useState(false);
    const [sending, setSending] = useState(false);
    const [saveName, setSaveName] = useState("");
    const [result, setResult] = useState(null);
    const [target, setTarget] = useState("simulator"); // 'simulator' | connection id
    const [connections, setConnections] = useState([]);
    const [connStatuses, setConnStatuses] = useState({}); // {id: {state}}
    const [pinHelperOpen, setPinHelperOpen] = useState(false);
    const [keyToolsOpen, setKeyToolsOpen] = useState(false);

    useEffect(() => {
        api.get("/specs").then((r) => setSpecs(r.data));
        api.get("/connections").then((r) => setConnections(r.data)).catch(() => {});
    }, []);

    // Poll connection statuses every 5s while on the page
    useEffect(() => {
        if (connections.length === 0) return;
        const refresh = async () => {
            const results = await Promise.all(
                connections.map((c) =>
                    api.get(`/connections/${c.id}/status`).then((r) => [c.id, r.data]).catch(() => [c.id, { state: "idle" }])
                )
            );
            setConnStatuses((prev) => {
                const next = { ...prev };
                results.forEach(([id, s]) => { next[id] = s; });
                return next;
            });
        };
        refresh();
        const t = setInterval(refresh, 5000);
        return () => clearInterval(t);
    }, [connections]);

    const selectedConnection = target === "simulator" ? null : connections.find((c) => c.id === target);
    const selectedConnectionLive = selectedConnection ? connStatuses[selectedConnection.id]?.state === "connected" : false;
    const canSend = target === "simulator" || selectedConnectionLive;

    useEffect(() => {
        api.get(`/specs/${networkId}/fields`).then((r) => setFields(r.data.fields));
    }, [networkId]);

    // Preload template if ?template=id, or sample if ?sample=id
    useEffect(() => {
        const tid = searchParams.get("template");
        const sid = searchParams.get("sample");
        if (tid) {
            api.get("/templates").then((r) => {
                const t = r.data.find((x) => x.id === tid);
                if (!t) return;
                setNetworkId(t.network_id);
                setMti(t.mti);
                const keys = Object.keys(t.data_elements || {}).map(Number);
                setActive(new Set(keys));
                setValues(t.data_elements || {});
                toast.success(`Loaded template "${t.name}"`);
            });
        } else if (sid) {
            api.get("/samples").then((r) => {
                const s = r.data.find((x) => x.id === sid);
                if (!s) return;
                setNetworkId(s.network_id);
                setMti(s.mti);
                const keys = Object.keys(s.data_elements || {}).map(Number);
                setActive(new Set(keys));
                setValues(s.data_elements || {});
                toast.success(`Loaded sample "${s.name}"`);
            });
        }
    }, [searchParams]);

    const fieldMap = useMemo(() => {
        const m = {};
        fields.forEach((f) => (m[f.field] = f));
        return m;
    }, [fields]);

    const toggle = (f) => {
        setActive((prev) => {
            const next = new Set(prev);
            if (next.has(f)) {
                next.delete(f);
                setValues((v) => {
                    const { [f]: _, ...rest } = v;
                    return rest;
                });
            } else {
                next.add(f);
            }
            return next;
        });
    };

    const onValue = (f, v) => setValues((prev) => ({ ...prev, [f]: v }));

    const buildDeMap = () => {
        const de = {};
        active.forEach((f) => {
            if (values[f]) de[String(f)] = String(values[f]);
        });
        return de;
    };

    const doPreview = async () => {
        try {
            const { data } = await api.post("/iso/preview", {
                mti,
                network_id: networkId,
                data_elements: buildDeMap(),
            });
            setPreview(data);
            if (data.validation_errors?.length) {
                toast.warning(`${data.validation_errors.length} validation issue(s) — see preview panel`);
            }
        } catch (e) {
            toast.error(apiErr(e));
        }
    };

    const doSend = async () => {
        setSending(true);
        setResult(null);
        try {
            let data;
            if (target === "simulator") {
                const resp = await api.post("/iso/send", {
                    mti,
                    network_id: networkId,
                    data_elements: buildDeMap(),
                });
                data = resp.data;
            } else {
                const resp = await api.post("/iso/send-tcp", {
                    connection_id: target,
                    mti,
                    network_id: networkId,
                    data_elements: buildDeMap(),
                });
                data = resp.data;
            }
            setResult(data);
            if (data.error) {
                toast.error(`Network error · ${data.error}`);
            } else {
                toast.success(`Response ${data.response_code} · ${data.response_description}`);
            }
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setSending(false);
        }
    };

    const doSave = async (e) => {
        e.preventDefault();
        if (!saveName.trim()) return;
        setSaving(true);
        try {
            await api.post("/templates", {
                name: saveName.trim(),
                network_id: networkId,
                mti,
                data_elements: buildDeMap(),
            });
            toast.success("Template saved");
            setSaveName("");
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setSaving(false);
        }
    };

    const renderBitmapSection = (start, end, label) => (
        <div>
            <div className="flex items-center justify-between text-[10px] uppercase tracking-widest text-[#4B5563] mb-2">
                <span>{label}</span>
                <span className="font-mono">{Array.from(active).filter((f) => f >= start && f <= end).length} active</span>
            </div>
            <div className="grid grid-cols-8 md:grid-cols-16 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                {Array.from({ length: end - start + 1 }, (_, i) => {
                    const f = start + i;
                    const isActive = active.has(f);
                    const hasValue = !!values[f];
                    const meta = fieldMap[f];
                    return (
                        <button
                            key={f}
                            type="button"
                            title={meta?.name || `Field ${f}`}
                            data-testid={`bitmap-tile-${f}`}
                            data-active={isActive}
                            data-has-value={hasValue}
                            onClick={() => toggle(f)}
                            className="bitmap-tile"
                        >
                            <span className="text-[10px] leading-none">{f}</span>
                        </button>
                    );
                })}
            </div>
        </div>
    );

    const activeSorted = useMemo(() => Array.from(active).sort((a, b) => a - b), [active]);

    return (
        <div className="p-6 space-y-6" data-testid="builder-page">
            <header className="flex items-center justify-between">
                <div>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">02 · Build</div>
                    <h1 className="text-3xl font-semibold tracking-tight mt-1">Message Builder</h1>
                </div>
                <div className="flex items-center gap-2">
                    <button data-testid="key-tools-btn" onClick={() => setKeyToolsOpen(true)} className="h-9 px-4 border border-gray-300 text-sm hover:bg-gray-50 flex items-center gap-2">
                        <Key size={14} /> Key tools
                    </button>
                    <button data-testid="preview-btn" onClick={doPreview} className="h-9 px-4 border border-gray-300 text-sm hover:bg-gray-50 flex items-center gap-2">
                        <ArrowsClockwise size={14} /> Preview
                    </button>
                    <button
                        data-testid="send-transaction-btn"
                        onClick={doSend}
                        disabled={sending || !canSend}
                        title={!canSend ? "Target connection is not active. Connect it from the Connections page first." : ""}
                        className="h-9 px-4 bg-[#002FA7] text-white text-sm flex items-center gap-2 hover:bg-[#002080] disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        <PaperPlaneTilt size={14} /> {sending ? "Sending…" : "Send transaction"}
                    </button>
                </div>
            </header>

            {/* Header row: network + MTI + target + save */}
            <section className="grid grid-cols-12 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                <div className="bg-white p-4 col-span-12 md:col-span-3">
                    <label className="text-[10px] uppercase tracking-widest text-[#4B5563]">Network Spec</label>
                    <select
                        data-testid="network-select"
                        value={networkId}
                        onChange={(e) => setNetworkId(e.target.value)}
                        className="mt-2 w-full h-9 border border-gray-300 px-2 text-sm font-mono bg-white"
                    >
                        {specs.map((s) => (
                            <option key={s.network_id} value={s.network_id}>{s.name}</option>
                        ))}
                    </select>
                </div>
                <div className="bg-white p-4 col-span-12 md:col-span-2">
                    <label className="text-[10px] uppercase tracking-widest text-[#4B5563]">MTI (4 digits)</label>
                    <input
                        data-testid="mti-input"
                        value={mti}
                        onChange={(e) => setMti(e.target.value.replace(/\D/g, "").slice(0, 4))}
                        maxLength={4}
                        className="mt-2 w-full h-9 border border-gray-300 px-2 text-lg font-mono tracking-widest focus:border-[#002FA7]"
                    />
                    <div className="mt-2 flex flex-wrap gap-1">
                        {COMMON_MTIS.slice(0, 6).map((m) => (
                            <button
                                key={m.code}
                                type="button"
                                onClick={() => setMti(m.code)}
                                title={m.label}
                                data-testid={`mti-preset-${m.code}`}
                                className={`text-[10px] px-1.5 h-6 border font-mono ${
                                    mti === m.code ? "border-[#002FA7] text-[#002FA7]" : "border-gray-300 text-[#4B5563] hover:bg-gray-50"
                                }`}
                            >
                                {m.code}
                            </button>
                        ))}
                    </div>
                </div>
                <div className="bg-white p-4 col-span-12 md:col-span-3">
                    <label className="text-[10px] uppercase tracking-widest text-[#4B5563]">Send to</label>
                    <select
                        data-testid="target-select"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        className="mt-2 w-full h-9 border border-gray-300 px-2 text-sm bg-white"
                    >
                        <option value="simulator">Built-in simulator (dev)</option>
                        {connections.length > 0 && (
                            <optgroup label="TCP / CBS endpoints">
                                {connections.map((c) => {
                                    const live = connStatuses[c.id]?.state === "connected";
                                    return (
                                        <option key={c.id} value={c.id}>
                                            {live ? "● " : "○ "}{c.name} · {c.host}:{c.port}
                                        </option>
                                    );
                                })}
                            </optgroup>
                        )}
                    </select>
                    {selectedConnection && (
                        <div className="mt-2 text-[11px] flex items-center gap-2" data-testid="target-status">
                            <span className={`inline-block w-2 h-2 rounded-full ${selectedConnectionLive ? "bg-[#16A34A] animate-pulse" : "bg-[#9CA3AF]"}`} />
                            <span className={selectedConnectionLive ? "text-[#16A34A]" : "text-[#4B5563]"}>
                                {selectedConnectionLive ? "Connected" : "Not connected"}
                            </span>
                            <span className="font-mono text-[10px] text-[#4B5563]">· {selectedConnection.length_header}</span>
                            {!selectedConnectionLive && (
                                <Link to="/app/connections" className="ml-auto text-[#002FA7] hover:underline text-[11px]" data-testid="target-open-connections">
                                    Open →
                                </Link>
                            )}
                        </div>
                    )}
                    {target === "simulator" && (
                        <div className="mt-2 text-[11px] text-[#4B5563]">
                            In-process mock host — safe for dev / exploration.
                        </div>
                    )}
                </div>
                <form onSubmit={doSave} className="bg-white p-4 col-span-12 md:col-span-4 flex gap-2 items-end">
                    <div className="flex-1">
                        <label className="text-[10px] uppercase tracking-widest text-[#4B5563]">Save as template</label>
                        <input
                            data-testid="template-name-input"
                            value={saveName}
                            onChange={(e) => setSaveName(e.target.value)}
                            placeholder="e.g. VISA POS Sale 125 USD"
                            className="mt-2 w-full h-9 border border-gray-300 px-2 text-sm focus:border-[#002FA7]"
                        />
                    </div>
                    <button
                        type="submit"
                        data-testid="save-template-btn"
                        disabled={saving || !saveName.trim()}
                        className="h-9 px-4 border border-gray-300 text-sm flex items-center gap-2 hover:bg-gray-50 disabled:opacity-50"
                    >
                        <FloppyDisk size={14} /> Save
                    </button>
                </form>
            </section>

            {/* Bitmap */}
            <section className="grid grid-cols-1 gap-6">
                {renderBitmapSection(1, 64, "Primary Bitmap · Fields 1–64")}
                {renderBitmapSection(65, 128, "Secondary Bitmap · Fields 65–128")}
            </section>

            {/* Active data elements */}
            <section className="border border-[#E5E7EB]" data-testid="de-panel">
                <div className="px-5 py-3 border-b border-[#E5E7EB] flex items-center justify-between">
                    <div className="text-[11px] uppercase tracking-widest text-[#4B5563]">Active Data Elements</div>
                    <span className="text-[11px] font-mono text-[#4B5563]">{activeSorted.length} fields</span>
                </div>
                {activeSorted.length === 0 ? (
                    <div className="p-10 text-center text-sm text-[#4B5563]">Toggle bitmap tiles above to activate data elements.</div>
                ) : (
                    <div className="divide-y divide-[#F3F4F6]">
                        {activeSorted.map((f) => {
                            const meta = fieldMap[f] || {};
                            return (
                                <div key={f} className="grid grid-cols-12 gap-3 px-5 py-3 items-center">
                                    <div className="col-span-2 md:col-span-1 font-mono text-sm text-[#002FA7]">[{String(f).padStart(3, "0")}]</div>
                                    <div className="col-span-10 md:col-span-4">
                                        <div className="text-sm">{meta.name || `Field ${f}`}</div>
                                        <div className="text-[10px] uppercase tracking-widest text-[#9CA3AF]">
                                            {meta.format || "?"} · {meta.length_type || "?"} · max {meta.max_length || "?"}
                                        </div>
                                    </div>
                                    <div className="col-span-12 md:col-span-7">
                                        <div className="flex gap-2">
                                            <input
                                                data-testid={`de-input-${f}`}
                                                value={values[f] || ""}
                                                onChange={(e) => onValue(f, e.target.value)}
                                                placeholder={meta.name}
                                                className="flex-1 h-9 border border-gray-300 px-2 text-sm font-mono focus:border-[#002FA7]"
                                            />
                                            {f === 52 && (
                                                <button
                                                    type="button"
                                                    onClick={() => setPinHelperOpen(true)}
                                                    data-testid="pin-helper-open-btn"
                                                    title="Build & encrypt a PIN block"
                                                    className="h-9 px-3 border border-[#002FA7] text-[#002FA7] text-xs font-medium hover:bg-[#F3F4F6] flex items-center gap-1"
                                                >
                                                    <LockKey size={13} weight="bold" /> Encrypt PIN
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </section>

            {preview && (
                <section className="border border-[#E5E7EB]" data-testid="preview-panel">
                    <div className="px-5 py-3 border-b border-[#E5E7EB] text-[11px] uppercase tracking-widest text-[#4B5563]">Wire preview · {preview.parsed?.wire_bytes ?? "?"} bytes</div>
                    {preview.validation_errors?.length > 0 && (
                        <div className="px-5 py-3 border-b border-[#E11D48] bg-[#FEF2F2]" data-testid="preview-errors">
                            <div className="text-[11px] uppercase tracking-widest text-[#E11D48] mb-1.5">{preview.validation_errors.length} validation issue(s)</div>
                            <ul className="text-xs text-[#9F1239] space-y-1 list-disc pl-5">
                                {preview.validation_errors.map((e, i) => <li key={i}>{e}</li>)}
                            </ul>
                        </div>
                    )}
                    <div className="p-5 space-y-2 text-xs">
                        <Row label="MTI" value={preview.parsed?.mti} mono />
                        <Row label="Bitmap" value={preview.parsed?.bitmap_hex} mono />
                        <Row label="Raw hex" value={preview.raw_hex} mono wrap />
                        <Row label="Base64" value={preview.raw_base64} mono wrap />
                    </div>
                </section>
            )}

            {result && (
                <section className="border border-[#E5E7EB]" data-testid="send-result-panel">
                    <div className="px-5 py-3 border-b border-[#E5E7EB] flex items-center justify-between">
                        <div className="text-[11px] uppercase tracking-widest text-[#4B5563]">Response</div>
                        <div className={`text-xs flex items-center gap-1 ${result.response_code === "00" ? "text-[#16A34A]" : "text-[#E11D48]"}`}>
                            {result.response_code === "00" ? <CheckCircle size={13} /> : <XCircle size={13} />} RC {result.response_code} · {result.response_description}
                        </div>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 divide-x divide-[#E5E7EB]">
                        <div className="p-5">
                            <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-2">Outbound {result.outbound.mti}</div>
                            <pre className="font-mono text-[11px] break-all whitespace-pre-wrap">{result.outbound.raw_hex}</pre>
                        </div>
                        <div className="p-5">
                            <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-2">Inbound {result.inbound.mti}</div>
                            <pre className="font-mono text-[11px] break-all whitespace-pre-wrap">{result.inbound.raw_hex}</pre>
                        </div>
                    </div>
                    <div className="px-5 py-3 border-t border-[#E5E7EB] text-[11px]">
                        <button
                            onClick={() => navigate(`/app/logs?open=${result.outbound.id}`)}
                            className="text-[#002FA7] hover:underline"
                            data-testid="send-result-open-log"
                        >
                            Open in Log Viewer →
                        </button>
                    </div>
                </section>
            )}

            <PinHelperModal
                open={pinHelperOpen}
                onClose={() => setPinHelperOpen(false)}
                onApply={(hex) => onValue(52, hex)}
                defaultPan={values[2] || ""}
            />

            <KeyToolsModal
                open={keyToolsOpen}
                onClose={() => setKeyToolsOpen(false)}
                builderState={{ values }}
                onInsertField={(field, value) => {
                    setActive((prev) => new Set(prev).add(field));
                    onValue(field, value);
                }}
            />
        </div>
    );
}

const Row = ({ label, value, mono, wrap }) => (
    <div className="grid grid-cols-12 gap-3">
        <div className="col-span-3 text-[10px] uppercase tracking-widest text-[#4B5563]">{label}</div>
        <div className={`col-span-9 text-[#111827] ${mono ? "font-mono" : ""} ${wrap ? "break-all" : "truncate"}`}>
            {value}
        </div>
    </div>
);
