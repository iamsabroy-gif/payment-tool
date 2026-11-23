import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import { CryptoChecks, KeysetSelect } from "../components/CryptoChecks";
import { toast } from "sonner";
import {
    Stack, Trash, PencilSimple, Play, X, FloppyDisk, CheckCircle, XCircle,
    ListChecks, ArrowRight, CircleNotch,
} from "@phosphor-icons/react";

export default function Buckets() {
    const [items, setItems] = useState([]);
    const [loading, setLoading] = useState(true);
    const [runFor, setRunFor] = useState(null);
    const [editing, setEditing] = useState(null);
    const [results, setResults] = useState(null);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const { data } = await api.get("/buckets");
            setItems(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setLoading(false); }
    }, []);
    useEffect(() => { load(); }, [load]);

    const del = async (b) => {
        if (!confirm(`Delete bucket "${b.name}"?`)) return;
        try {
            await api.delete(`/buckets/${b.id}`);
            setItems((prev) => prev.filter((x) => x.id !== b.id));
            toast.success("Bucket deleted");
        } catch (e) { toast.error(apiErr(e)); }
    };

    return (
        <div className="p-6 space-y-6" data-testid="buckets-page">
            <header className="flex items-center justify-between">
                <div>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">07 · Batch</div>
                    <h1 className="text-3xl font-semibold tracking-tight mt-1">Buckets</h1>
                    <p className="text-sm text-[#4B5563] mt-2 max-w-2xl">
                        Group saved templates and run them sequentially against the simulator or any open connection.
                        Every step is logged with a shared <code className="font-mono text-[#002FA7]">bucket_run_id</code>
                        so you can filter and export the whole run as one .txt.
                    </p>
                </div>
                <Link to="/app/templates" data-testid="buckets-go-templates" className="h-10 px-5 bg-[#002FA7] text-white text-sm font-semibold flex items-center gap-2 hover:bg-[#002080]">
                    <ListChecks size={14} weight="bold" /> Pick templates →
                </Link>
            </header>

            {loading ? (
                <div className="text-xs uppercase tracking-widest text-gray-500">Loading…</div>
            ) : items.length === 0 ? (
                <div className="border border-[#E5E7EB] p-16 text-center">
                    <Stack size={28} className="text-[#9CA3AF] mx-auto" />
                    <div className="text-sm text-[#4B5563] mt-3">
                        No buckets yet. Go to <Link to="/app/templates" className="text-[#002FA7] hover:underline">Templates</Link>,
                        select two or more, and click <strong>Save as bucket</strong>.
                    </div>
                </div>
            ) : (
                <section className="border border-[#E5E7EB] divide-y divide-[#E5E7EB]" data-testid="buckets-list">
                    {items.map((b) => (
                        <article key={b.id} className="p-5 grid grid-cols-12 gap-4 items-start" data-testid={`bucket-row-${b.id}`}>
                            <div className="col-span-12 md:col-span-5">
                                <div className="text-base font-medium">{b.name}</div>
                                {b.description && <div className="text-xs text-[#4B5563] mt-0.5">{b.description}</div>}
                                <div className="text-[10px] text-[#4B5563] mt-1 font-mono">
                                    {b.template_ids?.length || 0} step{(b.template_ids?.length || 0) === 1 ? "" : "s"}
                                    {b.last_run_at && <> · last ran {new Date(b.last_run_at).toLocaleString()}</>}
                                </div>
                            </div>
                            <div className="col-span-12 md:col-span-4 text-[11px] flex flex-wrap gap-1">
                                {(b.templates || []).slice(0, 6).map((t, i) => (
                                    <span key={t.id + i} className="border border-[#E5E7EB] px-1.5 py-0.5 font-mono text-[#4B5563]">
                                        {String(i + 1).padStart(2, "0")}·{t.mti}·{t.name.slice(0, 18)}{t.name.length > 18 ? "…" : ""}
                                    </span>
                                ))}
                                {(b.templates || []).length > 6 && (
                                    <span className="text-[10px] text-[#4B5563] px-1 py-0.5">+{b.templates.length - 6} more</span>
                                )}
                            </div>
                            <div className="col-span-12 md:col-span-3 flex justify-end gap-2 flex-wrap">
                                <button
                                    onClick={() => setRunFor(b)}
                                    data-testid={`bucket-run-${b.id}`}
                                    className="h-9 px-3 bg-[#16A34A] text-white text-xs font-semibold hover:bg-[#15803D] flex items-center gap-1"
                                >
                                    <Play size={12} weight="fill" /> Run
                                </button>
                                <button
                                    onClick={() => setEditing(b)}
                                    data-testid={`bucket-edit-${b.id}`}
                                    className="h-9 px-3 border border-gray-300 text-xs hover:bg-gray-50 flex items-center gap-1"
                                >
                                    <PencilSimple size={12} /> Edit
                                </button>
                                <button
                                    onClick={() => del(b)}
                                    data-testid={`bucket-delete-${b.id}`}
                                    className="h-9 px-2 border border-gray-300 text-[#E11D48] hover:bg-[#FEF2F2]"
                                >
                                    <Trash size={12} />
                                </button>
                                {b.last_run_id && (
                                    <Link
                                        to={`/app/logs?bucket_run_id=${b.last_run_id}`}
                                        data-testid={`bucket-view-logs-${b.id}`}
                                        className="h-9 px-3 border border-[#002FA7] text-[#002FA7] text-xs hover:bg-[#F3F4F6] flex items-center gap-1"
                                    >
                                        Last run logs <ArrowRight size={11} />
                                    </Link>
                                )}
                            </div>
                        </article>
                    ))}
                </section>
            )}

            {runFor && (
                <RunBucketModal
                    bucket={runFor}
                    onClose={() => setRunFor(null)}
                    onComplete={(res) => { setRunFor(null); setResults(res); load(); }}
                />
            )}
            {editing && (
                <EditBucketModal
                    bucket={editing}
                    onClose={() => setEditing(null)}
                    onSaved={(updated) => {
                        setItems((prev) => prev.map((x) => (x.id === updated.id ? updated : x)));
                        setEditing(null);
                        toast.success("Bucket updated");
                    }}
                />
            )}
            {results && <RunResultsModal results={results} onClose={() => setResults(null)} />}
        </div>
    );
}

// ----------------------------------------------------------------------
export function RunBucketModal({ bucket, onClose, onComplete, oneShot = false, templateIds = [] }) {
    const [target, setTarget] = useState("simulator");
    const [keysetId, setKeysetId] = useState("");
    const [delay, setDelay] = useState(0);
    const [conns, setConns] = useState([]);
    const [running, setRunning] = useState(false);

    useEffect(() => {
        api.get("/connections").then((r) => setConns(r.data)).catch(() => setConns([]));
    }, []);

    const start = async () => {
        setRunning(true);
        try {
            const url = oneShot ? "/buckets/run-once" : `/buckets/${bucket.id}/run`;
            const keyset_id = target === "simulator" && keysetId ? keysetId : null;
            const body = oneShot
                ? { template_ids: templateIds, target, delay_ms: Number(delay), keyset_id }
                : { target, delay_ms: Number(delay), keyset_id };
            const { data } = await api.post(url, body);
            toast.success(`Bucket finished: ${data.succeeded}/${data.total} approved`);
            onComplete?.(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setRunning(false); }
    };

    const stepCount = oneShot ? templateIds.length : (bucket?.template_ids?.length || 0);
    const title = oneShot ? `Run ${stepCount} selected templates` : `Run "${bucket.name}"`;

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose} data-testid="bucket-run-modal">
            <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-md border border-[#E5E7EB] shadow-xl">
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">Batch run</div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">{title}</h2>
                        <p className="text-[11px] text-[#4B5563] mt-1">{stepCount} step{stepCount === 1 ? "" : "s"}, executed sequentially.</p>
                    </div>
                    <button onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1"><X size={16} /></button>
                </div>
                <div className="px-6 py-5 space-y-4">
                    <label className="block">
                        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">Target</div>
                        <select
                            data-testid="bucket-run-target-select"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            className="w-full h-9 border border-gray-300 px-2 text-sm bg-white"
                        >
                            <option value="simulator">Built-in simulator (dev)</option>
                            {conns.length > 0 && (
                                <optgroup label="Connection profiles">
                                    {conns.map((c) => (
                                        <option key={c.id} value={c.id}>
                                            {c.name} · {c.transport === "websocket" ? c.ws_url : `${c.host}:${c.port}`}
                                        </option>
                                    ))}
                                </optgroup>
                            )}
                        </select>
                        {target !== "simulator" && (
                            <div className="text-[10px] text-[#4B5563] mt-1">
                                Connection must be <strong>connected</strong> on the Connections page first.
                            </div>
                        )}
                    </label>
                    {target === "simulator" && (
                        <KeysetSelect value={keysetId} onChange={setKeysetId} testid="bucket-run-keyset-select" />
                    )}
                    <label className="block">
                        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">Delay between sends</div>
                        <select
                            data-testid="bucket-run-delay-select"
                            value={delay}
                            onChange={(e) => setDelay(e.target.value)}
                            className="w-full h-9 border border-gray-300 px-2 text-sm bg-white"
                        >
                            <option value={0}>None — back-to-back</option>
                            <option value={100}>100 ms</option>
                            <option value={500}>500 ms</option>
                            <option value={1000}>1 s</option>
                            <option value={2500}>2.5 s</option>
                        </select>
                    </label>
                </div>
                <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3">
                    <button onClick={onClose} disabled={running} data-testid="bucket-run-cancel" className="flex-1 h-11 border border-gray-300 bg-white text-sm font-medium text-[#4B5563] hover:bg-gray-50 disabled:opacity-50">
                        Cancel
                    </button>
                    <button
                        onClick={start}
                        disabled={running || stepCount === 0}
                        data-testid="bucket-run-start"
                        className="flex-[2] h-11 bg-[#16A34A] text-white text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#15803D] disabled:opacity-50"
                    >
                        {running ? <CircleNotch size={14} className="animate-spin" /> : <Play size={14} weight="fill" />}
                        {running ? `Running ${stepCount} step${stepCount === 1 ? "" : "s"}…` : `Run ${stepCount} step${stepCount === 1 ? "" : "s"}`}
                    </button>
                </div>
            </div>
        </div>
    );
}

// ----------------------------------------------------------------------
export function RunResultsModal({ results, onClose }) {
    const ok = results.succeeded;
    const fail = (results.total || 0) - ok;
    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose} data-testid="bucket-results-modal">
            <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-2xl border border-[#E5E7EB] shadow-xl flex flex-col max-h-[88vh]">
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">Run finished</div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">{results.bucket_name}</h2>
                        <div className="text-[11px] text-[#4B5563] mt-1 flex items-center gap-3">
                            <span className="text-[#16A34A] flex items-center gap-1"><CheckCircle size={12} weight="fill" /> {ok} ok</span>
                            <span className="text-[#E11D48] flex items-center gap-1"><XCircle size={12} weight="fill" /> {fail} failed</span>
                            <span>· target {results.target}</span>
                            <span>· {results.delay_ms}ms delay</span>
                        </div>
                    </div>
                    <button onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1"><X size={16} /></button>
                </div>
                <div className="overflow-auto flex-1">
                    <table className="w-full text-xs font-mono" data-testid="bucket-results-table">
                        <thead className="sticky top-0 bg-white border-b border-[#E5E7EB] text-[10px] uppercase tracking-widest text-[#9CA3AF]">
                            <tr>
                                <th className="text-left py-2 px-4">#</th>
                                <th className="text-left py-2">Template</th>
                                <th className="text-left py-2">MTI</th>
                                <th className="text-left py-2">RC</th>
                                <th className="text-left py-2 px-4">Detail</th>
                            </tr>
                        </thead>
                        <tbody>
                            {results.results.map((r) => (
                                <tr key={`${r.step}-${r.template_id}`} className="border-b border-[#F3F4F6]" data-testid={`bucket-results-row-${r.step}`}>
                                    <td className="py-2 px-4 text-[#4B5563]">{r.step}</td>
                                    <td className="py-2">{r.template_name}</td>
                                    <td className="py-2">{r.mti || "—"}</td>
                                    <td className="py-2">
                                        {r.status_code ? (
                                            <span className={`px-1.5 py-0.5 border ${r.status_code === "00" ? "border-[#16A34A] text-[#16A34A]" : "border-[#E11D48] text-[#E11D48]"}`}>{r.status_code}</span>
                                        ) : <span className="text-[#9CA3AF]">—</span>}
                                    </td>
                                    <td className="py-2 px-4 text-[#4B5563] max-w-md">
                                        <div className="truncate">{r.error || r.response_description || "ok"}</div>
                                        {r.crypto_checks && r.crypto_checks.length > 0 && (
                                            <div className="mt-1 font-sans">
                                                <CryptoChecks checks={r.crypto_checks} testid={`bucket-results-checks-${r.step}`} />
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3">
                    <Link
                        to={`/app/logs?bucket_run_id=${results.bucket_run_id}`}
                        data-testid="bucket-results-view-logs"
                        className="flex-1 h-10 border border-[#002FA7] text-[#002FA7] text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#F3F4F6]"
                    >
                        View logs <ArrowRight size={13} />
                    </Link>
                    <button onClick={onClose} className="flex-1 h-10 bg-[#002FA7] text-white text-sm font-semibold hover:bg-[#002080]">Close</button>
                </div>
            </div>
        </div>
    );
}

// ----------------------------------------------------------------------
function EditBucketModal({ bucket, onClose, onSaved }) {
    const [name, setName] = useState(bucket.name);
    const [desc, setDesc] = useState(bucket.description || "");
    const [tids, setTids] = useState(bucket.template_ids || []);
    const [allTpls, setAllTpls] = useState([]);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        api.get("/templates").then((r) => setAllTpls(r.data)).catch(() => setAllTpls([]));
    }, []);

    const move = (idx, dir) => {
        const next = [...tids];
        const swap = idx + dir;
        if (swap < 0 || swap >= next.length) return;
        [next[idx], next[swap]] = [next[swap], next[idx]];
        setTids(next);
    };
    const remove = (idx) => setTids(tids.filter((_, i) => i !== idx));
    const add = (id) => { if (!tids.includes(id)) setTids([...tids, id]); };

    const save = async () => {
        if (!tids.length) { toast.error("Pick at least one template"); return; }
        setSaving(true);
        try {
            const { data } = await api.put(`/buckets/${bucket.id}`, {
                name: name.trim() || bucket.name,
                description: desc,
                template_ids: tids,
            });
            onSaved(data);
        } catch (e) { toast.error(apiErr(e)); }
        finally { setSaving(false); }
    };

    const tplById = Object.fromEntries(allTpls.map((t) => [t.id, t]));
    const available = allTpls.filter((t) => !tids.includes(t.id));

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={onClose} data-testid="bucket-edit-modal">
            <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-2xl border border-[#E5E7EB] shadow-xl flex flex-col max-h-[88vh]">
                <div className="px-6 py-5 border-b border-[#E5E7EB] flex items-start justify-between">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">Edit bucket</div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">{bucket.name}</h2>
                    </div>
                    <button onClick={onClose} className="text-[#9CA3AF] hover:text-[#111827] p-1"><X size={16} /></button>
                </div>
                <div className="px-6 py-5 space-y-4 overflow-y-auto flex-1">
                    <div className="grid grid-cols-2 gap-3">
                        <label className="block">
                            <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">Name</div>
                            <input data-testid="bucket-edit-name" value={name} onChange={(e) => setName(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm" />
                        </label>
                        <label className="block">
                            <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">Description</div>
                            <input data-testid="bucket-edit-desc" value={desc} onChange={(e) => setDesc(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm" />
                        </label>
                    </div>
                    <div>
                        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-2">Steps (drag/move to reorder)</div>
                        <div className="border border-[#E5E7EB] divide-y divide-[#E5E7EB]" data-testid="bucket-edit-steps">
                            {tids.length === 0 && <div className="p-3 text-xs text-[#9CA3AF]">No templates yet — add some from the list below.</div>}
                            {tids.map((id, i) => {
                                const t = tplById[id];
                                return (
                                    <div key={id + i} className="p-2 flex items-center gap-2 text-xs">
                                        <span className="text-[10px] font-mono text-[#4B5563] w-6">{String(i + 1).padStart(2, "0")}</span>
                                        <div className="flex-1 truncate">{t ? `${t.mti} · ${t.name}` : "(deleted template)"}</div>
                                        <button onClick={() => move(i, -1)} className="text-[#4B5563] hover:text-[#002FA7] px-1">↑</button>
                                        <button onClick={() => move(i, 1)} className="text-[#4B5563] hover:text-[#002FA7] px-1">↓</button>
                                        <button onClick={() => remove(i)} className="text-[#9CA3AF] hover:text-[#E11D48] p-1"><Trash size={12} /></button>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                    <div>
                        <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-2">Add a template</div>
                        <select
                            data-testid="bucket-edit-add"
                            onChange={(e) => { if (e.target.value) { add(e.target.value); e.target.value = ""; } }}
                            className="w-full h-9 border border-gray-300 px-2 text-sm bg-white"
                        >
                            <option value="">— pick to append —</option>
                            {available.map((t) => (
                                <option key={t.id} value={t.id}>{t.mti} · {t.name}</option>
                            ))}
                        </select>
                    </div>
                </div>
                <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3">
                    <button onClick={onClose} className="flex-1 h-10 border border-gray-300 bg-white text-sm">Cancel</button>
                    <button onClick={save} disabled={saving} data-testid="bucket-edit-save" className="flex-[2] h-10 bg-[#002FA7] text-white text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#002080] disabled:opacity-50">
                        <FloppyDisk size={14} weight="bold" /> {saving ? "Saving…" : "Save changes"}
                    </button>
                </div>
            </div>
        </div>
    );
}
