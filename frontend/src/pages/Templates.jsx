import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import { Trash, ArrowRight, BookBookmark, CopySimple, Star, Stack, Play, X, FloppyDisk } from "@phosphor-icons/react";
import { RunBucketModal, RunResultsModal } from "./Buckets";

export default function Templates() {
    const [items, setItems] = useState([]);
    const [samples, setSamples] = useState([]);
    const [loading, setLoading] = useState(true);
    const [cloningId, setCloningId] = useState(null);
    const [selected, setSelected] = useState(() => new Set());
    const [savingBucket, setSavingBucket] = useState(false);
    const [bucketName, setBucketName] = useState("");
    const [bucketDesc, setBucketDesc] = useState("");
    const [showSaveBucket, setShowSaveBucket] = useState(false);
    const [runOnce, setRunOnce] = useState(false);
    const [runResults, setRunResults] = useState(null);

    const load = () => {
        setLoading(true);
        Promise.all([api.get("/templates"), api.get("/samples")])
            .then(([t, s]) => {
                setItems(t.data);
                setSamples(s.data);
            })
            .finally(() => setLoading(false));
    };
    useEffect(load, []);

    const toggle = (id) => {
        setSelected((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id); else next.add(id);
            return next;
        });
    };
    const clearSelection = () => setSelected(new Set());
    const selectedIds = items.filter((t) => selected.has(t.id)).map((t) => t.id); // preserves render order

    const del = async (id) => {
        if (!confirm("Delete this template?")) return;
        try {
            await api.delete(`/templates/${id}`);
            setItems((prev) => prev.filter((x) => x.id !== id));
            setSelected((prev) => { const n = new Set(prev); n.delete(id); return n; });
            toast.success("Template deleted");
        } catch (e) {
            toast.error(apiErr(e));
        }
    };

    const clone = async (sample) => {
        setCloningId(sample.id);
        try {
            const { data } = await api.post(`/samples/${sample.id}/clone`);
            setItems((prev) => [data, ...prev]);
            toast.success(`Cloned "${sample.name}" to your templates`);
        } catch (e) {
            toast.error(apiErr(e));
        } finally {
            setCloningId(null);
        }
    };

    const saveBucket = async () => {
        if (!selectedIds.length) return;
        setSavingBucket(true);
        try {
            await api.post("/buckets", {
                name: bucketName.trim() || `Bucket of ${selectedIds.length}`,
                description: bucketDesc,
                template_ids: selectedIds,
            });
            toast.success(`Bucket "${bucketName.trim() || `Bucket of ${selectedIds.length}`}" saved`);
            setShowSaveBucket(false);
            setBucketName("");
            setBucketDesc("");
            clearSelection();
        } catch (e) { toast.error(apiErr(e)); }
        finally { setSavingBucket(false); }
    };

    return (
        <div className="p-6 space-y-8" data-testid="templates-page">
            <header>
                <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">03 · Library</div>
                <h1 className="text-3xl font-semibold tracking-tight mt-1">Templates</h1>
            </header>

            {/* Sample library */}
            <section data-testid="sample-library">
                <div className="flex items-center justify-between mb-3">
                    <div>
                        <div className="text-[11px] uppercase tracking-widest text-[#002FA7] flex items-center gap-1">
                            <Star size={12} weight="fill" /> Sample library
                        </div>
                        <h2 className="text-xl font-semibold tracking-tight mt-1">Starter messages</h2>
                    </div>
                    <div className="text-[11px] font-mono text-[#4B5563]">{samples.length} samples</div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                    {samples.map((s) => (
                        <article key={s.id} className="bg-white p-5 flex flex-col" data-testid={`sample-card-${s.id}`}>
                            <div className="flex items-start justify-between">
                                <div>
                                    <div className="text-[10px] uppercase tracking-widest text-[#4B5563]">{s.network_id} · MTI {s.mti}</div>
                                    <div className="text-base font-medium mt-1">{s.name}</div>
                                    {s.description && <div className="text-xs text-[#4B5563] mt-1 leading-relaxed">{s.description}</div>}
                                </div>
                            </div>
                            <div className="mt-3 text-xs text-[#4B5563] font-mono flex-1">
                                {Object.keys(s.data_elements || {}).sort((a, b) => +a - +b).slice(0, 10).map((k) => (
                                    <span key={k} className="inline-block border border-[#E5E7EB] px-1.5 py-0.5 mr-1 mb-1">[{String(k).padStart(3, "0")}]</span>
                                ))}
                            </div>
                            <div className="mt-4 grid grid-cols-2 gap-2">
                                <button
                                    onClick={() => clone(s)}
                                    disabled={cloningId === s.id}
                                    data-testid={`sample-clone-${s.id}`}
                                    className="h-9 border border-gray-300 text-sm flex items-center justify-center gap-2 hover:bg-gray-50 disabled:opacity-50"
                                >
                                    <CopySimple size={13} /> {cloningId === s.id ? "Cloning…" : "Clone"}
                                </button>
                                <Link
                                    to={`/app/builder?sample=${s.id}`}
                                    data-testid={`sample-load-${s.id}`}
                                    className="h-9 border border-[#002FA7] text-[#002FA7] text-sm flex items-center justify-center hover:bg-[#F3F4F6]"
                                >
                                    Open in builder →
                                </Link>
                            </div>
                        </article>
                    ))}
                </div>
            </section>

            {/* User templates */}
            <section>
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-xl font-semibold tracking-tight">Your saved templates</h2>
                    <Link to="/app/builder" data-testid="templates-go-builder" className="text-[11px] text-[#002FA7] hover:underline">Open Builder →</Link>
                </div>
                {loading ? (
                    <div className="text-xs uppercase tracking-widest text-gray-500">Loading…</div>
                ) : items.length === 0 ? (
                    <div className="border border-[#E5E7EB] p-10 text-center">
                        <BookBookmark size={22} className="text-[#9CA3AF] mx-auto" />
                        <div className="text-sm text-[#4B5563] mt-3">No saved templates yet. Clone a sample above or save one from the Builder.</div>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                        {items.map((t) => {
                            const isSel = selected.has(t.id);
                            return (
                                <article key={t.id} className={`bg-white p-5 flex flex-col ${isSel ? "ring-2 ring-[#002FA7] ring-inset" : ""}`} data-testid={`template-card-${t.id}`}>
                                    <div className="flex items-start justify-between gap-2">
                                        <label className="flex items-start gap-2 cursor-pointer flex-1 min-w-0">
                                            <input
                                                type="checkbox"
                                                checked={isSel}
                                                onChange={() => toggle(t.id)}
                                                data-testid={`template-checkbox-${t.id}`}
                                                className="mt-1 h-4 w-4 accent-[#002FA7]"
                                            />
                                            <div className="min-w-0">
                                                <div className="text-[10px] uppercase tracking-widest text-[#4B5563]">{t.network_id} · MTI {t.mti}</div>
                                                <div className="text-base font-medium mt-1 truncate">{t.name}</div>
                                            </div>
                                        </label>
                                        <button data-testid={`template-delete-${t.id}`} onClick={() => del(t.id)} className="text-[#9CA3AF] hover:text-[#E11D48] p-1 shrink-0">
                                            <Trash size={16} />
                                        </button>
                                    </div>
                                    <div className="mt-3 text-xs text-[#4B5563] font-mono flex-1">
                                        {Object.keys(t.data_elements || {}).sort((a, b) => +a - +b).slice(0, 10).map((k) => (
                                            <span key={k} className="inline-block border border-[#E5E7EB] px-1.5 py-0.5 mr-1 mb-1">[{String(k).padStart(3, "0")}]</span>
                                        ))}
                                    </div>
                                    <Link
                                        to={`/app/builder?template=${t.id}`}
                                        data-testid={`template-load-${t.id}`}
                                        className="mt-4 h-9 border border-gray-300 text-sm flex items-center justify-center hover:bg-gray-50"
                                    >
                                        Load into builder →
                                    </Link>
                                </article>
                            );
                        })}
                    </div>
                )}
            </section>

            {/* Multi-select action toolbar — sticks to bottom while items are selected */}
            {selectedIds.length > 0 && (
                <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 bg-[#111827] text-white shadow-2xl border border-[#111827] flex items-center gap-3 px-5 py-3" data-testid="templates-bulk-toolbar">
                    <span className="text-[11px] uppercase tracking-widest opacity-70">{selectedIds.length} selected</span>
                    <button
                        onClick={() => setRunOnce(true)}
                        data-testid="templates-bulk-run"
                        className="h-9 px-3 bg-[#16A34A] text-white text-xs font-semibold hover:bg-[#15803D] flex items-center gap-1"
                    >
                        <Play size={12} weight="fill" /> Run as bucket
                    </button>
                    <button
                        onClick={() => setShowSaveBucket(true)}
                        data-testid="templates-bulk-save"
                        className="h-9 px-3 border border-white/40 text-xs font-semibold hover:bg-white/10 flex items-center gap-1"
                    >
                        <Stack size={12} weight="fill" /> Save as bucket
                    </button>
                    <button
                        onClick={clearSelection}
                        data-testid="templates-bulk-clear"
                        className="h-9 px-2 text-white/60 hover:text-white"
                        title="Clear selection"
                    >
                        <X size={14} />
                    </button>
                </div>
            )}

            {showSaveBucket && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4" onClick={() => !savingBucket && setShowSaveBucket(false)} data-testid="bucket-save-modal">
                    <div onClick={(e) => e.stopPropagation()} className="bg-white w-full max-w-md border border-[#E5E7EB] shadow-xl">
                        <div className="px-6 py-5 border-b border-[#E5E7EB]">
                            <div className="text-[11px] uppercase tracking-widest text-[#002FA7]">New bucket</div>
                            <h2 className="text-xl font-semibold tracking-tight mt-1">Save {selectedIds.length} templates as a bucket</h2>
                        </div>
                        <div className="px-6 py-5 space-y-4">
                            <label className="block">
                                <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">Bucket name</div>
                                <input data-testid="bucket-save-name" autoFocus value={bucketName} onChange={(e) => setBucketName(e.target.value)} placeholder="Smoke pack · POS Sale + Reversal" className="w-full h-9 border border-gray-300 px-2 text-sm" />
                            </label>
                            <label className="block">
                                <div className="text-[10px] uppercase tracking-widest text-[#4B5563] mb-1">Description (optional)</div>
                                <input data-testid="bucket-save-desc" value={bucketDesc} onChange={(e) => setBucketDesc(e.target.value)} className="w-full h-9 border border-gray-300 px-2 text-sm" />
                            </label>
                        </div>
                        <div className="px-6 py-4 border-t border-[#E5E7EB] bg-[#F9FAFB] flex gap-3">
                            <button onClick={() => setShowSaveBucket(false)} disabled={savingBucket} className="flex-1 h-10 border border-gray-300 bg-white text-sm">Cancel</button>
                            <button onClick={saveBucket} disabled={savingBucket} data-testid="bucket-save-submit" className="flex-[2] h-10 bg-[#002FA7] text-white text-sm font-semibold flex items-center justify-center gap-2 hover:bg-[#002080] disabled:opacity-50">
                                <FloppyDisk size={14} weight="bold" /> {savingBucket ? "Saving…" : "Save bucket"}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {runOnce && (
                <RunBucketModal
                    bucket={null}
                    oneShot
                    templateIds={selectedIds}
                    onClose={() => setRunOnce(false)}
                    onComplete={(res) => { setRunOnce(false); setRunResults(res); clearSelection(); }}
                />
            )}
            {runResults && <RunResultsModal results={runResults} onClose={() => setRunResults(null)} />}
        </div>
    );
}
