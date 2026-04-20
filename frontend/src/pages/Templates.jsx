import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import { Trash, ArrowRight, BookBookmark, CopySimple, Star } from "@phosphor-icons/react";

export default function Templates() {
    const [items, setItems] = useState([]);
    const [samples, setSamples] = useState([]);
    const [loading, setLoading] = useState(true);
    const [cloningId, setCloningId] = useState(null);

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

    const del = async (id) => {
        if (!confirm("Delete this template?")) return;
        try {
            await api.delete(`/templates/${id}`);
            setItems((prev) => prev.filter((x) => x.id !== id));
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
                        {items.map((t) => (
                            <article key={t.id} className="bg-white p-5 flex flex-col" data-testid={`template-card-${t.id}`}>
                                <div className="flex items-start justify-between">
                                    <div>
                                        <div className="text-[10px] uppercase tracking-widest text-[#4B5563]">{t.network_id} · MTI {t.mti}</div>
                                        <div className="text-base font-medium mt-1">{t.name}</div>
                                    </div>
                                    <button data-testid={`template-delete-${t.id}`} onClick={() => del(t.id)} className="text-[#9CA3AF] hover:text-[#E11D48] p-1">
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
                        ))}
                    </div>
                )}
            </section>
        </div>
    );
}
