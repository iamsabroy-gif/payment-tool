import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import { toast } from "sonner";
import { Trash, ArrowRight, BookBookmark } from "@phosphor-icons/react";

export default function Templates() {
    const [items, setItems] = useState([]);
    const [loading, setLoading] = useState(true);

    const load = () => {
        setLoading(true);
        api.get("/templates").then((r) => setItems(r.data)).finally(() => setLoading(false));
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

    return (
        <div className="p-6 space-y-6" data-testid="templates-page">
            <header>
                <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">03 · Library</div>
                <h1 className="text-3xl font-semibold tracking-tight mt-1">Saved Templates</h1>
            </header>

            {loading ? (
                <div className="text-xs uppercase tracking-widest text-gray-500">Loading…</div>
            ) : items.length === 0 ? (
                <div className="border border-[#E5E7EB] p-16 text-center">
                    <BookBookmark size={28} weight="regular" className="text-[#9CA3AF] mx-auto" />
                    <div className="text-sm text-[#4B5563] mt-3">No templates yet. Create one from the Message Builder.</div>
                    <Link to="/app/builder" data-testid="templates-empty-go-builder" className="inline-flex mt-4 h-9 px-4 bg-[#002FA7] text-white text-sm items-center hover:bg-[#002080]">
                        Open Builder <ArrowRight size={14} className="ml-2" />
                    </Link>
                </div>
            ) : (
                <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
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
                </section>
            )}
        </div>
    );
}
