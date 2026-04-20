import { useEffect, useState, useMemo, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import { PanelGroup, Panel, PanelResizeHandle } from "react-resizable-panels";
import { MagnifyingGlass, CheckCircle, XCircle, ArrowsDownUp } from "@phosphor-icons/react";

export default function Logs() {
    const [params] = useSearchParams();
    const [q, setQ] = useState("");
    const [direction, setDirection] = useState("");
    const [status, setStatus] = useState("");
    const [network, setNetwork] = useState("");
    const [items, setItems] = useState([]);
    const [total, setTotal] = useState(0);
    const [selected, setSelected] = useState(null);
    const [loading, setLoading] = useState(true);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const { data } = await api.get("/logs", {
                params: { q: q || undefined, direction: direction || undefined, status: status || undefined, network: network || undefined },
            });
            setItems(data.items);
            setTotal(data.total);
        } catch (e) {
            console.error(apiErr(e));
        } finally {
            setLoading(false);
        }
    }, [q, direction, status, network]);

    useEffect(() => { load(); }, [load]);

    // open=logId param: find and select when items load
    useEffect(() => {
        const openId = params.get("open");
        if (openId && items.length) {
            const match = items.find((x) => x.id === openId);
            if (match) setSelected(match);
        }
    }, [params, items]);

    const openLog = async (id) => {
        try {
            const { data } = await api.get(`/logs/${id}`);
            setSelected(data);
        } catch (e) {
            console.error(apiErr(e));
        }
    };

    return (
        <div className="h-screen flex flex-col" data-testid="logs-page">
            <header className="px-6 pt-6 pb-4 border-b border-[#E5E7EB]">
                <div className="flex items-center justify-between">
                    <div>
                        <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">04 · Capture</div>
                        <h1 className="text-3xl font-semibold tracking-tight mt-1">Transaction Logs</h1>
                    </div>
                    <div className="text-[11px] font-mono text-[#4B5563]" data-testid="logs-total">{total} records</div>
                </div>

                <div className="mt-4 grid grid-cols-12 gap-2">
                    <div className="col-span-12 md:col-span-5 relative">
                        <MagnifyingGlass size={14} className="absolute left-2.5 top-2.5 text-[#9CA3AF]" />
                        <input
                            data-testid="logs-search-input"
                            value={q}
                            onChange={(e) => setQ(e.target.value)}
                            placeholder="Search hex, MTI, status…"
                            className="w-full h-9 border border-gray-300 pl-8 pr-3 text-sm font-mono focus:border-[#002FA7]"
                        />
                    </div>
                    <select data-testid="logs-direction-select" value={direction} onChange={(e) => setDirection(e.target.value)} className="col-span-6 md:col-span-2 h-9 border border-gray-300 px-2 text-sm">
                        <option value="">All directions</option>
                        <option value="outbound">Outbound</option>
                        <option value="inbound">Inbound</option>
                    </select>
                    <select data-testid="logs-status-select" value={status} onChange={(e) => setStatus(e.target.value)} className="col-span-6 md:col-span-2 h-9 border border-gray-300 px-2 text-sm">
                        <option value="">All statuses</option>
                        <option value="00">00 Approved</option>
                        <option value="05">05 Do not honour</option>
                        <option value="51">51 Insufficient funds</option>
                        <option value="96">96 System malfunction</option>
                    </select>
                    <select data-testid="logs-network-select" value={network} onChange={(e) => setNetwork(e.target.value)} className="col-span-12 md:col-span-2 h-9 border border-gray-300 px-2 text-sm">
                        <option value="">All networks</option>
                        <option value="visa">VISA</option>
                        <option value="mastercard">Mastercard</option>
                        <option value="amex">AMEX</option>
                        <option value="rupay">RuPay</option>
                    </select>
                    <button onClick={load} data-testid="logs-refresh-btn" className="col-span-12 md:col-span-1 h-9 border border-gray-300 text-xs hover:bg-gray-50">Refresh</button>
                </div>
            </header>

            <div className="flex-1 min-h-0">
                <PanelGroup direction="horizontal" className="h-full">
                    <Panel defaultSize={55} minSize={30}>
                        <div className="h-full overflow-auto" data-testid="logs-table-wrap">
                            <table className="w-full text-xs font-mono">
                                <thead className="sticky top-0 bg-white border-b border-[#E5E7EB] text-[10px] uppercase tracking-widest text-[#9CA3AF]">
                                    <tr>
                                        <th className="text-left py-2 px-4">Timestamp</th>
                                        <th className="text-left py-2">Dir</th>
                                        <th className="text-left py-2">MTI</th>
                                        <th className="text-left py-2">Net</th>
                                        <th className="text-left py-2">RC</th>
                                        <th className="text-left py-2 px-4">Raw hex</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {loading ? (
                                        <tr><td colSpan={6} className="p-6 text-center text-[#4B5563]">Loading…</td></tr>
                                    ) : items.length === 0 ? (
                                        <tr><td colSpan={6} className="p-10 text-center text-[#4B5563]">No logs match the current filter.</td></tr>
                                    ) : items.map((r) => (
                                        <tr
                                            key={r.id}
                                            onClick={() => openLog(r.id)}
                                            data-testid={`logs-row-${r.id}`}
                                            className={`cursor-pointer border-b border-[#F3F4F6] hover:bg-[#F9FAFB] ${selected?.id === r.id ? "bg-[#F3F4F6]" : ""}`}
                                        >
                                            <td className="py-2 px-4 text-[#4B5563]">{(r.timestamp || "").replace("T", " ").slice(0, 19)}</td>
                                            <td className="py-2">
                                                <span className="inline-flex items-center gap-1">
                                                    <ArrowsDownUp size={11} className={r.direction === "inbound" ? "text-[#16A34A]" : "text-[#002FA7]"} />
                                                    {r.direction.slice(0, 3)}
                                                </span>
                                            </td>
                                            <td className="py-2">{r.mti}</td>
                                            <td className="py-2 uppercase">{r.network_id}</td>
                                            <td className="py-2">
                                                {r.status_code === "00" ? (
                                                    <span className="inline-flex items-center gap-1 text-[#16A34A]"><CheckCircle size={11} /> 00</span>
                                                ) : r.status_code ? (
                                                    <span className="inline-flex items-center gap-1 text-[#E11D48]"><XCircle size={11} /> {r.status_code}</span>
                                                ) : (
                                                    <span className="text-[#9CA3AF]">—</span>
                                                )}
                                            </td>
                                            <td className="py-2 px-4 text-[#4B5563] truncate max-w-[320px]">{r.raw_hex?.slice(0, 48)}…</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </Panel>
                    <PanelResizeHandle className="w-[1px] bg-[#E5E7EB] hover:bg-[#002FA7] transition-colors" />
                    <Panel defaultSize={45} minSize={25}>
                        {selected ? <LogDetail log={selected} /> : (
                            <div className="h-full flex items-center justify-center text-sm text-[#4B5563]" data-testid="logs-empty-detail">
                                Select a row to inspect the message.
                            </div>
                        )}
                    </Panel>
                </PanelGroup>
            </div>
        </div>
    );
}

function LogDetail({ log }) {
    const fields = log?.parsed?.fields || [];
    return (
        <div className="h-full flex flex-col" data-testid="log-detail">
            <div className="px-5 py-3 border-b border-[#E5E7EB] flex items-center justify-between">
                <div>
                    <div className="text-[10px] uppercase tracking-widest text-[#4B5563]">{log.direction} · {log.network_id.toUpperCase()}</div>
                    <div className="text-base font-medium mt-0.5">MTI {log.mti} · {log.status_code || "—"}</div>
                </div>
                <div className="text-[10px] font-mono text-[#4B5563]">{(log.timestamp || "").slice(0, 19).replace("T", " ")}</div>
            </div>
            <PanelGroup direction="horizontal" className="flex-1">
                <Panel defaultSize={50} minSize={25}>
                    <div className="h-full overflow-auto bg-[#F9FAFB]" data-testid="log-raw-pane">
                        <div className="sticky top-0 bg-[#F9FAFB] px-4 py-2 text-[10px] uppercase tracking-widest text-[#4B5563] border-b border-[#E5E7EB]">Raw hex</div>
                        <pre className="p-4 text-[11px] font-mono break-all whitespace-pre-wrap text-[#111827]">{formatHex(log.raw_hex)}</pre>
                        <div className="px-4 py-2 text-[10px] uppercase tracking-widest text-[#4B5563] border-t border-b border-[#E5E7EB] bg-[#F9FAFB]">Base64</div>
                        <pre className="p-4 text-[11px] font-mono break-all whitespace-pre-wrap text-[#111827]">{log.raw_base64}</pre>
                    </div>
                </Panel>
                <PanelResizeHandle className="w-[1px] bg-[#E5E7EB]" />
                <Panel defaultSize={50} minSize={25}>
                    <div className="h-full overflow-auto" data-testid="log-parsed-pane">
                        <div className="sticky top-0 bg-white px-4 py-2 text-[10px] uppercase tracking-widest text-[#4B5563] border-b border-[#E5E7EB]">Parsed fields</div>
                        <div className="text-xs">
                            <div className="grid grid-cols-12 py-2 px-4 border-b border-[#F3F4F6]">
                                <div className="col-span-4 text-[#4B5563]">MTI</div>
                                <div className="col-span-8 font-mono">{log.parsed?.mti}</div>
                            </div>
                            <div className="grid grid-cols-12 py-2 px-4 border-b border-[#F3F4F6]">
                                <div className="col-span-4 text-[#4B5563]">Bitmap</div>
                                <div className="col-span-8 font-mono break-all">{log.parsed?.bitmap_hex}</div>
                            </div>
                            {fields.map((f) => (
                                <div key={f.field} className="grid grid-cols-12 py-2 px-4 border-b border-[#F3F4F6]">
                                    <div className="col-span-2 text-[#002FA7] font-mono">[{String(f.field).padStart(3, "0")}]</div>
                                    <div className="col-span-4 text-[#4B5563]">{f.name}</div>
                                    <div className="col-span-6 font-mono break-all">{String(f.value)}</div>
                                </div>
                            ))}
                            {log.parsed?.response_code && (
                                <div className="grid grid-cols-12 py-3 px-4 bg-[#F3F4F6]">
                                    <div className="col-span-4 text-[#4B5563]">Authorization</div>
                                    <div className="col-span-8 font-mono">{log.parsed.authorization_code || "—"}</div>
                                </div>
                            )}
                        </div>
                    </div>
                </Panel>
            </PanelGroup>
        </div>
    );
}

function formatHex(hex) {
    if (!hex) return "";
    return hex.match(/.{1,2}/g)?.join(" ").match(/(\S+\s?){1,16}/g)?.join("\n") || hex;
}
