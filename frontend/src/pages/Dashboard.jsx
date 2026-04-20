import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErr } from "../lib/api";
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    CartesianGrid,
    ResponsiveContainer,
    PieChart,
    Pie,
    Cell,
    Legend,
} from "recharts";
import { ArrowRight, CheckCircle, XCircle, ArrowsDownUp } from "@phosphor-icons/react";

const SUCCESS = "#16A34A";
const DANGER = "#E11D48";
const KLEIN = "#002FA7";

export default function Dashboard() {
    const [stats, setStats] = useState(null);
    const [err, setErr] = useState("");

    useEffect(() => {
        api.get("/stats").then((r) => setStats(r.data)).catch((e) => setErr(apiErr(e)));
    }, []);

    if (err) return <div className="p-6 text-sm text-[#E11D48]" data-testid="dashboard-error">{err}</div>;
    if (!stats) return <div className="p-6 text-xs uppercase tracking-widest text-gray-500">Loading metrics…</div>;

    const donut = [
        { name: "Approved", value: stats.success || 0, fill: SUCCESS },
        { name: "Declined/Error", value: stats.failed || 0, fill: DANGER },
    ];

    return (
        <div className="p-6 space-y-6" data-testid="dashboard-page">
            <header className="flex items-center justify-between">
                <div>
                    <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563]">01 · Overview</div>
                    <h1 className="text-3xl font-semibold tracking-tight mt-1">Mission Control</h1>
                </div>
                <Link to="/app/builder" data-testid="dashboard-new-tx-btn" className="h-9 px-4 bg-[#002FA7] text-white text-sm flex items-center hover:bg-[#002080]">
                    New Transaction <ArrowRight size={14} className="ml-2" />
                </Link>
            </header>

            {/* KPI strip */}
            <section className="grid grid-cols-2 md:grid-cols-4 border border-[#E5E7EB] divide-x divide-[#E5E7EB]" data-testid="kpi-strip">
                <Kpi label="Total Messages" value={stats.total} sub={`${stats.outbound} out · ${stats.inbound} in`} />
                <Kpi label="Approvals" value={stats.success} sub={`${stats.success_rate}% success rate`} accent={SUCCESS} />
                <Kpi label="Declines / Errors" value={stats.failed} sub="Non-00 response codes" accent={DANGER} />
                <Kpi
                    label="Plan"
                    value={(stats.plan || "free").toUpperCase()}
                    sub={stats.log_limit == null ? "Unlimited capture" : `${stats.log_limit_used} / ${stats.log_limit} logs used`}
                    accent={KLEIN}
                />
            </section>

            {/* Charts */}
            <section className="grid grid-cols-1 lg:grid-cols-3 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                <div className="bg-white p-5 lg:col-span-2">
                    <div className="flex items-center justify-between mb-3">
                        <div className="text-[11px] uppercase tracking-widest text-[#4B5563]">Traffic · Last 7 days</div>
                        <div className="text-[11px] font-mono text-[#4B5563]">stacked outbound vs inbound</div>
                    </div>
                    <div className="h-64 min-h-[220px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={stats.volume_by_day || []} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
                                <CartesianGrid stroke="#F3F4F6" vertical={false} />
                                <XAxis dataKey="date" stroke="#9CA3AF" fontSize={11} tickLine={false} />
                                <YAxis stroke="#9CA3AF" fontSize={11} tickLine={false} />
                                <Tooltip
                                    contentStyle={{ border: "1px solid #E5E7EB", borderRadius: 0, fontSize: 12 }}
                                    cursor={{ fill: "#F9FAFB" }}
                                />
                                <Bar dataKey="success" stackId="a" fill={SUCCESS} />
                                <Bar dataKey="failed" stackId="a" fill={DANGER} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
                <div className="bg-white p-5">
                    <div className="text-[11px] uppercase tracking-widest text-[#4B5563] mb-3">Auth outcomes</div>
                    <div className="h-64 min-h-[220px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie data={donut} innerRadius={55} outerRadius={85} paddingAngle={0} dataKey="value">
                                    {donut.map((d, i) => (<Cell key={i} fill={d.fill} />))}
                                </Pie>
                                <Legend iconType="square" wrapperStyle={{ fontSize: 11 }} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </section>

            {/* Recent feed + RC breakdown */}
            <section className="grid grid-cols-1 lg:grid-cols-3 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                <div className="bg-white lg:col-span-2" data-testid="recent-feed">
                    <div className="flex items-center justify-between px-5 py-3 border-b border-[#E5E7EB]">
                        <div className="text-[11px] uppercase tracking-widest text-[#4B5563]">Most recent</div>
                        <Link to="/app/logs" className="text-[11px] text-[#002FA7] hover:underline" data-testid="recent-view-all">View all</Link>
                    </div>
                    {(stats.recent || []).length === 0 ? (
                        <div className="p-10 text-center text-sm text-[#4B5563]">
                            No traffic yet. <Link to="/app/builder" className="text-[#002FA7] hover:underline">Send your first message →</Link>
                        </div>
                    ) : (
                        <table className="w-full text-xs font-mono">
                            <thead className="text-[10px] uppercase tracking-widest text-[#9CA3AF]">
                                <tr className="border-b border-[#E5E7EB]">
                                    <th className="text-left py-2 px-5">Time</th>
                                    <th className="text-left py-2">Dir</th>
                                    <th className="text-left py-2">MTI</th>
                                    <th className="text-left py-2">Network</th>
                                    <th className="text-left py-2">Status</th>
                                    <th className="text-left py-2 px-5">Hex</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(stats.recent || []).map((r) => (
                                    <tr key={r.id} className="border-b border-[#F3F4F6]">
                                        <td className="py-2 px-5 text-[#4B5563]">{(r.timestamp || "").replace("T", " ").slice(0, 19)}</td>
                                        <td className="py-2">
                                            <span className="inline-flex items-center gap-1">
                                                <ArrowsDownUp size={11} className={r.direction === "inbound" ? "text-[#16A34A]" : "text-[#002FA7]"} />
                                                {r.direction}
                                            </span>
                                        </td>
                                        <td className="py-2">{r.mti}</td>
                                        <td className="py-2 uppercase">{r.network_id}</td>
                                        <td className="py-2">
                                            {r.status_code === "00" ? (
                                                <span className="inline-flex items-center gap-1 text-[#16A34A]"><CheckCircle size={12} /> 00</span>
                                            ) : r.status_code ? (
                                                <span className="inline-flex items-center gap-1 text-[#E11D48]"><XCircle size={12} /> {r.status_code}</span>
                                            ) : (
                                                <span className="text-[#9CA3AF]">—</span>
                                            )}
                                        </td>
                                        <td className="py-2 px-5 text-[#4B5563] truncate max-w-[280px]">{r.raw_hex?.slice(0, 48)}…</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
                <div className="bg-white p-5" data-testid="rc-breakdown">
                    <div className="text-[11px] uppercase tracking-widest text-[#4B5563] mb-3">Response code mix</div>
                    {(stats.response_code_breakdown || []).length === 0 ? (
                        <div className="text-sm text-[#4B5563]">No inbound data yet.</div>
                    ) : (
                        <ul className="space-y-2 text-xs">
                            {stats.response_code_breakdown.map((rc) => (
                                <li key={rc.code} className="flex items-center justify-between border-b border-[#F3F4F6] pb-2">
                                    <span className="font-mono">{rc.code}</span>
                                    <span className="text-[#4B5563] text-[11px] flex-1 mx-3 truncate">{rc.description}</span>
                                    <span className="font-mono text-[#111827]">{rc.count}</span>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </section>
        </div>
    );
}

const Kpi = ({ label, value, sub, accent }) => (
    <div className="p-5">
        <div className="text-[10px] uppercase tracking-widest text-[#4B5563]">{label}</div>
        <div className="mt-2 text-3xl font-semibold font-mono" style={accent ? { color: accent } : {}}>
            {value ?? "—"}
        </div>
        <div className="mt-1 text-xs text-[#4B5563]">{sub}</div>
    </div>
);
