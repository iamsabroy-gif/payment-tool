import { NavLink, Outlet, Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import {
    ChartBar,
    Wrench,
    BookBookmark,
    ListDashes,
    CreditCard,
    SignOut,
    Lightning,
    Plug,
} from "@phosphor-icons/react";

const NAV = [
    { to: "/app", label: "Dashboard", icon: ChartBar, end: true, testid: "nav-dashboard" },
    { to: "/app/builder", label: "Builder", icon: Wrench, testid: "nav-builder" },
    { to: "/app/templates", label: "Templates", icon: BookBookmark, testid: "nav-templates" },
    { to: "/app/logs", label: "Logs", icon: ListDashes, testid: "nav-logs" },
    { to: "/app/connections", label: "Connections", icon: Plug, testid: "nav-connections" },
    { to: "/app/pricing", label: "Billing", icon: CreditCard, testid: "nav-pricing" },
];

export default function AppShell() {
    const { user, logout } = useAuth();
    return (
        <div className="min-h-screen grid grid-cols-[220px_1fr] bg-white">
            <aside className="border-r border-[#E5E7EB] flex flex-col">
                <Link
                    to="/app"
                    className="h-14 flex items-center gap-2 px-5 border-b border-[#E5E7EB] font-semibold tracking-tight"
                    data-testid="sidebar-logo"
                >
                    <Lightning weight="fill" size={18} className="text-[#002FA7]" />
                    <span>ISO-8583 LAB</span>
                </Link>
                <nav className="flex-1 py-3">
                    {NAV.map(({ to, label, icon: Icon, end, testid }) => (
                        <NavLink
                            key={to}
                            to={to}
                            end={end}
                            data-testid={testid}
                            className={({ isActive }) =>
                                `flex items-center gap-3 px-5 py-2.5 text-sm border-l-2 transition-colors ${
                                    isActive
                                        ? "border-[#002FA7] bg-[#F3F4F6] text-[#111827] font-medium"
                                        : "border-transparent text-[#4B5563] hover:bg-[#F9FAFB]"
                                }`
                            }
                        >
                            <Icon size={16} weight="regular" />
                            {label}
                        </NavLink>
                    ))}
                </nav>
                <div className="border-t border-[#E5E7EB] p-4 text-xs space-y-2">
                    <div className="flex items-center justify-between">
                        <span className="truncate text-[#4B5563]" data-testid="sidebar-user-email">
                            {user?.email}
                        </span>
                        <span
                            className={`text-[10px] tracking-widest uppercase px-1.5 py-0.5 border ${
                                user?.plan === "pro"
                                    ? "border-[#002FA7] text-[#002FA7]"
                                    : "border-gray-300 text-[#4B5563]"
                            }`}
                            data-testid="sidebar-plan-badge"
                        >
                            {user?.plan || "free"}
                        </span>
                    </div>
                    <button
                        onClick={logout}
                        data-testid="logout-btn"
                        className="w-full flex items-center justify-center gap-2 h-8 text-xs border border-gray-300 hover:bg-gray-50"
                    >
                        <SignOut size={14} /> Sign out
                    </button>
                </div>
            </aside>
            <main className="min-h-screen">
                <Outlet />
            </main>
        </div>
    );
}
