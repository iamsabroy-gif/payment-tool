import React, { useEffect, useState } from "react";
import { api } from "../lib/api";

const COLORS = {
    pass: "text-[#16A34A]",
    fail: "text-[#E11D48]",
    skipped: "text-[#9CA3AF]",
};

/** Simulator issuer checks: [{check, result: pass|fail|skipped, detail}] */
export function CryptoChecks({ checks, testid = "crypto-checks" }) {
    if (!checks || checks.length === 0) return null;
    return (
        <ul className="space-y-1 text-[11px]" data-testid={testid}>
            {checks.map((c) => (
                <li key={c.check} className="flex gap-2">
                    <span className={`w-16 font-semibold uppercase ${COLORS[c.result] || ""}`}>{c.result}</span>
                    <span className="w-28 text-[#111827]">{c.check}</span>
                    <span className="text-[#4B5563]">{c.detail}</span>
                </li>
            ))}
        </ul>
    );
}

/** Key-set picker for simulator runs. Value "" = no cryptogram checks. */
export function KeysetSelect({ value, onChange, testid = "keyset-select" }) {
    const [keysets, setKeysets] = useState([]);
    useEffect(() => {
        api.get("/user-keys").then((r) => setKeysets(r.data)).catch(() => {});
    }, []);
    return (
        <div className="mt-2">
            <label className="text-[10px] uppercase tracking-widest text-[#4B5563]">Verify cryptograms with</label>
            <select
                data-testid={testid}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                className="mt-1 w-full h-9 border border-gray-300 px-2 text-sm bg-white"
            >
                <option value="">No checks</option>
                {keysets.map((k) => (
                    <option key={k.id} value={k.id}>{k.name}</option>
                ))}
            </select>
            {value && (
                <div className="mt-1 text-[10px] text-[#4B5563]">
                    Checks ARQC (F55), track 2 CVV (F35) and PIN/PVV (F52; PIN key in extras as ZPK, PEK or TPK).
                </div>
            )}
        </div>
    );
}
