import { Link } from "react-router-dom";
import { ArrowRight, Lightning, Code, CreditCard, ShieldCheck, Wrench } from "@phosphor-icons/react";

export default function Landing() {
    return (
        <div className="min-h-screen bg-white text-[#111827]">
            <header className="border-b border-[#E5E7EB]">
                <div className="max-w-7xl mx-auto flex items-center justify-between px-6 h-14">
                    <div className="flex items-center gap-2 font-semibold tracking-tight">
                        <Lightning weight="fill" size={18} className="text-[#002FA7]" />
                        ISO-8583 LAB
                    </div>
                    <div className="flex items-center gap-1">
                        <Link to="/login" data-testid="nav-login" className="text-sm px-4 h-9 flex items-center hover:bg-gray-50">Sign in</Link>
                        <Link to="/register" data-testid="nav-register" className="text-sm px-4 h-9 flex items-center bg-[#002FA7] text-white hover:bg-[#002080]">
                            Get started <ArrowRight size={14} className="ml-2" />
                        </Link>
                    </div>
                </div>
            </header>

            <section className="grid-bg border-b border-[#E5E7EB]">
                <div className="max-w-7xl mx-auto px-6 py-24 grid grid-cols-12 gap-6">
                    <div className="col-span-12 lg:col-span-7">
                        <div className="text-[11px] tracking-[0.2em] uppercase text-[#4B5563] mb-6" data-testid="hero-eyebrow">
                            Build · Simulate · Capture
                        </div>
                        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold tracking-tight leading-[1.05] max-w-3xl">
                            The precision instrument for <span className="text-[#002FA7]">ISO-8583</span> payment engineers.
                        </h1>
                        <p className="mt-6 max-w-xl text-base leading-relaxed text-[#4B5563]">
                            Compose authorization messages with bitmap-level control. Capture every byte on the wire.
                            Re-run traffic against VISA, Mastercard, AMEX and RuPay field catalogues — all from a single cockpit.
                        </p>
                        <div className="mt-8 flex gap-3">
                            <Link to="/register" data-testid="hero-cta-primary" className="h-10 px-5 flex items-center bg-[#002FA7] text-white hover:bg-[#002080] text-sm font-medium">
                                Start building free
                            </Link>
                            <Link to="/login" data-testid="hero-cta-secondary" className="h-10 px-5 flex items-center border border-gray-300 hover:bg-gray-50 text-sm">
                                Sign in
                            </Link>
                        </div>
                        <div className="mt-10 grid grid-cols-3 gap-6 max-w-lg text-xs">
                            <Stat value="128" label="Addressable data elements" />
                            <Stat value="1987" label="ISO-8583 revision" />
                            <Stat value="4" label="Pre-loaded networks" />
                        </div>
                    </div>
                    <div className="col-span-12 lg:col-span-5 border border-[#E5E7EB] bg-white p-5 font-mono text-[11px] leading-relaxed">
                        <div className="flex items-center justify-between text-[10px] uppercase tracking-widest text-[#4B5563] mb-3 pb-2 border-b border-[#E5E7EB]">
                            <span>pos_auth_0200.iso</span>
                            <span className="text-[#16A34A]">● LIVE</span>
                        </div>
                        <pre className="text-[11px] text-[#111827] whitespace-pre-wrap break-all">
{`MTI        : 0200 (Authorization Request)
BITMAP     : 7234 4501 A8E0 8000
[002] PAN      4111111111111111
[003] PROC     000000
[004] AMOUNT   000000012500   // 125.00 USD
[007] TRN      0221143055
[011] STAN     000001
[041] TERMID   POS00012
[049] CURRENCY 840`}
                        </pre>
                        <div className="mt-4 pt-3 border-t border-[#E5E7EB] text-[10px] uppercase tracking-widest text-[#4B5563]">
                            → Response 0210 · <span className="text-[#16A34A]">[039] 00 Approved · AUTH 512904</span>
                        </div>
                    </div>
                </div>
            </section>

            <section className="border-b border-[#E5E7EB]">
                <div className="max-w-7xl mx-auto px-6 py-20 grid grid-cols-12 gap-6">
                    <div className="col-span-12 lg:col-span-4">
                        <div className="text-[11px] uppercase tracking-[0.2em] text-[#002FA7]">01 · Capabilities</div>
                        <h2 className="text-3xl font-semibold tracking-tight mt-3">Designed for the acquirer's bench.</h2>
                    </div>
                    <div className="col-span-12 lg:col-span-8 grid grid-cols-1 md:grid-cols-2 gap-px bg-[#E5E7EB] border border-[#E5E7EB]">
                        <Feature Icon={Wrench} title="Bitmap-level builder" body="Toggle fields 1–128 on a 16-column grid. Primary and secondary bitmaps recompute in real time." />
                        <Feature Icon={Code} title="Hex & parsed split-pane" body="Every captured message gets a raw hex pane and a decoded field-by-field JSON pane." />
                        <Feature Icon={ShieldCheck} title="Deterministic simulator" body="Built-in authorization host with realistic response codes — no network dependency to test." />
                        <Feature Icon={CreditCard} title="Multi-network specs" body="VISA Base I, Mastercard CIS, AMEX GCAG and RuPay (NPCI) profiles ship out of the box." />
                    </div>
                </div>
            </section>

            <footer className="text-xs text-[#4B5563]">
                <div className="max-w-7xl mx-auto px-6 py-6 flex items-center justify-between">
                    <div>© {new Date().getFullYear()} ISO-8583 Lab · Built for payments engineers.</div>
                    <Link to="/login" data-testid="footer-login-link" className="hover:text-[#111827]">Access</Link>
                </div>
            </footer>
        </div>
    );
}

const Stat = ({ value, label }) => (
    <div>
        <div className="text-2xl font-semibold font-mono">{value}</div>
        <div className="text-[#4B5563] mt-1">{label}</div>
    </div>
);

const Feature = ({ Icon, title, body }) => (
    <div className="bg-white p-6">
        <Icon size={22} weight="regular" className="text-[#002FA7]" />
        <div className="mt-4 text-base font-medium">{title}</div>
        <div className="mt-1 text-sm text-[#4B5563] leading-relaxed">{body}</div>
    </div>
);
