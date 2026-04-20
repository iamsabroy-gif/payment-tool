# PRD — ISO-8583 Lab

## Original problem statement
Build a SaaS web application for simulating, building, and testing ISO-8583 financial transactions, with email/password + Stripe Free/Pro billing, a dashboard, a dynamic bitmap-level message builder (fields 1–128), a searchable transaction log viewer with split-pane detail, and a REST workflow that POSTs a JSON payload to an external API and displays the response.

## Architecture
- **Backend**: FastAPI (Python), Motor/MongoDB, emergentintegrations Stripe checkout, JWT cookie auth (bcrypt), in-house ISO-8583 encoder/decoder + deterministic simulator.
- **Frontend**: React 19 (CRA + Craco), Tailwind 3, Shadcn components where used, Recharts for data viz, react-resizable-panels for split-pane log viewer, Phosphor icons, Sonner toasts.
- **Design**: Swiss & High-Contrast Light theme (IBM Plex Sans + JetBrains Mono, Klein Blue #002FA7 accent).

## Personas
- Payment engineers / acquirer test leads exercising ISO-8583 traffic against VISA, Mastercard and AMEX profiles.
- QA simulating decline paths and replaying transaction traffic from saved templates.

## Implemented (2026-02)
- Email/password registration + login with httpOnly access/refresh cookies; admin seeded at `admin@iso8583.dev`.
- Brute-force throttling on login (5/15min), MongoDB indexes + spec seeding on startup.
- Message Specs: VISA, Mastercard, AMEX with base ISO-8583:1987 catalogue + network-specific name overrides (F48/F61/F62/F63).
- Saved templates (create/list/delete) with 10-template free-tier cap.
- Transaction logs collection (direction, raw hex, base64, parsed JSON, status code, related_id linking request↔response).
- ISO-8583 in-house encoder/decoder (ASCII payload, LLVAR/LLLVAR prefixes, primary+secondary bitmap). Deterministic simulator generates realistic response codes.
- REST workflow: `/api/iso/send` encodes → calls external endpoint (or internal simulator) → persists both outbound & inbound logs → returns them to the UI.
- Stripe checkout (Free vs Pro @ $29/mo) with `payment_transactions` collection; status endpoint degrades gracefully when test key can't retrieve session state; webhook also promotes user plan.
- Frontend: Landing / Login / Register / Dashboard (KPIs + 7-day volume stacked bar + donut + recent feed + RC breakdown) / Builder (16×8 primary + 16×4 secondary bitmap, dynamic DE inputs, preview, send, save) / Templates / Logs (split-pane detail w/ resizable panels) / Pricing / Checkout return.

## Prioritized backlog
### P1 (next session)
- External endpoint configurator per-user (store in profile) so Pro users can point `send transaction` at their own host.
- CSV / NDJSON export of captured logs (Pro).
- Re-send / Replay button on a log row.

### P2
- Custom network spec editor (users can add new networks + override fields).
- Field-level validation (regex per `format`/`length_type`).
- Team workspaces (shared templates).

## Notes
- Stripe status polling returns a cached "pending" state if the live status call fails (test-mode limitation); webhook still upgrades user.
- Recharts ResponsiveContainer wrappers use `min-h-[220px]` to avoid `width/height=-1` warnings on initial mount.
