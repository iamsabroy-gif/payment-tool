# PRD — ISO-8583 Lab

## Original problem statement
Build a SaaS web application for simulating, building, and testing ISO-8583
financial transactions: email/password + Stripe Free/Pro billing, dashboard,
dynamic bitmap-level message builder (fields 1–128), searchable transaction-log
viewer with split-pane detail, and a REST workflow that POSTs an encoded
ISO-8583 payload to an external CBS endpoint.

## Architecture
- **Backend**: FastAPI · Motor/MongoDB · `emergentintegrations` Stripe
  · JWT-cookie auth (bcrypt) · in-house ISO-8583 codec with both ASCII and
  full-fidelity native (binary bitmap, BCD, EBCDIC) wire formats · async
  TCP and WebSocket transports · in-memory session manager with 0800
  heartbeats · 3DES/AES PIN-block helpers · KCV / CVV / PVV / ARQC / ARPC.
- **Frontend**: React 19 (CRA + Craco) · Tailwind 3 · Shadcn / Phosphor /
  Recharts / react-resizable-panels / sonner.
- **Design**: Swiss high-contrast light theme (IBM Plex Sans + JetBrains Mono,
  Klein-Blue accent).

## Personas
- Payment engineers / acquirer test leads exercising VISA, Mastercard, AMEX,
  RuPay traffic.
- QA simulating decline paths and replaying captured traffic from saved templates.

## Implemented
### 2026-02 — MVP
- Email/password auth (bcrypt, httpOnly cookies, brute-force throttling).
- Networks (VISA, Mastercard, AMEX, RuPay) + name overrides.
- Saved templates (free-tier 10-cap), transaction logs (request↔response link).
- ASCII ISO-8583 encoder/decoder + deterministic simulator.
- REST workflow `/api/iso/send` (encode → external endpoint or simulator → log).
- Stripe checkout (Free vs Pro $29/mo) with webhook upgrades.
- Builder, Logs (split-pane), Templates, Pricing, Dashboard (KPIs+charts).

### 2026-02 — Full-fidelity protocol session
- **Codecs**: BCD, EBCDIC, binary bitmap, Track-2 in `iso8583_codecs.py`;
  `wire_format` flag selects `native` (per-network binary) vs `ascii` (debug).
- **TCP transport** (`tcp_transport.py`) with 4 length-header types
  (2-byte BE, 4-byte BE, ASCII-4, none) and optional TLS.
- **WebSocket transport** (`ws_transport.py`) — `wss://…?token=<JWT>`,
  binary or hex-text frames. Same length-framing as TCP.
- **Session manager** (`session_manager.py`) — persistent registry, 0800
  echo heartbeats per profile.
- **Cryptography**: PIN block formats ISO-0/1/3 (3DES + AES), KCV, CVV,
  PVV, ARQC, ARPC (`pin_crypto.py`, `key_management.py`) + UI modals.
- **Sample templates** library with one-click clone (`samples.py`).
- **Connection profiles** w/ live status indicator, heartbeats, edit/connect/
  disconnect, transport-aware UI (TCP vs WebSocket fields).

### 2026-02 — Live WS wiring + secondary-bitmap fix (this session)
- `ConnectionProfile.auth_token` field added — paste a pre-issued JWT directly
  (preferred over username/password). Token is appended to the WS URL as
  `?token=<JWT>` by `ws_transport.open_ws_connection`.
- `Connections.jsx` modal now exposes `transport`, `ws_url`, `auth_token`,
  `ws_text_mode`, `wire_format` and conditionally hides TCP-only / WS-only
  fields. List rows show wss URL or host:port + `wss/tcp` badge.
- `iso8583.decode_message` ASCII branch fixed — when the primary bitmap has
  bit 1 set we now read the secondary 8 bytes BEFORE invoking
  `binary_bitmap_decode` so it no longer raises *secondary bitmap truncated*.
- Live round-trip verified end-to-end against
  `wss://iso8583-server.emergent.host/api/ws/iso8583` with 0800 → 0810 RC=00.
- New unit tests `tests/test_iso8583_codecs.py` (4 tests covering native +
  ASCII round-trips and the secondary-bitmap regression). Full backend
  pytest now 34/34.

## Test credentials
- Admin: `admin@iso8583.dev` / `admin12345` (Pro).
- Live WS upstream JWT (provided by user, expires 2026-05-02): see
  `/app/memory/test_credentials.md`.

## Prioritized backlog
### P1
- CSV / NDJSON export of captured logs (Pro).
- One-click *Replay* on any log row in Logs viewer.
- External-endpoint configurator per-user (drop the URL into Settings).

### P2
- Custom network-spec editor (users add networks + override fields).
- Field-level validation (regex per `format` / `length_type`).
- Team workspaces (shared templates).
- Frontend: silence the rare React hydration warning about a `<span>` inside an
  `<option>` (origin not yet identified — non-functional).

## Code review (carry-over)
- `server.py` — split into `routes/` modules once it crosses ~1500 lines.
- `simulate_response` MTI-increment uses decimal +10; document or use 0x10 nibble bump.
- `update_connection` does not re-validate transport-specific required fields.
- `connect_endpoint` error message hard-codes `host:port` even for WS profiles.
- Migrate `@app.on_event('startup'/'shutdown')` to FastAPI lifespan.
- Add Mongo TTL on stale `login_attempts` rows.

## Notes
- Stripe `billing/status` returns 502 with the Emergent test key (known –
  test suite tolerates 200|502; webhook upgrades the user regardless).
