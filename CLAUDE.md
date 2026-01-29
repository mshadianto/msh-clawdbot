# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Clawdbot is a WhatsApp chatbot that uses Groq's Llama 3.3 70B model for AI responses. It connects to WAHA (WhatsApp HTTP API) to send/receive messages via webhooks. The entire application is a single-file Node.js Express server (`index-secure.js`).

## Commands

```bash
# Install dependencies
pnpm install

# Run in development (auto-reload on file changes)
npm run dev

# Run in production
npm start

# Docker deployment (all services)
docker-compose up -d --build
```

There are no tests or linting configured.

## Architecture

**Single-file design:** All application logic lives in `index-secure.js` (~566 lines). The file uses ES5-compatible patterns with `require()` (despite `"type": "module"` in package.json — it actually uses CommonJS).

**Key sections in `index-secure.js` (in order):**

1. **Logger** — Winston with timestamp formatting
2. **Config** — Environment variables with defaults
3. **Encryption** — AES-256-CBC encrypt/decrypt for conversation history stored in memory
4. **ConversationStore** — In-memory Map storing encrypted per-chat message histories (not persisted across restarts)
5. **Groq AI Client** — OpenAI SDK configured to use Groq's API endpoint
6. **Metrics** — In-memory request/reply/error counters with daily reset
7. **Rate Limiting** — Two layers: Express `express-rate-limit` (60 req/min per IP) and custom per-user sliding window (10 msg/min per chat)
8. **Input Sanitization** — Regex-based prompt injection detection and message length cap (4000 chars)
9. **WAHA Helpers** — Typing indicators, message sending, human-like delays (2-5s), message chunking (3000 char split)
10. **Bot Mention Detection** — Group chat logic: only responds when @mentioned or nickname used
11. **Command Handlers** — `/reset`, `/help`, `/stats`
12. **Express Endpoints** — `POST /webhook` (main handler), `GET /health`, `GET /metrics` (optional Bearer token)

**Infrastructure (docker-compose.yml):**
- `waha` — WhatsApp HTTP API service (port 3000, local only)
- `clawdbot` — This application (port 3001, local only)
- `linkedin-monitor` — Separate service for LinkedIn monitoring
- `nginx` — Reverse proxy (ports 80/443, public-facing) with rate limiting and security headers
- All containers use read-only filesystems, `no-new-privileges`, and `cap_drop: ALL`

**Message flow:** WAHA receives WhatsApp messages → sends webhook POST to clawdbot → clawdbot validates signature → deduplicates → checks rate limits → sanitizes input → calls Groq AI → sends reply back through WAHA.

## Environment Variables

Required: `GROQ_API_KEY`, `WAHA_API_KEY`, `WEBHOOK_SECRET`, `ENCRYPTION_PASSWORD`

Optional: `SYSTEM_PROMPT`, `MAX_HISTORY` (default 20), `WAHA_API_URL` (default `http://waha:3000`), `PORT` (default 3001), `ALERT_CHAT_ID`, `METRICS_TOKEN`, `ADMIN_PHONE`, `ALLOWED_USERS`

## Key Conventions

- Bot responds in all DMs but only when @mentioned in group chats (`@g.us` suffix)
- Rate limit messages and the empty-mention fallback are in Indonesian ("Terlalu banyak pesan...", "Halo")
- `index.js` and `index-secure.js` are the same file; `index-secure.js` is the production entry point
- The `@anthropic-ai/sdk` dependency in package.json is unused legacy — the bot uses OpenAI SDK pointed at Groq
