# Clawdbot

A WhatsApp chatbot powered by Groq AI (Llama 3.3 70B) via [WAHA](https://github.com/devlikeapro/waha) (WhatsApp HTTP API).

## Features

- AI-powered conversations using Groq's Llama 3.3 70B model
- Group chat support (responds only when @mentioned)
- Encrypted in-memory conversation history (AES-256-CBC)
- Per-user and per-IP rate limiting
- Input sanitization with prompt injection detection
- Human-like typing delays
- Built-in metrics and alerting
- Docker deployment with security hardening (read-only filesystems, no-new-privileges, dropped capabilities)

## Setup

### Prerequisites

- Node.js 18+
- A [WAHA](https://github.com/devlikeapro/waha) instance
- A [Groq](https://console.groq.com/) API key

### Environment Variables

Create a `.env` file:

```env
GROQ_API_KEY=your-groq-api-key
WAHA_API_KEY=your-waha-api-key
WEBHOOK_SECRET=your-webhook-hmac-secret
ENCRYPTION_PASSWORD=your-encryption-password
```

Optional:

| Variable | Default | Description |
|---|---|---|
| `SYSTEM_PROMPT` | Generic assistant prompt | AI system prompt |
| `MAX_HISTORY` | `20` | Messages per conversation |
| `WAHA_API_URL` | `http://waha:3000` | WAHA service URL |
| `PORT` | `3001` | Server port |
| `METRICS_TOKEN` | _(open)_ | Bearer token for `/metrics` endpoint |
| `ALERT_CHAT_ID` | _(disabled)_ | WhatsApp chat ID for error alerts |

### Run Locally

```bash
pnpm install
npm run dev
```

### Run with Docker

```bash
docker-compose up -d --build
```

This starts four services: WAHA, Clawdbot, a LinkedIn monitor, and an Nginx reverse proxy.

## Bot Commands

| Command | Description |
|---|---|
| `/reset` | Clear conversation history |
| `/help` | Show available commands |
| `/stats` | Show chat and bot statistics |

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/webhook` | POST | WAHA webhook receiver (HMAC-validated) |
| `/health` | GET | Health check |
| `/metrics` | GET | Bot metrics (optional Bearer auth) |
