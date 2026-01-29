const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const OpenAI = require("openai");
const axios = require("axios");
const crypto = require("crypto");
const winston = require("winston");

// ─── Logger ────────────────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}`;
    })
  ),
  transports: [new winston.transports.Console()],
});

// ─── Config ────────────────────────────────────────────────────────────────────
const PORT = 3001;
const WAHA_API_URL = process.env.WAHA_API_URL || "http://waha:3000";
const WAHA_API_KEY = process.env.WAHA_API_KEY || "";
const GROQ_API_KEY = process.env.GROQ_API_KEY || "";
const SYSTEM_PROMPT =
  process.env.SYSTEM_PROMPT ||
  "You are a helpful assistant on WhatsApp. Keep responses concise and conversational.";
const MAX_HISTORY = parseInt(process.env.MAX_HISTORY || "20", 10);
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";
const ENCRYPTION_PASSWORD = process.env.ENCRYPTION_PASSWORD || "";
const ALERT_CHAT_ID = process.env.ALERT_CHAT_ID || "";
const METRICS_TOKEN = process.env.METRICS_TOKEN || "";

// ─── Encryption ────────────────────────────────────────────────────────────────
const ENCRYPTION_KEY = ENCRYPTION_PASSWORD
  ? crypto.scryptSync(ENCRYPTION_PASSWORD, "clawdbot-salt", 32)
  : null;

function encrypt(text) {
  if (!ENCRYPTION_KEY) return text;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(text) {
  if (!ENCRYPTION_KEY) return text;
  const parts = text.split(":");
  const iv = Buffer.from(parts[0], "hex");
  const encrypted = parts.slice(1).join(":");
  const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ─── Secure Conversation Store ─────────────────────────────────────────────────
class ConversationStore {
  constructor() {
    this.store = new Map();
  }

  getHistory(chatId) {
    if (!this.store.has(chatId)) return [];
    try {
      return JSON.parse(decrypt(this.store.get(chatId)));
    } catch (err) {
      logger.error(`Decrypt error for ${chatId}, resetting history`);
      this.store.delete(chatId);
      return [];
    }
  }

  saveHistory(chatId, history) {
    this.store.set(chatId, encrypt(JSON.stringify(history)));
  }

  addMessage(chatId, role, content) {
    const history = this.getHistory(chatId);
    history.push({ role, content });
    if (history.length > MAX_HISTORY) {
      history.splice(0, history.length - MAX_HISTORY);
    }
    this.saveHistory(chatId, history);
  }

  clear(chatId) {
    this.store.delete(chatId);
  }

  get size() {
    return this.store.size;
  }
}

const conversations = new ConversationStore();
const processedMessages = new Set();

// ─── Groq AI Client ───────────────────────────────────────────────────────────
const groq = new OpenAI({
  apiKey: GROQ_API_KEY,
  baseURL: "https://api.groq.com/openai/v1",
});

// ─── Metrics ───────────────────────────────────────────────────────────────────
const metrics = {
  totalRequests: 0,
  totalReplies: 0,
  errorCount: 0,
  blockedCount: 0,
  rateLimitedCount: 0,
  commandsHandled: 0,
  tokensUsed: 0,
  startTime: Date.now(),
  dailyReset: new Date().toISOString().split("T")[0],
  daily: {
    requests: 0,
    replies: 0,
    errors: 0,
  },
};

function resetDailyMetrics() {
  const today = new Date().toISOString().split("T")[0];
  if (metrics.dailyReset !== today) {
    logger.info(`Daily metrics reset (previous: ${metrics.dailyReset})`);
    metrics.daily = { requests: 0, replies: 0, errors: 0 };
    metrics.dailyReset = today;
  }
}

// ─── Rate Limiting ─────────────────────────────────────────────────────────────
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW = 60000;
const userLimiters = new Map();

function getUserLimiter(chatId) {
  if (!userLimiters.has(chatId)) {
    const messages = [];
    userLimiters.set(chatId, {
      messages,
      check: function () {
        const now = Date.now();
        while (messages.length > 0 && now - messages[0] > RATE_LIMIT_WINDOW) {
          messages.shift();
        }
        if (messages.length >= RATE_LIMIT_MAX) {
          return false;
        }
        messages.push(now);
        return true;
      },
    });
  }
  return userLimiters.get(chatId);
}

// ─── Input Sanitization ───────────────────────────────────────────────────────
const DANGEROUS_PATTERNS = [
  /ignore.*previous.*instructions/gi,
  /you are now/gi,
  /jailbreak/gi,
  /pretend you are/gi,
  /disregard.*system.*prompt/gi,
  /override.*instructions/gi,
];
const MAX_MESSAGE_LENGTH = 4000;

function sanitizeInput(text) {
  if (!text) return null;
  for (let i = 0; i < DANGEROUS_PATTERNS.length; i++) {
    DANGEROUS_PATTERNS[i].lastIndex = 0;
    if (DANGEROUS_PATTERNS[i].test(text)) return null;
  }
  if (text.length > MAX_MESSAGE_LENGTH) {
    return text.substring(0, MAX_MESSAGE_LENGTH);
  }
  return text;
}

// ─── Safe Logging ──────────────────────────────────────────────────────────────
function safeLog(chatId, message) {
  const masked = message.replace(/\d{10,}/g, "***REDACTED***");
  logger.info(`[${chatId}] ${masked.substring(0, 100)}`);
}

// ─── WAHA Helpers ──────────────────────────────────────────────────────────────
let botId = null;

async function startTyping(chatId, session) {
  try {
    await axios.post(
      WAHA_API_URL + "/api/startTyping",
      { chatId, session: session || "default" },
      { headers: { "X-Api-Key": WAHA_API_KEY, "Content-Type": "application/json" } }
    );
  } catch (err) {}
}

async function stopTyping(chatId, session) {
  try {
    await axios.post(
      WAHA_API_URL + "/api/stopTyping",
      { chatId, session: session || "default" },
      { headers: { "X-Api-Key": WAHA_API_KEY, "Content-Type": "application/json" } }
    );
  } catch (err) {}
}

async function sendWahaReply(chatId, text, session) {
  try {
    await axios.post(
      WAHA_API_URL + "/api/sendText",
      { chatId, text, session: session || "default" },
      { headers: { "X-Api-Key": WAHA_API_KEY, "Content-Type": "application/json" } }
    );
  } catch (err) {
    logger.error(`Failed to send reply to ${chatId}: ${err.message}`);
  }
}

function humanDelay() {
  const ms = 2000 + Math.random() * 3000;
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function splitMessage(text, maxLen) {
  maxLen = maxLen || 3000;
  if (text.length <= maxLen) return [text];
  const chunks = [];
  let remaining = text;
  while (remaining.length > 0) {
    if (remaining.length <= maxLen) {
      chunks.push(remaining);
      break;
    }
    let splitAt = remaining.lastIndexOf("\n", maxLen);
    if (splitAt < maxLen * 0.5) splitAt = remaining.lastIndexOf(". ", maxLen);
    if (splitAt < maxLen * 0.5) splitAt = maxLen;
    chunks.push(remaining.substring(0, splitAt + 1).trim());
    remaining = remaining.substring(splitAt + 1).trim();
  }
  return chunks;
}

// ─── Alerts ────────────────────────────────────────────────────────────────────
function sendAlert(text) {
  if (!ALERT_CHAT_ID) return;
  sendWahaReply(ALERT_CHAT_ID, "[ALERT] " + text, "default").catch(function () {});
}

function checkMetrics() {
  resetDailyMetrics();
  if (metrics.errorCount > 0 && metrics.errorCount % 50 === 0) {
    sendAlert("Error count: " + metrics.errorCount);
  }
  if (metrics.rateLimitedCount > 0 && metrics.rateLimitedCount % 20 === 0) {
    sendAlert("Rate limited " + metrics.rateLimitedCount + " times");
  }
}

// ─── Bot Mention Detection ─────────────────────────────────────────────────────
const BOT_NICKNAMES = ["@ms hadianto", "@bot", "@ai"];

function isBotMentioned(payload) {
  const body = (payload.body || "").toLowerCase();
  if (botId) {
    const botNumber = botId.split("@")[0];
    if (body.includes("@" + botNumber)) return true;
  }
  for (let i = 0; i < BOT_NICKNAMES.length; i++) {
    if (body.includes(BOT_NICKNAMES[i])) return true;
  }
  const mentioned = payload.mentionedIds || [];
  const dataList = (payload._data && payload._data.mentionedJidList) || [];
  const all = mentioned.concat(dataList);
  if (botId) {
    const botNumber = botId.split("@")[0];
    for (let i = 0; i < all.length; i++) {
      const id = typeof all[i] === "string" ? all[i] : all[i]._serialized || "";
      if (id === botId || id.includes(botNumber)) return true;
    }
  }
  return false;
}

// ─── AI ────────────────────────────────────────────────────────────────────────
async function askAI(chatId, userMessage) {
  conversations.addMessage(chatId, "user", userMessage);

  const response = await groq.chat.completions.create({
    model: "llama-3.3-70b-versatile",
    max_tokens: 1024,
    messages: [{ role: "system", content: SYSTEM_PROMPT }, ...conversations.getHistory(chatId)],
  });

  const reply = response.choices[0].message.content;
  conversations.addMessage(chatId, "assistant", reply);

  // Track token usage
  if (response.usage) {
    metrics.tokensUsed += (response.usage.total_tokens || 0);
  }

  return reply;
}

// ─── Command Handlers ──────────────────────────────────────────────────────────
const COMMANDS = {
  "/reset": async function (chatId, session) {
    conversations.clear(chatId);
    await humanDelay();
    await sendWahaReply(chatId, "Conversation reset. Start fresh!", session);
    return true;
  },

  "/help": async function (chatId, session) {
    const helpText =
      "*Clawdbot Commands:*\n\n" +
      "/reset - Clear conversation history\n" +
      "/help - Show this help message\n" +
      "/stats - Show your chat statistics\n\n" +
      "_Powered by Groq AI (Llama 3.3 70B)_";
    await humanDelay();
    await sendWahaReply(chatId, helpText, session);
    return true;
  },

  "/stats": async function (chatId, session) {
    const history = conversations.getHistory(chatId);
    const userMsgs = history.filter((m) => m.role === "user").length;
    const aiMsgs = history.filter((m) => m.role === "assistant").length;
    const uptime = Math.floor((Date.now() - metrics.startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const mins = Math.floor((uptime % 3600) / 60);

    const statsText =
      "*Your Chat Stats:*\n\n" +
      `Messages sent: ${userMsgs}\n` +
      `Replies received: ${aiMsgs}\n` +
      `History size: ${history.length}/${MAX_HISTORY}\n\n` +
      "*Bot Stats:*\n" +
      `Uptime: ${hours}h ${mins}m\n` +
      `Total requests: ${metrics.totalRequests}\n` +
      `Total replies: ${metrics.totalReplies}\n` +
      `Tokens used: ${metrics.tokensUsed}\n` +
      `Active chats: ${conversations.size}`;
    await humanDelay();
    await sendWahaReply(chatId, statsText, session);
    return true;
  },
};

async function handleCommand(command, chatId, session) {
  const handler = COMMANDS[command];
  if (handler) {
    metrics.commandsHandled++;
    await handler(chatId, session);
    return true;
  }
  return false;
}

// ─── Express App ───────────────────────────────────────────────────────────────
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

const ipLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: "Too many requests" },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Webhook Endpoint ──────────────────────────────────────────────────────────
app.post("/webhook", ipLimiter, async (req, res) => {
  // Validate webhook signature
  if (WEBHOOK_SECRET) {
    const signature = req.headers["x-webhook-signature"];
    const expectedSignature = crypto
      .createHmac("sha256", WEBHOOK_SECRET)
      .update(JSON.stringify(req.body))
      .digest("hex");

    if (signature !== expectedSignature) {
      logger.warn("[AUTH] Invalid webhook signature");
      return res.status(401).json({ error: "Unauthorized" });
    }
  }

  // Validate WAHA API key
  if (WAHA_API_KEY) {
    const apiKey = req.headers["x-api-key"];
    if (apiKey && apiKey !== WAHA_API_KEY) {
      return res.status(401).json({ error: "Invalid API key" });
    }
  }

  res.status(200).json({ ok: true });
  metrics.totalRequests++;
  metrics.daily.requests++;

  const event = req.body;
  if (!event || !event.payload) return;

  // Capture bot ID
  if (event.me && event.me.id && !botId) {
    botId = event.me.id;
    logger.info(`[BOT] ID set to: ${botId}`);
  }

  const payload = event.payload;
  const msgId = payload.id;

  // Deduplicate
  if (processedMessages.has(msgId)) return;
  processedMessages.add(msgId);
  if (processedMessages.size > 1000) {
    const first = processedMessages.values().next().value;
    processedMessages.delete(first);
  }

  const isFromMe = payload.fromMe;
  const chatId = payload.from;
  const body = payload.body;
  const session = event.session || "default";
  const isGroup = chatId.indexOf("@g.us") !== -1;

  if (isFromMe || !body) return;

  // GROUP: only respond when bot is mentioned
  if (isGroup) {
    if (!isBotMentioned(payload)) return;
    logger.info(`[GROUP] ${chatId} - Bot mentioned`);
  }

  // Per-user rate limit
  if (!getUserLimiter(chatId).check()) {
    logger.warn(`[RATE-LIMIT] ${chatId} exceeded ${RATE_LIMIT_MAX} msgs/min`);
    metrics.rateLimitedCount++;
    await sendWahaReply(chatId, "Terlalu banyak pesan. Tunggu 1 menit ya.", session);
    return;
  }

  // Strip mention tags from message
  let cleanBody = body;
  if (isGroup) {
    if (botId) {
      const botNumber = botId.split("@")[0];
      cleanBody = cleanBody.replace(new RegExp("@" + botNumber + "\\s*", "gi"), "");
    }
    BOT_NICKNAMES.forEach(function (nick) {
      cleanBody = cleanBody.replace(
        new RegExp(nick.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*", "gi"),
        ""
      );
    });
    cleanBody = cleanBody.trim();
    if (!cleanBody) cleanBody = "Halo";
  }

  // Check commands first (before sanitization)
  const trimmed = cleanBody.trim().toLowerCase();
  if (await handleCommand(trimmed, chatId, session)) return;

  // Sanitize input
  cleanBody = sanitizeInput(cleanBody);
  if (!cleanBody) {
    logger.warn(`[BLOCKED] ${chatId} - prompt injection attempt`);
    metrics.blockedCount++;
    await sendWahaReply(chatId, "Pesan tidak valid.", session);
    return;
  }

  safeLog(chatId, ">> " + cleanBody);

  try {
    await startTyping(chatId, session);

    const reply = await askAI(chatId, cleanBody);
    metrics.totalReplies++;
    metrics.daily.replies++;
    safeLog(chatId, "<< " + reply);

    await humanDelay();
    await stopTyping(chatId, session);

    const chunks = splitMessage(reply);
    for (let i = 0; i < chunks.length; i++) {
      if (i > 0) {
        await startTyping(chatId, session);
        await humanDelay();
        await stopTyping(chatId, session);
      }
      await sendWahaReply(chatId, chunks[i], session);
    }
  } catch (err) {
    metrics.errorCount++;
    metrics.daily.errors++;
    logger.error(`AI error for ${chatId}: ${err.message}`);
    await stopTyping(chatId, session);
    await humanDelay();
    await sendWahaReply(chatId, "Sorry, something went wrong. Please try again.", session);
  }
});

// ─── Health Endpoint ───────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    conversations: conversations.size,
    botId,
    model: "llama-3.3-70b-versatile (Groq)",
  });
});

// ─── Protected Metrics Endpoint ────────────────────────────────────────────────
app.get("/metrics", (req, res) => {
  if (METRICS_TOKEN) {
    const token = req.headers["authorization"];
    if (token !== `Bearer ${METRICS_TOKEN}`) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  }

  resetDailyMetrics();
  const uptime = Math.floor((Date.now() - metrics.startTime) / 1000);

  res.json({
    status: "ok",
    uptime,
    conversations: conversations.size,
    botId,
    model: "llama-3.3-70b-versatile (Groq)",
    metrics: {
      ...metrics,
      uptimeFormatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`,
    },
  });
});

// ─── Start ─────────────────────────────────────────────────────────────────────
setInterval(checkMetrics, 60000);

app.listen(PORT, () => {
  logger.info("Clawdbot v2.0 running on port " + PORT);
  logger.info("WAHA API: " + WAHA_API_URL);
  logger.info("AI: Groq (llama-3.3-70b-versatile)");
  logger.info("History limit: " + MAX_HISTORY + " messages per chat");
  logger.info("Rate limit: " + RATE_LIMIT_MAX + " msgs per " + RATE_LIMIT_WINDOW / 1000 + "s per chat");
  logger.info("Group support: reply on mention only");
  logger.info("Security: helmet, encryption, rate-limit, sanitization, signature validation");
  logger.info("Commands: /reset, /help, /stats");
  if (METRICS_TOKEN) {
    logger.info("Metrics endpoint: protected with token");
  } else {
    logger.info("Metrics endpoint: open (set METRICS_TOKEN to protect)");
  }
});
