/**
 * ABA PayWay Telegram Group Listener Bridge — Strict Shop Chat ID Whitelist Edition (listener.mjs)
 *
 * ROOT CAUSES FIXED IN THIS VERSION:
 * 1. STRICT FAIL-CLOSED CHAT ID WHITELIST:
 *    - Previously, `if (allowedChatIds.length === 0) return true` and `if (!stripped) return true`
 *      caused the listener to scan and save ABA PayWay messages from ALL Telegram groups the user
 *      belonged to (e.g. "-5207801009", "-5433742888") even when those shops had NOT enabled
 *      ABA PayWay Auto-Verification!
 *    - Now dynamically syncs the `shops` collection from Firestore and ONLY allows Chat IDs
 *      belonging to shops where `khqrConfig.paywayVerifyEnabled !== false` and `khqrConfig.paywayChatId`
 *      is explicitly configured (plus any explicit `PAYWAY_CHAT_ID` env var).
 *    - Fails closed (`return false`) if `chatId` is missing or not in the active whitelist!
 * 2. REMOVED `prewarmFirestoreChannel()` 45-second heartbeat write to protect Firebase Free Tier quota.
 * 3. FIXED URL parsing (`const urlObj = new URL(req.url, ...)`) for `/recent?scan=1`.
 * 4. PRESERVES actual Telegram message timestamp on wake-up / boot.
 */
import http from "node:http";
import https from "node:https";
import { TelegramClient } from "telegram";
import { StringSession } from "telegram/sessions/index.js";
import { NewMessage } from "telegram/events/index.js";
import { initializeApp, applicationDefault, cert } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

// 1. Initialize Firebase Admin SDK
const serviceAccountEnv =
  process.env.FIREBASE_SERVICE_ACCOUNT || process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
if (serviceAccountEnv) {
  try {
    const parsedCreds =
      typeof serviceAccountEnv === "string"
        ? JSON.parse(serviceAccountEnv)
        : serviceAccountEnv;
    initializeApp({ credential: cert(parsedCreds) });
  } catch (e) {
    console.error("Failed to parse Firebase service account JSON:", e.message);
    initializeApp({ credential: applicationDefault() });
  }
} else {
  initializeApp({ credential: applicationDefault() });
}

const db = getFirestore();
db.settings({ ignoreUndefinedProperties: true, preferRest: false });

// Quota Circuit Breaker for Firestore Writes (Prevents retry storms if daily free quota is exhausted)
let firestoreQuotaExhaustedUntil = 0;

// 2. Strict Whitelist of Configured & Enabled Shop PayWay Chat IDs
const normalizeChatId = (rawId) =>
  String(rawId || "")
    .trim()
    .replace(/^-100/, "")
    .replace(/^-/, "")
    .trim();

const rawTargetChats = String(process.env.PAYWAY_CHAT_ID || "").trim();
const envAllowedChatIds = rawTargetChats
  .split(/[\s,|;]+/)
  .map((id) => normalizeChatId(id))
  .filter(Boolean);

let dynamicFirestoreChatIds = new Set();

async function refreshConfiguredShopChatIds() {
  try {
    const snap = await db.collection("shops").get();
    const activeIds = new Set();
    snap.forEach((doc) => {
      const data = doc.data() || {};
      const cfg = data.khqrConfig;
      // Strictly include ONLY shops where PayWay Auto-Verification is enabled AND paywayChatId is set
      if (cfg && cfg.paywayVerifyEnabled !== false && cfg.paywayChatId) {
        String(cfg.paywayChatId)
          .split(/[\s,|;]+/)
          .map((id) => normalizeChatId(id))
          .filter(Boolean)
          .forEach((id) => activeIds.add(id));
      }
    });
    dynamicFirestoreChatIds = activeIds;
    console.log(
      `🔒 Active Shop PayWay Chat ID Whitelist Synced:`,
      Array.from(getEffectiveAllowedChatIds())
    );
  } catch (err) {
    console.warn("Could not refresh shop Chat IDs from Firestore (using env whitelist):", err.message);
  }
}

function getEffectiveAllowedChatIds() {
  // If Firestore shops have configured Chat IDs, strictly use those; otherwise fall back to env var
  if (dynamicFirestoreChatIds.size > 0) {
    return dynamicFirestoreChatIds;
  }
  return new Set(envAllowedChatIds);
}

// FAIL-CLOSED CHAT ID CHECK: Never save unconfigured Chat IDs or empty Chat IDs
const isChatAllowed = (chatIdStr) => {
  const stripped = normalizeChatId(chatIdStr);
  if (!stripped) return false;
  const allowedSet = getEffectiveAllowedChatIds();
  if (allowedSet.size === 0) return false;
  return allowedSet.has(stripped);
};

// Initial load + refresh every 5 minutes
await refreshConfiguredShopChatIds();
setInterval(refreshConfiguredShopChatIds, 5 * 60 * 1000);

// 3. In-Memory Ring Buffer & SSE Clients for 0ms Direct-to-POS Delivery
const recentPaymentsBuffer = [];
const savedTrxMemory = new Set();
const sseClients = new Set();

function broadcastToSseClients(paymentObj) {
  const payload = `data: ${JSON.stringify(paymentObj)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch (e) {
      sseClients.delete(res);
    }
  }
}

// Keep SSE connections alive through Render's load balancer every 20 seconds
setInterval(() => {
  for (const res of sseClients) {
    try {
      res.write(`: heartbeat ${Date.now()}\n\n`);
    } catch (e) {
      sseClients.delete(res);
    }
  }
}, 20000);

// 4. HTTP Health-Check + Query-Safe `/recent`, `/events` (SSE), and `/claim` Server
const port = Number(process.env.PORT || 10000);
http
  .createServer(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const urlObj = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = urlObj.pathname;
    const shouldScan = urlObj.searchParams.get("scan") === "1";

    // Optional on-demand Telegram group sweep when POS requests `?scan=1`
    if (shouldScan) {
      syncRecentGroupHistory(false).catch(() => {});
    }

    const allowedPayments = recentPaymentsBuffer.filter((p) => isChatAllowed(p.chatId));

    // Endpoint A: Server-Sent Events (`/events`, `/stream`, `/sse`)
    if (pathname === "/events" || pathname === "/stream" || pathname === "/sse") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
      });
      res.write(
        `data: ${JSON.stringify({
          type: "CONNECTED",
          ts: Date.now(),
          payments: allowedPayments.slice(0, 35),
        })}\n\n`
      );
      sseClients.add(res);
      req.on("close", () => sseClients.delete(res));
      return;
    }

    // Endpoint B: Mark a payment as claimed in memory (`/claim?trxId=123&orderId=abc&invoiceNo=HOP-001`)
    if (pathname === "/claim") {
      const trxId = String(urlObj.searchParams.get("trxId") || "").trim();
      const orderId = String(urlObj.searchParams.get("orderId") || "").trim();
      const invoiceNo = String(urlObj.searchParams.get("invoiceNo") || "").trim();
      if (trxId) {
        const found = recentPaymentsBuffer.find((p) => String(p.trxId) === trxId);
        if (found) {
          found.claimedByOrderId = orderId || "CLAIMED";
          if (invoiceNo) found.claimedByInvoiceNo = invoiceNo;
        }
      }
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(JSON.stringify({ ok: true, trxId }));
      return;
    }

    // Endpoint B2: Delete payment(s) from in-memory ring buffer (`/delete?trxIds=123,456`)
    if (pathname === "/delete") {
      const rawIds = String(urlObj.searchParams.get("trxIds") || urlObj.searchParams.get("trxId") || "").trim();
      const idsToDelete = new Set(rawIds.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean));
      let removed = 0;
      if (idsToDelete.size > 0) {
        for (let i = recentPaymentsBuffer.length - 1; i >= 0; i--) {
          const itemTrx = String(recentPaymentsBuffer[i]?.trxId || "").trim();
          if (idsToDelete.has(itemTrx)) {
            recentPaymentsBuffer.splice(i, 1);
            removed++;
          }
        }
      }
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(JSON.stringify({ ok: true, removed }));
      return;
    }

    // Endpoint C: JSON Payment Feed (`/recent`, `/payments`, or root `/?scan=1`)
    if (pathname === "/recent" || pathname === "/payments" || shouldScan) {
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(
        JSON.stringify({
          ok: true,
          status: "ok",
          service: "solaris-aba-listener-v4-strict",
          uptimeSeconds: Math.round(process.uptime()),
          allowedChatIds: Array.from(getEffectiveAllowedChatIds()),
          firestoreQuotaPaused: Date.now() < firestoreQuotaExhaustedUntil,
          payments: allowedPayments.slice(0, 50),
        })
      );
      return;
    }

    // Default Root Health Check (`/`)
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(
      JSON.stringify({
        ok: true,
        status: "ok",
        service: "solaris-aba-listener-v4-strict",
        uptimeSeconds: Math.round(process.uptime()),
        allowedChatIds: Array.from(getEffectiveAllowedChatIds()),
        cachedPayments: allowedPayments.length,
        firestoreQuotaPaused: Date.now() < firestoreQuotaExhaustedUntil,
        payments: allowedPayments.slice(0, 50),
      })
    );
  })
  .listen(port, () => {
    console.log(`🌐 Listener HTTP & SSE server active on port ${port}`);
  });

// Self-Keep-Alive Ping every 4 minutes to prevent Render Free Tier 15-minute inactivity spin-down
const selfExternalUrl =
  process.env.RENDER_EXTERNAL_URL || "https://po-listener.onrender.com";
setInterval(() => {
  try {
    https
      .get(`${selfExternalUrl}/?keepalive=${Date.now()}`, (res) => {
        res.resume();
      })
      .on("error", () => {});
  } catch (e) {}
}, 4 * 60 * 1000);

// 5. Minute-Granularity Timestamp Alignment Helper
function parseAbaPaidAtToMs(paidAtStr, referenceMs = Date.now()) {
  if (!paidAtStr || typeof paidAtStr !== "string") return referenceMs;
  const clean = paidAtStr.trim();
  const refDate = new Date(referenceMs);
  const currentYear = refDate.getFullYear();

  const match = clean.match(
    /^([A-Za-z]{3,9})\s+(\d{1,2})(?:,\s*(\d{4}))?,?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?$/i
  );
  if (match) {
    const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    const mIdx = months.indexOf(match[1].slice(0, 3).toLowerCase());
    if (mIdx !== -1) {
      const day = parseInt(match[2], 10);
      const year = match[3] ? parseInt(match[3], 10) : currentYear;
      let hours = parseInt(match[4], 10);
      const mins = parseInt(match[5], 10);
      const hasSecs = !!match[6];
      const secs = hasSecs ? parseInt(match[6], 10) : 0;
      const ampm = (match[7] || "").toUpperCase();

      if (ampm === "PM" && hours < 12) hours += 12;
      if (ampm === "AM" && hours === 12) hours = 0;

      const constructed = new Date(year, mIdx, day, hours, mins, secs, 0);
      if (!isNaN(constructed.getTime())) {
        if (!hasSecs) {
          const diffMs = referenceMs - constructed.getTime();
          if (diffMs >= 0 && diffMs < 60000) return referenceMs;
          return constructed.getTime() + 59000;
        }
        return constructed.getTime();
      }
    }
  }
  return referenceMs;
}

// 6. Unified Indoor ABA PAY + Outdoor Bank KHQR Parser (Supports All ABA Bot Formats)
function parseABAPayWay(raw, msgDateMs = Date.now()) {
  if (!raw || typeof raw !== "string") return null;
  const t = raw.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim();

  const strictRegex =
    /(?:(៛|\$|KHR|USD)\s*([0-9,]+(?:\.[0-9]{1,2})?))\s+paid by\s+(.+?)(?:\s*\(\s*\*\s*([0-9A-Za-z]+)\s*\))?\s+on\s+([A-Za-z]{3,9}\s+\d{1,2}(?:,\s*\d{4})?,?\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?|\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)\s+via\s+(.+?)\s+at\s+(.+?)(?:\.\s*|\s+)Trx\.?\s*ID\s*[:#]?\s*([0-9A-Za-z]+)[,\s]+APV\s*[:#]?\s*([0-9A-Za-z]+)/i;

  const m = t.match(strictRegex);
  if (m) {
    const cur = m[1] === "៛" || /^khr$/i.test(m[1]) ? "KHR" : "USD";
    const amount = parseFloat(m[2].replace(/,/g, ""));
    if (isNaN(amount) || amount <= 0) return null;

    const payerName = m[3].replace(/\(\s*\*\s*[0-9A-Za-z]+\s*\)\s*$/, "").trim();
    const maskedAccount = m[4] ? `*${m[4].trim()}` : "*ABA";
    const paidAtStr = m[5].trim();
    const paymentChannel = m[6].trim();
    const bankParenMatch = paymentChannel.match(/ABA\s*KHQR\s*\(\s*([^)]+)\s*\)/i);
    const isOutdoor = /ABA\s*KHQR/i.test(paymentChannel) || !!bankParenMatch;
    const sourceBank = bankParenMatch
      ? bankParenMatch[1].trim()
      : isOutdoor
      ? paymentChannel.replace(/^ABA\s*KHQR\s*/i, "").replace(/[()]/g, "").trim() || "External Bank"
      : "ABA Bank";

    const merchantName = m[7].replace(/\.$/, "").trim();
    const trxId = m[8].trim();
    const apv = m[9].replace(/\.$/, "").trim();

    return {
      currency: cur,
      amount,
      payerName,
      maskedAccount,
      paidAtStr,
      paidTimestamp: parseAbaPaidAtToMs(paidAtStr, msgDateMs),
      paymentChannel,
      paymentCategory: isOutdoor ? "OUTDOOR_KHQR" : "INDOOR_ABA",
      sourceBank,
      merchantName,
      trxId,
      apv,
      rawText: t,
    };
  }

  // Fallback Flexible Matcher in case ABA PayWay Bot slightly alters punctuation
  const amtMatch = t.match(/(?:(៛|\$|KHR|USD)\s*([0-9,]+(?:\.[0-9]{1,2})?))\s*(?:paid by|received from)/i);
  const trxMatch = t.match(/Trx\.?\s*ID\s*[:#]?\s*([0-9A-Za-z]+)/i);
  const apvMatch = t.match(/APV\s*[:#]?\s*([0-9A-Za-z]+)/i);
  if (amtMatch && (trxMatch || apvMatch)) {
    const cur = amtMatch[1] === "៛" || /^khr$/i.test(amtMatch[1]) ? "KHR" : "USD";
    const amount = parseFloat(amtMatch[2].replace(/,/g, ""));
    if (isNaN(amount) || amount <= 0) return null;
    const payerMatch = t.match(/(?:paid by|received from)\s+([^(]+?)(?:\s*\(\s*\*\s*([0-9A-Za-z]+)\s*\)|\s+on\s+|\s+via\s+)/i);
    const onMatch = t.match(/\bon\s+(.+?)\s+via\s+/i);
    const viaMatch = t.match(/\bvia\s+(.+?)\s+at\s+/i);
    const atMatch = t.match(/\bat\s+(.+?)(?:\.\s*Trx|\s+Trx)/i);
    const trxId = trxMatch ? trxMatch[1].trim() : `APV-${apvMatch[1].trim()}`;
    const apv = apvMatch ? apvMatch[1].trim().replace(/\.$/, "") : trxId.slice(-6);
    const paidAtStr = onMatch ? onMatch[1].trim() : "";
    const paymentChannel = viaMatch ? viaMatch[1].trim() : "ABA PAY";
    const isOutdoor = /ABA\s*KHQR/i.test(paymentChannel);
    return {
      currency: cur,
      amount,
      payerName: payerMatch ? payerMatch[1].trim() : "ABA Customer",
      maskedAccount: payerMatch && payerMatch[2] ? `*${payerMatch[2].trim()}` : "*ABA",
      paidAtStr,
      paidTimestamp: parseAbaPaidAtToMs(paidAtStr, msgDateMs),
      paymentChannel,
      paymentCategory: isOutdoor ? "OUTDOOR_KHQR" : "INDOOR_ABA",
      sourceBank: isOutdoor ? paymentChannel : "ABA Bank",
      merchantName: atMatch ? atMatch[1].replace(/\.$/, "").trim() : "",
      trxId,
      apv,
      rawText: t,
    };
  }

  return null;
}

const apiId = Number(process.env.TG_API_ID);
const apiHash = String(process.env.TG_API_HASH || "").trim();
const sessionStr = String(process.env.TG_SESSION || "").trim();

if (!apiId || !apiHash || !sessionStr) {
  console.error("Missing TG_API_ID, TG_API_HASH, or TG_SESSION in environment variables.");
  process.exit(1);
}

// 7. Quota-Safe Single-Write + Strict Chat ID Guard + 0ms SSE Broadcast
async function saveParsedPaymentToFirestore(parsed, chatIdStr, messageTimestampMs = null) {
  if (!parsed || !parsed.trxId) return false;

  const cleanChatId = String(chatIdStr || "").trim();
  // STRICT GUARD: Never save a payment if its Chat ID is not in the active shop whitelist!
  if (!isChatAllowed(cleanChatId)) {
    return false;
  }

  const trxId = String(parsed.trxId).trim();
  if (savedTrxMemory.has(trxId)) return false;
  savedTrxMemory.add(trxId);

  const writeStartMs = performance.now();
  const effectiveReceivedAt =
    Number(messageTimestampMs) > 0 ? Number(messageTimestampMs) : Date.now();

  const docPayload = {
    ...parsed,
    chatId: cleanChatId,
    receivedAt: effectiveReceivedAt,
    claimedByOrderId: null,
  };

  // 1. Push to in-memory ring buffer (sorted newest first) & SSE clients in 0ms
  recentPaymentsBuffer.unshift(docPayload);
  recentPaymentsBuffer.sort((a, b) => (Number(b.receivedAt) || 0) - (Number(a.receivedAt) || 0));
  if (recentPaymentsBuffer.length > 80) recentPaymentsBuffer.length = 80;
  broadcastToSseClients(docPayload);

  // 2. Write to Firestore ONLY if daily quota is not currently exhausted
  if (Date.now() < firestoreQuotaExhaustedUntil) {
    console.log(
      `⚡ [ABA VERIFIED -> SSE/MEMORY (Firestore Quota Paused)] Chat: ${cleanChatId} | Trx: ${trxId} | ${parsed.currency} ${parsed.amount}`
    );
    return true;
  }

  try {
    await db.collection("aba_payments").doc(trxId).set(docPayload, { merge: true });

    const elapsedMs = Math.round(performance.now() - writeStartMs);
    console.log(
      `⚡ [ABA VERIFIED -> CLOUD+SSE in ${elapsedMs}ms] Chat: ${cleanChatId} | Trx: ${trxId} | ${parsed.currency} ${parsed.amount} | ${parsed.payerName} (${parsed.maskedAccount}) | APV: ${parsed.apv}`
    );
    return true;
  } catch (e) {
    const errMsg = String(e?.message || e || "");
    if (e?.code === 8 || /RESOURCE_EXHAUSTED|Quota exceeded/i.test(errMsg)) {
      firestoreQuotaExhaustedUntil = Date.now() + 10 * 60 * 1000;
      console.warn(
        "⚠️ Firestore Daily Quota Exhausted — Serving payments directly via Render SSE (/events) & HTTP (/recent)!"
      );
      return true;
    }
    console.error("Firestore write warning (still available in /recent & SSE):", errMsg);
    return false;
  }
}

// 8. Native TCP Transport in Node.js
const client = new TelegramClient(new StringSession(sessionStr), apiId, apiHash, {
  connectionRetries: 10,
  retryDelay: 1000,
  autoReconnect: true,
  useWSS: false,
});

client.setLogLevel("error");

await client.connect();
console.log("==================================================================");
console.log("⚡ Connected to Telegram MTProto (Strict Shop Whitelist Mode)!");
console.log(
  "   Allowed Shop Chat IDs:",
  Array.from(getEffectiveAllowedChatIds())
);
console.log("==================================================================");

// 9A. REAL-TIME EVENT LISTENER
client.addEventHandler(async (ev) => {
  try {
    const rawMessage = ev.message?.message || ev.message?.text || "";
    if (!rawMessage) return;

    const peer = ev.message?.peerId;
    const incomingChatId = String(
      ev.chatId ||
        ev.message?.chatId ||
        (peer?.channelId ? `-100${peer.channelId}` : peer?.chatId ? `-${peer.chatId}` : "")
    );
    if (!isChatAllowed(incomingChatId)) return;

    const nowMs = Date.now();
    const parsed = parseABAPayWay(rawMessage, nowMs);
    if (!parsed) return;

    await saveParsedPaymentToFirestore(parsed, incomingChatId, nowMs);
  } catch (err) {}
}, new NewMessage({}));

// 9B. RAW MTPROTO UPDATE FALLBACK
client.addEventHandler(async (update) => {
  try {
    const msgObj = update?.message || update?.newMessage?.message;
    const rawText = typeof msgObj === "string" ? msgObj : msgObj?.message || msgObj?.text || "";
    if (!rawText) return;

    const peer = msgObj?.peerId || update?.peerId;
    const rawPeerId = peer?.channelId
      ? `-100${peer.channelId}`
      : peer?.chatId
      ? `-${peer.chatId}`
      : "";

    if (!isChatAllowed(rawPeerId)) return;

    const nowMs = Date.now();
    const parsed = parseABAPayWay(rawText, nowMs);
    if (!parsed) return;

    await saveParsedPaymentToFirestore(parsed, rawPeerId, nowMs);
  } catch (err) {}
});

// 10. FAST PARALLEL TARGET-GROUP SWEEP (Strictly Whitelisted Dialogs Only)
let cachedTargetDialogs = [];
let lastDialogRefreshMs = 0;
let isSweeping = false;

async function syncRecentGroupHistory(isInitialBoot = false) {
  if (isSweeping) return;
  if (getEffectiveAllowedChatIds().size === 0) return;
  isSweeping = true;
  try {
    const now = Date.now();
    if (isInitialBoot || cachedTargetDialogs.length === 0 || now - lastDialogRefreshMs > 300000) {
      const dialogs = await client.getDialogs({ limit: 35 });
      cachedTargetDialogs = dialogs.filter((d) => {
        const dialogIdStr = String(d.id || "");
        return (d.isGroup || d.isChannel) && isChatAllowed(dialogIdStr);
      });
      lastDialogRefreshMs = now;
    }

    await Promise.all(
      cachedTargetDialogs.map(async (d) => {
        try {
          const dialogIdStr = String(d.id || "");
          if (!isChatAllowed(dialogIdStr)) return;
          const messages = await client.getMessages(d.entity, { limit: isInitialBoot ? 15 : 5 });
          for (const msg of messages) {
            const text = msg?.message || msg?.text || "";
            if (!text) continue;
            const msgServerMs = msg.date ? Number(msg.date) * 1000 : Date.now();
            const effectiveMs =
              !isInitialBoot && Math.abs(Date.now() - msgServerMs) < 90000
                ? Date.now()
                : msgServerMs;
            const parsed = parseABAPayWay(text, effectiveMs);
            if (parsed) {
              await saveParsedPaymentToFirestore(parsed, dialogIdStr, effectiveMs);
            }
          }
        } catch (innerErr) {}
      })
    );
  } catch (err) {
    if (!/RPCError|INTERNAL|FLOOD/i.test(err.message || "")) {
      console.warn("History sweep warning:", err.message || err);
    }
  } finally {
    isSweeping = false;
  }
}

await syncRecentGroupHistory(true);
setInterval(() => syncRecentGroupHistory(false), 3500);
