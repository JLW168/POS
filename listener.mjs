/**
 * ABA PayWay Telegram Group Listener Bridge — Deep Historical Backfill & Strict Whitelist Edition (listener.mjs)
 *
 * BUGS FIXED & OPTIMIZATIONS IN THIS VERSION:
 * 1. NEW `/history` & `/sync-config` ENDPOINTS (Deep Past/Any-Time Telegram History Fetch):
 *    - Supports `GET /history?chatId=-100...&startMs=...&endMs=...&limit=500`
 *    - Uses Telegram MTProto `offsetDate` pagination to jump directly to `endMs` and walk backwards
 *      to `startMs`, extracting 100% of historical ABA PayWay transactions from the Telegram Group Chat ID
 *      for any past date, week, month, or custom date range!
 * 2. DIRECT PEER RESOLUTION + `payway_secrets` FALLBACK:
 *    - Reads allowed Chat IDs from BOTH `shops` AND `payway_secrets` (so backup configs are never missed).
 *    - Resolves Telegram group peers directly by Chat ID (`-100...` / `-...`) if a group is older than the top 100 dialogs.
 * 3. SAFE FIRESTORE BATCH BACKFILL (NEVER OVERWRITES `claimedByOrderId`):
 *    - Live/Historical writes no longer overwrite `claimedByOrderId: null` on already-verified receipts in Firestore.
 * 4. EXPANDED IN-MEMORY RING BUFFER (500 transactions) & Instant Date-Range Filtering on `/recent`.
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

// Quota Circuit Breaker for Firestore Writes
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
// Map of normalizedChatId -> raw configured chatId string (e.g. "-1001987654321" or "-5433015912")
const configuredRawChatIdMap = new Map();

async function refreshConfiguredShopChatIds() {
  try {
    const [shopsSnap, secretsSnap] = await Promise.all([
      db.collection("shops").get().catch(() => null),
      db.collection("payway_secrets").get().catch(() => null),
    ]);

    const activeIds = new Set();

    const registerRawChatIds = (rawStr) => {
      String(rawStr || "")
        .split(/[\s,|;]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .forEach((raw) => {
          const norm = normalizeChatId(raw);
          if (norm) {
            activeIds.add(norm);
            if (!configuredRawChatIdMap.has(norm) || raw.startsWith("-")) {
              configuredRawChatIdMap.set(norm, raw);
            }
          }
        });
    };

    if (shopsSnap) {
      shopsSnap.forEach((doc) => {
        const data = doc.data() || {};
        const cfg = data.khqrConfig;
        if (cfg && cfg.paywayVerifyEnabled !== false && cfg.paywayChatId) {
          registerRawChatIds(cfg.paywayChatId);
        }
      });
    }

    if (secretsSnap) {
      secretsSnap.forEach((doc) => {
        const sec = doc.data() || {};
        const backupCfg = sec.khqrConfigBackup || {};
        if (backupCfg.paywayVerifyEnabled !== false) {
          registerRawChatIds(sec.paywayChatId || backupCfg.paywayChatId);
        }
      });
    }

    envAllowedChatIds.forEach((id) => activeIds.add(id));
    dynamicFirestoreChatIds = activeIds;

    console.log(
      `🔒 Active Shop PayWay Chat ID Whitelist Synced:`,
      Array.from(getEffectiveAllowedChatIds())
    );
  } catch (err) {
    console.warn(
      "Could not refresh shop Chat IDs from Firestore (using env whitelist):",
      err.message
    );
  }
}

function getEffectiveAllowedChatIds() {
  if (dynamicFirestoreChatIds.size > 0) {
    return dynamicFirestoreChatIds;
  }
  return new Set(envAllowedChatIds);
}

// FAIL-CLOSED CHAT ID CHECK: Never save unconfigured Chat IDs or empty Chat IDs
const isChatAllowed = (chatIdStr, explicitFilterChatId = "") => {
  const stripped = normalizeChatId(chatIdStr);
  if (!stripped) return false;

  if (explicitFilterChatId) {
    const explicitSet = new Set(
      String(explicitFilterChatId)
        .split(/[\s,|;]+/)
        .map((id) => normalizeChatId(id))
        .filter(Boolean)
    );
    if (explicitSet.size > 0 && !explicitSet.has(stripped)) {
      return false;
    }
  }

  const allowedSet = getEffectiveAllowedChatIds();
  if (allowedSet.size === 0) return false;
  return allowedSet.has(stripped);
};

await refreshConfiguredShopChatIds();
setInterval(refreshConfiguredShopChatIds, 3 * 60 * 1000);

// 3. In-Memory Ring Buffer (Up to 500 items) & SSE Clients for 0ms Direct-to-POS Delivery
const recentPaymentsBuffer = [];
const recentPaymentsMap = new Map(); // trxId -> paymentObj
const savedTrxMemory = new Set();
const sseClients = new Set();

function upsertMemoryBuffer(docPayload) {
  if (!docPayload || !docPayload.trxId) return docPayload;
  const trxId = String(docPayload.trxId).trim();
  const existing = recentPaymentsMap.get(trxId) || {};
  const merged = {
    ...existing,
    ...docPayload,
    claimedByOrderId: existing.claimedByOrderId || docPayload.claimedByOrderId || null,
    claimedByInvoiceNo: existing.claimedByInvoiceNo || docPayload.claimedByInvoiceNo || null,
  };
  recentPaymentsMap.set(trxId, merged);

  const idx = recentPaymentsBuffer.findIndex((p) => String(p.trxId) === trxId);
  if (idx !== -1) {
    recentPaymentsBuffer[idx] = merged;
  } else {
    recentPaymentsBuffer.unshift(merged);
  }

  recentPaymentsBuffer.sort((a, b) => (Number(b.receivedAt) || 0) - (Number(a.receivedAt) || 0));
  if (recentPaymentsBuffer.length > 500) {
    const removed = recentPaymentsBuffer.splice(500);
    removed.forEach((r) => recentPaymentsMap.delete(String(r.trxId)));
  }
  return merged;
}

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

setInterval(() => {
  for (const res of sseClients) {
    try {
      res.write(`: heartbeat ${Date.now()}\n\n`);
    } catch (e) {
      sseClients.delete(res);
    }
  }
}, 20000);

// 4. Minute-Granularity Timestamp Alignment Helper (Supports Past Years & Historical Dates)
function parseAbaPaidAtToMs(paidAtStr, referenceMs = Date.now()) {
  if (!paidAtStr || typeof paidAtStr !== "string") return referenceMs;
  const clean = paidAtStr.trim();
  const refDate = new Date(referenceMs);
  const refYear = refDate.getFullYear();

  const match = clean.match(
    /^([A-Za-z]{3,9})\s+(\d{1,2})(?:,\s*(\d{4}))?,?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?$/i
  );
  if (match) {
    const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    const mIdx = months.indexOf(match[1].slice(0, 3).toLowerCase());
    if (mIdx !== -1) {
      const day = parseInt(match[2], 10);
      const year = match[3] ? parseInt(match[3], 10) : refYear;
      let hours = parseInt(match[4], 10);
      const mins = parseInt(match[5], 10);
      const hasSecs = !!match[6];
      const secs = hasSecs ? parseInt(match[6], 10) : 0;
      const ampm = (match[7] || "").toUpperCase();

      if (ampm === "PM" && hours < 12) hours += 12;
      if (ampm === "AM" && hours === 12) hours = 0;

      const constructed = new Date(year, mIdx, day, hours, mins, secs, 0);
      if (!isNaN(constructed.getTime())) {
        // Year-boundary rollover protection (e.g., Dec 31 message viewed in Jan)
        if (!match[3] && constructed.getTime() - referenceMs > 60 * 24 * 60 * 60 * 1000) {
          constructed.setFullYear(year - 1);
        }
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

// 5. Unified Indoor ABA PAY + Outdoor Bank KHQR Parser (Supports All ABA Bot Formats)
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

  // Fallback Flexible Matcher
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

// 6. Quota-Safe Single-Write + Strict Chat ID Guard + Safe Merge (Never Overwrites claimedByOrderId)
async function saveParsedPaymentToFirestore(
  parsed,
  chatIdStr,
  messageTimestampMs = null,
  broadcastLive = true
) {
  if (!parsed || !parsed.trxId) return null;

  const cleanChatId = String(chatIdStr || "").trim();
  if (!isChatAllowed(cleanChatId)) {
    return null;
  }

  const trxId = String(parsed.trxId).trim();
  const effectiveReceivedAt =
    Number(messageTimestampMs) > 0 ? Number(messageTimestampMs) : Date.now();

  // Do not include `claimedByOrderId: null` in the Firestore merge payload so we NEVER wipe an existing claim!
  const docPayload = {
    ...parsed,
    chatId: cleanChatId,
    receivedAt: effectiveReceivedAt,
  };

  const mergedInMemory = upsertMemoryBuffer(docPayload);

  if (savedTrxMemory.has(trxId)) {
    return mergedInMemory;
  }
  savedTrxMemory.add(trxId);

  if (broadcastLive) {
    broadcastToSseClients(mergedInMemory);
  }

  if (Date.now() < firestoreQuotaExhaustedUntil) {
    return mergedInMemory;
  }

  const writeStartMs = performance.now();
  try {
    await db.collection("aba_payments").doc(trxId).set(docPayload, { merge: true });
    const elapsedMs = Math.round(performance.now() - writeStartMs);
    if (broadcastLive) {
      console.log(
        `⚡ [ABA VERIFIED -> CLOUD+SSE in ${elapsedMs}ms] Chat: ${cleanChatId} | Trx: ${trxId} | ${parsed.currency} ${parsed.amount} | ${parsed.payerName} (${parsed.maskedAccount}) | APV: ${parsed.apv}`
      );
    }
    return mergedInMemory;
  } catch (e) {
    const errMsg = String(e?.message || e || "");
    if (e?.code === 8 || /RESOURCE_EXHAUSTED|Quota exceeded/i.test(errMsg)) {
      firestoreQuotaExhaustedUntil = Date.now() + 10 * 60 * 1000;
      console.warn(
        "⚠️ Firestore Daily Quota Exhausted — Serving payments directly via Render SSE (/events) & HTTP (/recent, /history)!"
      );
      return mergedInMemory;
    }
    return mergedInMemory;
  }
}

// 7. Native TCP Transport in Node.js
const client = new TelegramClient(new StringSession(sessionStr), apiId, apiHash, {
  connectionRetries: 10,
  retryDelay: 1000,
  autoReconnect: true,
  useWSS: false,
});

client.setLogLevel("error");

await client.connect();
console.log("==================================================================");
console.log("⚡ Connected to Telegram MTProto (Deep History + Strict Whitelist)!");
console.log("   Allowed Shop Chat IDs:", Array.from(getEffectiveAllowedChatIds()));
console.log("==================================================================");

// 8. Target Dialog & Direct Peer Resolver Cache
let cachedTargetDialogs = [];
const resolvedPeerByNormId = new Map();
let lastDialogRefreshMs = 0;
let isSweeping = false;

async function resolveWhitelistedPeers(forceRefresh = false, targetChatIdFilter = "") {
  const now = Date.now();
  if (!forceRefresh && cachedTargetDialogs.length > 0 && now - lastDialogRefreshMs < 300000) {
    if (!targetChatIdFilter) return cachedTargetDialogs;
    const filterNorms = new Set(
      String(targetChatIdFilter)
        .split(/[\s,|;]+/)
        .map((s) => normalizeChatId(s))
        .filter(Boolean)
    );
    const filtered = cachedTargetDialogs.filter((d) => filterNorms.has(normalizeChatId(d.chatId)));
    if (filtered.length > 0) return filtered;
  }

  try {
    const dialogs = await client.getDialogs({ limit: 100 });
    const matched = [];
    for (const d of dialogs) {
      const dialogIdStr = String(d.id || "");
      const norm = normalizeChatId(dialogIdStr);
      if ((d.isGroup || d.isChannel) && isChatAllowed(dialogIdStr)) {
        const entry = { chatId: dialogIdStr, normId: norm, entity: d.entity, title: d.title || "" };
        matched.push(entry);
        resolvedPeerByNormId.set(norm, entry);
      }
    }

    // Fallback: Direct peer resolution for any configured Chat ID not in the top 100 dialogs
    for (const normId of getEffectiveAllowedChatIds()) {
      if (!resolvedPeerByNormId.has(normId)) {
        const rawHint = configuredRawChatIdMap.get(normId) || `-${normId}`;
        const candidates = [rawHint, `-100${normId}`, `-${normId}`];
        for (const cand of candidates) {
          try {
            const ent = await client.getInputEntity(cand);
            if (ent) {
              const entry = { chatId: cand, normId, entity: ent, title: `Chat ${cand}` };
              matched.push(entry);
              resolvedPeerByNormId.set(normId, entry);
              break;
            }
          } catch (e) {}
        }
      }
    }

    cachedTargetDialogs = matched;
    lastDialogRefreshMs = now;
  } catch (err) {
    console.warn("Dialog discovery warning:", err.message || err);
  }

  if (!targetChatIdFilter) return cachedTargetDialogs;
  const filterNorms = new Set(
    String(targetChatIdFilter)
      .split(/[\s,|;]+/)
      .map((s) => normalizeChatId(s))
      .filter(Boolean)
  );
  return cachedTargetDialogs.filter((d) => filterNorms.has(d.normId));
}

// 9. DEEP HISTORICAL TELEGRAM BACKFILL ENGINE (`/history`)
// Fetches messages from Telegram Group Chat IDs across any historical date range (`startMs` .. `endMs`)
async function fetchHistoricalGroupMessages({
  chatId = "",
  startMs = 0,
  endMs = Date.now(),
  maxMessagesPerChat = 600,
} = {}) {
  const peers = await resolveWhitelistedPeers(false, chatId);
  if (!peers || peers.length === 0) {
    await refreshConfiguredShopChatIds();
    await resolveWhitelistedPeers(true, chatId);
  }
  const activePeers = await resolveWhitelistedPeers(false, chatId);
  const extractedResults = [];
  const safeEndSec = Math.floor((Number(endMs) || Date.now()) / 1000) + 120;
  const safeStartMs = Number(startMs) > 0 ? Number(startMs) - 120000 : 0;
  const cap = Math.min(1500, Math.max(50, Number(maxMessagesPerChat) || 600));

  for (const peerObj of activePeers) {
    if (!isChatAllowed(peerObj.chatId, chatId)) continue;

    let offsetId = 0;
    let fetchedCount = 0;
    let reachedBeforeStart = false;

    while (fetchedCount < cap && !reachedBeforeStart) {
      const batchLimit = Math.min(100, cap - fetchedCount);
      const queryOpts = { limit: batchLimit };
      if (offsetId > 0) {
        queryOpts.offsetId = offsetId;
      } else if (endMs && Number(endMs) < Date.now() - 60000) {
        queryOpts.offsetDate = safeEndSec;
      }

      let messages = [];
      try {
        messages = await client.getMessages(peerObj.entity, queryOpts);
      } catch (err) {
        console.warn(`Historical getMessages warning for ${peerObj.chatId}:`, err.message);
        break;
      }

      if (!messages || messages.length === 0) break;

      for (const msg of messages) {
        fetchedCount++;
        if (msg.id && (offsetId === 0 || msg.id < offsetId)) {
          offsetId = msg.id;
        }

        const msgServerMs = msg.date ? Number(msg.date) * 1000 : Date.now();
        if (safeStartMs > 0 && msgServerMs < safeStartMs) {
          reachedBeforeStart = true;
          break;
        }
        if (endMs && msgServerMs > Number(endMs) + 120000) {
          continue;
        }

        const text = msg?.message || msg?.text || "";
        if (!text) continue;

        const parsed = parseABAPayWay(text, msgServerMs);
        if (parsed && parsed.trxId) {
          const saved = await saveParsedPaymentToFirestore(
            parsed,
            peerObj.chatId,
            msgServerMs,
            false
          );
          if (saved) {
            extractedResults.push(saved);
          }
        }
      }

      if (messages.length < batchLimit) break;
    }
  }

  extractedResults.sort((a, b) => (Number(b.receivedAt) || 0) - (Number(a.receivedAt) || 0));
  return extractedResults;
}

// 10. HTTP Health-Check + `/recent`, `/history`, `/sync-config`, `/events` (SSE), `/claim`, and `/delete`
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

    // Endpoint 0: Instant Config & Whitelist Reload (`/sync-config`)
    if (pathname === "/sync-config") {
      await refreshConfiguredShopChatIds();
      await resolveWhitelistedPeers(true);
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(
        JSON.stringify({
          ok: true,
          allowedChatIds: Array.from(getEffectiveAllowedChatIds()),
        })
      );
      return;
    }

    // Endpoint A: Deep Historical Backfill (`/history?chatId=...&startMs=...&endMs=...&limit=600`)
    if (pathname === "/history") {
      try {
        const chatId = String(urlObj.searchParams.get("chatId") || "").trim();
        const startMs = Number(urlObj.searchParams.get("startMs")) || 0;
        const endMs = Number(urlObj.searchParams.get("endMs")) || Date.now();
        const limit = Number(urlObj.searchParams.get("limit")) || 600;

        const historicalPayments = await fetchHistoricalGroupMessages({
          chatId,
          startMs,
          endMs,
          maxMessagesPerChat: limit,
        });

        res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
        res.end(
          JSON.stringify({
            ok: true,
            count: historicalPayments.length,
            chatId,
            startMs,
            endMs,
            payments: historicalPayments,
          })
        );
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json", "Cache-Control": "no-store" });
        res.end(JSON.stringify({ ok: false, error: err.message || "History scan failed" }));
      }
      return;
    }

    if (shouldScan) {
      syncRecentGroupHistory(false).catch(() => {});
    }

    const filterChatParam = String(urlObj.searchParams.get("chatId") || "").trim();
    const startMsParam = Number(urlObj.searchParams.get("startMs")) || 0;
    const endMsParam = Number(urlObj.searchParams.get("endMs")) || 0;

    const allowedPayments = recentPaymentsBuffer.filter((p) => {
      if (!isChatAllowed(p.chatId, filterChatParam)) return false;
      const rec = Number(p.receivedAt) || 0;
      if (startMsParam > 0 && rec < startMsParam) return false;
      if (endMsParam > 0 && rec > endMsParam) return false;
      return true;
    });

    // Endpoint B: Server-Sent Events (`/events`, `/stream`, `/sse`)
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
          payments: allowedPayments.slice(0, 60),
        })}\n\n`
      );
      sseClients.add(res);
      req.on("close", () => sseClients.delete(res));
      return;
    }

    // Endpoint C: Mark a payment as claimed in memory (`/claim`)
    if (pathname === "/claim") {
      const trxId = String(urlObj.searchParams.get("trxId") || "").trim();
      const orderId = String(urlObj.searchParams.get("orderId") || "").trim();
      const invoiceNo = String(urlObj.searchParams.get("invoiceNo") || "").trim();
      if (trxId) {
        const found = recentPaymentsMap.get(trxId);
        if (found) {
          found.claimedByOrderId = orderId || "CLAIMED";
          if (invoiceNo) found.claimedByInvoiceNo = invoiceNo;
        }
      }
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(JSON.stringify({ ok: true, trxId }));
      return;
    }

    // Endpoint D: Delete payment(s) from in-memory ring buffer (`/delete`)
    if (pathname === "/delete") {
      const rawIds = String(
        urlObj.searchParams.get("trxIds") || urlObj.searchParams.get("trxId") || ""
      ).trim();
      const idsToDelete = new Set(
        rawIds
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean)
      );
      let removed = 0;
      if (idsToDelete.size > 0) {
        for (let i = recentPaymentsBuffer.length - 1; i >= 0; i--) {
          const itemTrx = String(recentPaymentsBuffer[i]?.trxId || "").trim();
          if (idsToDelete.has(itemTrx)) {
            recentPaymentsBuffer.splice(i, 1);
            recentPaymentsMap.delete(itemTrx);
            savedTrxMemory.delete(itemTrx);
            removed++;
          }
        }
      }
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(JSON.stringify({ ok: true, removed }));
      return;
    }

    // Endpoint E: JSON Payment Feed (`/recent`, `/payments`, or root `/?scan=1`)
    const limitParam = Math.min(500, Math.max(50, Number(urlObj.searchParams.get("limit")) || 150));
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(
      JSON.stringify({
        ok: true,
        status: "ok",
        service: "solaris-aba-listener-v5-history",
        uptimeSeconds: Math.round(process.uptime()),
        allowedChatIds: Array.from(getEffectiveAllowedChatIds()),
        cachedPayments: allowedPayments.length,
        firestoreQuotaPaused: Date.now() < firestoreQuotaExhaustedUntil,
        payments: allowedPayments.slice(0, limitParam),
      })
    );
  })
  .listen(port, () => {
    console.log(`🌐 Listener HTTP, History & SSE server active on port ${port}`);
  });

// Self-Keep-Alive Ping every 4 minutes
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

// 11A. REAL-TIME EVENT LISTENER
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

    const msgServerMs = ev.message?.date ? Number(ev.message.date) * 1000 : Date.now();
    const effectiveMs = Math.abs(Date.now() - msgServerMs) < 90000 ? Date.now() : msgServerMs;
    const parsed = parseABAPayWay(rawMessage, effectiveMs);
    if (!parsed) return;

    await saveParsedPaymentToFirestore(parsed, incomingChatId, effectiveMs, true);
  } catch (err) {}
}, new NewMessage({}));

// 11B. RAW MTPROTO UPDATE FALLBACK
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

    const msgServerMs = msgObj?.date ? Number(msgObj.date) * 1000 : Date.now();
    const effectiveMs = Math.abs(Date.now() - msgServerMs) < 90000 ? Date.now() : msgServerMs;
    const parsed = parseABAPayWay(rawText, effectiveMs);
    if (!parsed) return;

    await saveParsedPaymentToFirestore(parsed, rawPeerId, effectiveMs, true);
  } catch (err) {}
});

// 12. INITIAL BOOT & LIVE TARGET-GROUP SWEEP
async function syncRecentGroupHistory(isInitialBoot = false) {
  if (isSweeping) return;
  if (getEffectiveAllowedChatIds().size === 0) return;
  isSweeping = true;
  try {
    const peers = await resolveWhitelistedPeers(isInitialBoot);
    await Promise.all(
      peers.map(async (d) => {
        try {
          if (!isChatAllowed(d.chatId)) return;
          // On initial boot, pull the last 100 messages per shop group so recent history is immediately ready!
          const messages = await client.getMessages(d.entity, {
            limit: isInitialBoot ? 100 : 8,
          });
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
              await saveParsedPaymentToFirestore(
                parsed,
                d.chatId,
                effectiveMs,
                !isInitialBoot
              );
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
