import { buildPushPayload } from '@block65/webcrypto-web-push';

/* Timetable Gemini API + anonymous Web Push proxy
 * Existing Gemini API behavior is retained. Push subscription metadata is stored in D1.
 * Firebase Authentication is not used.
 */
const ALLOWED_ORIGIN = 'https://894-tt.github.io';
const DEFAULT_MODEL = 'gemini-3.5-flash';
const MAX_IMAGE_BASE64_LENGTH = 12 * 1024 * 1024;
const MAX_RETRIES = 3;
const PUSH_PREFIX = '/api/push/';
const DOW_JA = ['日', '月', '火', '水', '木', '金', '土'];
const INCLUDE_KEYS = ['items', 'homework', 'quiz', 'location', 'forgotten', 'notes', 'schedule'];

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
async function hashToken(token) {
  return base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
}
function isValidPushEndpoint(endpoint) {
  try {
    const u = new URL(endpoint);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase();
    return h === 'fcm.googleapis.com' || h === 'web.push.apple.com' ||
      h.endsWith('.push.apple.com') || h === 'updates.push.services.mozilla.com' ||
      h.endsWith('.push.services.mozilla.com') || h.endsWith('.notify.windows.com');
  } catch { return false; }
}
function validSubscription(s) {
  return !!s && typeof s.endpoint === 'string' && isValidPushEndpoint(s.endpoint) &&
    typeof s.keys?.p256dh === 'string' && typeof s.keys?.auth === 'string';
}
function validSettings(s) {
  return !!s && typeof s.time === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(s.time) &&
    Array.isArray(s.days) && s.days.length > 0 && s.days.every(d => Number.isInteger(d) && d >= 0 && d <= 6) &&
    s.include && INCLUDE_KEYS.every(k => typeof s.include[k] === 'boolean');
}
function localParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit',
    weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(date);
  return Object.fromEntries(parts.map(p => [p.type, p.value]));
}
function dateAfterDays(iso, days) {
  const [y, m, d] = iso.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d + days));
  return `${dt.getUTCFullYear()}-${String(dt.getUTCMonth() + 1).padStart(2, '0')}-${String(dt.getUTCDate()).padStart(2, '0')}`;
}
function weekdayForIso(iso) {
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d)).getUTCDay();
}
function slotNumber(v) {
  const s = String(v || '');
  if (s === '朝') return 0;
  const n = Number(s.match(/[1-7]/)?.[0]);
  return Number.isFinite(n) ? n : 99;
}
function makeNotificationBody(events, settings, tomorrow) {
  const [y, m, d] = tomorrow.split('-').map(Number);
  const dow = DOW_JA[weekdayForIso(tomorrow)];
  const selected = events.filter(e => e.dateKey === tomorrow).sort((a, b) => slotNumber(a.slot) - slotNumber(b.slot));
  if (!selected.length) return '';
  const lines = [`明日(${m}/${String(d).padStart(2, '0')} ${dow})の予定です。`];
  const inc = settings.include || {};
  const labels = [['items', '持ち物'], ['homework', '宿題'], ['quiz', '小テスト'], ['location', '場所'], ['forgotten', '忘れ物'], ['notes', '備考']];
  const details = [];
  for (const [key, label] of labels) {
    if (!inc[key]) continue;
    for (const e of selected) {
      const value = String(e[key] || '').trim();
      if (value) details.push(`${label}: ${e.subject}(${value})`);
    }
  }
  if (details.length) lines.push(`{\n${details.join('\n')}\n}`);
  if (inc.schedule) {
    const periods = selected.filter(e => e.subject).map(e => {
      const slot = e.slot === '朝' ? '朝' : String(e.slot || '');
      const end = e.endSlot && e.endSlot !== e.slot ? `〜${e.endSlot}` : '';
      const place = inc.location && e.location ? ` (${e.location})` : '';
      return `${slot}${end}: ${e.subject}${place}`;
    });
    if (periods.length) lines.push(`{\n${periods.join('\n')}\n}`);
  }
  return lines.join('\n').slice(0, 3500);
}

async function handlePushRequest(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith(PUSH_PREFIX)) return null;
  const origin = request.headers.get('Origin') || '';
  if (origin !== ALLOWED_ORIGIN) return jsonResponse({ error: 'Origin not allowed' }, 403);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });
  if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405);
  if (!env.DB) return jsonResponse({ error: 'D1 binding DB is not configured' }, 500);

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }

  if (url.pathname === '/api/push/subscribe') {
    const token = String(body.token || '');
    const events = Array.isArray(body.events) ? body.events.slice(0, 500) : [];
    if (!/^[a-f0-9]{64}$/.test(token) || !validSubscription(body.subscription) || !validSettings(body.settings)) {
      return jsonResponse({ error: 'Invalid subscription or settings' }, 400);
    }
    const tokenHash = await hashToken(token);
    await env.DB.prepare(`INSERT INTO push_devices(token_hash, subscription_json, settings_json, events_json, updated_at)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(token_hash) DO UPDATE SET
        subscription_json=excluded.subscription_json,
        settings_json=excluded.settings_json,
        events_json=excluded.events_json,
        updated_at=CURRENT_TIMESTAMP`)
      .bind(tokenHash, JSON.stringify(body.subscription), JSON.stringify(body.settings), JSON.stringify(events)).run();
    return jsonResponse({ ok: true });
  }

  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!/^[a-f0-9]{64}$/.test(token)) return jsonResponse({ error: 'Unauthorized' }, 401);
  const tokenHash = await hashToken(token);

  if (url.pathname === '/api/push/schedule') {
    const events = Array.isArray(body.events) ? body.events.slice(0, 500) : [];
    const result = await env.DB.prepare('UPDATE push_devices SET events_json=?, updated_at=CURRENT_TIMESTAMP WHERE token_hash=?')
      .bind(JSON.stringify(events), tokenHash).run();
    if (!(result.meta?.changes > 0)) return jsonResponse({ error: 'Device not found' }, 404);
    return jsonResponse({ ok: true });
  }
  if (url.pathname === '/api/push/unsubscribe') {
    await env.DB.prepare('DELETE FROM push_devices WHERE token_hash=?').bind(tokenHash).run();
    return jsonResponse({ ok: true });
  }
  return jsonResponse({ error: 'Not found' }, 404);
}

async function sendScheduledPushes(env) {
  if (!env.DB || !env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY || !env.VAPID_SUBJECT) {
    throw new Error('Missing D1 or VAPID configuration');
  }
  const now = localParts();
  const today = `${now.year}-${now.month}-${now.day}`;
  const tomorrow = dateAfterDays(today, 1);
  const rows = await env.DB.prepare('SELECT token_hash, subscription_json, settings_json, events_json, last_sent_date FROM push_devices').all();

  for (const row of rows.results || []) {
    let settings, subscription, events;
    try {
      settings = JSON.parse(row.settings_json);
      subscription = JSON.parse(row.subscription_json);
      events = JSON.parse(row.events_json || '[]');
    } catch { continue; }
    if (!settings.enabled || settings.time !== `${now.hour}:${now.minute}` ||
        !(settings.days || []).includes(weekdayForIso(today)) || row.last_sent_date === today) continue;
    const body = makeNotificationBody(events, settings, tomorrow);
    if (!body) continue;

    const message = {
      data: { title: '明日の時間割', body, url: './', sound: settings.sound !== false },
      options: { ttl: 3600, urgency: 'high' }
    };
    try {
      const payload = await buildPushPayload(message, subscription, {
        subject: env.VAPID_SUBJECT,
        publicKey: env.VAPID_PUBLIC_KEY,
        privateKey: env.VAPID_PRIVATE_KEY
      });
      const response = await fetch(subscription.endpoint, payload);
      if (response.status === 404 || response.status === 410) {
        await env.DB.prepare('DELETE FROM push_devices WHERE token_hash=?').bind(row.token_hash).run();
        continue;
      }
      if (!response.ok) throw new Error(`Push service returned ${response.status}`);
      await env.DB.prepare('UPDATE push_devices SET last_sent_date=?, updated_at=CURRENT_TIMESTAMP WHERE token_hash=?')
        .bind(today, row.token_hash).run();
    } catch (error) {
      console.error('Push delivery failed:', error?.message || error);
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Push endpoints are handled before the original Gemini route.
    const pushResponse = await handlePushRequest(request, env);
    if (pushResponse) return pushResponse;

    if (request.method === 'GET' && url.pathname === '/') {
      const apiKey = env.gem_api || env.GEM_API;
      return jsonResponse({
        ok: true,
        service: 'timetable-gem-api',
        message: 'Worker is running.',
        secretConfigured: Boolean(apiKey),
        pushConfigured: Boolean(env.DB && env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY && env.VAPID_SUBJECT)
      }, 200);
    }

    if (url.pathname !== '/api/timetable') {
      return jsonResponse({ error: 'Not Found', message: '利用可能なパスは /api/timetable です。' }, 404);
    }
    if (request.method !== 'POST') return jsonResponse({ error: 'Method Not Allowed' }, 405);
    if (origin && origin !== ALLOWED_ORIGIN) {
      return jsonResponse({ error: 'Forbidden', message: '許可されていないアクセス元です。' }, 403);
    }

    const apiKey = env.gem_api || env.GEM_API;
    if (!apiKey) {
      return jsonResponse({ error: 'API key is not configured', message: 'Cloudflare WorkerのSecret gem_api または GEM_API を確認してください。' }, 500);
    }

    try {
      const input = await request.json();
      const prompt = typeof input.prompt === 'string' ? input.prompt.trim() : '';
      const image = input.image || {};
      const mimeType = image.mimeType;
      const imageData = image.data;
      const model = typeof input.model === 'string' && /^[a-zA-Z0-9._-]+$/.test(input.model) ? input.model : DEFAULT_MODEL;

      if (!prompt) return jsonResponse({ error: 'Invalid request', message: 'prompt が指定されていません。' }, 400);
      if (typeof mimeType !== 'string' || !/^image\/(jpeg|jpg|png|webp|heic|heif)$/.test(mimeType)) {
        return jsonResponse({ error: 'Invalid image MIME type', message: '対応していない画像形式です。' }, 400);
      }
      if (typeof imageData !== 'string' || imageData.length === 0 || imageData.length > MAX_IMAGE_BASE64_LENGTH) {
        return jsonResponse({ error: 'Invalid image data', message: '画像データが空、またはサイズ上限を超えています。' }, 400);
      }

      const geminiRequest = {
        contents: [{ role: 'user', parts: [{ text: prompt }, { inlineData: { mimeType, data: imageData } }] }],
        generationConfig: { responseMimeType: 'application/json', temperature: 0.1, maxOutputTokens: 8192 }
      };
      const endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent';
      let geminiResponse;
      let lastError = null;

      for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);
        try {
          geminiResponse = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
            body: JSON.stringify(geminiRequest),
            signal: controller.signal
          });
        } catch (error) {
          lastError = error;
          if (attempt === MAX_RETRIES) throw error;
          await sleep(1000 * Math.pow(2, attempt));
          continue;
        } finally {
          clearTimeout(timeout);
        }
        if (geminiResponse.ok) break;
        const retryable = [500, 502, 503, 504].includes(geminiResponse.status);
        if (!retryable || attempt === MAX_RETRIES) break;
        await sleep(1000 * Math.pow(2, attempt));
      }

      if (!geminiResponse) throw lastError || new Error('Gemini APIへの接続に失敗しました。');
      const responseText = await geminiResponse.text();
      let result;
      try { result = JSON.parse(responseText); }
      catch {
        return jsonResponse({ error: 'Gemini returned a non-JSON response', message: 'GeminiからJSON以外の応答が返されました。', upstreamStatus: geminiResponse.status }, 502);
      }
      if (!geminiResponse.ok) {
        return jsonResponse({
          error: 'Gemini API Error',
          message: result.error?.message || 'Gemini APIでエラーが発生しました。',
          upstreamStatus: geminiResponse.status,
          details: result.error || result
        }, geminiResponse.status);
      }
      return jsonResponse(result, 200);
    } catch (error) {
      if (error.name === 'AbortError') {
        return jsonResponse({ error: 'Request Timeout', message: 'Gemini APIの応答が30秒以内に完了しませんでした。' }, 504);
      }
      return jsonResponse({ error: 'Worker Error', message: error.message || '不明なエラーが発生しました。' }, 500);
    }
  },

  scheduled(controller, env, ctx) {
    ctx.waitUntil(sendScheduledPushes(env));
  }
};
