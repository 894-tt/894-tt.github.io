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
    headers: {
      ...corsHeaders(),
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

// Decode Base64URL without logging or exposing the key contents.
function decodeBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Base64URL文字列ではありません');
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);

  return Uint8Array.from(binary, ch => ch.charCodeAt(0));
}

function bytesToBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

// Independently validate the VAPID key pair and each browser subscription key.
// Only lengths and pass/fail messages are returned; key material is never logged.
async function diagnoseCryptoKeys(subscription, env) {
  const result = {
    vapid: { ok: false, message: '' },
    p256dh: { ok: false, message: '' },
    auth: { ok: false, message: '' }
  };

  try {
    const publicBytes = decodeBase64Url(env.VAPID_PUBLIC_KEY);
    const privateBytes = decodeBase64Url(env.VAPID_PRIVATE_KEY);

    if (publicBytes.length !== 65) {
      throw new Error(`公開鍵の長さが65バイトではありません (${publicBytes.length})`);
    }

    if (publicBytes[0] !== 0x04) {
      throw new Error('公開鍵の先頭が04ではありません');
    }

    if (privateBytes.length !== 32) {
      throw new Error(`秘密鍵の長さが32バイトではありません (${privateBytes.length})`);
    }

    const x = bytesToBase64Url(publicBytes.slice(1, 33));
    const y = bytesToBase64Url(publicBytes.slice(33, 65));

    const signingKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC',
        crv: 'P-256',
        x,
        y,
        d: env.VAPID_PRIVATE_KEY
      },
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      false,
      ['sign']
    );

    const verifyKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC',
        crv: 'P-256',
        x,
        y
      },
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      false,
      ['verify']
    );

    const testData = new TextEncoder().encode('VAPID key pair diagnostic');

    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      signingKey,
      testData
    );

    const matches = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      verifyKey,
      signature,
      testData
    );

    if (!matches) {
      throw new Error('公開鍵と秘密鍵が同じペアではありません');
    }

    result.vapid = {
      ok: true,
      message: 'OK (65-byte public key; matching P-256 pair)'
    };

  } catch (error) {
    result.vapid = {
      ok: false,
      message: error.message || 'VAPID鍵の検証に失敗'
    };
  }

  try {
    const p256dhBytes = decodeBase64Url(subscription?.keys?.p256dh);

    if (p256dhBytes.length !== 65) {
      throw new Error(`p256dhの長さが65バイトではありません (${p256dhBytes.length})`);
    }

    if (p256dhBytes[0] !== 0x04) {
      throw new Error('p256dhの先頭が04ではありません');
    }

    await crypto.subtle.importKey(
      'raw',
      p256dhBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    result.p256dh = {
      ok: true,
      message: 'OK (valid uncompressed P-256 point)'
    };

  } catch (error) {
    result.p256dh = {
      ok: false,
      message: error.message || 'p256dhの検証に失敗'
    };
  }

  try {
    const authBytes = decodeBase64Url(subscription?.keys?.auth);

    if (authBytes.length !== 16) {
      throw new Error(`authの長さが16バイトではありません (${authBytes.length})`);
    }

    result.auth = {
      ok: true,
      message: 'OK (16 bytes)'
    };

  } catch (error) {
    result.auth = {
      ok: false,
      message: error.message || 'authの検証に失敗'
    };
  }

  return result;
}

async function hashToken(token) {
  return base64url(
    await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(token)
    )
  );
}

function isValidPushEndpoint(endpoint) {
  try {
    const u = new URL(endpoint);

    if (u.protocol !== 'https:') return false;

    const h = u.hostname.toLowerCase();

    return h === 'fcm.googleapis.com' ||
      h === 'web.push.apple.com' ||
      h.endsWith('.push.apple.com') ||
      h === 'updates.push.services.mozilla.com' ||
      h.endsWith('.push.services.mozilla.com') ||
      h.endsWith('.notify.windows.com');

  } catch {
    return false;
  }
}

function validSubscription(s) {
  return !!s &&
    typeof s.endpoint === 'string' &&
    isValidPushEndpoint(s.endpoint) &&
    typeof s.keys?.p256dh === 'string' &&
    typeof s.keys?.auth === 'string';
}

function validSettings(s) {
  return !!s &&
    typeof s.time === 'string' &&
    /^([01]\d|2[0-3]):[0-5]\d$/.test(s.time) &&
    Array.isArray(s.days) &&
    s.days.length > 0 &&
    s.days.every(d => Number.isInteger(d) && d >= 0 && d <= 6) &&
    s.include &&
    INCLUDE_KEYS.every(k => typeof s.include[k] === 'boolean');
}

function localParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23'
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

  const selected = events
    .filter(e => e.dateKey === tomorrow)
    .sort((a, b) => slotNumber(a.slot) - slotNumber(b.slot));

  if (!selected.length) return '';

  const lines = [`明日(${m}/${String(d).padStart(2, '0')} ${dow})の予定です。`];
  const inc = settings.include || {};

  const labels = [
    ['items', '持ち物'],
    ['homework', '宿題'],
    ['quiz', '小テスト'],
    ['location', '場所'],
    ['forgotten', '忘れ物'],
    ['notes', '備考']
  ];

  const details = [];

  for (const [key, label] of labels) {
    if (!inc[key]) continue;

    for (const e of selected) {
      const value = String(e[key] || '').trim();

      if (value) {
        details.push(`${label}: ${e.subject}(${value})`);
      }
    }
  }

  if (details.length) {
    lines.push(details.join('\n'));
  }

  if (inc.schedule) {
    const periods = selected
      .filter(e => e.subject)
      .map(e => {
        const slot = e.slot === '朝' ? '朝' : String(e.slot || '');
        const end = e.endSlot && e.endSlot !== e.slot ? `〜${e.endSlot}` : '';
        const place = inc.location && e.location ? ` (${e.location})` : '';

        return `${slot}${end}: ${e.subject}${place}`;
      });

    if (periods.length) {
      lines.push(periods.join('\n'));
    }
  }

  return lines.join('\n').slice(0, 3500);
}


async function ensureAdminSchema(env) {
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS admin_templates (id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)').run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS admin_login_attempts (ip_hash TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, blocked_until INTEGER NOT NULL DEFAULT 0)').run();
  const cols = await env.DB.prepare('PRAGMA table_info(push_devices)').all();
  if (!(cols.results || []).some(c => c.name === 'class_id')) {
    await env.DB.prepare('ALTER TABLE push_devices ADD COLUMN class_id TEXT').run();
  }
}
function randomHex(bytes = 32) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function adminSession(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!/^[a-f0-9]{64}$/.test(token)) return false;
  const hash = await hashToken(token);
  const row = await env.DB.prepare('SELECT expires_at FROM admin_sessions WHERE token_hash=?').bind(hash).first();
  if (!row || Number(row.expires_at) <= Math.floor(Date.now() / 1000)) {
    if (row) await env.DB.prepare('DELETE FROM admin_sessions WHERE token_hash=?').bind(hash).run();
    return false;
  }
  return true;
}
async function sendAdminPush(env, subscription, title, body) {
  if (!validSubscription(subscription)) throw new Error('Invalid subscription');
  const payload = await buildPushPayload({data:{title,body,url:'./',sound:true},options:{ttl:3600,urgency:'high'}}, subscription, {
    subject:env.VAPID_SUBJECT, publicKey:env.VAPID_PUBLIC_KEY, privateKey:env.VAPID_PRIVATE_KEY
  });
  const response = await fetch(subscription.endpoint, payload);
  if (response.status === 404 || response.status === 410) return 'expired';
  if (!response.ok) throw new Error('Push service returned ' + response.status);
  return 'sent';
}
async function handleAdminRequest(request, env, url, body) {
  const path = url.pathname;
  if (!path.startsWith('/api/push/admin/')) return null;
  await ensureAdminSchema(env);

  if (path === '/api/push/admin/login') {
    const ipHash = await hashToken(request.headers.get('CF-Connecting-IP') || 'unknown');
    const now = Math.floor(Date.now() / 1000);
    const attempt = await env.DB.prepare('SELECT attempts,blocked_until FROM admin_login_attempts WHERE ip_hash=?').bind(ipHash).first();
    if (attempt && Number(attempt.blocked_until) > now) return jsonResponse({error:'ログイン試行が多すぎます。15分後に再試行してください。'},429);
    const supplied = typeof body.password === 'string' ? body.password : '';
    const expected = env.ADMIN_PASSWORD || '';
    let diff = supplied.length ^ expected.length;
    const length = Math.max(supplied.length, expected.length);
    for (let i=0;i<length;i++) diff |= (supplied.charCodeAt(i)||0) ^ (expected.charCodeAt(i)||0);
    if (!expected || diff !== 0) {
      const count = (attempt ? Number(attempt.attempts) : 0) + 1;
      const blocked = count >= 5 ? now + 900 : 0;
      await env.DB.prepare('INSERT INTO admin_login_attempts(ip_hash,attempts,blocked_until) VALUES(?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET attempts=excluded.attempts,blocked_until=excluded.blocked_until')
        .bind(ipHash, blocked ? 0 : count, blocked).run();
      return jsonResponse({error:'パスワードが違います。'},401);
    }
    await env.DB.prepare('DELETE FROM admin_login_attempts WHERE ip_hash=?').bind(ipHash).run();
    const token = randomHex();
    await env.DB.prepare('INSERT INTO admin_sessions(token_hash,expires_at) VALUES(?,?)').bind(await hashToken(token),now+43200).run();
    return jsonResponse({ok:true,token,expiresIn:43200});
  }

  if (!(await adminSession(request,env))) return jsonResponse({error:'管理者ログインが必要です。'},401);
  if (path === '/api/push/admin/logout') {
    const token = (request.headers.get('Authorization') || '').slice(7);
    await env.DB.prepare('DELETE FROM admin_sessions WHERE token_hash=?').bind(await hashToken(token)).run();
    return jsonResponse({ok:true});
  }
  if (path === '/api/push/admin/summary') {
    const rows = await env.DB.prepare('SELECT class_id,settings_json FROM push_devices').all();
    const devices = rows.results || [], classes = {};
    let enabled = 0;
    for (const row of devices) {
      const id = row.class_id || '未分類';
      classes[id] = (classes[id] || 0) + 1;
      try { if (JSON.parse(row.settings_json || '{}').enabled) enabled++; } catch {}
    }
    return jsonResponse({total:devices.length,enabled,classes});
  }
  if (path === '/api/push/admin/send') {
    const title = typeof body.title === 'string' ? body.title.trim().slice(0,100) : '';
    const message = typeof body.body === 'string' ? body.body.trim().slice(0,3500) : '';
    const target = body.target === 'class' ? 'class' : 'all';
    const classId = typeof body.classId === 'string' ? body.classId.slice(0,100) : '';
    const enabledOnly = body.enabledOnly === true;
    if (!title || !message || (target === 'class' && !classId)) return jsonResponse({error:'タイトル・本文・対象クラスを確認してください。'},400);
    if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY || !env.VAPID_SUBJECT) return jsonResponse({error:'Push設定が不足しています。'},500);
    const rows = await env.DB.prepare('SELECT token_hash,subscription_json,settings_json,class_id FROM push_devices').all();
    const selected = (rows.results || []).filter(row =>
      (target !== 'class' || row.class_id === classId) &&
      (!enabledOnly || (() => { try { return JSON.parse(row.settings_json || '{}').enabled === true; } catch { return false; } })())
    );
    let sent=0, failed=0, expired=0;
    for (const row of selected) {
      try {
        const result = await sendAdminPush(env,JSON.parse(row.subscription_json),title,message);
        if (result === 'sent') sent++;
        else { expired++; await env.DB.prepare('DELETE FROM push_devices WHERE token_hash=?').bind(row.token_hash).run(); }
      } catch (error) { failed++; console.error('[ADMIN_PUSH] delivery failed',error.message); }
    }
    return jsonResponse({ok:true,targets:selected.length,sent,failed,expired});
  }
  if (path === '/api/push/admin/templates') {
    if (request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT id,title,body,updated_at FROM admin_templates ORDER BY updated_at DESC').all();
      return jsonResponse({templates:rows.results || []});
    }
    if (request.method === 'POST') {
      const id = typeof body.id === 'string' && /^[a-f0-9]{16}$/.test(body.id) ? body.id : randomHex(8);
      const title = typeof body.title === 'string' ? body.title.trim().slice(0,100) : '';
      const message = typeof body.body === 'string' ? body.body.trim().slice(0,3500) : '';
      if (!title || !message) return jsonResponse({error:'テンプレート名と本文を入力してください。'},400);
      await env.DB.prepare('INSERT INTO admin_templates(id,title,body,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET title=excluded.title,body=excluded.body,updated_at=CURRENT_TIMESTAMP').bind(id,title,message).run();
      return jsonResponse({ok:true,id});
    }
    if (request.method === 'DELETE') {
      await env.DB.prepare('DELETE FROM admin_templates WHERE id=?').bind(typeof body.id === 'string' ? body.id : '').run();
      return jsonResponse({ok:true});
    }
  }
  return jsonResponse({error:'Not found'},404);
}

async function handlePushRequest(request, env) {
  const url = new URL(request.url);

  if (!url.pathname.startsWith(PUSH_PREFIX)) return null;

  const origin = request.headers.get('Origin') || '';

  if (origin !== ALLOWED_ORIGIN) {
    return jsonResponse({ error: 'Origin not allowed' }, 403);
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: corsHeaders()
    });
  }

  if (request.method !== 'POST' && !(url.pathname === '/api/push/admin/templates' && (request.method === 'GET' || request.method === 'DELETE'))) {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }

  if (!env.DB) {
    return jsonResponse({ error: 'D1 binding DB is not configured' }, 500);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    if (request.method === 'GET') body = {};
    else return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  const adminBody = await request.clone().json().catch(() => ({}));
  const adminResponse = await handleAdminRequest(request, env, url, adminBody);
  if (adminResponse) return adminResponse;

  if (url.pathname === '/api/push/subscribe') {
    const token = String(body.token || '');
    const events = Array.isArray(body.events) ? body.events.slice(0, 500) : [];

    if (
      !/^[a-f0-9]{64}$/.test(token) ||
      !validSubscription(body.subscription) ||
      !validSettings(body.settings)
    ) {
      return jsonResponse({ error: 'Invalid subscription or settings' }, 400);
    }

    const tokenHash = await hashToken(token);

    await env.DB.prepare(`INSERT INTO push_devices(token_hash, subscription_json, settings_json, events_json, class_id, updated_at)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(token_hash) DO UPDATE SET
        subscription_json=excluded.subscription_json,
        settings_json=excluded.settings_json,
        events_json=excluded.events_json,
        class_id=excluded.class_id,
        last_sent_date=NULL,
        updated_at=CURRENT_TIMESTAMP`)
      .bind(
        tokenHash,
        JSON.stringify(body.subscription),
        JSON.stringify(body.settings),
        JSON.stringify(events),
        typeof body.classId === 'string' ? body.classId.slice(0, 100) : null
      )
      .run();

    return jsonResponse({ ok: true });
  }

  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (!/^[a-f0-9]{64}$/.test(token)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const tokenHash = await hashToken(token);

  if (url.pathname === '/api/push/schedule') {
    const events = Array.isArray(body.events) ? body.events.slice(0, 500) : [];

    const result = await env.DB.prepare(
      'UPDATE push_devices SET events_json=?, class_id=?, updated_at=CURRENT_TIMESTAMP WHERE token_hash=?'
    )
      .bind(JSON.stringify(events), typeof body.classId === 'string' ? body.classId.slice(0, 100) : null, tokenHash)
      .run();

    if (!(result.meta?.changes > 0)) {
      return jsonResponse({ error: 'Device not found' }, 404);
    }

    return jsonResponse({ ok: true });
  }

  if (url.pathname === '/api/push/unsubscribe') {
    await env.DB.prepare(
      'DELETE FROM push_devices WHERE token_hash=?'
    )
      .bind(tokenHash)
      .run();

    return jsonResponse({ ok: true });
  }

  return jsonResponse({ error: 'Not found' }, 404);
}

async function sendScheduledPushes(env) {
  console.log('[PUSH_DIAG] START', new Date().toISOString());

  if (
    !env.DB ||
    !env.VAPID_PUBLIC_KEY ||
    !env.VAPID_PRIVATE_KEY ||
    !env.VAPID_SUBJECT
  ) {
    console.error('[PUSH_DIAG] Missing configuration', {
      DB: !!env.DB,
      publicKey: !!env.VAPID_PUBLIC_KEY,
      privateKey: !!env.VAPID_PRIVATE_KEY,
      subject: !!env.VAPID_SUBJECT
    });

    throw new Error('Missing D1 or VAPID configuration');
  }

  const now = localParts();
  const today = `${now.year}-${now.month}-${now.day}`;
  const tomorrow = dateAfterDays(today, 1);

  console.log('[PUSH_DIAG] CLOCK', {
    today,
    time: `${now.hour}:${now.minute}`,
    weekday: weekdayForIso(today),
    tomorrow
  });

  const rows = await env.DB.prepare(
    'SELECT token_hash, subscription_json, settings_json, events_json, last_sent_date FROM push_devices'
  ).all();

  console.log('[PUSH_DIAG] DEVICES', rows.results?.length || 0);

  for (let i = 0; i < (rows.results || []).length; i++) {
    const row = rows.results[i];

    let settings, subscription, events;

    try {
      settings = JSON.parse(row.settings_json);
      subscription = JSON.parse(row.subscription_json);
      events = JSON.parse(row.events_json || '[]');

    } catch (error) {
      console.error('[PUSH_DIAG] JSON ERROR', i, error.message);
      continue;
    }

    const timeMatch = settings.time === `${now.hour}:${now.minute}`;
    const dayMatch = (settings.days || []).includes(weekdayForIso(today));
    const alreadySent = row.last_sent_date === today;

    const tomorrowCount = events.filter(
      e => e.dateKey === tomorrow
    ).length;

    console.log('[PUSH_DIAG] DEVICE', {
      index: i,
      enabled: settings.enabled,
      time: settings.time,
      timeMatch,
      dayMatch,
      alreadySent,
      tomorrowCount,
      validSubscription: validSubscription(subscription)
    });

    if (!settings.enabled || !timeMatch || !dayMatch || alreadySent) {
      console.log('[PUSH_DIAG] SKIPPED', i);
      continue;
    }

    const body = makeNotificationBody(events, settings, tomorrow);

    if (!body) {
      console.log('[PUSH_DIAG] NO TOMORROW EVENTS', i, tomorrow);
      continue;
    }

    const message = {
      data: {
        title: '明日の時間割',
        body,
        url: './',
        sound: settings.sound !== false
      },
      options: {
        ttl: 3600,
        urgency: 'high'
      }
    };

    try {
      const keyDiag = await diagnoseCryptoKeys(subscription, env);

      console.log('[KEY_DIAG]', {
        index: i,
        vapid: keyDiag.vapid,
        p256dh: keyDiag.p256dh,
        auth: keyDiag.auth
      });

      if (
        !keyDiag.vapid.ok ||
        !keyDiag.p256dh.ok ||
        !keyDiag.auth.ok
      ) {
        console.error('[PUSH_DIAG] KEY VALIDATION FAILED', i);
        continue;
      }

      console.log('[PUSH_DIAG] KEY VALIDATION PASSED', i);

      const payload = await buildPushPayload(message, subscription, {
        subject: env.VAPID_SUBJECT,
        publicKey: env.VAPID_PUBLIC_KEY,
        privateKey: env.VAPID_PRIVATE_KEY
      });

      const response = await fetch(subscription.endpoint, payload);

      console.log('[PUSH_DIAG] PUSH RESPONSE', {
        index: i,
        status: response.status,
        ok: response.ok
      });

      if (response.status === 404 || response.status === 410) {
        await env.DB.prepare(
          'DELETE FROM push_devices WHERE token_hash=?'
        )
          .bind(row.token_hash)
          .run();

        continue;
      }

      if (!response.ok) {
        throw new Error(`Push service returned ${response.status}`);
      }

      await env.DB.prepare(
        'UPDATE push_devices SET last_sent_date=?, updated_at=CURRENT_TIMESTAMP WHERE token_hash=?'
      )
        .bind(today, row.token_hash)
        .run();

      console.log('[PUSH_DIAG] SENT', i);

    } catch (error) {
      console.error('[PUSH_DIAG] DELIVERY ERROR', i, error.message);
    }
  }

  console.log('[PUSH_DIAG] FINISHED');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      });
    }

    // Push endpoints (including the admin API) are handled before the original Gemini route.
    const pushResponse = await handlePushRequest(request, env);

    if (pushResponse) return pushResponse;

    if (request.method === 'GET' && url.pathname === '/') {
      const apiKey = env.gem_api || env.GEM_API;

      return jsonResponse({
        ok: true,
        service: 'timetable-gem-api',
        message: 'Worker is running.',
        secretConfigured: Boolean(apiKey),
        pushConfigured: Boolean(
          env.DB &&
          env.VAPID_PUBLIC_KEY &&
          env.VAPID_PRIVATE_KEY &&
          env.VAPID_SUBJECT
        )
      }, 200);
    }

    if (url.pathname !== '/api/timetable') {
      return jsonResponse({
        error: 'Not Found',
        message: '利用可能なパスは /api/timetable です。'
      }, 404);
    }

    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method Not Allowed' }, 405);
    }

    if (origin && origin !== ALLOWED_ORIGIN) {
      return jsonResponse({
        error: 'Forbidden',
        message: '許可されていないアクセス元です。'
      }, 403);
    }

    const apiKey = env.gem_api || env.GEM_API;

    if (!apiKey) {
      return jsonResponse({
        error: 'API key is not configured',
        message: 'Cloudflare WorkerのSecret gem_api または GEM_API を確認してください。'
      }, 500);
    }

    try {
      const input = await request.json();
      const prompt = typeof input.prompt === 'string' ? input.prompt.trim() : '';
      const image = input.image || {};
      const mimeType = image.mimeType;
      const imageData = image.data;

      const model = typeof input.model === 'string' &&
        /^[a-zA-Z0-9._-]+$/.test(input.model)
        ? input.model
        : DEFAULT_MODEL;

      if (!prompt) {
        return jsonResponse({
          error: 'Invalid request',
          message: 'prompt が指定されていません。'
        }, 400);
      }

      if (
        typeof mimeType !== 'string' ||
        !/^image\/(jpeg|jpg|png|webp|heic|heif)$/.test(mimeType)
      ) {
        return jsonResponse({
          error: 'Invalid image MIME type',
          message: '対応していない画像形式です。'
        }, 400);
      }

      if (
        typeof imageData !== 'string' ||
        imageData.length === 0 ||
        imageData.length > MAX_IMAGE_BASE64_LENGTH
      ) {
        return jsonResponse({
          error: 'Invalid image data',
          message: '画像データが空、またはサイズ上限を超えています。'
        }, 400);
      }

      const geminiRequest = {
        contents: [{
          role: 'user',
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType,
                data: imageData
              }
            }
          ]
        }],
        generationConfig: {
          responseMimeType: 'application/json',
          temperature: 0.1,
          maxOutputTokens: 8192
        }
      };

      const endpoint =
        'https://generativelanguage.googleapis.com/v1beta/models/' +
        encodeURIComponent(model) +
        ':generateContent';

      let geminiResponse;
      let lastError = null;

      for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000);

        try {
          geminiResponse = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-goog-api-key': apiKey
            },
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

        const retryable = [500, 502, 503, 504].includes(
          geminiResponse.status
        );

        if (!retryable || attempt === MAX_RETRIES) break;

        await sleep(1000 * Math.pow(2, attempt));
      }

      if (!geminiResponse) {
        throw lastError || new Error('Gemini APIへの接続に失敗しました。');
      }

      const responseText = await geminiResponse.text();

      let result;

      try {
        result = JSON.parse(responseText);

      } catch {
        return jsonResponse({
          error: 'Gemini returned a non-JSON response',
          message: 'GeminiからJSON以外の応答が返されました。',
          upstreamStatus: geminiResponse.status
        }, 502);
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
        return jsonResponse({
          error: 'Request Timeout',
          message: 'Gemini APIの応答が30秒以内に完了しませんでした。'
        }, 504);
      }

      return jsonResponse({
        error: 'Worker Error',
        message: error.message || '不明なエラーが発生しました。'
      }, 500);
    }
  },

  async scheduled(controller, env, ctx) {
    console.log('[CRON_DIAG] START', {
      cron: controller.cron,
      scheduledTime: new Date(controller.scheduledTime).toISOString()
    });

    ctx.waitUntil(
      sendScheduledPushes(env).catch(error => {
        console.error('[CRON_DIAG] ERROR', error.stack || error.message);
        throw error;
      })
    );
  }
};
