/* 日記帳 core.js
 * 画面に依存しない処理（暗号化・CSV取り込み・最新版の判定・集計）。
 * ブラウザでは window.DiaryCore、Node(テスト)では require('./core.js') で使う。
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DiaryCore = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------
  // 暗号化
  //  合言葉は創作帳と同じものを使うが、saltと反復回数が違うので鍵は別物になる
  // ---------------------------------------------------------------
  const KDF_SALT_B64 = 'Aevu4Eqkqr6wG6NOTa1iLA=='; // 日記専用のsalt（秘密ではない。変えると過去の記録が読めなくなる）
  const KDF_ITERATIONS = 600000;                   // OWASP推奨（PBKDF2-HMAC-SHA256）
  const PAYLOAD_VERSION = 1;

  const subtle = () => (globalThis.crypto && globalThis.crypto.subtle);

  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }
  function b64ToBuf(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  async function deriveKey(passphrase, opts) {
    const o = opts || {};
    const enc = new TextEncoder();
    const base = await subtle().importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle().deriveKey(
      { name: 'PBKDF2', salt: b64ToBuf(o.salt || KDF_SALT_B64), iterations: o.iterations || KDF_ITERATIONS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
  }
  async function exportKey(key) { return bufToB64(await subtle().exportKey('raw', key)); }
  async function importKey(rawB64) {
    return subtle().importKey('raw', b64ToBuf(rawB64), 'AES-GCM', true, ['encrypt', 'decrypt']);
  }

  // 暗号化するときに day を「追加認証データ」にも入れる。
  // → 暗号文を別の日付の行にコピーされても復号に失敗する
  async function encryptJSON(key, obj, day) {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(obj));
    const params = { name: 'AES-GCM', iv };
    if (day) params.additionalData = new TextEncoder().encode('diary:' + day);
    const ct = await subtle().encrypt(params, key, data);
    return { iv: bufToB64(iv), ciphertext: bufToB64(ct) };
  }
  async function decryptJSON(key, ivB64, ctB64, day) {
    const params = { name: 'AES-GCM', iv: b64ToBuf(ivB64) };
    if (day) params.additionalData = new TextEncoder().encode('diary:' + day);
    const buf = await subtle().decrypt(params, key, b64ToBuf(ctB64));
    return JSON.parse(new TextDecoder().decode(buf));
  }

  // 1日分の「版」を作る
  function makeVersion(day, fields, ts) {
    const title = (fields.title || '').trim();
    const body = (fields.body || '').replace(/\s+$/, '');
    const tags = uniq((fields.tags || []).map(normalizeTag).filter(Boolean));
    const people = uniq((fields.people || []).map(normalizeTag).filter(Boolean));
    const deleted = !!fields.deleted || (!title && !body.trim() && !tags.length && !people.length);
    return { v: PAYLOAD_VERSION, day, ts: ts || Date.now(), title, body, tags, people, deleted };
  }

  async function encryptRow(key, version) {
    const { iv, ciphertext } = await encryptJSON(key, version, version.day);
    return { day: version.day, iv, ciphertext };
  }

  // 行を復号。失敗（偽の行・壊れた行・別の合言葉）は null
  async function decryptRow(key, row) {
    try {
      const p = await decryptJSON(key, row.iv, row.ciphertext, row.day);
      if (!p || p.day !== row.day || typeof p.ts !== 'number') return null;
      return {
        day: p.day, ts: p.ts, title: p.title || '', body: p.body || '',
        tags: Array.isArray(p.tags) ? p.tags : [], people: Array.isArray(p.people) ? p.people : [],
        deleted: !!p.deleted,
      };
    } catch (e) { return null; }
  }

  // 版の集まりから、日ごとの最新版だけを残す（削除された日は除く）
  // 「最新」は暗号文の中の ts で決める（サーバーの時刻や行番号は信用しない）
  function reduceLatest(versions) {
    const latest = new Map();
    for (const v of versions) {
      if (!v) continue;
      const cur = latest.get(v.day);
      if (!cur || v.ts > cur.ts) latest.set(v.day, v);
    }
    const out = new Map();
    for (const [day, v] of latest) if (!v.deleted) out.set(day, v);
    return out;
  }

  // ---------------------------------------------------------------
  // 日付
  // ---------------------------------------------------------------
  const WEEKDAYS = ['日', '月', '火', '水', '木', '金', '土'];
  const pad = (n) => String(n).padStart(2, '0');
  function toDay(d) { return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }
  function parseDay(s) { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); }
  function addDays(day, n) { const d = parseDay(day); d.setDate(d.getDate() + n); return toDay(d); }
  function weekday(day) { return WEEKDAYS[parseDay(day).getDay()]; }
  function isValidDay(s) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    return toDay(parseDay(s)) === s;
  }
  function formatDay(day, withYear) {
    const [y, m, d] = day.split('-').map(Number);
    return `${withYear ? y + '年' : ''}${m}月${d}日(${weekday(day)})`;
  }

  // ---------------------------------------------------------------
  // タグ
  // ---------------------------------------------------------------
  function normalizeTag(s) {
    return String(s || '')
      .replace(/^[\s#＃@＠]+/, '')
      .replace(/[\s,、，]+/g, '')
      .trim()
      .slice(0, 40);
  }
  function uniq(arr) { return Array.from(new Set(arr)); }

  // 入力欄の文字列 "#北野神社 #万博、ピラティス" → ["北野神社","万博","ピラティス"]
  function splitTagInput(s) {
    return uniq(String(s || '').split(/[\s,、，]+/).map(normalizeTag).filter(Boolean));
  }

  // entries: 最新版の配列（日付順でなくてよい）
  function tagStats(entries, field, year) {
    const total = new Map(), inYear = new Map(), last = new Map();
    for (const e of entries) {
      for (const t of e[field] || []) {
        total.set(t, (total.get(t) || 0) + 1);
        if (year && e.day.startsWith(String(year))) inYear.set(t, (inYear.get(t) || 0) + 1);
        if (!last.has(t) || e.day > last.get(t)) last.set(t, e.day);
      }
    }
    return Array.from(total.keys()).map(name => ({
      name, total: total.get(name), year: inYear.get(name) || 0, last: last.get(name),
    })).sort((a, b) => b.total - a.total || (a.last < b.last ? 1 : -1));
  }

  // その日の記録が「そのタグで今年何回目・通算何回目か」
  function occurrence(entries, field, tag, day) {
    const y = day.slice(0, 4);
    let total = 0, year = 0;
    for (const e of entries) {
      if (e.day > day) continue;
      if (!(e[field] || []).includes(tag)) continue;
      total++;
      if (e.day.slice(0, 4) === y) year++;
    }
    return { total, year };
  }

  // ---------------------------------------------------------------
  // 一覧・振り返り
  // ---------------------------------------------------------------
  function sortDesc(entries) { return entries.slice().sort((a, b) => (a.day < b.day ? 1 : a.day > b.day ? -1 : 0)); }

  // 過去の同じ日（1年前・2年前…）
  function sameDayPast(entryMap, day) {
    const out = [];
    const [y, m, d] = day.split('-');
    const years = new Set(Array.from(entryMap.keys()).map(k => k.slice(0, 4)));
    for (const py of Array.from(years).sort().reverse()) {
      if (py >= y) continue;
      const e = entryMap.get(`${py}-${m}-${d}`);
      if (e) out.push({ yearsAgo: Number(y) - Number(py), entry: e });
    }
    return out;
  }

  // 直近 n 日の未記入日（今日を含まない、新しい順）
  function missingDays(entryMap, today, n) {
    const out = [];
    for (let i = 1; i <= n; i++) {
      const day = addDays(today, -i);
      if (!entryMap.has(day)) out.push(day);
    }
    return out;
  }

  function isEvent(e) { return !!e.title || (e.tags || []).includes('イベント'); }

  // イベント一覧：見出しのある日。同じタグが連続する日は1枚にまとめる（旅行など）
  const NON_GROUPING_TAGS = new Set(['イベント', '日常', '気づき', '思索']);
  function groupEvents(entries) {
    const ev = entries.filter(isEvent).sort((a, b) => (a.day < b.day ? -1 : 1));
    const groups = [];
    for (const e of ev) {
      const g = groups[groups.length - 1];
      if (g) {
        const prev = g.items[g.items.length - 1];
        const shared = (e.tags || []).filter(t => !NON_GROUPING_TAGS.has(t) && (prev.tags || []).includes(t));
        if (addDays(prev.day, 1) === e.day && shared.length) {
          g.items.push(e);
          g.sharedTags = g.sharedTags ? g.sharedTags.filter(t => shared.includes(t)) : shared;
          if (!g.sharedTags.length) g.sharedTags = shared;
          continue;
        }
      }
      groups.push({ items: [e], sharedTags: null });
    }
    return groups.map(g => ({
      start: g.items[0].day, end: g.items[g.items.length - 1].day, items: g.items,
      label: g.items.length > 1 ? (g.sharedTags || [])[0] : null,
    })).reverse();
  }

  function search(entries, q) {
    const kw = (q.keyword || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    return sortDesc(entries.filter(e => {
      if (q.from && e.day < q.from) return false;
      if (q.to && e.day > q.to) return false;
      if (q.tag && !(e.tags || []).includes(q.tag)) return false;
      if (q.person && !(e.people || []).includes(q.person)) return false;
      if (kw.length) {
        const hay = [e.title, e.body, ...(e.tags || []), ...(e.people || [])].join('\n').toLowerCase();
        if (!kw.every(k => hay.includes(k))) return false;
      }
      return true;
    }));
  }

  // キーワード一括タグ付けの対象を探す（|区切りで複数語）
  function findByKeywords(entries, pattern) {
    const words = String(pattern || '').split(/[|｜]/).map(s => s.trim()).filter(Boolean);
    if (!words.length) return [];
    return sortDesc(entries.filter(e => {
      const hay = (e.title || '') + '\n' + (e.body || '');
      return words.some(w => hay.includes(w));
    }));
  }

  // ---------------------------------------------------------------
  // CSV（Googleスプレッドシートの書き出し）
  // ---------------------------------------------------------------
  function parseCSV(text) {
    const rows = [];
    let row = [], field = '', i = 0, inQ = false;
    const s = String(text).replace(/^﻿/, '');
    while (i < s.length) {
      const c = s[i];
      if (inQ) {
        if (c === '"') {
          if (s[i + 1] === '"') { field += '"'; i += 2; continue; }
          inQ = false; i++; continue;
        }
        field += c; i++; continue;
      }
      if (c === '"') { inQ = true; i++; continue; }
      if (c === ',') { row.push(field); field = ''; i++; continue; }
      if (c === '\r') { i++; continue; }
      if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
      field += c; i++;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows;
  }

  // スプレッドシートの日記 → [{day,title,body,flags}]
  // 列：A=日付 B=出来事 C=日記 … H=日常 I=気づき J=思索 K=イベント
  function extractDiaryRows(text) {
    // 「## Sheet name:」付きの形式なら最初のシートだけ使う
    let t = String(text);
    const marks = [...t.matchAll(/^## Sheet name:.*$/gm)];
    if (marks.length) {
      const start = marks[0].index + marks[0][0].length + 1;
      const end = marks.length > 1 ? marks[1].index : t.length;
      t = t.slice(start, end);
    }
    const out = [];
    for (const r of parseCSV(t)) {
      const m = /^\s*(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})/.exec(r[0] || '');
      if (!m) continue;
      const day = `${m[1]}-${pad(m[2])}-${pad(m[3])}`;
      if (!isValidDay(day)) continue;
      const title = (r[1] || '').trim();
      const body = (r[2] || '').replace(/\s+$/, '').replace(/^\s+/, '');
      if (!title && !body) continue;
      const flag = (v) => String(v || '').trim().toUpperCase() === 'TRUE';
      out.push({ day, title, body, flags: { 日常: flag(r[7]), 気づき: flag(r[8]), 思索: flag(r[9]), イベント: flag(r[10]) } });
    }
    return out;
  }

  // 取り込み用の版を作る。既に記録がある日は飛ばす
  function buildImport(rows, opts, existingDays, ts) {
    const o = opts || {};
    const seen = new Set();
    const versions = [], skipped = [];
    for (const r of rows) {
      if ((existingDays && existingDays.has(r.day)) || seen.has(r.day)) { skipped.push(r.day); continue; }
      seen.add(r.day);
      const tags = [];
      if (o.eventTag && r.flags.イベント) tags.push('イベント');
      if (o.otherTags) for (const k of ['日常', '気づき', '思索']) if (r.flags[k]) tags.push(k);
      versions.push(makeVersion(r.day, { title: r.title, body: r.body, tags }, ts));
    }
    return { versions, skipped };
  }

  // 一覧で見出しがない日の代わりに出す短い文
  function headline(e, n) {
    if (e.title) return e.title;
    const first = (e.body || '').split(/\n/)[0].trim();
    const lim = n || 24;
    return first.length > lim ? first.slice(0, lim) + '…' : first;
  }

  return {
    KDF_SALT_B64, KDF_ITERATIONS,
    bufToB64, b64ToBuf, deriveKey, exportKey, importKey, encryptJSON, decryptJSON,
    makeVersion, encryptRow, decryptRow, reduceLatest,
    toDay, parseDay, addDays, weekday, isValidDay, formatDay, WEEKDAYS,
    normalizeTag, splitTagInput, tagStats, occurrence,
    sortDesc, sameDayPast, missingDays, isEvent, groupEvents, search, findByKeywords,
    parseCSV, extractDiaryRows, buildImport, headline,
  };
});
