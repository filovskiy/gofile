'use strict';
(() => {

const cfg = Object.assign(
  { owner: '', repo: '', branch: 'main', token: '', maxBytes: 40 * 1024 * 1024, ttlDays: 7 },
  window.GOFILE_CONFIG || {}
);
if (!cfg.owner || !cfg.repo) {
  document.querySelector('.wrap').innerHTML =
    '<p class="stage err">config.js не настроен: укажите owner и repo.</p>';
  return;
}
const API = `https://api.github.com/repos/${cfg.owner}/${cfg.repo}/contents`;
const RAW = `https://raw.githubusercontent.com/${cfg.owner}/${cfg.repo}/${cfg.branch}`;

const $ = (id) => document.getElementById(id);
const els = {
  tabSend: $('tab-send'), tabGet: $('tab-get'),
  panelSend: $('panel-send'), panelGet: $('panel-get'),
  tokenBox: $('token-box'), tokenInput: $('token-input'), tokenSave: $('token-save'),
  drop: $('dropzone'), file: $('file-input'), dropHint: $('drop-hint'),
  prog: $('upload-progress'), bar: $('upload-bar'), pct: $('upload-pct'), stage: $('upload-stage'),
  result: $('upload-result'), resId: $('result-id'), resLink: $('result-link'),
  hex: $('hex-input'), btnGet: $('btn-get'), getStage: $('get-status'),
};

let token = String(cfg.token || '').trim() || localStorage.getItem('gofile-token') || '';

/* ---------------- utils ---------------- */

const enc = new TextEncoder();
const MAGIC = enc.encode('GOF1');
const DAY_MS = 86400000;
const EPOCH = Date.UTC(2020, 0, 1);

const fmtBytes = (n) => {
  if (n >= 1048576) return (n / 1048576).toFixed(1).replace('.', ',') + ' МБ';
  if (n >= 1024) return (n / 1024).toFixed(1).replace('.', ',') + ' КБ';
  return n + ' Б';
};
const normId = (s) => String(s || '').toLowerCase().replace(/[^0-9a-f]/g, '');
const fmtId = (h) => (h.match(/.{1,8}/g) || []).join(' ');
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (nBytes) => hex(crypto.getRandomValues(new Uint8Array(nBytes)));

// id: 6 hex = дни с 2020-01-01 (даёт директорию хранения и срок жизни) + 26 hex случайных
const nowDays = () => Math.floor((Date.now() - EPOCH) / DAY_MS);
const daysToDate = (days) => new Date(EPOCH + days * DAY_MS).toISOString().slice(0, 10);
const makeId = () => nowDays().toString(16).padStart(6, '0') + randomHex(13);

function parseId(id) {
  if (!/^[0-9a-f]{32}$/.test(id)) return null;
  const days = parseInt(id.slice(0, 6), 16);
  if (!Number.isInteger(days) || days < 0 || days > 40000) return null;
  return { dir: daysToDate(days) };
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { return document.execCommand('copy'); } catch { return false; }
    finally { ta.remove(); }
  }
}

/* ---------------- crypto ---------------- */

// оба ключа выводятся из hex-id: AES-GCM для данных, HMAC для имени файла в хранилище.
// имя блоба = HMAC(id) ≠ id, поэтому по списку файлов в публичном репозитории
// нельзя восстановить ни один id и расшифровать чужие файлы.
async function deriveKeys(id) {
  const salt = await crypto.subtle.digest('SHA-256', enc.encode('gofile-v1'));
  const mat = await crypto.subtle.importKey('raw', enc.encode(id), 'PBKDF2', false, ['deriveKey']);
  const params = { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' };
  const aes = await crypto.subtle.deriveKey(params, mat,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const mac = await crypto.subtle.deriveKey(params, mat,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return { aes, mac };
}

async function storageName(keys) {
  const sig = await crypto.subtle.sign('HMAC', keys.mac, enc.encode('gofile-path-v1'));
  return hex(new Uint8Array(sig)).slice(0, 40);
}

function bytesToB64(bytes) {
  let bin = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  }
  return btoa(bin);
}

// plaintext: [4B nameLen BE][name utf8][4B mimeLen BE][mime utf8][file bytes]
async function packPlain(file) {
  const nameB = enc.encode(file.name || 'file');
  const typeB = enc.encode(file.type || 'application/octet-stream');
  const data = new Uint8Array(await file.arrayBuffer());
  const plain = new Uint8Array(8 + nameB.length + typeB.length + data.length);
  const dv = new DataView(plain.buffer);
  dv.setUint32(0, nameB.length, false);
  plain.set(nameB, 4);
  let off = 4 + nameB.length;
  dv.setUint32(off, typeB.length, false);
  plain.set(typeB, off + 4);
  plain.set(data, off + 4 + typeB.length);
  return plain;
}

function unpackPlain(plain) {
  const dv = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const nameLen = dv.getUint32(0, false);
  if (8 + nameLen > plain.length) throw new Error('bad-format');
  const name = new TextDecoder().decode(plain.subarray(4, 4 + nameLen));
  let off = 4 + nameLen;
  const typeLen = dv.getUint32(off, false);
  if (off + 4 + typeLen > plain.length) throw new Error('bad-format');
  const type = new TextDecoder().decode(plain.subarray(off + 4, off + 4 + typeLen));
  off += 4 + typeLen;
  return { name, type, data: plain.subarray(off) };
}

// blob: "GOF1" + 12B IV + AES-GCM(plaintext)
async function encryptBlob(aesKey, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plain));
  const out = new Uint8Array(16 + ct.length);
  out.set(MAGIC, 0);
  out.set(iv, 4);
  out.set(ct, 16);
  return out;
}

async function decryptBlob(aesKey, blob) {
  let magic = '';
  for (let i = 0; i < 4; i++) magic += String.fromCharCode(blob[i]);
  if (blob.length < 33 || magic !== 'GOF1') {
    const err = new Error('файл не в формате gofile'); err.badFormat = true; throw err;
  }
  const plain = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.subarray(4, 16) }, aesKey, blob.subarray(16)));
  return unpackPlain(plain);
}

/* ---------------- upload ---------------- */

function ghPut(dir, name, b64, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', `${API}/files/${dir}/${name}.bin`);
    xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.setRequestHeader('Accept', 'application/vnd.github+json');
    xhr.setRequestHeader('X-GitHub-Api-Version', '2022-11-28');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) return resolve();
      let msg = `HTTP ${xhr.status}`;
      try { const j = JSON.parse(xhr.responseText); if (j.message) msg = j.message; } catch {}
      reject(Object.assign(new Error(msg), { status: xhr.status }));
    };
    xhr.onerror = () => reject(new Error('сетевая ошибка'));
    xhr.send(JSON.stringify({ message: 'file', content: b64 }));
  });
}

async function upload(file) {
  if (!token) { els.tokenBox.hidden = false; return; }
  if (file.size > cfg.maxBytes) {
    return failUpload(`файл ${fmtBytes(file.size)} — превышен лимит ${fmtBytes(cfg.maxBytes)}`);
  }
  els.result.hidden = true;
  els.tokenBox.hidden = true;
  els.prog.hidden = false;
  setProgress(0, 'чтение и шифрование…');
  try {
    const id = makeId();
    const { dir } = parseId(id);
    const keys = await deriveKeys(id);
    const name = await storageName(keys);
    const plain = await packPlain(file);
    const blob = await encryptBlob(keys.aes, plain);
    const b64 = bytesToB64(blob);
    setProgress(0, `загрузка ${fmtBytes(blob.length)}…`);
    await ghPut(dir, name, b64, (f) => setProgress(f, 'загрузка на сервер…'));
    finishUpload(id);
  } catch (e) {
    let msg = e.message || 'ошибка';
    if (e.status === 401) msg = 'токен недействителен или истёк';
    else if (e.status === 403) msg = 'у токена нет прав записи или превышен rate limit';
    else if (e.status === 409) msg = 'редкая коллизия имени — попробуйте ещё раз';
    else if (e.status === 422) msg = 'GitHub отклонил размер файла';
    failUpload(msg);
  }
}

function finishUpload(id) {
  els.prog.hidden = true;
  els.resId.textContent = fmtId(id);
  const link = `${location.origin}${location.pathname}#id=${id}`;
  els.resLink.textContent = link;
  els.resLink.dataset.raw = link;
  els.result.hidden = false;
  els.result.dataset.id = id;
}

function failUpload(msg) {
  els.result.hidden = true;
  els.prog.hidden = false;
  els.bar.style.width = '0%';
  els.pct.textContent = '';
  els.stage.textContent = '✗ ' + msg;
}

function setProgress(f, stageText) {
  els.bar.style.width = Math.round(f * 100) + '%';
  els.pct.textContent = Math.round(f * 100) + '%';
  if (stageText) els.stage.textContent = stageText;
}

/* ---------------- download ---------------- */

function showGet(msg, isErr) {
  els.getStage.hidden = false;
  els.getStage.className = 'stage' + (isErr ? ' err' : '');
  els.getStage.textContent = msg;
}

async function download(rawInput) {
  const id = normId(rawInput);
  const parsed = parseId(id);
  if (!parsed) return showGet('✗ некорректный id — нужно 32 hex-символа', true);
  els.btnGet.disabled = true;
  showGet('вычисление пути…');
  try {
    const keys = await deriveKeys(id);
    const name = await storageName(keys);
    const r = await fetch(`${RAW}/files/${parsed.dir}/${name}.bin`, { cache: 'no-store' });
    if (r.status === 404) {
      throw Object.assign(new Error('файл не найден — неверный id или истёк срок хранения'), { status: 404 });
    }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);

    const total = +(r.headers.get('content-length') || 0);
    let blob;
    if (!r.body) {
      blob = new Uint8Array(await r.arrayBuffer());
    } else {
      const reader = r.body.getReader();
      const chunks = [];
      let got = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        got += value.length;
        if (total) showGet(`загрузка… ${Math.round((got / total) * 100)}%`);
      }
      blob = new Uint8Array(got);
      let off = 0;
      for (const c of chunks) { blob.set(c, off); off += c.length; }
    }

    showGet('расшифровка…');
    const { name: fname, type, data } = await decryptBlob(keys.aes, blob);
    const url = URL.createObjectURL(new Blob([data], { type: type || 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = fname || 'file';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    showGet(`✓ ${fname} (${fmtBytes(data.length)}) расшифрован — скачивание началось`);
  } catch (e) {
    let msg = e.message || 'ошибка';
    if (e.name === 'OperationError') msg = 'неверный id — расшифровать не удалось';
    showGet('✗ ' + msg, true);
  } finally {
    els.btnGet.disabled = false;
  }
}

/* ---------------- wiring ---------------- */

function switchTab(which) {
  const send = which === 'send';
  els.tabSend.classList.toggle('active', send);
  els.tabGet.classList.toggle('active', !send);
  els.tabSend.setAttribute('aria-selected', String(send));
  els.tabGet.setAttribute('aria-selected', String(!send));
  els.panelSend.hidden = !send;
  els.panelGet.hidden = send;
}

els.tabSend.addEventListener('click', () => switchTab('send'));
els.tabGet.addEventListener('click', () => switchTab('get'));

els.drop.addEventListener('click', () => els.file.click());
els.drop.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); els.file.click(); }
});
['dragenter', 'dragover'].forEach((ev) =>
  els.drop.addEventListener(ev, (e) => { e.preventDefault(); els.drop.classList.add('active'); }));
['dragleave', 'drop'].forEach((ev) =>
  els.drop.addEventListener(ev, (e) => { e.preventDefault(); els.drop.classList.remove('active'); }));
els.drop.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) upload(f);
});
els.file.addEventListener('change', () => {
  if (els.file.files[0]) upload(els.file.files[0]);
  els.file.value = '';
});

els.tokenSave.addEventListener('click', () => {
  const t = els.tokenInput.value.trim();
  if (!t) return;
  localStorage.setItem('gofile-token', t);
  token = t;
  els.tokenBox.hidden = true;
});
if (!token) els.tokenBox.hidden = false;

$('btn-copy-id').addEventListener('click', (e) => {
  e.currentTarget.textContent = copy(els.result.dataset.id || '') ? 'скопировано ✓' : 'не удалось';
  setTimeout(() => { $('btn-copy-id').textContent = 'копировать id'; }, 1500);
});
$('btn-copy-link').addEventListener('click', (e) => {
  e.currentTarget.textContent = copy(els.resLink.dataset.raw || '') ? 'скопировано ✓' : 'не удалось';
  setTimeout(() => { $('btn-copy-link').textContent = 'копировать ссылку'; }, 1500);
});
$('btn-new').addEventListener('click', () => {
  els.result.hidden = true;
  els.prog.hidden = true;
});

els.btnGet.addEventListener('click', () => download(els.hex.value));
els.hex.addEventListener('keydown', (e) => { if (e.key === 'Enter') download(els.hex.value); });

els.dropHint.textContent =
  `до ${fmtBytes(cfg.maxBytes)} · шифруется до отправки · хранение ${cfg.ttlDays} дн.`;

// ссылка вида #id=… открывает вкладку получения и заполняет поле
const applyHash = () => {
  const m = location.hash.match(/id=([0-9a-fA-F]{32})/);
  if (m) {
    switchTab('get');
    els.hex.value = fmtId(m[1].toLowerCase());
  }
};
applyHash();
window.addEventListener('hashchange', applyHash);

})();
