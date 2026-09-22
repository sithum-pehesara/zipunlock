/**
 * app.js
 * ----------------------------------------------------------------------------
 * Main UI controller for ZipUnlock.
 * Orchestrates:
 *   1. File loading & zip-parser.js header extraction
 *   2. Attack mode configuration (dictionary / mask brute-force)
 *   3. Web Worker lifecycle (worker.js) — spin up N workers, distribute
 *      batches, gather progress, render results
 *
 * Security notes:
 *   - All text inserted into DOM uses textContent, not innerHTML.
 *   - No user-provided strings are eval'd or passed to innerHTML.
 *   - No data is transmitted outside the browser.
 *   - Workers are created from a Blob URL derived from the local worker.js
 *     so no remote code is loaded.
 */

import { parseLocalFileHeader } from './zip-parser.js';
import { parseRarEntry }        from './rar-parser.js';

// ── DOM refs ─────────────────────────────────────────────────────────────────

const dropZone       = document.getElementById('drop-zone');
const fileInput      = document.getElementById('file-input');
const fileInfo       = document.getElementById('file-info');
const fileName       = document.getElementById('file-name');
const fileSize       = document.getElementById('file-size');
const encBadge       = document.getElementById('enc-badge');
const parseError     = document.getElementById('parse-error');

const tabDict        = document.getElementById('tab-dict');
const tabMask        = document.getElementById('tab-mask');
const panelDict      = document.getElementById('panel-dict');
const panelMask      = document.getElementById('panel-mask');

const dictTextarea   = document.getElementById('dict-textarea');
const dictCount      = document.getElementById('dict-count');
const wordlistInput  = document.getElementById('wordlist-input');

const csLower        = document.getElementById('cs-lower');
const csUpper        = document.getElementById('cs-upper');
const csDigits       = document.getElementById('cs-digits');
const csSpecial      = document.getElementById('cs-special');
const customChars    = document.getElementById('custom-chars');
const minLen         = document.getElementById('min-len');
const maxLen         = document.getElementById('max-len');
const maskEstimate   = document.getElementById('mask-estimate');
const estCount       = document.getElementById('est-count');

const workerCount    = document.getElementById('worker-count');
const workerVal      = document.getElementById('worker-val');
const recWorkers     = document.getElementById('rec-workers');

const startBtn       = document.getElementById('start-btn');
const stopBtn        = document.getElementById('stop-btn');
const progressArea   = document.getElementById('progress-area');
const resultArea     = document.getElementById('result-area');

const statRate       = document.getElementById('stat-rate');
const statTested     = document.getElementById('stat-tested');
const statTime       = document.getElementById('stat-time');
const statWorkers    = document.getElementById('stat-workers');
const progressBar    = document.getElementById('progress-bar');
const progressPct    = document.getElementById('progress-pct');
const progressWrap   = progressBar.parentElement;
const currentCand    = document.getElementById('current-candidate');

// ── State ─────────────────────────────────────────────────────────────────────

/** @type {ArrayBuffer|null} */
let zipBuffer   = null;
/** @type {import('./zip-parser.js').ParsedEntry|null} */
let parsedEntry = null;
/** @type {Worker[]} */
let activeWorkers = [];
let running = false;
let startTimestamp = 0;
let totalTested = 0;
let totalCandidates = 0;

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

function formatNum(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(Math.round(n));
}

function elapsedSec() {
  return ((performance.now() - startTimestamp) / 1000).toFixed(1) + 's';
}

// Safe text setter – never uses innerHTML
function setText(el, text) {
  el.textContent = text;
}

function showEl(el)  { el.classList.remove('hidden'); }
function hideEl(el)  { el.classList.add('hidden'); }

// ── Recommended worker count ──────────────────────────────────────────────────

const hw = navigator.hardwareConcurrency || 4;
const recommended = Math.max(1, Math.min(hw - 1, 8));
setText(recWorkers, recommended);
workerCount.value = recommended;
setText(workerVal, recommended);

// ── File handling ─────────────────────────────────────────────────────────────

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', e => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});
dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const f = e.dataTransfer?.files?.[0];
  if (f) handleFile(f);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files?.[0]) handleFile(fileInput.files[0]);
});

/** @type {'zip'|'rar'|null} */
let fileType = null;

function handleFile(file) {
  hideEl(fileInfo);
  hideEl(parseError);
  parsedEntry = null;
  zipBuffer = null;
  startBtn.disabled = true;

  const ext = file.name.split('.').pop().toLowerCase();
  fileType = (ext === 'rar') ? 'rar' : 'zip';

  const reader = new FileReader();
  reader.onload = e => {
    zipBuffer = e.target.result;
    try {
      if (fileType === 'rar') {
        parsedEntry = parseRarEntry(zipBuffer);
      } else {
        parsedEntry = parseLocalFileHeader(zipBuffer);
      }
      showFileInfo(file, parsedEntry);
      startBtn.disabled = (parsedEntry.scheme === 'none');
    } catch (err) {
      showParseError(err.message);
    }
  };
  reader.onerror = () => showParseError('Failed to read file.');
  reader.readAsArrayBuffer(file);
}

function showFileInfo(file, entry) {
  setText(fileName, file.name);
  setText(fileSize, formatBytes(file.size));

  encBadge.className = 'enc-badge';
  switch (entry.scheme) {
    case 'aes': {
      const bits = { 1: 128, 2: 192, 3: 256 }[entry.aesStrength] || '?';
      setText(encBadge, `WinZip AES-${bits}`);
      encBadge.classList.add('aes'); break;
    }
    case 'zipcrypto':
      setText(encBadge, 'ZipCrypto'); encBadge.classList.add('zipcrypto'); break;
    case 'rar5': {
      const kdf = entry.kdfCount ? `(2^${entry.kdfCount} iters)` : '';
      setText(encBadge, `RAR5 AES-256 ${kdf}`.trim());
      encBadge.classList.add('aes'); break;
    }
    case 'rar3':
      setText(encBadge, entry.headerEncrypted ? 'RAR3 -hp AES-128' : 'RAR3 AES-128');
      encBadge.classList.add('zipcrypto'); break;
    default:
      setText(encBadge, 'Not Encrypted');
      encBadge.classList.add('none');
  }

  showEl(fileInfo);
}

function showParseError(msg) {
  setText(parseError, '⚠ ' + msg);
  showEl(parseError);
}

// ── Dictionary word count live update ────────────────────────────────────────

dictTextarea.addEventListener('input', updateDictCount);
function updateDictCount() {
  const lines = dictTextarea.value.split('\n').filter(l => l.trim()).length;
  setText(dictCount, lines + ' word' + (lines !== 1 ? 's' : ''));
}

// ── Wordlist file upload ──────────────────────────────────────────────────────

wordlistInput.addEventListener('change', () => {
  const f = wordlistInput.files?.[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = e => {
    dictTextarea.value = e.target.result;
    updateDictCount();
  };
  reader.readAsText(f);
});

// ── Tabs ──────────────────────────────────────────────────────────────────────

tabDict.addEventListener('click', () => switchTab('dict'));
tabMask.addEventListener('click', () => switchTab('mask'));

function switchTab(mode) {
  if (mode === 'dict') {
    tabDict.classList.add('tab-active'); tabDict.setAttribute('aria-selected','true');
    tabMask.classList.remove('tab-active'); tabMask.setAttribute('aria-selected','false');
    showEl(panelDict); hideEl(panelMask);
  } else {
    tabMask.classList.add('tab-active'); tabMask.setAttribute('aria-selected','true');
    tabDict.classList.remove('tab-active'); tabDict.setAttribute('aria-selected','false');
    showEl(panelMask); hideEl(panelDict);
  }
  updateMaskEstimate();
}

// ── Mask estimate ─────────────────────────────────────────────────────────────

function buildCharset() {
  let cs = '';
  if (csLower.checked)   cs += 'abcdefghijklmnopqrstuvwxyz';
  if (csUpper.checked)   cs += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (csDigits.checked)  cs += '0123456789';
  if (csSpecial.checked) cs += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  // Append validated custom chars (printable ASCII only, deduplicated)
  const extra = customChars.value.replace(/[^\x20-\x7E]/g, '');
  for (const c of extra) { if (!cs.includes(c)) cs += c; }
  return [...new Set(cs)].join('');
}

function countMaskCombinations() {
  const cs = buildCharset();
  if (!cs) return 0;
  const lo = parseInt(minLen.value, 10) || 1;
  const hi = parseInt(maxLen.value, 10) || 1;
  let total = BigInt(0);
  const base = BigInt(cs.length);
  for (let l = lo; l <= hi; l++) {
    total += base ** BigInt(l);
  }
  return total;
}

function updateMaskEstimate() {
  const n = countMaskCombinations();
  setText(estCount, n === BigInt(0) ? '0' : formatBigNum(n));
}

function formatBigNum(n) {
  if (n > BigInt(1e15)) return '> 1 quadrillion';
  const num = Number(n);
  return formatNum(num);
}

[csLower, csUpper, csDigits, csSpecial, customChars, minLen, maxLen].forEach(el =>
  el.addEventListener('input', updateMaskEstimate)
);
updateMaskEstimate();

// ── Worker slider ─────────────────────────────────────────────────────────────

workerCount.addEventListener('input', () => {
  setText(workerVal, workerCount.value);
  workerCount.setAttribute('aria-valuenow', workerCount.value);
});

// ── Mask generator (synchronous, streaming batches) ───────────────────────────

/**
 * Generates brute-force candidates for a given charset and length range.
 * Yields flat arrays of strings (BATCH_SIZE each) to avoid large in-memory lists.
 */
const BATCH_SIZE = 2000;

function* maskGenerator(charset, minL, maxL) {
  const chars = [...charset];
  const base  = chars.length;

  for (let len = minL; len <= maxL; len++) {
    // Indices array, all starting at 0
    const indices = new Array(len).fill(0);
    let batch = [];

    while (true) {
      batch.push(indices.map(i => chars[i]).join(''));
      if (batch.length >= BATCH_SIZE) { yield batch; batch = []; }

      // Increment indices (right-to-left, like counting)
      let pos = len - 1;
      while (pos >= 0) {
        indices[pos]++;
        if (indices[pos] < base) break;
        indices[pos] = 0;
        pos--;
      }
      if (pos < 0) break; // exhausted this length
    }
    if (batch.length) { yield batch; batch = []; }
  }
}

// ── Start / Stop ──────────────────────────────────────────────────────────────

startBtn.addEventListener('click', startRecovery);
stopBtn.addEventListener('click', stopRecovery);

async function startRecovery() {
  if (!parsedEntry || parsedEntry.scheme === 'none') return;

  // Determine candidates source
  const isDictMode = tabDict.getAttribute('aria-selected') === 'true';
  let dictList = [];
  let generator = null;

  if (isDictMode) {
    dictList = dictTextarea.value.split('\n').map(l => l.trimEnd()).filter(l => l.length > 0);
    if (!dictList.length) {
      showResult('failure', '⚠ No passwords in the list. Add some entries first.');
      return;
    }
    totalCandidates = dictList.length;
  } else {
    const cs = buildCharset();
    if (!cs) {
      showResult('failure', '⚠ Charset is empty. Select at least one character set.');
      return;
    }
    const lo = parseInt(minLen.value, 10);
    const hi = parseInt(maxLen.value, 10);
    if (lo < 1 || hi < lo) {
      showResult('failure', '⚠ Invalid length range.');
      return;
    }
    generator = maskGenerator(cs, lo, hi);
    totalCandidates = Number(countMaskCombinations());
  }

  // UI reset
  running = true;
  startTimestamp = performance.now();
  totalTested = 0;
  startBtn.disabled = true;
  hideEl(startBtn);
  showEl(stopBtn);
  showEl(progressArea);
  hideEl(resultArea);
  resultArea.className = 'result-area hidden';
  updateProgress(0);
  setText(statWorkers, workerCount.value);

  // Prepare header info
  const nWorkers = parseInt(workerCount.value, 10);
  const workerInit = buildWorkerInit();

  // Spin workers up
  activeWorkers = [];
  for (let i = 0; i < nWorkers; i++) {
    const w = new Worker('worker.js', { type: 'module' });
    w.postMessage(workerInit);
    activeWorkers.push(w);
  }

  // Run the actual search
  if (isDictMode) {
    await runDictionary(dictList);
  } else {
    await runMask(generator);
  }
}

function buildWorkerInit() {
  const e = parsedEntry;
  if (e.scheme === 'zipcrypto') {
    return { type: 'init', scheme: 'zipcrypto',
      header: { zipCryptoHeader: e.zipCryptoHeader, passwordVerification: e.passwordVerification,
                useTimeByteCheck: e.useTimeByteCheck, _lastModTimeHighByte: e._lastModTimeHighByte ?? 0 } };
  }
  if (e.scheme === 'aes') {
    return { type: 'init', scheme: 'aes',
      header: { passwordVerification: e.passwordVerification },
      aes:    { salt: e.salt, keyBytes: e.aesKeyBytes } };
  }
  if (e.scheme === 'rar5') {
    if (!e.checkValue) throw new Error('RAR5 archive has no password-check field. Create the archive with the -hp flag in WinRAR.');
    return { type: 'init', scheme: 'rar5',
      rar5: { salt: e.salt, kdfCount: e.kdfCount, checkValue: e.checkValue } };
  }
  if (e.scheme === 'rar3') {
    if (!e.firstBlock) throw new Error('RAR3: could not read first encrypted block.');
    return { type: 'init', scheme: 'rar3',
      rar3: { salt: e.salt, firstBlock: e.firstBlock } };
  }
  throw new Error(`Unknown encryption scheme: ${e.scheme}`);
}

// ── Dictionary mode ───────────────────────────────────────────────────────────

async function runDictionary(list) {
  const nWorkers = activeWorkers.length;
  const chunkSize = Math.ceil(list.length / nWorkers);
  let found = null;
  let completedWorkers = 0;

  await new Promise(resolve => {
    activeWorkers.forEach((w, idx) => {
      const chunk = list.slice(idx * chunkSize, (idx + 1) * chunkSize);
      if (!chunk.length) { completedWorkers++; if (completedWorkers === nWorkers) resolve(); return; }

      w.onmessage = e => handleWorkerMsg(e.data, resolve, f => { found = f; });
      w.postMessage({ type: 'batch', mode: 'dictionary', candidates: chunk });
    });
  });

  finishRecovery(found, list.length);
}

// ── Mask / brute-force mode ───────────────────────────────────────────────────

async function runMask(generator) {
  let found = null;
  let totalSent = 0;

  // Round-robin distribution to workers
  let workerIdx = 0;
  const pending = new Map(); // workerId -> resolve
  let resolveAll;

  const allDone = new Promise(r => { resolveAll = r; });

  // Keep N workers busy simultaneously
  const nWorkers = activeWorkers.length;
  let activeCount = 0;
  let generatorDone = false;

  function sendNextBatch(workerIndex) {
    if (!running || found) {
      activeCount--;
      if (activeCount === 0) resolveAll();
      return;
    }

    const next = generator.next();
    if (next.done) {
      generatorDone = true;
      activeCount--;
      if (activeCount === 0) resolveAll();
      return;
    }

    const batch = next.value;
    totalSent += batch.length;
    const w = activeWorkers[workerIndex];

    w.onmessage = e => {
      const msg = e.data;
      if (msg.type === 'rate') {
        totalTested += msg.testedCount;
        const rate = msg.hashRate;
        setText(statRate, formatNum(rate));
        setText(statTested, formatNum(totalTested));
        setText(statTime, elapsedSec());
        updateProgress(totalTested / Math.max(totalCandidates, 1));
        if (batch[batch.length - 1]) setText(currentCand, batch[batch.length - 1]);
      } else if (msg.type === 'match') {
        found = msg.password;
      } else if (msg.type === 'done') {
        sendNextBatch(workerIndex);
      }
    };

    w.postMessage({ type: 'batch', mode: 'mask', candidates: batch });
  }

  // Seed workers
  for (let i = 0; i < nWorkers; i++) {
    activeCount++;
    sendNextBatch(i);
  }

  await allDone;
  finishRecovery(found, totalSent);
}

// ── Shared worker message handler (dictionary mode) ───────────────────────────

function handleWorkerMsg(msg, resolve, onFound) {
  if (msg.type === 'rate') {
    totalTested += msg.testedCount;
    setText(statRate, formatNum(msg.hashRate));
    setText(statTested, formatNum(totalTested));
    setText(statTime, elapsedSec());
    updateProgress(totalTested / Math.max(totalCandidates, 1));
  } else if (msg.type === 'match') {
    onFound(msg.password);
  } else if (msg.type === 'done') {
    resolve();
  }
}

// ── UI updates ────────────────────────────────────────────────────────────────

function updateProgress(fraction) {
  const pct = Math.min(100, Math.round(fraction * 100));
  progressBar.style.width = pct + '%';
  setText(progressPct, pct + '%');
  progressWrap.setAttribute('aria-valuenow', pct);
}

function finishRecovery(foundPassword, testedTotal) {
  stopRecovery();

  if (!running && !foundPassword) {
    // User manually stopped
    showResult('stopped', `⏹ Stopped after testing ${formatNum(testedTotal)} candidates. No password found yet.`);
    return;
  }

  running = false;

  if (foundPassword !== null) {
    showFoundResult(foundPassword);
  } else {
    showResult('failure',
      `❌ Password not found. Tested ${formatNum(testedTotal)} candidates in ${elapsedSec()}.`
    );
  }
}

function showFoundResult(password) {
  resultArea.className = 'result-area success';

  // Build DOM safely — no innerHTML
  resultArea.replaceChildren();

  const icon = document.createElement('div');
  icon.style.cssText = 'font-size:2rem;margin-bottom:12px;';
  icon.textContent = '🎉';

  const heading = document.createElement('div');
  heading.style.cssText = 'font-size:1rem;font-weight:700;color:#10b981;margin-bottom:8px;';
  heading.textContent = 'Password Found!';

  const pwBox = document.createElement('div');
  pwBox.style.cssText = `
    display:inline-block;
    font-family:var(--mono, monospace);
    font-size:1.3rem;
    font-weight:700;
    background:rgba(16,185,129,0.1);
    border:1px solid rgba(16,185,129,0.4);
    border-radius:10px;
    padding:12px 24px;
    color:#10b981;
    letter-spacing:0.04em;
    margin-bottom:12px;
    word-break:break-all;
  `;
  pwBox.textContent = password; // safe — textContent

  const meta = document.createElement('div');
  meta.style.cssText = 'font-size:0.8rem;color:var(--text-muted,#7a78a0);';
  meta.textContent = `Found after ${formatNum(totalTested)} tests in ${elapsedSec()}`;

  const copyBtn = document.createElement('button');
  copyBtn.style.cssText = `
    display:inline-flex;align-items:center;gap:6px;
    margin-top:12px;padding:8px 18px;
    border-radius:8px;border:1px solid rgba(16,185,129,0.35);
    background:rgba(16,185,129,0.1);color:#10b981;
    font-family:var(--font,sans-serif);font-size:0.85rem;font-weight:600;
    cursor:pointer;transition:background 0.2s;
  `;
  copyBtn.textContent = '📋 Copy Password';
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(password).then(() => {
      copyBtn.textContent = '✅ Copied!';
      setTimeout(() => { copyBtn.textContent = '📋 Copy Password'; }, 2000);
    });
  });

  resultArea.appendChild(icon);
  resultArea.appendChild(heading);
  resultArea.appendChild(pwBox);
  resultArea.appendChild(document.createElement('br'));
  resultArea.appendChild(meta);
  resultArea.appendChild(document.createElement('br'));
  resultArea.appendChild(copyBtn);

  showEl(resultArea);
}

function showResult(type, msg) {
  resultArea.className = 'result-area ' + type;
  resultArea.replaceChildren();

  const p = document.createElement('p');
  p.style.cssText = 'font-size:0.95rem;font-weight:500;line-height:1.6;';
  p.textContent = msg;
  resultArea.appendChild(p);

  showEl(resultArea);
}

function stopRecovery() {
  running = false;
  activeWorkers.forEach(w => w.terminate());
  activeWorkers = [];
  showEl(startBtn);
  hideEl(stopBtn);
  startBtn.disabled = !parsedEntry || parsedEntry.scheme === 'none';
}
