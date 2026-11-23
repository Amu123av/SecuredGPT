// Paper 2 core experiments (release 58.2). Pure text-level; no network.
// node exp_core.js <sgpt582.js> <corpus_v2.jsonl> <fa_flags.csv|-> <out_dir> [seed]
// Writes: positives.jsonl (one row per detected positive), negatives.jsonl (flagged benign),
//         fa_real.jsonl (flagged real WildChat prompts), typing.json, summary_core.json
const fs = require('fs'), path = require('path');
const E = require(path.resolve(process.argv[2]));
const rows = fs.readFileSync(process.argv[3], 'utf8').split('\n').filter(Boolean).map(JSON.parse);
const FA = process.argv[4];
const OUT = process.argv[5];
const SEED = +(process.argv[6] || 2027);
fs.mkdirSync(OUT, { recursive: true });

function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }

// retention: share of original characters that survive (placeholders not counted)
function retention(x, n) { return n ? x.idx.filter(i => i >= 0).length / n : 1; }

// character-level coverage of a ground-truth secret located at [pos, pos+len)
function coverage(x, pos, len) {
    let mx = 0; for (const i of x.idx) if (i > mx) mx = i; const kept = new Uint8Array(mx + 2);
    for (const i of x.idx) if (i >= 0) kept[i] = 1;
    let k = 0, run = 0, best = 0;
    for (let i = pos; i < pos + len; i++) { if (kept[i]) { k++; run++; best = Math.max(best, run); } else run = 0; }
    return { char_cov: 1 - k / len, longest_residual: best };
}

function decodeRuns(t) {
    const out = [];
    for (const m of t.matchAll(/[A-Za-z0-9+\/]{16,}={0,2}/g)) {
        try { out.push(Buffer.from(m[0], 'base64').toString('latin1')); } catch (e) { }
    }
    return out;
}

// ---------- E1/E2: detection and redaction on corpus_v2 ----------
const pos = [], neg = [];
let TP = 0, FP = 0, FN = 0, TN = 0;
for (const r of rows) {
    const v = E.scanText(r.text);
    if (r.label === 1) {
        if (!v) { FN++; pos.push({ id: r.id, category: r.category, subset: r.subset, detected: false }); continue; }
        TP++;
        const t0 = process.hrtime.bigint();
        const x = E.redactText(r.text, true);
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        const rec = { id: r.id, category: r.category, subset: r.subset, detected: true, label: v, clean: x.clean,
            n_spans: x.count, passes: x.passes, retention: retention(x, r.text.length), redact_ms: ms, len: r.text.length };
        if (r.secret && r.text.includes(r.secret)) {
            const c = coverage(x, r.text.indexOf(r.secret), r.secret.length);
            const res = x.clean ? longestResidual(x.text, r.secret) : '';
            Object.assign(rec, { verbatim: true, secret_len: r.secret.length, char_cov: c.char_cov, longest_residual: c.longest_residual,
                full_leak: x.clean && x.text.includes(r.secret),
                partial_leak: x.clean && res.length >= Math.min(8, r.secret.length) && !isStructural(res) && !x.text.includes(r.secret),
                residual_str: x.clean && res.length >= 8 ? res.slice(0, 16) : '' });
        } else if (r.secret) {   // encoded secrets: does any base64 run of the output still decode to the secret?
            rec.verbatim = false;
            rec.full_leak = x.clean && decodeRuns(x.text).some(d => d.includes(r.secret));
            rec.encoded_still_present = decodeRuns(x.text).length > 0;
        }
        pos.push(rec);
    } else {
        if (!v) { TN++; continue; }
        FP++;
        const x = E.redactText(r.text, true);
        neg.push({ id: r.id, category: r.category, subset: r.subset, label: v, clean: x.clean, n_spans: x.count,
            retention: retention(x, r.text.length), removed_chars: r.text.length - x.idx.filter(i => i >= 0).length, len: r.text.length });
    }
}
fs.writeFileSync(path.join(OUT, 'positives.jsonl'), pos.map(o => JSON.stringify(o)).join('\n') + '\n');
fs.writeFileSync(path.join(OUT, 'negatives.jsonl'), neg.map(o => JSON.stringify(o)).join('\n') + '\n');

// ---------- real WildChat false-alarm set (paper 1, 20k study): flagged prompts only ----------
let fa = [];
if (FA && FA !== '-' && fs.existsSync(FA)) {
    const parseCSV = (s) => {   // minimal RFC4180 parser
        const out = []; let row = [], f = '', q = false;
        for (let i = 0; i < s.length; i++) {
            const c = s[i];
            if (q) { if (c === '"') { if (s[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
            else if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; }
            else if (c === '\n') { row.push(f); out.push(row); row = []; f = ''; } else if (c !== '\r') f += c;
        }
        if (f || row.length) { row.push(f); out.push(row); }
        return out;
    };
    const t = parseCSV(fs.readFileSync(FA, 'utf8')); const h = t[0];
    for (const r of t.slice(1)) {
        const o = Object.fromEntries(h.map((k, i) => [k, r[i]]));
        if (!o.text) continue;
        const v = E.scanText(o.text);
        if (!v) continue;
        const x = E.redactText(o.text, true);
        fa.push({ id: o.id, label: v, is_sensitive: (o.is_sensitive || '').trim().toUpperCase() || null, clean: x.clean,
            n_spans: x.count, retention: retention(x, o.text.length), len: o.text.length });
    }
    fs.writeFileSync(path.join(OUT, 'fa_real.jsonl'), fa.map(o => JSON.stringify(o)).join('\n') + '\n');
}

// ---------- E5: typed-text redaction simulation (M7) ----------
// The user types the prompt one character at a time. Inter-key gaps are log-normal
// (median 180 ms); at word boundaries a "think" pause of 0.3-2.5 s occurs with prob 0.15.
// Scenario "mid": one extra pause of 0.8-3 s is placed inside the secret (the user looks it up).
// Whenever a gap >= T ms occurs, the 58.2 pause-redaction runs on the field (redactText, or
// block-fallback). At the end the user presses Enter: redactBeforeSend runs on the whole field.
// Leak = the sent text still contains the full secret (full) or >= 8 consecutive secret chars (partial).
function lognormal(rng, median, sigma) { const u = 1 - rng(), v = rng(); return median * Math.exp(sigma * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v)); }
// structural residue that is not secret material (PEM armour lines, scheme/path punctuation)
function isStructural(r) { return /^[-\s]*(?:BEGIN|END)?[ A-Z]*(?:PRIVATE KEY)?-*\s*$/.test(r) || !/[A-Za-z0-9]{4}/.test(r); }
function longestResidual(field, s) {
    for (let L = s.length; L > 0; L--) for (let a = 0; a + L <= s.length; a++) if (field.includes(s.substr(a, L))) return s.substr(a, L);
    return '';
}
function simulateTyping(text, secretPos, secretLen, T, scenario, rng, absorb) {
    let field = '', blocked = false, redactions = 0;
    const midAt = scenario === 'mid' ? secretPos + 1 + Math.floor(rng() * Math.max(1, secretLen - 2)) : -1;
    const tryRedact = () => {
        if (absorb) field = E.absorbTails(field);
        if (!E.scanText(field)) return;
        const x = E.redactText(field);
        if (!x.clean) { blocked = true; return; }
        field = x.text; redactions++;
    };
    for (let i = 0; i < text.length && !blocked; i++) {
        field += text[i];
        let gap = lognormal(rng, 180, 0.5);
        if (/\s/.test(text[i]) && rng() < 0.15) gap += 300 + rng() * 2200;
        if (i + 1 === midAt) gap += 800 + rng() * 2200;
        if (gap >= T) tryRedact();
    }
    if (!blocked) tryRedact();      // Enter: redactBeforeSend (send held once, user presses Enter again)
    if (blocked) return { blocked: true, full: false, partial: false, residual: 0, redactions };
    const s = text.substr(secretPos, secretLen);
    const res = longestResidual(field, s);
    const partial = res.length >= Math.min(8, s.length) && !isStructural(res);
    return { blocked: false, full: field.includes(s), partial, residual: res.length, residual_str: partial ? res.slice(0, 12) : '', redactions };
}
const typing = [];
const rngT = mulberry32(SEED);
const typedSet = rows.filter(r => r.label === 1 && r.secret && r.text.includes(r.secret) && E.scanText(r.text));
// type only the sentence around the secret (carrier prose is pasted, not typed): 200 chars window
for (const r of typedSet) {
    const p = r.text.indexOf(r.secret);
    const a = Math.max(0, p - 120), b = Math.min(r.text.length, p + r.secret.length + 80);
    const snippet = r.text.slice(a, b);
    if (!E.scanText(snippet)) continue;      // the window alone must be detectable
    for (const T of [300, 700, 1500]) for (const sc of ['natural', 'mid']) for (const absorb of [false, true]) {
        const rngCase = mulberry32(SEED ^ (T * 7919) ^ (sc === 'mid' ? 104729 : 0) ^ (typing.length >>> 2));
        const o = simulateTyping(snippet, p - a, r.secret.length, T, sc, rngCase, absorb);
        typing.push({ id: r.id, category: r.category, T, scenario: sc, design: absorb ? '58.2 (tail absorption)' : '58.1 (no absorption)', ...o });
    }
}
fs.writeFileSync(path.join(OUT, 'typing.jsonl'), typing.map(o => JSON.stringify(o)).join('\n') + '\n');

// ---------- E6: processing time (Node, single core) ----------
function median(a) { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; }
function pct(a, q) { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(q * s.length))]; }
const benignText = rows.filter(r => r.subset === 'real_benign' && !E.scanText(r.text)).map(r => r.text).join('\n\n');
const secretLine = '\nAlso my config has api_key="sk-proj-Zx81kPq2LmN0vB7rT5yW3hJ9dF4gS6aQ" and it fails.\n';
const timing = [];
for (const kb of [1, 10, 50, 100]) {
    let base = benignText.slice(0, kb * 1024);
    while (E.scanText(base)) base = base.slice(0, -200);
    for (const kind of ['clean', 'flagged_end', 'flagged_start']) {
        const t = kind === 'clean' ? base : kind === 'flagged_end' ? base + secretLine : secretLine + base;
        const det = [], red = [];
        for (let i = 0; i < 35; i++) {
            let t0 = process.hrtime.bigint(); E.scanText(t); const d = Number(process.hrtime.bigint() - t0) / 1e6;
            let r = 0;
            if (kind !== 'clean') { t0 = process.hrtime.bigint(); E.redactText(t); r = Number(process.hrtime.bigint() - t0) / 1e6; }
            if (i >= 5) { det.push(d); red.push(r); }
        }
        timing.push({ kb, kind, detect_med: median(det), detect_p95: pct(det, 0.95), redact_med: kind === 'clean' ? null : median(red), redact_p95: kind === 'clean' ? null : pct(red, 0.95) });
    }
}

fs.writeFileSync(path.join(OUT, 'summary_core.json'), JSON.stringify({
    seed: SEED, detection: { TP, FP, FN, TN }, n_fa_real_flagged: fa.length, n_typing_runs: typing.length, timing,
    node: process.version
}, null, 1));
console.log(JSON.stringify({ TP, FP, FN, TN, fa: fa.length, typing: typing.length }));
