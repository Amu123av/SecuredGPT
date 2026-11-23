// Long-document experiment (reviewer M6), release 58.2.
// node docs_exp.js <sgpt582.js> <corpus_v2.jsonl> <docs_manifest.jsonl> <docs_dir> <out_dir> [seed] [per_doc]
// docs_manifest.jsonl rows: {id, kind, source, file}   (kind: readme | env_example | source | log | email ...)
// 1) Unmodified documents: flagged?, label, redaction result, removed snippets (for manual cause coding).
// 2) Insertion: positives from ALL 875 corpus positives (detected or not), category-balanced, drawn
//    without replacement, inserted at random paragraph breaks with exact offsets recorded.
const fs = require('fs'), path = require('path');
const E = require(path.resolve(process.argv[2]));
const corpus = fs.readFileSync(process.argv[3], 'utf8').split('\n').filter(Boolean).map(JSON.parse);
const manifest = fs.readFileSync(process.argv[4], 'utf8').split('\n').filter(Boolean).map(JSON.parse);
const DOCS = process.argv[5], OUT = process.argv[6];
const SEED = +(process.argv[7] || 2026), PER_DOC = +(process.argv[8] || 3);
fs.mkdirSync(OUT, { recursive: true });
function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
const rng = mulberry32(SEED);
const shuffle = (xs) => { const a = [...xs]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };

const docs = manifest.map(m => ({ ...m, text: fs.readFileSync(path.join(DOCS, m.file), 'utf8') })).filter(d => d.text.trim().length > 200);

// ---------- 1) unmodified ----------
const unmod = [];
for (const d of docs) {
    const v = E.scanText(d.text);
    const rec = { id: d.id, kind: d.kind, source: d.source, bytes: Buffer.byteLength(d.text), flagged: !!v, label: v };
    if (v) {
        const x = E.redactText(d.text, true);
        const kept = new Set(x.idx.filter(i => i >= 0));
        const snippets = []; let a = -1;
        for (let i = 0; i <= d.text.length; i++) {
            const rem = i < d.text.length && !kept.has(i);
            if (rem && a < 0) a = i;
            if (!rem && a >= 0) { snippets.push(d.text.slice(Math.max(0, a - 30), Math.min(d.text.length, i + 30)).replace(/\s+/g, ' ')); a = -1; }
        }
        Object.assign(rec, { redact_clean: x.clean, n_spans: x.count, retention: kept.size / d.text.length,
            removed_chars: d.text.length - kept.size, snippets: snippets.slice(0, 6) });
    }
    unmod.push(rec);
}
fs.writeFileSync(path.join(OUT, 'docs_unmodified.jsonl'), unmod.map(o => JSON.stringify(o)).join('\n') + '\n');

// ---------- 2) insertion ----------
const pos = corpus.filter(r => r.label === 1);
const byCat = {}; for (const r of pos) (byCat[r.category] = byCat[r.category] || []).push(r);
for (const k in byCat) byCat[k] = shuffle(byCat[k]);
const cats = shuffle(Object.keys(byCat)); const draw = [];
while (true) { let any = false; for (const c of cats) if (byCat[c].length) { draw.push(byCat[c].pop()); any = true; } if (!any) break; }
const nDocs = Math.min(docs.length, Math.floor(draw.length / PER_DOC));
const docOrder = shuffle(docs).slice(0, nDocs);
const inserts = [], docRes = [];
let di = 0;
for (const d of docOrder) {
    const chosen = draw.slice(di * PER_DOC, di * PER_DOC + PER_DOC); di++;
    // candidate insertion points: paragraph breaks, else line breaks
    let breaks = [...d.text.matchAll(/\n\s*\n/g)].map(m => m.index + m[0].length);
    if (breaks.length < PER_DOC) breaks = [...d.text.matchAll(/\n/g)].map(m => m.index + 1);
    if (!breaks.length) breaks = [d.text.length];
    const at = shuffle(breaks).slice(0, PER_DOC).sort((a, b) => a - b);
    while (at.length < chosen.length) at.push(d.text.length);
    let txt = '', last = 0; const pieces = [];
    chosen.forEach((p, i) => {
        txt += d.text.slice(last, at[i]);
        const block = '\n' + p.text + '\n\n';
        pieces.push({ start: txt.length + 1, end: txt.length + 1 + p.text.length, p });
        txt += block; last = at[i];
    });
    txt += d.text.slice(last);
    const v = E.scanText(txt);
    const x = v ? E.redactText(txt, true) : { clean: true, text: txt, idx: Array.from({ length: txt.length }, (_, i) => i), count: 0 };
    const kept = new Set(x.idx.filter(i => i >= 0));
    const insideInsert = (i) => pieces.some(q => i >= q.start - 1 && i < q.end + 2);
    let origChars = 0, origKept = 0;
    for (let i = 0; i < txt.length; i++) if (!insideInsert(i)) { origChars++; if (kept.has(i)) origKept++; }
    for (const q of pieces) {
        const p = q.p; let sStart = q.start, sLen = p.text.length;
        if (p.secret && p.text.includes(p.secret)) { sStart = q.start + p.text.indexOf(p.secret); sLen = p.secret.length; }
        let removed = 0; for (let i = sStart; i < sStart + sLen; i++) if (!kept.has(i)) removed++;
        const alone = !!E.scanText(p.text);
        inserts.push({ doc: d.id, kind: d.kind, pid: p.id, category: p.category, subset: p.subset, detected_alone: alone,
            found: removed > 0 || !x.clean, doc_blocked: !x.clean, char_cov: removed / sLen,
            full_leak: x.clean && !!p.secret && x.text.includes(p.secret) });
    }
    docRes.push({ doc: d.id, kind: d.kind, bytes: Buffer.byteLength(d.text), n_inserted: pieces.length, flagged: !!v,
        blocked: !x.clean, passes: x.passes || 0, doc_text_kept: origChars ? origKept / origChars : 1 });
}
fs.writeFileSync(path.join(OUT, 'docs_inserts.jsonl'), inserts.map(o => JSON.stringify(o)).join('\n') + '\n');
fs.writeFileSync(path.join(OUT, 'docs_inserted.jsonl'), docRes.map(o => JSON.stringify(o)).join('\n') + '\n');
console.log(JSON.stringify({ docs: docs.length, flagged_unmodified: unmod.filter(u => u.flagged).length, inserted_docs: docRes.length, inserts: inserts.length }));
