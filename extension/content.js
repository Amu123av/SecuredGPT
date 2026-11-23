/**
 * Secure-GPT: Enterprise Firewall (release 58.2 - Response Modes on Detection Engine v3)
 * --------------------------------------------------------
 * Detection: engine v3 of extension v58.0, copied byte-for-byte (ENGINE BEGIN/END block).
 * Response : monitor / warn / block / redact (REDACTOR BEGIN/END block + section 4).
 * Files    : upload hold (v57.1), plain-text formats (v58.0), pdf.js 3.11.174 with its
 *            matching worker loaded as a content script (58.2; earlier builds shipped a
 *            2.16.105 worker, so pdf.js never parsed a PDF).
 * --------------------------------------------------------
 */

console.log("🚀 Secure-GPT 58.2: response modes on detection engine v3 (v58)");

// 0. LINK WORKER (the worker script is also injected as a content script, so pdf.js runs it in-page)
if (typeof pdfjsLib !== 'undefined') {
    pdfjsLib.GlobalWorkerOptions.workerSrc = chrome.runtime.getURL('pdf.worker.js');
}

// 1. THREAT DATABASE + DETECTION ENGINE v3
// ==== SECURE-GPT ENGINE BEGIN ====
// Secure-GPT detection engine v3 (extension v58.0)
// Kept from engine v2 (v57.0):
//  F0  Regex state reset: global regexes no longer leak lastIndex between calls.
//  F1  riskKeywords anchored at word boundaries (optional plural "s").
//  F2  URL suppression is token-local: only tokens inside a URL host/path are skipped.
//  F3  Normalized Shannon entropy gate; a candidate must mix letters and digits.
//  F4  Academic safe words no longer suppress random-looking tokens.
//  F5  Credentials embedded in connection strings (scheme://user:pass@host).
//  F6  sk-proj- style OpenAI keys matched directly by the API-key signature.
//  F7  PII: payment cards (issuer prefix + Luhn), Aadhaar (Verhoeff), PAN, US SSN,
//      bulk phone lists (>= 3 numbers), password assignments ("password: x9!k").
// New in engine v3 (v58.0), addressing the held-out error analysis and reviewer comments:
//  G1  Input normalization: NFKC plus removal of zero-width / soft-hyphen characters.
//  G2  Known-prefix signatures: Slack (xox*-, xapp-), GitHub (ghp_..., github_pat_),
//      Stripe (sk_/rk_ live|test), Google API (AIza), JWT, PEM private-key header.
//  G3  Keyword boundaries treat "_" and camelCase humps as separators (SECRET_KEY, secretKey).
//  G4  Secret assignments: a name containing secret/token/key/password = a value that is
//      neither code nor a placeholder (.env files, settings.py, JSON config).
//  G5  Dictionary-word passwords in explicit assignments ("my password is sunshine").
//  G6  Hex secrets (>= 32 hex chars) flagged when a risk keyword precedes them and no
//      hash/commit context does (hex cannot reach the 0.80 entropy threshold).
//  G7  Base64 runs that decode to readable text are scanned as text: encoded secrets are
//      caught and encoded prose is no longer reported as a random token.
//  G8  Hyphen/underscore compounds whose parts are each all-letter or all-digit ("10-year-old",
//      "COVID-19") are ordinary words, not random tokens.
// ENGINE_DEFAULTS is the shipped configuration. The alternative option values reproduce
// earlier engine versions and are used only by the ablation study; the extension never
// passes options.

const ENGINE_DEFAULTS = Object.freeze({
    normalize: true,            // G1
    prefixSignatures: true,     // G2
    keywordMode: 'separator',   // G3 | 'word' (v57) | 'substring' (v56)
    secretAssign: true,         // G4
    pwdDictionary: true,        // G5
    hexRule: true,              // G6
    base64Decode: true,         // G7
    compoundWords: true,        // G8
    suppression: 'token',       // F2 | 'message' (v56: URL or academic word disables token checks)
    entropyGate: true,          // F3 | false = length-only test (v56)
    connString: true,           // F5
    skProj: true,               // F6
    pii: true                   // F7
});

const RISK_WORDS = 'secret|private|key|token|password|credential|auth|id|code|number|access|dummy|confidential';
const KEYWORD_RE = {
    separator: new RegExp(`(?<![A-Za-z0-9])(?:${RISK_WORDS})s?(?![A-Za-z0-9])`, 'i'),   // G3
    word: new RegExp(`\\b(?:${RISK_WORDS})s?\\b`, 'i'),                                 // F1
    substring: new RegExp(`(?:${RISK_WORDS})`, 'i')                                     // v56
};

const CONFIG = {
    patterns: {
        testTrigger: /TEST-SECRET/i,
        apiKey: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b/,                 // F6
        apiKeyV56: /\bsk-[A-Za-z0-9]{20,}|\bAKIA[0-9A-Z]{16}\b/,                         // ablation only
        prefixSignatures: [                                                             // G2
            [/\bxox[abeoprs]-[A-Za-z0-9-]{10,}/, "API Key Detected (Slack)"],
            [/\bxapp-\d-[A-Za-z0-9-]{10,}/, "API Key Detected (Slack)"],
            [/\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}/, "API Key Detected (GitHub)"],
            [/\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/, "API Key Detected (Stripe)"],
            [/\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/, "API Key Detected (Google)"],
            [/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, "JSON Web Token Detected"],
            [/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/, "Private Key Block Detected"]
        ],
        connString: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:\/@]+:[^\s@\/]+@[^\s\/]+/i,           // F5
        highEntropy: /[A-Za-z0-9_-]{11,}/g,
        longNumbers: /\b\d{10,}\b/g,
        urlSpan: /\bhttps?:\/\/[^\s?#]+|\bwww\.[^\s?#]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|org|net|io|ai|dev|edu|gov|in|co)\b/gi, // F2
        academicWords: /\b(?:university|college|course|assignment|semester|lecture|thesis|research|paper|journal|professor|exam|syllabus|student|homework|project|lab)\b/i, // ablation only
        csvHeaders: /\b(Name|Client|Email|Phone|Contact|Company|Address)\s*[,|]\s*(Name|Client|Email|Phone|Contact|Company|Address)\b/i,
        emailPattern: /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi,
        // F7 PII
        cardCandidate: /\b\d(?:[ -]?\d){12,18}\b/g,
        aadhaarCandidate: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g,
        pan: /\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b/,
        ssn: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/,
        phone: /(?:\+?\d{1,3}[ -]?)?(?:\(\d{3}\)[ -]?\d{3}[ -]?\d{4}|\b\d{3}[ -]\d{3}[ -]\d{4}\b|\b[6-9]\d{4}[ -]?\d{5}\b)/g,
        passwordAssign: /\b(?:password|passwd|pwd|passcode|pin)\b\s*(?:is|=|:)\s*(?=\S*[\d!@#$%^&*])\S{4,}/i,
        // G4 secret assignment: NAME = value / "name": "value" / name: value
        secretAssign: /\b([A-Za-z][A-Za-z0-9]*(?:[_.-][A-Za-z0-9]+)*)["']?[ \t]*[:=][ \t]*["']?([^\s"',;]{8,})/g,
        // G5 dictionary-word password in an explicit assignment
        pwdDictionary: /\b(?:password|passwd|pwd|passcode|passphrase)\b\s*(?:is|=|:)\s*["']?([A-Za-z][A-Za-z'-]{3,})["']?(?=$|[\s.,;!?])/gi,
        // G6 hash-like context that must not be reported as a secret
        hashContext: /\b(?:commit|sha\d*|hash(?:es)?|checksum|md5|digest|git|revision|rev|fingerprint|etag|uuid|guid)\b/i,
        // G7 base64 run
        base64Run: /[A-Za-z0-9+\/]{16,}={0,2}/g
    },
    entropy: {
        minNormalized: 0.80   // H / log2(min(len, 62))
    }
};

// G4: name parts that make an assignment sensitive. "strong" parts accept any value;
// "weak" parts require the value to contain a digit or a symbol.
const ASSIGN_STRONG = new Set(['secret', 'secrets', 'password', 'passwd', 'pwd', 'pass', 'passphrase']);
const ASSIGN_WEAK = new Set(['token', 'tokens', 'key', 'keys', 'apikey', 'auth', 'credential', 'credentials']);
const VALUE_IS_CODE = /[()[\]{}<>]|^(?:\$|%|@|&)|:\/\/|^(?:os|process|env|settings|config|self|this|request|req|args|params|props)\.|getenv|environ/i;
const VALUE_IS_PLACEHOLDER = /^(?:\*+|x{3,}|\.{3,}|#+|your[_-]?\w*|my[_-]?\w*|example\w*|placeholder\w*|redacted|hidden|none|null|nil|undefined|true|false|changeme|change[_-]?me|secret|password|token|string|str|text|value|required|optional|enabled|disabled)$/i;
// G5: words that follow "password is" in ordinary prose and are not passwords
const PWD_STOPWORDS = new Set(('incorrect correct wrong invalid valid required optional mandatory needed necessary missing empty blank ' +
    'expired expiring changed reset updated saved stored hashed encrypted salted protected secure insecure strong weak ' +
    'long short same different case case-sensitive sensitive visible hidden masked shown too very not also still never ' +
    'always being been the this that these those mine yours ours theirs here there what which where when your their ' +
    'set unset ready done okay fine good bad simple easy hard complex unique common known unknown forgotten lost ' +
    'stolen compromised leaked weak strong enough longer shorter generated random temporary permanent new old ' +
    'provided given shared sent attached below above following something nothing anything everything').split(' '));

function shannon(s) {                                                                // F3
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    let h = 0;
    for (const k in freq) { const p = freq[k] / s.length; h -= p * Math.log2(p); }
    return h;
}

function isPlainCompound(t) {                                                       // G8
    return /[-_]/.test(t) && t.split(/[-_]+/).every(part => /^(?:[A-Za-z]*|\d*)$/.test(part));
}

function looksRandom(t, opts = ENGINE_DEFAULTS) {                                    // F3
    if (!/[0-9]/.test(t) || !/[A-Za-z]/.test(t)) return false;
    if (opts.compoundWords && isPlainCompound(t)) return false;                      // G8
    const hNorm = shannon(t) / Math.log2(Math.min(t.length, 62));
    return hNorm >= CONFIG.entropy.minNormalized;
}

function luhn(d) {                                                                  // F7
    let sum = 0, dbl = false;
    for (let i = d.length - 1; i >= 0; i--) {
        let x = +d[i];
        if (dbl) { x *= 2; if (x > 9) x -= 9; }
        sum += x; dbl = !dbl;
    }
    return sum % 10 === 0;
}

const VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
            [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
            [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
            [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function verhoeff(d) {                                                              // F7
    let c = 0;
    for (let i = 0; i < d.length; i++) c = VD[c][VP[i % 8][+d[d.length - 1 - i]]];
    return c === 0;
}

function splitNameParts(name) {                                                     // G3, G4
    return name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[\s_.-]+/).filter(Boolean);
}

function keywordInContext(ctx, opts) {                                              // F1, G3
    const re = KEYWORD_RE[opts.keywordMode] || KEYWORD_RE.word;
    if (opts.keywordMode === 'separator') ctx = ctx.replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    return re.test(ctx);
}

function detectSecretAssignment(t) {                                                // G4
    for (const m of t.matchAll(CONFIG.patterns.secretAssign)) {
        const parts = splitNameParts(m[1]);
        const strong = parts.some(p => ASSIGN_STRONG.has(p));
        const weak = !strong && parts.some(p => ASSIGN_WEAK.has(p));
        if (!strong && !weak) continue;
        const value = m[2].replace(/["'`]+$/, '');
        if (value.length < 8 || VALUE_IS_CODE.test(value) || VALUE_IS_PLACEHOLDER.test(value)) continue;
        if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(value) && /_/.test(value) && value === value.toUpperCase()) continue; // CONSTANT_NAME reference
        if (weak && !/[\d!@#$%^&*+=~?]/.test(value)) continue;
        return `Secret Assignment Detected (${m[1]})`;
    }
    return null;
}

function detectPII(t, opts) {                                                       // F7
    const P = CONFIG.patterns;
    for (const m of t.matchAll(P.cardCandidate)) {
        const d = m[0].replace(/\D/g, '');
        if (d.length >= 13 && d.length <= 19 && /^[2-6]/.test(d) && luhn(d)) return "Payment Card Number Detected";
    }
    for (const m of t.matchAll(P.aadhaarCandidate)) {
        if (verhoeff(m[0].replace(/\D/g, ''))) return "National ID Detected (Aadhaar)";
    }
    if (P.pan.test(t)) return "National ID Detected (PAN)";
    if (P.ssn.test(t)) return "National ID Detected (SSN)";
    const phones = new Set([...t.matchAll(P.phone)].map(m => m[0].replace(/\D/g, '')));
    if (phones.size >= 3) return `Bulk Personal Data Leak (${phones.size} Phone Numbers)`;
    if (P.passwordAssign.test(t)) return "Password Assignment Detected";
    if (opts.pwdDictionary) {                                                       // G5
        for (const m of t.matchAll(P.pwdDictionary)) {
            if (!PWD_STOPWORDS.has(m[1].toLowerCase())) return "Password Assignment Detected";
        }
    }
    return null;
}

function urlSpans(text) {                                                            // F2
    const spans = [];
    for (const m of text.matchAll(CONFIG.patterns.urlSpan)) spans.push([m.index, m.index + m[0].length]);
    return spans;
}

function decodeBase64Text(run) {                                                     // G7
    const body = run.replace(/=+$/, '');
    if (body.length % 4 === 1) return null;
    let s;
    try { s = atob(body + '='.repeat((4 - body.length % 4) % 4)); } catch (e) { return null; }
    if (s.length < 8 || !/ /.test(s)) return null;
    let printable = 0;
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) printable++;
    }
    return printable / s.length >= 0.95 ? s : null;
}

function scanText(text, opts = ENGINE_DEFAULTS, depth = 0) {
    if (!text) return null;
    if (opts.normalize) text = text.normalize('NFKC').replace(/[\u00AD\u180E\u200B-\u200F\u2060-\u2064\uFEFF]/g, ''); // G1
    if (text.length < 5) return null;
    const cleanText = text.replace(/\s+/g, ' ');
    const P = CONFIG.patterns;

    if (P.testTrigger.test(cleanText)) return "⚠️ DEMO TRIGGER DETECTED";
    if ((opts.skProj ? P.apiKey : P.apiKeyV56).test(cleanText)) return "API Key Detected";    // F6
    if (opts.prefixSignatures) {                                                             // G2
        for (const [re, label] of P.prefixSignatures) if (re.test(text)) return label;
    }
    if (opts.connString && P.connString.test(cleanText)) return "Credentials in Connection String"; // F5
    if (P.csvHeaders.test(cleanText)) return "Client List Format Detected (CSV Headers)";

    const emails = cleanText.match(P.emailPattern);
    if (emails && emails.length >= 3) return `Bulk Personal Data Leak (${emails.length} Emails Detected)`;

    if (opts.pii) {                                                                          // F7
        const pii = detectPII(cleanText, opts);
        if (pii) return pii;
    }
    if (opts.secretAssign) {                                                                 // G4
        const sa = detectSecretAssignment(text);
        if (sa) return sa;
    }

    for (const m of cleanText.matchAll(P.longNumbers)) {                                     // F0
        if (m[0].length > 20) return `Long Secret Number Detected (${m[0].length} digits)`;
    }

    const spans = urlSpans(cleanText);
    if (opts.base64Decode) {                                                                 // G7
        for (const m of cleanText.matchAll(P.base64Run)) {
            const decoded = decodeBase64Text(m[0]);
            if (decoded === null) continue;
            spans.push([m.index, m.index + m[0].length]);
            if (depth === 0) {
                const inner = scanText(decoded, opts, 1);
                if (inner) return `Encoded Secret (base64): ${inner}`;
            }
        }
    }
    if (opts.suppression === 'message' &&
        (spans.length > 0 || P.academicWords.test(cleanText))) return null;                 // v56 ablation

    for (const m of cleanText.matchAll(P.highEntropy)) {                                     // F0
        const token = m[0], s = m.index, e = s + token.length;
        if (opts.suppression === 'token' && spans.some(([a, b]) => s < b && e > a)) continue; // F2
        const ctx = cleanText.substring(Math.max(0, s - 100), s);
        if (opts.hexRule && token.length >= 32 && /^[0-9a-fA-F]+$/.test(token) &&           // G6
            /[0-9]/.test(token) && /[a-fA-F]/.test(token)) {
            if (keywordInContext(ctx, opts) && !P.hashContext.test(ctx.slice(-60))) {
                return `Contextual Secret (Hex, ${token.length} chars)`;
            }
            continue;
        }
        if (opts.entropyGate ? !looksRandom(token, opts) : false) continue;                        // F3, F4
        if (token.length > 21) return `High Entropy String (${token.length} chars)`;
        if (keywordInContext(ctx, opts)) return `Contextual Secret (Keyword found near '${token}')`;
    }
    return null;
}
// ==== SECURE-GPT ENGINE END ====

// ==== SECURE-GPT REDACTOR BEGIN ====
// Redaction routine (release 58.2). It reads the detection rules of engine v58 above and does
// not change them. scanText() stops at the first finding, so redaction runs every rule again,
// collects all matching spans, maps them back to the original text (through the G1 normalisation
// and the whitespace collapsing that scanText applies), merges overlaps and replaces each span by
// [REDACTED:TYPE]. Placeholders contain no digits, and their TYPE names avoid the detector's risk
// keywords (key, id, secret, token, password, number ...), so a placeholder can neither be flagged
// itself nor act as keyword context for the tokens around it.
// Because shortening the text can move a token into a keyword window, it re-scans and repeats
// (at most 5 passes); the caller falls back to blocking if scanText() still reports a finding.

const REDACT_MAX_PASSES = 5;
const ZERO_WIDTH = /[­᠎​-‏⁠-⁤﻿]/;

// normalised text + index map (normalised char -> original char), mirroring G1
function rdNormalize(text) {
    let out = '', map = [], i = 0;
    for (const ch of text) {
        if (!ZERO_WIDTH.test(ch)) {
            for (const c of ch.normalize('NFKC')) { for (let k = 0; k < c.length; k++) { out += c[k]; map.push(i); } }
        }
        i += ch.length;
    }
    return { out, map };
}

// whitespace-collapsed text + index map (clean char -> normalised char), mirroring scanText
function rdCollapse(text) {
    let clean = '', map = [], prevWs = false;
    for (let i = 0; i < text.length; i++) {
        if (/\s/.test(text[i])) { if (!prevWs) { clean += ' '; map.push(i); } prevWs = true; }
        else { clean += text[i]; map.push(i); prevWs = false; }
    }
    return { clean, map };
}

function rdGlobal(re) { return new RegExp(re.source, re.flags.replace(/[gd]/g, '') + 'gd'); }

// Spans in normalised (n) or clean (c) coordinates: {a, b, type, sp: 'n' | 'c'}
function collectSpans(norm, clean) {
    const P = CONFIG.patterns, spans = [];
    const add = (a, b, type, sp) => { if (b > a) spans.push({ a, b, type, sp }); };
    const all = (re, str, type, sp, keep) => {
        for (const m of str.matchAll(rdGlobal(re))) if (!keep || keep(m)) add(m.index, m.index + m[0].length, type, sp);
    };
    all(P.testTrigger, clean, 'SECRETVALUE', 'c');
    all(P.apiKey, clean, 'APIKEY', 'c');
    for (const [re, label] of P.prefixSignatures) {                                         // G2
        if (/Private Key/.test(label)) {
            for (const m of norm.matchAll(rdGlobal(re))) {
                const rest = norm.slice(m.index);
                const end = rest.match(/-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/);
                add(m.index, end ? m.index + end.index + end[0].length : norm.length, 'PRIVATEKEY', 'n');
            }
        } else {
            all(re, norm, /Web Token/.test(label) ? 'AUTHTOKEN' : 'APIKEY', 'n');
        }
    }
    all(P.connString, clean, 'CONNSTRING', 'c');                                           // F5
    const em = clean.match(rdGlobal(P.emailPattern));
    if (em && em.length >= 3) all(P.emailPattern, clean, 'EMAIL', 'c');
    all(P.cardCandidate, clean, 'CARD', 'c', (m) => {                                       // F7
        const d = m[0].replace(/\D/g, '');
        return d.length >= 13 && d.length <= 19 && /^[2-6]/.test(d) && luhn(d);
    });
    all(P.aadhaarCandidate, clean, 'NATIONALID', 'c', (m) => verhoeff(m[0].replace(/\D/g, '')));
    all(P.pan, clean, 'NATIONALID', 'c');
    all(P.ssn, clean, 'NATIONALID', 'c');
    const ph = [...clean.matchAll(rdGlobal(P.phone))];
    if (new Set(ph.map((m) => m[0].replace(/\D/g, ''))).size >= 3) ph.forEach((m) => add(m.index, m.index + m[0].length, 'PHONE', 'c'));
    for (const m of clean.matchAll(rdGlobal(P.passwordAssign))) {                           // value only
        const pre = m[0].match(/^(?:password|passwd|pwd|passcode|pin)\b\s*(?:is|=|:)\s*/i);
        if (pre) add(m.index + pre[0].length, m.index + m[0].length, 'PASSWD', 'c');
    }
    for (const m of clean.matchAll(rdGlobal(P.pwdDictionary))) {                           // G5, value only
        if (!PWD_STOPWORDS.has(m[1].toLowerCase())) add(m.indices[1][0], m.indices[1][1], 'PASSWD', 'c');
    }
    for (const m of norm.matchAll(rdGlobal(P.secretAssign))) {                              // G4, value only
        const parts = splitNameParts(m[1]);
        const strong = parts.some(p => ASSIGN_STRONG.has(p));
        const weak = !strong && parts.some(p => ASSIGN_WEAK.has(p));
        if (!strong && !weak) continue;
        const value = m[2].replace(/["'`]+$/, '');
        if (value.length < 8 || VALUE_IS_CODE.test(value) || VALUE_IS_PLACEHOLDER.test(value)) continue;
        if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(value) && /_/.test(value) && value === value.toUpperCase()) continue;
        if (weak && !/[\d!@#$%^&*+=~?]/.test(value)) continue;
        add(m.indices[2][0], m.indices[2][0] + value.length, strong ? 'PASSWD' : 'SECRETVALUE', 'n');
    }
    for (const m of clean.matchAll(rdGlobal(P.longNumbers))) {
        if (m[0].length > 20) add(m.index, m.index + m[0].length, 'LONGNUM', 'c');
    }
    const supp = urlSpans(clean);                                                           // F2
    for (const m of clean.matchAll(rdGlobal(P.base64Run))) {                                // G7
        const decoded = decodeBase64Text(m[0]);
        if (decoded === null) continue;
        supp.push([m.index, m.index + m[0].length]);
        if (scanText(decoded, ENGINE_DEFAULTS, 1)) add(m.index, m.index + m[0].length, 'ENCODED', 'c');
    }
    for (const m of clean.matchAll(rdGlobal(P.highEntropy))) {
        const t = m[0], s = m.index, e = s + t.length;
        if (supp.some(([a, b]) => s < b && e > a)) continue;
        const ctx = clean.substring(Math.max(0, s - 100), s);
        if (t.length >= 32 && /^[0-9a-fA-F]+$/.test(t) && /[0-9]/.test(t) && /[a-fA-F]/.test(t)) { // G6
            if (keywordInContext(ctx, ENGINE_DEFAULTS) && !P.hashContext.test(ctx.slice(-60))) add(s, e, 'SECRETVALUE', 'c');
            continue;
        }
        if (!looksRandom(t, ENGINE_DEFAULTS)) continue;                                     // F3, G8
        if (t.length > 21 || keywordInContext(ctx, ENGINE_DEFAULTS)) add(s, e, 'SECRETVALUE', 'c');
    }
    return spans;
}

// One pass. origIdx[i] = index of text[i] in the user's original text, or -1 inside a placeholder.
function redactOnce(text, origIdx) {
    const n = rdNormalize(text), c = rdCollapse(n.out);
    const toText = (sp, i) => sp === 'c' ? n.map[c.map[i]] : n.map[i];
    const spans = collectSpans(n.out, c.clean)
        .map((s) => ({ a: toText(s.sp, s.a), b: toText(s.sp, s.b - 1) + 1, type: s.type }))
        .sort((x, y) => x.a - y.a || y.b - x.b);
    const merged = [];
    for (const s of spans) {
        const last = merged[merged.length - 1];
        if (last && s.a < last.b) last.b = Math.max(last.b, s.b); else merged.push({ ...s });
    }
    let out = '', idx = [], pos = 0;
    const keep = (from, to) => { for (let k = from; k < to; k++) idx.push(origIdx[k]); };
    for (const s of merged) {
        out += text.slice(pos, s.a); keep(pos, s.a);
        const ph = `[REDACTED:${s.type}]`;
        out += ph; for (let k = 0; k < ph.length; k++) idx.push(-1);
        pos = s.b;
    }
    out += text.slice(pos); keep(pos, text.length);
    return { text: out, idx, count: merged.length };
}

// Typed text only: a user who pauses inside a secret gets the typed part redacted and then types
// the rest directly after the placeholder. Characters glued to a placeholder (no separator) are
// therefore treated as the continuation of the redacted value and removed as well.
const RD_TAIL = /(\[REDACTED:[A-Z_]+\])([A-Za-z0-9_\-+\/=@!#$%^&*~.:?]*[A-Za-z0-9_\-+\/=@!#$%^&*~])/g;
function absorbTails(text) { return text.replace(RD_TAIL, '$1'); }

// Returns {text, count, passes, clean}. clean === false means the caller must block instead.
function redactText(text, wantIdx) {
    let cur = text, idx = Array.from({ length: text.length }, (_, i) => i), count = 0, passes = 0;
    for (; passes < REDACT_MAX_PASSES; ) {
        const r = redactOnce(cur, idx);
        passes++;
        cur = r.text; idx = r.idx; count += r.count;
        if (r.count === 0 || !scanText(cur)) break;
    }
    const res = { text: cur, count, passes, clean: !scanText(cur) };
    if (wantIdx) res.idx = idx;
    return res;
}
// ==== SECURE-GPT REDACTOR END ====

// 2. STYLES
const styleSheet = document.createElement("style");
styleSheet.innerText = `
    @keyframes slideIn { from { transform: translateX(120%); } to { transform: translateX(0); } }
    @keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-6px); } 100% { transform: translateY(0px); } }
    @keyframes blink { 0%, 90%, 100% { transform: scaleY(1); } 95% { transform: scaleY(0.1); } }
    @keyframes shiver { 0% { transform: translate(0,0) rotate(0deg); } 25% { transform: translate(1px, 1px) rotate(1deg); } 50% { transform: translate(-1px, -1px) rotate(-1deg); } 75% { transform: translate(1px, -1px) rotate(1deg); } 100% { transform: translate(0,0) rotate(0deg); } }
    @keyframes jitter { 0% { transform: translateX(0); } 20% { transform: translateX(-2px); } 40% { transform: translateX(2px); } 60% { transform: translateX(-1px); } 80% { transform: translateX(1px); } 100% { transform: translateX(0); } }
    @keyframes throb { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }
    @keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(220, 20, 60, 0.7); } 70% { box-shadow: 0 0 0 40px rgba(220, 20, 60, 0); } 100% { box-shadow: 0 0 0 0 rgba(220, 20, 60, 0); } }
`;
document.head.appendChild(styleSheet);


// 3. UI: ALERTS
function esc(x) { return String(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }


// A. RED SCREEN (FIXED BUTTON)
function showBlockScreen(source, risk) {
    const overlay = document.createElement("div");
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; 
        background: radial-gradient(circle at center, #4a0000 0%, #1a0000 100%); z-index: 2147483647; 
        display: flex; flex-direction: column; justify-content: center; align-items: center;
        color: white; font-family: 'Segoe UI', sans-serif; text-align: center;
    `;
    
    const angryFace = `
    <svg width="180" height="180" viewBox="0 0 100 100" style="animation: throb 1.5s infinite ease-in-out, pulse-red 2s infinite;">
        <defs>
            <radialGradient id="gradRed" cx="35%" cy="35%" r="60%">
                <stop offset="0%" style="stop-color:#ff6b6b;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#8e0000;stop-opacity:1" />
            </radialGradient>
        </defs>
        <circle cx="50" cy="50" r="48" fill="url(#gradRed)" style="filter: drop-shadow(0 15px 25px rgba(0,0,0,0.6));"/>
        <ellipse cx="30" cy="25" rx="15" ry="8" fill="white" opacity="0.25" transform="rotate(-45 30 25)"/>
        <g fill="white" stroke="none">
            <path d="M22,38 L45,45 L45,40 L22,32 Z" fill="#500000"/>
            <path d="M78,38 L55,45 L55,40 L78,32 Z" fill="#500000"/>
            <circle cx="35" cy="50" r="5" fill="#fff"/>
            <circle cx="35" cy="50" r="2" fill="#000"/>
            <circle cx="65" cy="50" r="5" fill="#fff"/>
            <circle cx="65" cy="50" r="2" fill="#000"/>
            <path d="M32,72 Q50,62 68,72" stroke="#500000" stroke-width="4" fill="none" stroke-linecap="round"/>
        </g>
    </svg>`;

    overlay.innerHTML = `
        <div style="margin-bottom: 30px;">${angryFace}</div>
        <h1 style="font-size: 50px; margin: 0; font-weight: 800; text-shadow: 0 4px 10px rgba(0,0,0,0.5); letter-spacing: 1px;">DATA LEAK BLOCKED</h1>
        <div style="margin-top: 35px; background: rgba(255,255,255,0.08); padding: 30px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.15); max-width: 650px; backdrop-filter: blur(12px);">
            <p style="font-size: 22px; margin-bottom: 10px;"><strong>Source:</strong> ${esc(source)}</p>
            <p style="font-size: 22px; color: #ff8a80; font-weight:bold; margin: 0;"><strong>Threat:</strong> ${esc(risk)}</p>
        </div>
        <button id="secure-reload-btn" style="margin-top: 50px; padding: 18px 50px; font-size: 18px; cursor: pointer; border: none; background: linear-gradient(to bottom, #ffffff, #e0e0e0); color: #8e0000; font-weight: 800; border-radius: 50px; box-shadow: 0 10px 25px rgba(0,0,0,0.4); transition: transform 0.2s;">ACKNOWLEDGE & RELOAD</button>
    `;
    document.body.appendChild(overlay);

    document.getElementById("secure-reload-btn").addEventListener("click", () => {
        window.location.reload();
    });

    const chatInput = document.querySelector('#prompt-textarea') || document.querySelector('div[contenteditable="true"]') || document.querySelector('textarea');
    if (chatInput) { clearField(chatInput); chatInput.remove(); }
}

// B. GREEN TOAST
function showSafeNotification(fileName) {
    const happyFace = `
    <svg width="50" height="50" viewBox="0 0 100 100" style="animation: float 3s ease-in-out infinite;">
        <defs>
            <radialGradient id="gradGreen" cx="35%" cy="35%" r="60%">
                <stop offset="0%" style="stop-color:#66ff66;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#1b5e20;stop-opacity:1" />
            </radialGradient>
        </defs>
        <circle cx="50" cy="50" r="48" fill="url(#gradGreen)" style="filter: drop-shadow(0 5px 10px rgba(0,0,0,0.3));"/>
        <ellipse cx="30" cy="25" rx="12" ry="6" fill="white" opacity="0.4" transform="rotate(-45 30 25)"/>
        <g fill="white">
            <ellipse cx="35" cy="45" rx="5" ry="8" fill="#003300" style="animation: blink 4s infinite; transform-origin: center;"/>
            <ellipse cx="65" cy="45" rx="5" ry="8" fill="#003300" style="animation: blink 4s infinite 0.2s; transform-origin: center;"/>
            <path d="M30,65 Q50,80 70,65" stroke="#003300" stroke-width="5" fill="none" stroke-linecap="round"/>
        </g>
    </svg>`;
    
    createToast(happyFace, "linear-gradient(to right, #2e7d32, #43a047)", "SCAN PASSED", `${esc(fileName)} is safe.`);
}

// C. YELLOW TOAST
function showWarningNotification(fileName) {
    const shockedFace = `
    <svg width="60" height="60" viewBox="0 0 100 100" style="animation: shiver 0.2s infinite; filter: drop-shadow(0 5px 10px rgba(0,0,0,0.3));">
        <defs>
            <radialGradient id="gradYellow" cx="35%" cy="35%" r="60%">
                <stop offset="0%" style="stop-color:#fff176;stop-opacity:1" />
                <stop offset="50%" style="stop-color:#fdd835;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#f57f17;stop-opacity:1" />
            </radialGradient>
        </defs>
        <circle cx="50" cy="50" r="48" fill="url(#gradYellow)"/>
        <ellipse cx="30" cy="25" rx="12" ry="6" fill="white" opacity="0.5" transform="rotate(-45 30 25)"/>
        <g>
            <g style="animation: jitter 0.5s infinite;">
                <circle cx="35" cy="40" r="11" fill="white" stroke="#e65100" stroke-width="2"/>
                <circle cx="35" cy="40" r="4" fill="#000"/>
                <circle cx="65" cy="40" r="11" fill="white" stroke="#e65100" stroke-width="2"/>
                <circle cx="65" cy="40" r="4" fill="#000"/>
            </g>
            <ellipse cx="50" cy="72" rx="10" ry="14" fill="#3e2723"/>
        </g>
    </svg>`;

    const toast = document.createElement("div");
    toast.style.cssText = `
        position: fixed; top: 20px; right: 20px; 
        background: linear-gradient(to right, #f57f17, #ffb300); color: white; 
        padding: 15px 25px; border-radius: 12px; 
        box-shadow: 0 8px 25px rgba(0,0,0,0.4); 
        z-index: 2147483647; font-family: 'Segoe UI', sans-serif; 
        display: flex; flex-direction: column; gap: 5px;
        animation: slideIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); max-width: 350px;
        border: 1px solid rgba(255,255,255,0.25);
    `;
    
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 15px;">
            ${shockedFace}
            <div style="font-weight: 800; font-size: 19px; text-shadow: 0 1px 2px rgba(0,0,0,0.2);">SCAN LIMITED</div>
        </div>
        <div style="font-size: 15px; opacity: 0.95; line-height: 1.4; margin-top:8px; font-weight: 500;">
            We could not fully read <b>${esc(fileName)}</b>.
        </div>
        <div style="font-size: 13px; background: rgba(0,0,0,0.15); padding: 10px; border-radius: 8px; margin-top: 8px; border: 1px solid rgba(255,255,255,0.1);">
            💡 <b>Advice:</b> Convert to <b>.docx</b> for a full check.
        </div>
    `;

    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.5s";
        setTimeout(() => toast.remove(), 500);
    }, 6000); 
}

// Helper
function createToast(iconHTML, background, title, message) {
    const toast = document.createElement("div");
    toast.style.cssText = `
        position: fixed; top: 20px; right: 20px; 
        background: ${background}; color: white; 
        padding: 15px 25px; border-radius: 12px; 
        box-shadow: 0 8px 25px rgba(0,0,0,0.4); 
        z-index: 2147483647; font-family: 'Segoe UI', sans-serif; 
        font-weight: 600; display: flex; align-items: center; gap: 15px;
        animation: slideIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        border: 1px solid rgba(255,255,255,0.25);
    `;
    toast.innerHTML = `
        ${iconHTML}
        <div>
            <div style="font-size: 14px; opacity: 0.9;">${title}</div>
            <div style="font-size: 16px; font-weight: 700; text-shadow: 0 1px 2px rgba(0,0,0,0.2);">${message}</div>
        </div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.5s";
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

// 4. RESPONSE LAYER (release 58.2)
// ---------------------------------------------------------------------------
// Four response modes share one detector (engine v58, unchanged):
//   monitor : no intervention (baseline condition); detections are only logged
//   warn    : paste is held behind a dialog ("Remove it" / "Continue anyway");
//             typed text and files get a closable banner
//   block   : v58.0 behaviour (red overlay, input cleared, reload; files held back)
//   redact  : detected spans are replaced by [REDACTED:TYPE] and the text is inserted;
//             files cannot be rewritten in place, so they fall back to block
// The event log stores categories, lengths, timings and decisions only. It never
// stores prompt text, matched values, or file names.
// ---------------------------------------------------------------------------

const STUDY = { mode: 'block', pid: '', task: '' };
const MODES = ['monitor', 'warn', 'block', 'redact'];
let _internalEdit = false;
let _suppressWarnUntil = 0;
let _lastTypedLog = { cat: null, t: 0 };
let _redactTimer = null;
const REDACT_PAUSE_MS = 700;

function loadSettings() {
    try {
        chrome.storage.local.get(['mode', 'pid', 'task'], (r) => {
            if (r && MODES.includes(r.mode)) STUDY.mode = r.mode;
            STUDY.pid = (r && r.pid) || '';
            STUDY.task = (r && r.task) || '';
        });
        chrome.storage.onChanged.addListener((ch, area) => {
            if (area !== 'local') return;
            if (ch.mode && MODES.includes(ch.mode.newValue)) STUDY.mode = ch.mode.newValue;
            if (ch.pid) STUDY.pid = ch.pid.newValue || '';
            if (ch.task) STUDY.task = ch.task.newValue || '';
        });
    } catch (e) { /* storage unavailable: defaults (block) stay in force */ }
}
loadSettings();

// ---- event log (serialised so concurrent events are never lost) ----
let _logChain = Promise.resolve();
function category(label) {
    return label ? String(label).replace(/^[^A-Za-z]+/, '').split(' (')[0].split(':')[0] : null;
}
function logEvent(ev, extra) {
    const rec = Object.assign({ t: Date.now(), pid: STUDY.pid, task: STUDY.task, mode: STUDY.mode, ev }, extra || {});
    _logChain = _logChain.then(() => new Promise((resolve) => {
        try {
            chrome.storage.local.get(['log'], (r) => {
                const log = (r && r.log) || [];
                log.push(rec);
                if (log.length > 5000) log.splice(0, log.length - 5000);
                chrome.storage.local.set({ log }, resolve);
            });
        } catch (e) { resolve(); }
    }));
}

// ---- DOM helpers ----
function insertText(el, text) {
    _internalEdit = true;
    try {
        if (el && el.focus) el.focus();
        if (!document.execCommand('insertText', false, text) && el && 'value' in el) {
            el.setRangeText(text, el.selectionStart, el.selectionEnd, 'end');
            el.dispatchEvent(new Event('input', { bubbles: true }));
        }
    } finally { _internalEdit = false; }
}

function replaceFieldText(el, text) {
    _internalEdit = true;
    try {
        el.focus();
        if ('value' in el && el.tagName === 'TEXTAREA') {
            const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
            setter.call(el, text);
            el.dispatchEvent(new Event('input', { bubbles: true }));
        } else { document.execCommand('selectAll', false, null); document.execCommand('insertText', false, text); }
    } finally { _internalEdit = false; }
}

function clearField(el) {
    if (!el) return;
    if (el.tagName === 'TEXTAREA') {
        const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
        setter.call(el, '');
        el.dispatchEvent(new Event('input', { bubbles: true }));
    } else { el.innerHTML = ''; }
}

function showWarnDialog(cat, kind) {
    return new Promise((resolve) => {
        const ov = document.createElement('div');
        ov.id = 'sgpt-warn-dialog';
        ov.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,.55);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:Segoe UI,sans-serif;';
        ov.innerHTML = `
            <div style="background:#fff8e1;color:#4e3b00;border:2px solid #f9a825;border-radius:16px;padding:28px 32px;max-width:480px;box-shadow:0 12px 40px rgba(0,0,0,.5);text-align:center;">
                <div style="font-size:42px;">⚠️</div>
                <div style="font-size:22px;font-weight:800;margin:6px 0;">Possible sensitive data</div>
                <div style="font-size:16px;margin-bottom:20px;">${esc(cat)} was found in what you are ${kind === 'paste' ? 'pasting' : 'sending'}.</div>
                <button id="sgpt-cancel" style="padding:12px 26px;font-size:16px;font-weight:700;border:none;border-radius:30px;background:#f9a825;color:#3e2d00;cursor:pointer;margin-right:10px;">Remove it</button>
                <button id="sgpt-allow" style="padding:12px 26px;font-size:16px;font-weight:700;border:2px solid #f9a825;border-radius:30px;background:transparent;color:#4e3b00;cursor:pointer;">Continue anyway</button>
            </div>`;
        document.body.appendChild(ov);
        const done = (c) => { ov.remove(); resolve(c); };
        ov.querySelector('#sgpt-cancel').addEventListener('click', () => done('cancel'));
        ov.querySelector('#sgpt-allow').addEventListener('click', () => done('override'));
    });
}

function showWarnBanner(cat) {
    const old = document.getElementById('sgpt-warn-banner');
    if (old) old.remove();
    const b = document.createElement('div');
    b.id = 'sgpt-warn-banner';
    b.style.cssText = 'position:fixed;top:16px;left:50%;transform:translateX(-50%);background:#fff8e1;color:#4e3b00;border:2px solid #f9a825;border-radius:12px;padding:12px 22px;z-index:2147483647;font-family:Segoe UI,sans-serif;font-size:15px;font-weight:600;box-shadow:0 8px 25px rgba(0,0,0,.4);';
    b.textContent = `⚠️ Possible sensitive data in your prompt (${cat}). Remove it before sending.`;
    document.body.appendChild(b);
    setTimeout(() => b.remove(), 6000);
}

function showRedactToast(n) {
    createToast('<div style="font-size:30px;">✂️</div>', 'linear-gradient(to right, #1565c0, #1e88e5)', 'REDACTED', `${n} item${n === 1 ? '' : 's'} replaced before sending`);
}

function evaluateRisk(source, risk, isWarning = false) {
    if (isWarning) {
        console.warn(`⚠️ Warning: ${source}`);
        showWarningNotification(source);
        return;
    }
    if (risk) {
        console.warn(`🛑 BLOCKED: ${risk}`);
        showBlockScreen(source, risk);
    } else {
        console.log(`✅ Safe: ${source}`);
        if (source.includes(".") || source === "Clipboard Paste") {
            showSafeNotification(source);
        }
    }
}

// 5. LISTENERS
document.addEventListener('paste', (e) => {
    const pastedText = (e.clipboardData || window.clipboardData).getData('text');
    const t0 = performance.now();
    const risk = scanText(pastedText);
    const scan_ms = Math.round((performance.now() - t0) * 1000) / 1000;
    const mode = STUDY.mode, len = pastedText.length;
    if (!risk) {
        logEvent('paste_clean', { src: 'paste', len, scan_ms });
        if (mode !== 'monitor') evaluateRisk("Clipboard Paste", null);
        return;
    }
    const cat = category(risk), target = e.target;
    if (mode === 'monitor') {
        _lastTypedLog = { cat, t: Date.now() };   // the native paste fires an input event next; count it once
        logEvent('detect', { src: 'paste', cat, len, scan_ms, action: 'allowed' });
        return;
    }
    e.preventDefault(); e.stopPropagation();
    if (mode === 'block') {
        logEvent('detect', { src: 'paste', cat, len, scan_ms, action: 'blocked' });
        evaluateRisk("Clipboard Paste", risk);
    } else if (mode === 'warn') {
        logEvent('detect', { src: 'paste', cat, len, scan_ms, action: 'warned' });
        const t1 = performance.now();
        showWarnDialog(cat, 'paste').then((choice) => {
            logEvent('decision', { src: 'paste', cat, choice, ms: Math.round(performance.now() - t1) });
            if (choice === 'override') { _suppressWarnUntil = Date.now() + 8000; insertText(target, pastedText); }
        });
    } else { // redact
        const t1 = performance.now();
        const r = redactText(pastedText);
        const redact_ms = Math.round((performance.now() - t1) * 1000) / 1000;
        if (!r.clean) {
            logEvent('detect', { src: 'paste', cat, len, scan_ms, redact_ms, action: 'redact_fallback_block' });
            evaluateRisk("Clipboard Paste", risk);
        } else {
            logEvent('detect', { src: 'paste', cat, len, scan_ms, redact_ms, action: 'redacted', n_spans: r.count });
            insertText(target, r.text);
            showRedactToast(r.count);
        }
    }
}, true);

document.addEventListener('input', (e) => {
    if (_internalEdit) return;
    const target = e.target;
    if (!(target.contentEditable === 'true' || target.tagName === 'TEXTAREA')) return;
    const text = target.innerText || target.value || "";
    const mode = STUDY.mode;
    if (mode === 'redact') {
        // wait until typing pauses, so a value is never cut in half; Enter/Send also triggers it
        clearTimeout(_redactTimer);
        _redactTimer = setTimeout(() => redactField(target, 'typed', 'redacted'), REDACT_PAUSE_MS);
        return;
    }
    const risk = scanText(text);
    if (!risk) return;
    const cat = category(risk), now = Date.now(), len = text.length;
    const fresh = !(_lastTypedLog.cat === cat && now - _lastTypedLog.t < 5000);
    if (mode === 'block') {
        clearField(target);
        logEvent('detect', { src: 'typed', cat, len, action: 'blocked' });
        evaluateRisk("Typed Input", risk);
    } else if (mode === 'monitor') {
        if (fresh) { _lastTypedLog = { cat, t: now }; logEvent('detect', { src: 'typed', cat, len, action: 'allowed' }); }
    } else if (mode === 'warn') {
        if (now < _suppressWarnUntil) return;
        if (fresh) { _lastTypedLog = { cat, t: now }; logEvent('detect', { src: 'typed', cat, len, action: 'warned' }); showWarnBanner(cat); }
    }
}, true);

// Redacts the whole prompt field. Returns true if the field held sensitive content.
function redactField(target, src, action) {
    let text = target.innerText || target.value || "";
    const glued = absorbTails(text);
    if (glued !== text) {                       // tail of a value typed after its placeholder
        text = glued;
        replaceFieldText(target, text);
        logEvent('tail_absorbed', { src });
    }
    const risk = scanText(text);
    if (!risk) return false;
    const cat = category(risk), len = text.length;
    const r = redactText(text);
    if (!r.clean) {
        logEvent('detect', { src, cat, len, action: 'redact_fallback_block' });
        clearField(target);
        evaluateRisk("Typed Input", risk);
    } else {
        logEvent('detect', { src, cat, len, action, n_spans: r.count });
        replaceFieldText(target, r.text);
        showRedactToast(r.count);
    }
    return true;
}

// Submission probe: records whether sensitive text was in the prompt box when the
// user pressed Enter / Send. Outside redact mode it never blocks or alters the submission.
function currentInputEl() {
    const a = document.activeElement;
    if (a && (a.contentEditable === 'true' || a.tagName === 'TEXTAREA')) return a;
    return document.querySelector('#prompt-textarea') || document.querySelector('div[contenteditable="true"]') || document.querySelector('textarea');
}
function currentInputText() {
    const el = currentInputEl();
    return el ? (el.innerText || el.value || '') : '';
}
// Redact mode only: if sensitive text is still in the field when the user sends
// (typing pause not reached yet), hold this one send, redact, and let the user send again.
function redactBeforeSend(e) {
    if (STUDY.mode !== 'redact') return false;
    const el = currentInputEl();
    if (!el) return false;
    clearTimeout(_redactTimer);
    const text = el.innerText || el.value || '';
    if (!scanText(text) && absorbTails(text) === text) return false;
    e.preventDefault(); e.stopImmediatePropagation();
    redactField(el, 'typed', 'redacted_at_send');
    return true;
}
function logSubmit(src) {
    const text = currentInputText();
    if (!text || !text.trim()) return;
    const risk = scanText(text);
    logEvent('submit', { src, sensitive: !!risk, cat: category(risk), len: text.length });
}
document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
        if (!redactBeforeSend(e)) logSubmit('enter');
    }
}, true);
document.addEventListener('click', (e) => {
    const b = e.target && e.target.closest ? e.target.closest('button') : null;
    if (b && /send|submit/i.test((b.getAttribute('data-testid') || '') + ' ' + (b.getAttribute('aria-label') || ''))) {
        if (!redactBeforeSend(e)) logSubmit('click');
    }
}, true);

// v57.1: file and drop events are held until the scan finishes, so the host page cannot upload
// a file before the verdict. Allowed files are released by re-dispatching the event.
const _sgReleased = new WeakSet();
const _sgPending = new Map();
// v58.0: plain-text formats read with file.text().
const TEXT_EXTENSIONS = ['.txt', '.md', '.csv', '.tsv', '.json', '.jsonl', '.yaml', '.yml', '.toml', '.ini', '.cfg',
    '.conf', '.env', '.properties', '.xml', '.html', '.htm', '.log', '.sql', '.sh', '.bash', '.ps1', '.bat',
    '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.ipynb', '.java', '.kt', '.c', '.h', '.cpp', '.hpp',
    '.cs', '.go', '.rs', '.rb', '.php', '.swift', '.r', '.m', '.scala', '.pem', '.key', '.tf', '.gradle'];
function isTextFile(file) {
    const n = file.name.toLowerCase();
    return (file.type && file.type.startsWith('text/')) || file.type === 'application/json' ||
        n === '.env' || n.startsWith('.env.') || TEXT_EXTENSIONS.some(ext => n.endsWith(ext));
}
function scanFileVerdict(file) {
    const n = file.name.toLowerCase();
    const handled = n.endsWith('.docx') || n.endsWith('.pdf') || isTextFile(file);
    if (!handled) return Promise.resolve(true);
    return new Promise((resolve) => {
        _sgPending.set(file.name, resolve);
        setTimeout(() => { if (_sgPending.get(file.name) === resolve) { _sgPending.delete(file.name); resolve(true); } }, 20000);
        scanFile(file);
    });
}
function scanFilesVerdict(files) { return Promise.all(files.map(scanFileVerdict)).then(v => v.every(Boolean)); }

function holdFileInput(e) {
    const t = e.target;
    if (!(t && t.tagName === 'INPUT' && t.type === 'file' && t.files && t.files.length)) return;
    if (_sgReleased.has(e)) return;
    e.stopImmediatePropagation();
    if (e.type !== 'change') return;          // 'input' is held too, then released with 'change'
    scanFilesVerdict(Array.from(t.files)).then((allow) => {
        if (!allow) { t.value = ''; return; }
        for (const type of ['input', 'change']) {
            const ev = new Event(type, { bubbles: true }); _sgReleased.add(ev); t.dispatchEvent(ev);
        }
    });
}
document.addEventListener('input', holdFileInput, true);
document.addEventListener('change', holdFileInput, true);

document.addEventListener('drop', (e) => {
    if (_sgReleased.has(e)) return;
    const files = e.dataTransfer && e.dataTransfer.files;
    if (!files || !files.length) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const target = e.target, list = Array.from(files), x = e.clientX, y = e.clientY;
    scanFilesVerdict(list).then((allow) => {
        if (!allow) return;
        const dt = new DataTransfer(); list.forEach(f => dt.items.add(f));
        const ev = new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt, clientX: x, clientY: y });
        _sgReleased.add(ev); target.dispatchEvent(ev);
    });
}, true);

// 6. FILE EXTRACTION
// Result of a file scan: show the response for the current mode and release or hold the file.
function fileResult(name, risk, limited, ms) {
    const ext = (name.split('.').pop() || '').toLowerCase().slice(0, 8);
    const mode = STUDY.mode;
    let allow;
    if (!risk) {
        logEvent(limited ? 'file_limited' : 'file_clean', { src: 'file', ext, ms });
        if (mode !== 'monitor') evaluateRisk(name, null, !!limited);
        allow = true;
    } else {
        const cat = category(risk);
        if (mode === 'monitor') { logEvent('detect', { src: 'file', ext, cat, ms, action: 'allowed' }); allow = true; }
        else if (mode === 'warn') {
            logEvent('detect', { src: 'file', ext, cat, ms, action: 'warned' });
            showWarnBanner(cat + ' in attached file');
            allow = true;
        } else {
            // block, and redact (files cannot be rewritten in place, so redact falls back to block)
            logEvent('detect', { src: 'file', ext, cat, ms, action: mode === 'redact' ? 'redact_fallback_block' : 'blocked' });
            evaluateRisk(name, risk);
            allow = false;
        }
    }
    const done = _sgPending.get(name);
    if (done) { _sgPending.delete(name); done(allow); }
}

function runBinaryScan(file, t0) {
    console.log("⚠️ Running Fallback...");
    const reader = new FileReader();
    reader.onload = function(e) {
        const binary = e.target.result;
        const readableText = binary.replace(/[^\x20-\x7E]/g, " ");
        fileResult(file.name, scanText(readableText), true, Math.round(performance.now() - t0));
    };
    reader.readAsBinaryString(file);
}

async function scanFile(file) {
    const t0 = performance.now();
    const ms = () => Math.round(performance.now() - t0);
    const n = file.name.toLowerCase();
    if (n.endsWith('.docx')) {
        const reader = new FileReader();
        reader.onload = function(e) {
            if (typeof mammoth !== 'undefined') {
                mammoth.extractRawText({arrayBuffer: e.target.result})
                    .then(result => fileResult(file.name, scanText(result.value), false, ms()))
                    .catch(() => fileResult(file.name, null, true, ms()));
            }
        };
        reader.readAsArrayBuffer(file);
    }
    else if (n.endsWith('.pdf')) {
        // 58.2: pdf.js 3.11.174 with its matching worker, loaded as a content script (see manifest).
        try {
            const data = new Uint8Array(await file.arrayBuffer());
            const pdf = await pdfjsLib.getDocument({ data }).promise;
            let fullText = "";
            for (let i = 1; i <= pdf.numPages; i++) {
                const page = await pdf.getPage(i);
                const textContent = await page.getTextContent();
                fullText += textContent.items.map(item => item.str).join(" ") + " ";
            }
            fileResult(file.name, scanText(fullText), false, ms());
        } catch (e) { console.warn('pdf.js failed', e); runBinaryScan(file, t0); }
    }
    else if (isTextFile(file)) {
        const text = await file.text();
        fileResult(file.name, scanText(text), false, ms());
    }
}
