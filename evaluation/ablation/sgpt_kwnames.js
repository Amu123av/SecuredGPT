// Block between the ENGINE BEGIN/END markers of Secure-GPT extension v58.0 content.js, copied verbatim.
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

// ==== SECURE-GPT REDACTOR BEGIN ====
// Redaction routine (release 58.2). It reads the detection rules of engine v58 above and does
// not change them. scanText() stops at the first finding, so redaction runs every rule again,
// collects all matching spans, maps them back to the original text (through the G1 normalisation
// and the whitespace collapsing that scanText applies), merges overlaps and replaces each span by
// [REDACTED:TYPE]. Placeholders contain no digits, so they cannot trigger a rule themselves.
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
    all(P.testTrigger, clean, 'SECRET', 'c');
    all(P.apiKey, clean, 'API_KEY', 'c');
    for (const [re, label] of P.prefixSignatures) {                                         // G2
        if (/Private Key/.test(label)) {
            for (const m of norm.matchAll(rdGlobal(re))) {
                const rest = norm.slice(m.index);
                const end = rest.match(/-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/);
                add(m.index, end ? m.index + end.index + end[0].length : norm.length, 'PRIVATE_KEY', 'n');
            }
        } else {
            all(re, norm, /Web Token/.test(label) ? 'TOKEN' : 'API_KEY', 'n');
        }
    }
    all(P.connString, clean, 'CONN_STRING', 'c');                                           // F5
    const em = clean.match(rdGlobal(P.emailPattern));
    if (em && em.length >= 3) all(P.emailPattern, clean, 'EMAIL', 'c');
    all(P.cardCandidate, clean, 'CARD', 'c', (m) => {                                       // F7
        const d = m[0].replace(/\D/g, '');
        return d.length >= 13 && d.length <= 19 && /^[2-6]/.test(d) && luhn(d);
    });
    all(P.aadhaarCandidate, clean, 'NATIONAL_ID', 'c', (m) => verhoeff(m[0].replace(/\D/g, '')));
    all(P.pan, clean, 'NATIONAL_ID', 'c');
    all(P.ssn, clean, 'NATIONAL_ID', 'c');
    const ph = [...clean.matchAll(rdGlobal(P.phone))];
    if (new Set(ph.map((m) => m[0].replace(/\D/g, ''))).size >= 3) ph.forEach((m) => add(m.index, m.index + m[0].length, 'PHONE', 'c'));
    for (const m of clean.matchAll(rdGlobal(P.passwordAssign))) {                           // value only
        const pre = m[0].match(/^(?:password|passwd|pwd|passcode|pin)\b\s*(?:is|=|:)\s*/i);
        if (pre) add(m.index + pre[0].length, m.index + m[0].length, 'PASSWORD', 'c');
    }
    for (const m of clean.matchAll(rdGlobal(P.pwdDictionary))) {                           // G5, value only
        if (!PWD_STOPWORDS.has(m[1].toLowerCase())) add(m.indices[1][0], m.indices[1][1], 'PASSWORD', 'c');
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
        add(m.indices[2][0], m.indices[2][0] + value.length, strong ? 'PASSWORD' : 'SECRET', 'n');
    }
    for (const m of clean.matchAll(rdGlobal(P.longNumbers))) {
        if (m[0].length > 20) add(m.index, m.index + m[0].length, 'NUMBER', 'c');
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
            if (keywordInContext(ctx, ENGINE_DEFAULTS) && !P.hashContext.test(ctx.slice(-60))) add(s, e, 'SECRET', 'c');
            continue;
        }
        if (!looksRandom(t, ENGINE_DEFAULTS)) continue;                                     // F3, G8
        if (t.length > 21 || keywordInContext(ctx, ENGINE_DEFAULTS)) add(s, e, 'SECRET', 'c');
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
module.exports = { scanText, ENGINE_DEFAULTS, redactText, collectSpans, absorbTails };
