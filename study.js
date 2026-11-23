// Secure-GPT response-mode study runner (release 58.2).
// Within-subject design: 4 conditions (monitor, warn, block, redact) ordered by a
// Williams Latin square; 4 task sets (A-D, 6 tasks each) rotated across participants.
// The runner switches the extension's mode and task ID itself, so the researcher only
// enters the participant number. It stores no names and no prompt text.

const CONDS = ['monitor', 'warn', 'block', 'redact'];
const WILLIAMS = [[0, 1, 3, 2], [1, 2, 0, 3], [2, 3, 1, 0], [3, 0, 2, 1]];
const VERSION = '58.2';
const ENGINE_SHA256 = '229419ce8c5e8f775521bad68cc078ad40c3d38abac6ada1ee0dec7c96d57f7d';
const MIN_TASK_MS = 5000;
const PRACTICE = {
    id: 'PRACTICE', kind: 'practice', category: 'practice',
    scenario: 'Practice: ask the assistant for three tips to prepare for a viva.',
    material: 'I have my M.Tech viva next week on my project report. Give me three practical tips to prepare.',
};
const LIKERT = ['Strongly disagree', 'Disagree', 'Neutral', 'Agree', 'Strongly agree'];
const SUS = [
    'I think that I would like to use this protection frequently.',
    'I found this protection unnecessarily complex.',
    'I thought this protection was easy to use.',
    'I think that I would need the support of a technical person to be able to use this protection.',
    'I found the various functions in this protection were well integrated.',
    'I thought there was too much inconsistency in this protection.',
    'I would imagine that most people would learn to use this protection very quickly.',
    'I found this protection very cumbersome to use.',
    'I felt very confident using this protection.',
    'I needed to learn a lot of things before I could get going with this protection.',
];
const EXTRA = [
    ['false_alarm', 'The protection interrupted me when there was nothing sensitive.'],
    ['control', 'I felt in control of what I finally sent.'],
    ['keep', 'I would keep this protection switched on for my own work.'],
];
const MODE_LOOK = {
    warn: 'Yellow pop-up asking me to remove the item or continue',
    block: 'Red full-screen “DATA LEAK BLOCKED” page',
    redact: 'Blue “REDACTED” notice that replaced the item with [REDACTED]',
};

const store = {
    get: (k) => new Promise((r) => chrome.storage.local.get(k, r)),
    set: (o) => new Promise((r) => chrome.storage.local.set(o, r)),
};
let TASKS = [];
let ST = null;
let chain = Promise.resolve();

const $view = () => document.getElementById('view');
const pad2 = (n) => String(n).padStart(2, '0');
function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
        if (k === 'text') e.textContent = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v);
    }
    kids.flat().forEach((c) => e.append(c instanceof Node ? c : document.createTextNode(c)));
    return e;
}
function mulberry32(a) {
    return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
function shuffle(xs, seed) {
    const r = mulberry32(seed), a = xs.slice();
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
}
function schedule(n) {
    const row = WILLIAMS[(n - 1) % 4], shift = Math.floor((n - 1) / 4) % 4;
    return row.map((c, b) => {
        const set = 'ABCD'[(b + shift) % 4];
        return { cond: CONDS[c], set, tasks: shuffle(TASKS.filter((t) => t.set === set).map((t) => t.id), n * 31 + b) };
    });
}
const taskById = (id) => (id === 'PRACTICE' ? PRACTICE : TASKS.find((t) => t.id === id));

function runlog(ev, extra) {
    const rec = Object.assign({ t: Date.now(), pid: ST ? ST.pid : '', ev }, extra || {});
    chain = chain.then(async () => {
        const r = await store.get(['runlog']);
        const log = r.runlog || [];
        log.push(rec);
        await store.set({ runlog: log });
    });
    return chain;
}
async function save() { await chain; await store.set({ runstate: ST }); }
async function setExtension(mode, task) { await store.set({ mode, pid: ST.pid, task }); }

async function exportData(stateOverride) {
    await chain;
    const r = await store.get(['log', 'runlog', 'survey', 'final', 'runstate']);
    const st = stateOverride || r.runstate || ST;
    const data = {
        format: 'secure-gpt-study-v1', version: VERSION, engine_sha256: ENGINE_SHA256, synthetic: false,
        exported_at: new Date().toISOString(), pid: st.pid, n: st.n, schedule: st.sched,
        tasks: TASKS.map(({ id, set, kind, category, expected }) => ({ id, set, kind, category, expected })),
        log: (r.log || []).filter((e) => e.pid === st.pid),
        runlog: r.runlog || [], survey: r.survey || [], final: r.final || null,
    };
    const a = el('a', { href: URL.createObjectURL(new Blob([JSON.stringify(data, null, 1)], { type: 'application/json' })), download: `${st.pid}_secure-gpt-study.json` });
    document.body.append(a); a.click(); a.remove();
    st.exported = true;
    await store.set({ runstate: st });
}

function progress() {
    const p = document.getElementById('progress');
    if (!ST || ST.phase === 'setup') { p.textContent = ''; return; }
    const part = ST.block < 4 ? `Part ${ST.block + 1} of 4` : 'Final questions';
    p.textContent = `${ST.pid} · ${part}` + (ST.phase === 'task' ? ` · Task ${ST.idx + 1} of 6` : '');
}

// ---------------- views ----------------
function viewSetup() {
    const num = el('input', { type: 'number', min: '1', max: '200', id: 'pnum' });
    const consent = el('input', { type: 'checkbox', id: 'consent' });
    const info = el('p', { class: 'muted', id: 'sched' });
    const err = el('div', { class: 'err' });
    num.addEventListener('input', () => {
        const n = parseInt(num.value, 10);
        info.textContent = n >= 1 ? 'Order: ' + schedule(n).map((b) => `${b.cond} (set ${b.set})`).join(' → ') : '';
    });
    const start = el('button', { text: 'Start session', onclick: async () => {
        const n = parseInt(num.value, 10);
        if (!(n >= 1 && n <= 200)) { err.textContent = 'Enter a participant number between 1 and 200.'; return; }
        if (!consent.checked) { err.textContent = 'Please confirm that the signed consent form has been collected.'; return; }
        const prev = await store.get(['runstate', 'log', 'runlog']);
        if (prev.runstate && prev.runstate.pid && !prev.runstate.exported && ((prev.runlog || []).length || (prev.log || []).length)) {
            await exportData(prev.runstate);   // safety copy of the previous participant before clearing
        }
        await store.set({ log: [], runlog: [], survey: [], final: null });
        ST = { n, pid: 'P' + pad2(n), sched: schedule(n), block: -1, idx: 0, phase: 'practice', t0: Date.now(), exported: false };
        await setExtension('monitor', 'PRACTICE');
        await runlog('session_start', { n, schedule: ST.sched.map((b) => ({ cond: b.cond, set: b.set, tasks: b.tasks })) });
        await runlog('task_start', { task: 'PRACTICE', kind: 'practice', block: -1, cond: 'monitor' });
        await save(); render();
    } });
    $view().replaceChildren(
        el('h2', { text: 'Researcher setup' }),
        el('p', { text: 'Before starting: open ChatGPT in another tab of this browser and sign in with the study account.' }),
        el('label', { class: 'inline' }, 'Participant number ', num),
        info,
        el('label', { class: 'inline' }, consent, 'Signed consent form collected'),
        err,
        el('div', { class: 'row' }, start),
    );
}

function viewTask(task, isPractice) {
    const ta = el('textarea', { class: 'material', readonly: 'readonly' });
    ta.value = task.material;
    const copied = el('span', { class: 'muted' });
    const next = el('button', { text: isPractice ? 'Start the study' : 'Next task', disabled: 'disabled' });
    setTimeout(() => next.removeAttribute('disabled'), MIN_TASK_MS);
    next.addEventListener('click', () => (isPractice ? finishPractice() : finishTask()));
    $view().replaceChildren(
        el('h2', { text: isPractice ? 'Practice task' : 'Task' }),
        el('p', { class: 'scenario', text: task.scenario }),
        ta,
        el('div', { class: 'row' },
            el('button', { class: 'secondary', text: 'Copy material', onclick: async () => {
                await navigator.clipboard.writeText(task.material);
                copied.textContent = 'Copied.';
                runlog('copy', { task: task.id });
            } }), copied),
        el('div', { class: 'steps' },
            el('div', { text: '1. Switch to the ChatGPT tab and paste the material together with your own question.' }),
            el('div', { text: '2. You may change anything before sending. Send it only if you are comfortable doing so.' }),
            el('div', { text: '3. Come back to this tab and continue.' })),
        el('div', { class: 'row' }, next),
    );
}

async function finishPractice() {
    await runlog('task_end', { task: 'PRACTICE', block: -1, cond: 'monitor', dur_ms: Date.now() - ST.t0 });
    ST.block = 0; ST.phase = 'block_intro'; await save(); render();
}

function viewBlockIntro() {
    $view().replaceChildren(
        el('h2', { text: `Part ${ST.block + 1} of 4` }),
        el('p', { text: 'The next six tasks work like the practice task. Work as you normally would.' }),
        el('div', { class: 'row' }, el('button', { text: 'Begin', onclick: async () => {
            const b = ST.sched[ST.block];
            ST.idx = 0; ST.phase = 'task'; ST.t0 = Date.now();
            await setExtension(b.cond, b.tasks[0]);
            await runlog('block_start', { block: ST.block, cond: b.cond, set: b.set });
            await startTaskLog();
            await save(); render();
        } })),
    );
}

async function startTaskLog() {
    const b = ST.sched[ST.block], id = b.tasks[ST.idx], t = taskById(id);
    await runlog('task_start', { task: id, kind: t.kind, category: t.category, block: ST.block, cond: b.cond, set: b.set });
}

async function finishTask() {
    const b = ST.sched[ST.block], id = b.tasks[ST.idx];
    await runlog('task_end', { task: id, block: ST.block, cond: b.cond, dur_ms: Date.now() - ST.t0 });
    ST.idx++;
    if (ST.idx < b.tasks.length) {
        ST.t0 = Date.now();
        await setExtension(b.cond, b.tasks[ST.idx]);
        await startTaskLog();
    } else {
        await setExtension(b.cond, '');
        if (b.cond === 'monitor') nextBlock(); else ST.phase = 'survey';
    }
    await save(); render();
}

function nextBlock() {
    ST.block++;
    ST.phase = ST.block < 4 ? 'block_intro' : 'final';
}

function likertTable(rows, prefix) {
    const head = el('tr', {}, el('th', {}), ...LIKERT.map((l) => el('th', { text: l })));
    const body = rows.map(([key, q]) => el('tr', {},
        el('td', { class: 'q', text: q }),
        ...LIKERT.map((_, i) => el('td', { class: 'o' }, el('input', { type: 'radio', name: prefix + key, value: String(i + 1), 'aria-label': `${q}: ${LIKERT[i]}` })))));
    return el('table', { class: 'likert' }, head, ...body);
}
const answer = (name) => { const c = document.querySelector(`input[name="${name}"]:checked`); return c ? parseInt(c.value, 10) : null; };

function viewSurvey() {
    const b = ST.sched[ST.block];
    const err = el('div', { class: 'err' });
    const susRows = SUS.map((q, i) => [String(i + 1), q]);
    $view().replaceChildren(
        el('h2', { text: `About Part ${ST.block + 1}` }),
        el('p', { text: 'These questions are about the protection you saw while doing the last six tasks (the pop-ups or notices that appeared).' }),
        likertTable(susRows, 'sus'),
        el('p', { class: 'muted', text: ' ' }),
        likertTable(EXTRA, 'x_'),
        err,
        el('div', { class: 'row' }, el('button', { text: 'Continue', onclick: async () => {
            const sus = susRows.map(([k]) => answer('sus' + k));
            const extra = Object.fromEntries(EXTRA.map(([k]) => [k, answer('x_' + k)]));
            if (sus.includes(null) || Object.values(extra).includes(null)) { err.textContent = 'Please answer every statement.'; return; }
            const r = await store.get(['survey']);
            const survey = r.survey || [];
            survey.push(Object.assign({ t: Date.now(), pid: ST.pid, block: ST.block, cond: b.cond, set: b.set, sus }, extra));
            await store.set({ survey });
            await runlog('survey_done', { block: ST.block, cond: b.cond });
            nextBlock(); await save(); render();
        } })),
    );
}

function radioGroup(name, options) {
    return el('div', {}, ...options.map(([v, label]) => el('label', { class: 'inline' }, el('input', { type: 'radio', name, value: v }), label)));
}
const pick = (name) => { const c = document.querySelector(`input[name="${name}"]:checked`); return c ? c.value : null; };

function viewFinal() {
    const looks = Object.entries(MODE_LOOK);
    const err = el('div', { class: 'err' });
    const comment = el('textarea', { class: 'comment', maxlength: '1000' });
    $view().replaceChildren(
        el('h2', { text: 'Final questions' }),
        el('p', { text: 'You saw three kinds of protection. Which one would you most like to have on your own computer?' }),
        radioGroup('best', looks.concat([['none', 'None of them']])),
        el('p', { text: 'Which one would you least like to have?' }),
        radioGroup('worst', looks),
        el('p', { text: 'How often do you use AI chat assistants such as ChatGPT?' }),
        radioGroup('use', [['daily', 'Daily'], ['weekly', 'Weekly'], ['monthly', 'Monthly'], ['rarely', 'Rarely or never']]),
        el('p', { text: 'What is your role?' }),
        radioGroup('role', [['ug', 'Undergraduate student'], ['pg', 'Postgraduate student'], ['phd', 'Research scholar'], ['staff', 'Faculty or staff'], ['other', 'Other']]),
        el('p', { text: 'Any other comments? (optional; please do not include names or personal details)' }),
        comment, err,
        el('div', { class: 'row' }, el('button', { text: 'Finish', onclick: async () => {
            const final = { best: pick('best'), worst: pick('worst'), use: pick('use'), role: pick('role'), comment: comment.value.trim().slice(0, 1000) };
            if (!final.best || !final.worst || !final.use || !final.role) { err.textContent = 'Please answer the four multiple-choice questions.'; return; }
            await store.set({ final });
            await runlog('session_end', {});
            await store.set({ mode: 'block', task: '', pid: '' });
            ST.phase = 'done'; await save(); render();
            await exportData();
        } })),
    );
}

function viewDone() {
    $view().replaceChildren(
        el('h2', { text: 'Thank you!' }),
        el('p', { text: 'The session is complete. Please tell the researcher that you have finished.' }),
        el('p', { class: 'muted', text: 'Every key, password, card and ID number in the tasks was invented for this study and does not belong to anyone.' }),
        el('div', { class: 'row' },
            el('button', { class: 'secondary', text: 'Export data again', onclick: () => exportData() }),
            el('button', { text: 'Next participant', onclick: async () => { await store.set({ runstate: null }); ST = null; render(); } })),
    );
}

function render() {
    progress();
    if (!ST || ST.phase === 'setup') return viewSetup();
    if (ST.phase === 'practice') return viewTask(PRACTICE, true);
    if (ST.phase === 'block_intro') return viewBlockIntro();
    if (ST.phase === 'task') {
        const b = ST.sched[ST.block];
        setExtension(b.cond, b.tasks[ST.idx]);   // re-assert after a reload of this tab
        return viewTask(taskById(b.tasks[ST.idx]), false);
    }
    if (ST.phase === 'survey') return viewSurvey();
    if (ST.phase === 'final') return viewFinal();
    return viewDone();
}

(async () => {
    TASKS = await (await fetch(chrome.runtime.getURL('study/tasks.json'))).json();
    const r = await store.get(['runstate']);
    ST = r.runstate || null;
    render();
})();
