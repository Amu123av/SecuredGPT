const $ = (id) => document.getElementById(id);
const FIELDS = ['t', 'iso', 'pid', 'task', 'mode', 'ev', 'src', 'cat', 'action', 'choice', 'ms', 'scan_ms', 'redact_ms', 'len', 'n_spans', 'sensitive', 'ext'];

function say(text) { $('msg').textContent = text; }
function refresh() {
    chrome.storage.local.get(['mode', 'pid', 'task', 'log'], (r) => {
        $('mode').value = r.mode || 'block';
        $('pid').value = r.pid || '';
        $('task').value = r.task || '';
        say(`${(r.log || []).length} events logged`);
    });
}
function download(name, text, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type }));
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
}
function stamp(pid) { return `${pid || 'log'}_${new Date().toISOString().replace(/[:.]/g, '-')}`; }
function csvCell(v) {
    if (v === undefined || v === null) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

$('save').addEventListener('click', () => {
    chrome.storage.local.set({ mode: $('mode').value, pid: $('pid').value.trim(), task: $('task').value.trim() }, () => say('Saved'));
});
$('exportJson').addEventListener('click', () => {
    chrome.storage.local.get(['log', 'pid'], (r) => download(`${stamp(r.pid)}.json`, JSON.stringify(r.log || [], null, 1), 'application/json'));
});
$('exportCsv').addEventListener('click', () => {
    chrome.storage.local.get(['log', 'pid'], (r) => {
        const rows = (r.log || []).map((e) => FIELDS.map((f) => csvCell(f === 'iso' ? new Date(e.t).toISOString() : e[f])).join(','));
        download(`${stamp(r.pid)}.csv`, [FIELDS.join(',')].concat(rows).join('\n'), 'text/csv');
    });
});
$('clear').addEventListener('click', () => {
    if (confirm('Delete all logged events on this browser?')) chrome.storage.local.set({ log: [] }, () => say('Log cleared'));
});
$('runner').addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('study/study.html') }));
refresh();
