"""Analyses for paper 2 beyond the core corpus: documents (M6), real-prompt labels (M9), PDF timing (M10),
LLM utility (M5), browser trials (M7/M8, live), pilot user study (M2)."""
import os, json, csv, glob, math, statistics as st, collections
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write, wilson, set_tab

def rd(p): return [json.loads(l) for l in open(p) if l.strip()]
def pctf(x): return f"{100*x:.1f}%"
def ci(k, n): lo, hi = wilson(k, n); return f"{k}/{n} ({100*k/n:.1f}%, CI {lo:.1f}–{hi:.1f})" if n else '—'

# ---------------- documents (M6) ----------------
CAUSE = [('Example values (keys, JWTs, IDs) in docs', ('API Key', 'JSON Web Token', 'Private Key', 'Secret Assignment', 'Contextual Secret (Hex', 'Credentials in Connection')),
         ('Contact lists (>= 3 e-mails / phones)', ('Bulk Personal Data',)),
         ('Random-looking identifiers', ('High Entropy', 'Contextual Secret (Keyword')),
         ('Long numbers / Luhn-valid digits', ('Long Secret Number', 'Payment Card', 'National ID')),
         ('Password-like assignments', ('Password Assignment',)),
         ('Encoded data', ('Encoded Secret',)),
         ('CSV-style headers', ('Client List',))]
def cause_of(label):
    for name, keys in CAUSE:
        if any(label.startswith(k) for k in keys): return name
    return 'Other'

def analyze_docs(res_dir, tab_dir, tag=''):
    set_tab(tab_dir)
    U = rd(os.path.join(res_dir, 'docs_unmodified.jsonl'))
    I = rd(os.path.join(res_dir, 'docs_inserts.jsonl'))
    Dd = rd(os.path.join(res_dir, 'docs_inserted.jsonl'))
    kinds = sorted(set(u['kind'] for u in U))
    rows = []
    for k in kinds + ['all']:
        L = [u for u in U if k == 'all' or u['kind'] == k]
        F = [u for u in L if u['flagged']]
        cl = [u for u in F if u.get('redact_clean')]
        rows.append([k, len(L), ci(len(F), len(L)), len(cl), len(F) - len(cl),
                     pctf(st.median([u['retention'] for u in cl])) if cl else '—',
                     pctf(min([u['retention'] for u in cl])) if cl else '—'])
    write('table_docs_unmodified' + tag, ['Document type', 'n', 'Flagged (unmodified)', 'Redacted', 'To block', 'Text kept (median)', 'min'], rows,
          'Unmodified public documents under release 58.2. Every finding is a false alarm unless manual coding shows a real credential.', 'tab:docs' + tag, 'lrrrrrr')
    # size bins
    bins = [(0, 4096, '< 4 KB'), (4096, 16384, '4–16 KB'), (16384, 10**9, '>= 16 KB')]
    rows = []
    for a, b, name in bins:
        L = [u for u in U if a <= u['bytes'] < b]
        rows.append([name, len(L), ci(sum(u['flagged'] for u in L), len(L))])
    write('table_docs_size' + tag, ['Size', 'n', 'Flagged'], rows, 'False alarms on unmodified documents by size.', 'tab:docsize' + tag, 'lrr')
    # causes + manual coding sheet
    cc = collections.Counter(cause_of(u['label']) for u in U if u['flagged'])
    write('table_docs_causes' + tag, ['Cause (first finding)', 'Documents'], [[k, v] for k, v in cc.most_common()],
          'Why unmodified documents were flagged (automatic coding by first finding; see the manual sheet).', 'tab:causes' + tag, 'lr')
    with open(os.path.join(tab_dir, 'docs_flags_to_code' + tag + '.csv'), 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['id', 'kind', 'source', 'label', 'auto_cause', 'snippet_1', 'snippet_2', 'snippet_3', 'manual_cause', 'is_real_credential'])
        for u in U:
            if u['flagged']:
                s = (u.get('snippets') or []) + ['', '', '']
                w.writerow([u['id'], u['kind'], u['source'], u['label'], cause_of(u['label']), s[0], s[1], s[2], '', ''])
    # insertion
    n = len(I); alone = [i for i in I if i['detected_alone']]; notalone = [i for i in I if not i['detected_alone']]
    rows = [['Inserted secrets (all categories)', ci(sum(i['found'] for i in I), n)],
            ['  of which detectable on their own', ci(sum(i['found'] for i in alone), len(alone))],
            ['  of which missed on their own', ci(sum(i['found'] for i in notalone), len(notalone))],
            ['Residual full leaks after redaction', str(sum(i['full_leak'] for i in I))],
            ['Documents with insertions', str(len(Dd))],
            ['  sent to block (redaction impossible)', ci(sum(d['blocked'] for d in Dd), len(Dd))],
            ['  document text kept (median, min)', f"{pctf(st.median([d['doc_text_kept'] for d in Dd if not d['blocked']]))}, {pctf(min([d['doc_text_kept'] for d in Dd if not d['blocked']]))}"],
            ['  redaction passes (max)', str(max(d['passes'] for d in Dd))]]
    write('table_docs_insert' + tag, ['Insertion experiment', 'Result'], rows,
          'Secrets drawn category-balanced and without replacement from all 875 corpus positives and inserted into public documents.', 'tab:insert' + tag, 'lr')
    return {'docs': len(U), 'flagged': sum(u['flagged'] for u in U), 'inserted': n, 'found': sum(i['found'] for i in I),
            'found_alone': sum(i['found'] for i in alone), 'n_alone': len(alone), 'leaks': sum(i['full_leak'] for i in I),
            'blocked_docs': sum(d['blocked'] for d in Dd), 'n_docs_inserted': len(Dd)}

# ---------------- real-prompt labels (M9) ----------------
def label_summary(review_dir, tab_dir):
    set_tab(tab_dir)
    out = {}
    for name in ['benign_flags', 'fa_flags', 'benign_unflagged']:
        p = os.path.join(review_dir, f'{name}_reviewed.csv')
        if not os.path.exists(p): out[name] = None; continue
        R = list(csv.DictReader(open(p, encoding='utf-8')))
        lab = collections.Counter((r.get('is_sensitive') or '').strip().upper()[:1] for r in R)
        out[name] = {'n': len(R), 'Y': lab.get('Y', 0), 'N': lab.get('N', 0), 'blank': lab.get('', 0)}
    rows = [[k, *(['—'] * 4 if v is None else [v['n'], v['Y'], v['N'], v['blank']])] for k, v in out.items()]
    write('table_labels', ['Review file', 'Rows', 'Y (real secret/PII)', 'N', 'Unlabelled'], rows,
          'Manual labels of real WildChat prompts (paper 1 review sheets).', 'tab:labels', 'lrrrr')
    return out

# ---------------- PDF timing (M10) ----------------
def pdf_table(pdf_json, tab_dir):
    set_tab(tab_dir)
    R = json.load(open(pdf_json))
    rows = [[r['file'], r['pages'], r['kb'], f"{r['extract_med_ms']:.1f}", f"{r['scan_med_ms']:.2f}", r['verdict'] or 'clean'] for r in R]
    write('table_pdf_timing', ['File', 'Pages', 'KB', 'Extract (ms)', 'Scan (ms)', 'Verdict'], rows,
          'PDF text extraction with pdf.js 3.11.174 (as shipped in release 58.2) and engine v58, Node.js, median of runs.', 'tab:pdf', 'lrrrrl')

# ---------------- LLM utility (M5) ----------------
def utility_table(res_jsonl, tab_dir):
    set_tab(tab_dir)
    R = rd(res_jsonl)
    rows = []
    for t, name in [('a', 'Secret incidental to the task'), ('b', 'Secret is the object of the task'), ('c', 'Configuration debugging'), ('all', 'All')]:
        L = [r for r in R if t == 'all' or r['type'] == t]
        sc = [r['judge_score'] for r in L if r.get('judge_score') is not None]
        ok = sum(1 for s in sc if s >= 4)
        man = [r for r in L if (r.get('manual_ok') or '').strip()]
        rows.append([name, len(L), f"{st.mean(sc):.2f}" if sc else '—', ci(ok, len(sc)) if sc else '—',
                     f"{sum(1 for r in man if r['manual_ok'].strip().upper().startswith('Y'))}/{len(man)}" if man else '—'])
    write('table_utility', ['Prompt type', 'n', 'Judge score (1–5)', 'Redacted answer as useful (score >= 4)', 'Manual check (Y/n)'], rows,
          'Does the LLM answer the redacted prompt as usefully as the original? Answers by Qwen2.5-3B-Instruct, judged by Phi-3.5-mini-instruct; a subset checked by hand.', 'tab:utility', 'lrrrr')

# ---------------- browser trials (live) ----------------
def browser_table(trial_csv, tab_dir):
    set_tab(tab_dir)
    R = list(csv.DictReader(open(trial_csv, encoding='utf-8')))
    R = [r for r in R if (r.get('screen') or '').strip()]
    def ok(r):
        exp_s = r['expected_screen'].split()[0].upper(); got_s = r['screen'].strip().upper()
        return got_s.startswith(exp_s) and r['chat_shows'].strip().upper() == r['expected_chat'].strip().upper()
    by = collections.defaultdict(list)
    for r in R: by[(r['trial_id'].split('-', 1)[-1] if '-' in r['trial_id'] and not r['trial_id'].startswith('OLD') else r['trial_id'])].append(r)
    desc = {'B1': 'Block · paste', 'W1': 'Warn · paste → Remove it', 'W2': 'Warn · paste → Continue anyway', 'R1': 'Redact · paste',
            'R2': 'Redact · typed, pause', 'R3': 'Redact · typed, immediate Enter', 'R4': 'Redact · typed, pause inside key',
            'R5': 'Redact · secret PDF attached', 'R6': 'Redact · clean PDF attached', 'OLD-C': 'v58.0 · clean PDF', 'OLD-S': 'v58.0 · secret PDF'}
    plats = ['ChatGPT', 'Gemini', 'Claude', 'Perplexity']
    rows = []
    for k in desc:
        if k not in by: continue
        cells = []
        for p in plats:
            L = [r for r in by[k] if r['platform'] == p]
            cells.append('—' if not L else ('✓' if all(ok(r) for r in L) else '✗ ' + L[0]['screen'] + '/' + L[0]['chat_shows']))
        rows.append([desc[k], by[k][0]['expected_screen'].split()[0] + ' / ' + by[k][0]['expected_chat'], *cells])
    write('table_browser', ['Trial', 'Expected', *plats], rows,
          'Live trials with release 58.2 (Chrome, Windows 11). ✓ = screen and chat content as expected; the chat content is what the provider received.', 'tab:browser', 'llcccc')
    return {'trials': len(R), 'as_expected': sum(ok(r) for r in R)}

def browser_latency(log_csv, tab_dir):
    set_tab(tab_dir)
    R = list(csv.DictReader(open(log_csv, encoding='utf-8')))
    L = [r for r in R if r.get('ev') == 'detect' and r.get('src') == 'paste' and r.get('len') and int(r['len']) > 50000]
    rows = [[r.get('iso') or r.get('t'), r['len'], r.get('scan_ms', ''), r.get('redact_ms', ''), r.get('action', '')] for r in L]
    write('table_browser_latency', ['Time', 'Chars', 'Scan (ms)', 'Redact (ms)', 'Action'], rows,
          'In-browser timing of a 100 KB paste with one secret (event log of release 58.2).', 'tab:blat', 'lrrrl')
    return rows

# ---------------- pilot user study ----------------
def sus_score(items):   # items 1..5, standard SUS scoring
    s = sum((x - 1) if i % 2 == 0 else (5 - x) for i, x in enumerate(items)); return s * 2.5

def study_tables(study_dir, tab_dir):
    set_tab(tab_dir)
    files = sorted(glob.glob(os.path.join(study_dir, '*.json')))
    if not files: return None
    P = [json.load(open(f)) for f in files]
    per = collections.defaultdict(lambda: {'sens_tasks': 0, 'sens_sent': 0, 'trap_tasks': 0, 'trap_sent': 0, 'dur': [], 'sus': [],
                                           'warn_decisions': collections.Counter()})
    for d in P:
        kind = {t['id']: t['kind'] for t in d['tasks']}
        ends = {(e['task'], e.get('cond')): e for e in d['runlog'] if e['ev'] == 'task_end'}
        for (task, cond), e in ends.items():
            if task == 'PRACTICE': continue
            k = kind.get(task); m = per[cond]; m['dur'].append(e['dur_ms'] / 1000)
            subs = [x for x in d['log'] if x.get('task') == task and x.get('ev') == 'submit']
            sent_sensitive = any(x.get('sensitive') for x in subs)
            if k == 'sensitive': m['sens_tasks'] += 1; m['sens_sent'] += int(sent_sensitive)
            if k == 'trap': m['trap_tasks'] += 1; m['trap_sent'] += int(bool(subs))
        for x in d['log']:
            if x.get('ev') == 'decision': per[x.get('mode')]['warn_decisions'][x.get('choice')] += 1
        for s in d.get('survey', []):
            if None not in s['sus']: per[s['cond']]['sus'].append(sus_score(s['sus']))
    rows = []
    for cond in ['monitor', 'warn', 'block', 'redact']:
        m = per[cond]; wd = m['warn_decisions']
        rows.append([cond, ci(m['sens_sent'], m['sens_tasks']) if m['sens_tasks'] else '—',
                     f"{m['trap_sent']}/{m['trap_tasks']}" if m['trap_tasks'] else '—',
                     f"{st.median(m['dur']):.0f}" if m['dur'] else '—',
                     f"{st.mean(m['sus']):.1f} (n={len(m['sus'])})" if m['sus'] else '—',
                     f"{wd.get('override', 0)} continue / {wd.get('cancel', 0)} remove" if cond == 'warn' else '—'])
    write('table_study', ['Mode', 'Sensitive tasks sent with secret', 'False-alarm tasks completed', 'Median task time (s)', 'SUS (mean)', 'Warn dialog decisions'], rows,
          f'Pilot user study (n = {len(P)}), within-subject, Williams-square order. Leakage is measured by the send probe of the event log.', 'tab:study', 'lrrrrr')
    fin = collections.Counter((d.get('final') or {}).get('best') for d in P)
    return {'participants': len(P), 'best': dict(fin)}
