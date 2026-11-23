"""Paper 2 tables and figures from exp_core.js output.
python analyze_core.py <out_dir_of_exp_core> <tables_dir> <figures_dir>
Writes CSV + LaTeX tables and PDF/PNG figures; prints the headline numbers."""
import sys, os, json, math, statistics as st, collections
OUT, TAB, FIG = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(FIG, exist_ok=True)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import wilson, write, set_tab
set_tab(TAB)
rd = lambda f: [json.loads(l) for l in open(os.path.join(OUT, f)) if l.strip()]
P, N, T = rd('positives.jsonl'), rd('negatives.jsonl'), rd('typing.jsonl')
F = rd('fa_real.jsonl') if os.path.exists(os.path.join(OUT, 'fa_real.jsonl')) else []
S = json.load(open(os.path.join(OUT, 'summary_core.json')))

def ci(k, n): lo, hi = wilson(k, n); return f"{k} ({100*k/n:.1f}%, CI {lo:.1f}–{hi:.1f})" if n else '—'
def pctf(x): return f"{100*x:.1f}%"
def med(xs): return st.median(xs) if xs else float('nan')

GROUP = {
 'openai_key': 'API keys', 'aws_key': 'API keys', 'google_api_key': 'API keys', 'stripe_key': 'API keys', 'github_token': 'API keys',
 'slack_token': 'Service tokens', 'unseen_azure_key': 'Service tokens*', 'unseen_sendgrid': 'Service tokens*', 'unseen_twilio': 'Service tokens*',
 'unseen_telegram': 'Service tokens*', 'unseen_npm_token': 'Service tokens*',
 'jwt': 'JWTs, private keys', 'private_key': 'JWTs, private keys', 'unseen_bearer_header': 'JWTs, private keys',
 'bulk_emails': 'Bulk e-mail, CSV lists', 'csv_client_list': 'Bulk e-mail, CSV lists', 'phone_list': 'Phone lists',
 'long_number': 'Long numbers', 'hex_secret': 'Hex / encoded secrets', 'encoded_secret': 'Hex / encoded secrets',
 'keyword_secret': 'Keyword-adjacent secrets', 'django_secret_key': 'Secret assignments, .env', 'env_file': 'Secret assignments, .env',
 'secret_with_url': 'Secret + URL / academic word', 'secret_with_academic_word': 'Secret + URL / academic word',
 'db_connection_string': 'DB connection strings', 'payment_card': 'Payment cards', 'aadhaar': 'National IDs', 'pan': 'National IDs', 'ssn': 'National IDs',
 'unseen_passport': 'National IDs*', 'unseen_bank_ifsc': 'Bank account + IFSC*', 'password_symbol': 'Passwords', 'password_dictionary': 'Passwords',
 'unseen_docker_login': 'Passwords*'}
ORDER = ['API keys', 'Service tokens', 'Service tokens*', 'JWTs, private keys', 'Secret assignments, .env', 'Keyword-adjacent secrets',
         'Hex / encoded secrets', 'Secret + URL / academic word', 'DB connection strings', 'Bulk e-mail, CSV lists', 'Phone lists',
         'Long numbers', 'Payment cards', 'National IDs', 'National IDs*', 'Bank account + IFSC*', 'Passwords', 'Passwords*']

# ---------- Table II: redaction of detected positives ----------
g = collections.defaultdict(list)
for p in P: g[GROUP.get(p['category'], p['category'])].append(p)
rows = []; tot = collections.Counter()
def row_for(name, L):
    d = [p for p in L if p['detected']]; cl = [p for p in d if p['clean']]
    vb = [p for p in cl if p.get('verbatim')]
    full = sum(1 for p in cl if p.get('full_leak')); part = sum(1 for p in vb if p.get('partial_leak'))
    covfull = sum(1 for p in vb if p['char_cov'] >= 0.999)
    return [name, len(L), len(d), len(cl), len(d) - len(cl), f"{covfull}/{len(vb)}" if vb else '—',
            f"{full}/{part}", pctf(med([p['retention'] for p in cl])) if cl else '—']
for k in ORDER:
    if k in g: rows.append(row_for(k, g[k]))
rows.append(['__hline__']); rows.append(row_for('Total', P))
write('table2_redaction', ['Category', 'n', 'Det.', 'Redacted', 'To block', 'Secret fully covered', 'Leak full/partial', 'Text kept (median)'],
      rows, r'Redaction of the detected positives of the 3,335-case corpus (engine v58, release 58.2). * = category without a dedicated rule (unseen in paper 1). Partial = $\geq$8 consecutive secret characters remain.',
      'tab:redaction', 'lrrrrrrr')

# ---------- Table III: outcome of each response ----------
npos = sum(1 for p in P); det = [p for p in P if p['detected']]; FN = npos - len(det)
nneg = S['detection']['FP'] + S['detection']['TN']; FPn = len(N)
red_clean = [p for p in det if p['clean']]; red_fb = len(det) - len(red_clean)
red_full = sum(1 for p in red_clean if p.get('full_leak')); red_part = sum(1 for p in red_clean if p.get('partial_leak'))
neg_fb = sum(1 for n in N if not n['clean'])
ret_neg = med([n['retention'] for n in N if n['clean']])
rows = [
 ['Monitor', ci(npos, npos), '0', '0', '0 / 0'],
 ['Block', ci(FN, npos), str(len(det) + FPn), '0', f'{FPn} / 0'],
 ['Soft-block (modelled)', ci(FN, npos) + '†', '0', str(len(det) + FPn), f'0 / {FPn} edited'],
 ['Redact', ci(FN + red_full, npos), str(red_fb + neg_fb), '0', f'{neg_fb} / {FPn - neg_fb} (kept {pctf(ret_neg)})'],
]
warn_rows = []
for p_ in [0, .25, .5, .75, .9, 1.0]:
    leaked = FN + round(len(det) * (1 - p_)); lost = round((len(det) + FPn) * p_)
    warn_rows.append({'p': p_, 'leaked': leaked, 'lost': lost})
    rows.append([f'Warn, p={p_:.2f} (modelled)', ci(leaked, npos), str(lost), '0', f'{round(FPn*p_)} / 0'])
write('table3_outcomes', ['Response', f'Secrets reaching LLM (of {npos})', f'Prompts discarded (of {npos+nneg})', 'Prompts held for user edit', f'Harmless lost / altered (of {nneg})'],
      rows, r'Outcome of each response on the 3,335-case corpus. Warn is modelled: $p$ is the share of warned users who choose ``Remove it'' (paste path); typed text and files only receive a banner. † assumes every flagged span is edited out. Redact counts residual full leaks.',
      'tab:outcomes', 'lrrrr')
json.dump(warn_rows, open(os.path.join(TAB, 'warn_sweep.json'), 'w'), indent=1)

# McNemar (exact) block vs redact on "prompt discarded"
b = (len(det) + FPn) - (red_fb + neg_fb); c = 0
p_mc = 2 * sum(math.comb(b + c, k) for k in range(0, min(b, c) + 1)) / 2 ** (b + c) if b + c else 1.0

# ---------- Table: real prompts (paper 1, 20k WildChat FA study) ----------
if F:
    lab = collections.Counter(f['is_sensitive'] for f in F)
    rows = [['Flagged real prompts', str(len(F)), 'all lost', f"{sum(f['clean'] for f in F)} redacted, {sum(not f['clean'] for f in F)} to block"],
            ['Text kept per prompt (median, min)', '—', '0%', f"{pctf(med([f['retention'] for f in F if f['clean']]))}, {pctf(min(f['retention'] for f in F if f['clean']))}"],
            ['Manual labels (Y/N/blank)', f"{lab.get('Y',0)}/{lab.get('N',0)}/{lab.get(None,0)}", '', '']]
    write('table_real_prompts', ['Real WildChat prompts (20,000)', 'n', 'Block', 'Redact'], rows,
          'Block versus redact on the real prompts that engine v58 flags in the 20,000-prompt study of paper 1.', 'tab:realprompts', 'lrrr')

# ---------- Table: typed-text redaction ----------
paste_static = {p['id'] for p in P if p.get('partial_leak') or p.get('full_leak')}
rows = []; typ = []
for design in ['58.1 (no absorption)', '58.2 (tail absorption)']:
    for Tm in [300, 700, 1500]:
        for sc in ['natural', 'mid']:
            L = [t for t in T if t['design'] == design and t['T'] == Tm and t['scenario'] == sc]
            n = len(L); leak = sum(1 for t in L if (t['partial'] or t['full']) and t['id'] not in paste_static)
            lo, hi = wilson(leak, n)
            typ.append({'design': design, 'T': Tm, 'scenario': sc, 'n': n, 'leak': leak, 'lo': lo, 'hi': hi})
            rows.append([design, f'{Tm} ms', 'pause inside secret' if sc == 'mid' else 'natural pauses', n, f'{leak} ({100*leak/n:.1f}%, CI {lo:.1f}–{hi:.1f})'])
write('table_typing', ['Design', 'Pause', 'Typing', 'Runs', 'Typing-induced leaks'], rows,
      'Simulated typed-text redaction (text-level). A leak is a full secret or $\\geq$8 consecutive secret characters in the sent text that would not also remain after a paste.',
      'tab:typing', 'lllrr')

# ---------- Table: processing time ----------
rows = [[f"{t['kb']} KB", t['kind'].replace('_', ' '), f"{t['detect_med']:.2f}", f"{t['detect_p95']:.2f}",
         '—' if t['redact_med'] is None else f"{t['redact_med']:.2f}", '—' if t['redact_p95'] is None else f"{t['redact_p95']:.2f}"] for t in S['timing']]
write('table_timing', ['Input', 'Content', 'Detect med (ms)', 'p95', 'Redact med (ms)', 'p95'], rows,
      f"Processing time in Node.js {S['node']} (median and 95th percentile of 30 runs after 5 warm-ups).", 'tab:timing', 'llrrrr')

# ---------- Figure: protection vs prompts discarded ----------
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
plt.rcParams.update({'font.size': 8, 'font.family': 'serif', 'axes.spines.top': False, 'axes.spines.right': False})
C = {'Monitor': '#2a78d6', 'Block': '#eb6834', 'Redact': '#1baf7a', 'Warn': '#eda100', 'grid': '#d9d9d6', 'ink': '#2b2b2b', 'muted': '#6b6b6b'}
fig, ax = plt.subplots(figsize=(3.4, 2.35))
ax.grid(True, color=C['grid'], linewidth=0.5); ax.set_axisbelow(True)
wx = [w['lost'] for w in warn_rows]; wy = [w['leaked'] for w in warn_rows]
ax.plot(wx[1:-1], wy[1:-1], color=C['Warn'], linewidth=1.5, marker='o', markersize=4, zorder=2)
ax.plot(wx, wy, color=C['Warn'], linewidth=1.5, linestyle=(0, (3, 2)), zorder=1)
for w in warn_rows:
    if w['p'] in (0.25, 0.5, 0.9):
        ax.annotate(f"p={w['p']:.2f}", (w['lost'], w['leaked']), textcoords='offset points', xytext=(5, 5), fontsize=6.5, color=C['muted'])
pts = {'Monitor': (0, npos), 'Block': (len(det) + FPn, FN), 'Redact': (red_fb + neg_fb, FN + red_full)}
for k, (x, y) in pts.items():
    ax.scatter([x], [y], s=46, color=C[k], edgecolor='white', linewidth=1.5, zorder=3)
    off = {'Monitor': (8, -3), 'Block': (2, 9), 'Redact': (8, 4)}[k]
    ax.annotate(k, (x, y), textcoords='offset points', xytext=off, fontsize=7.5, color=C['ink'])
ax.annotate('Warn (modelled)', (wx[2], wy[2]), textcoords='offset points', xytext=(8, 14), fontsize=7.5, color=C['ink'])
ax.set_xlabel(f'Prompts discarded (of {npos+nneg})', color=C['ink']); ax.set_ylabel(f'Secrets reaching the LLM (of {npos})', color=C['ink'])
ax.set_xlim(-40, 950); ax.set_ylim(0, 950); ax.tick_params(colors=C['muted'], labelsize=7)
fig.tight_layout(); fig.savefig(os.path.join(FIG, 'fig_tradeoff.pdf')); fig.savefig(os.path.join(FIG, 'fig_tradeoff.png'), dpi=220); plt.close(fig)

head = {'detected': len(det), 'positives': npos, 'FN': FN, 'FP': FPn, 'redacted_clean': len(red_clean), 'redact_fallback': red_fb,
        'residual_full_leaks': red_full, 'residual_partial_leaks': red_part,
        'secret_fully_covered': sum(1 for p in red_clean if p.get('verbatim') and p['char_cov'] >= .999),
        'verbatim_redacted': sum(1 for p in red_clean if p.get('verbatim')),
        'retention_median': med([p['retention'] for p in red_clean]),
        'retention_iqr': st.quantiles([p['retention'] for p in red_clean], n=4),
        'max_passes': max(p['passes'] for p in det), 'fp_retention_median': ret_neg,
        'encoded_detected': sum(1 for p in det if p.get('verbatim') is False), 'encoded_leaks': sum(1 for p in det if p.get('verbatim') is False and p.get('full_leak')),
        'mcnemar_block_vs_redact_discarded': {'b': b, 'c': c, 'p': p_mc},
        'real_prompts': {'flagged': len(F), 'redacted': sum(f['clean'] for f in F), 'kept_median': med([f['retention'] for f in F if f['clean']])} if F else None,
        'typing': typ}
json.dump(head, open(os.path.join(TAB, 'headline.json'), 'w'), indent=1, default=float)
print(json.dumps({k: v for k, v in head.items() if k != 'typing'}, indent=1, default=float))
