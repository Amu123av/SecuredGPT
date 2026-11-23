"""Browser test kit for release 58.2 (paper 2). All secrets are invented and unique per platform.
python make_browser_kit.py <out_dir> <corpus_v2.jsonl>"""
import os, sys, csv, json, random, string
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
OUT = sys.argv[1]; os.makedirs(os.path.join(OUT, 'files'), exist_ok=True)
rng = random.Random(582)
A = string.ascii_letters + string.digits
rs = lambda n: ''.join(rng.choice(A) for _ in range(n))
D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
     [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
     [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
INV = [0,4,3,2,1,5,6,7,8,9]
def aadhaar():
    d = [rng.randrange(2, 10)] + [rng.randrange(10) for _ in range(10)]
    c = 0
    for i, x in enumerate(reversed(d)): c = D[c][P[(i + 1) % 8][x]]
    return ''.join(map(str, d + [INV[c]]))
WORDS = 'project schedule budget review team meeting report quarter customer delivery design module test release training planning'.split()
def pdf(path, lines):
    c = canvas.Canvas(path, pagesize=A4); y = 800
    for l in lines: c.drawString(50, y, l); y -= 18
    c.save()

PLAT = [('ch', 'ChatGPT', 'chatgpt.com'), ('ge', 'Gemini', 'gemini.google.com'), ('cl', 'Claude', 'claude.ai'), ('pe', 'Perplexity', 'www.perplexity.ai')]
trials, lines, manifest = [], [], {}
for code, name, host in PLAT:
    key = f'sk-proj-{code}{rs(46)}'
    half = len(key) // 2
    ad = aadhaar(); ad_fmt = f'{ad[:4]} {ad[4:8]} {ad[8:]}'
    manifest[code] = {'api_key': key, 'aadhaar': ad}
    paste_key = f'my python script fails with 401, why? client = OpenAI(api_key="{key}")'
    lines += [f'[{code}-B1 / {code}-W1 / {code}-W2 / {code}-R1]  COPY-PASTE this line:', paste_key, '',
              f'[{code}-R2 / {code}-R3]  TYPE this by hand:', f'please verify my aadhaar number {ad_fmt} for the bank form', '',
              f'[{code}-R4]  TYPE part 1, wait 2 seconds, then TYPE part 2 (no space between them):',
              f'part 1:  the key {key[:half]}', f'part 2:  {key[half:]} is not working', '', '-' * 70, '']
    pdf(os.path.join(OUT, 'files', f'sgt_{code}-secret.pdf'), ['KYC verification letter', 'Dear customer, please verify your details below.',
        f'Aadhaar: {ad_fmt}', 'Regards, Branch office, Mohali'])
    pdf(os.path.join(OUT, 'files', f'sgt_{code}-clean.pdf'), ['Meeting minutes - project review'] +
        [' '.join(rng.choice(WORDS) for _ in range(10)) for _ in range(12)])
    T = [
     ('B1', 'block', 'Paste the B1 line, press Enter', 'RED', 'NOTHING'),
     ('W1', 'warn', 'Paste the line; in the yellow dialog click "Remove it"', 'YELLOW', 'NOTHING'),
     ('W2', 'warn', 'Paste the line; click "Continue anyway"; press Enter', 'YELLOW', 'SECRET'),
     ('R1', 'redact', 'Paste the line, press Enter', 'BLUE', 'PLACEHOLDER'),
     ('R2', 'redact', 'Type the R2 line by hand, wait 2 s, press Enter', 'BLUE', 'PLACEHOLDER'),
     ('R3', 'redact', 'Type the R2 line by hand and press Enter IMMEDIATELY; if the text is still there press Enter again', 'BLUE', 'PLACEHOLDER'),
     ('R4', 'redact', 'Type part 1, wait 2 s, type part 2 right after it, press Enter (twice if needed)', 'BLUE', 'PLACEHOLDER'),
     ('R5', 'redact', f'Attach files/sgt_{code}-secret.pdf with the clip button', 'RED', 'NOTHING'),
     ('R6', 'redact', f'Attach files/sgt_{code}-clean.pdf, type "summarise this file", press Enter', 'GREEN', 'CLEAN'),
    ]
    for tid, mode, action, scr, chat in T:
        trials.append({'trial_id': f'{code}-{tid}', 'platform': name, 'url': f'https://{host}', 'mode': mode, 'action': action,
                       'expected_screen': scr, 'expected_chat': chat, 'screen': '', 'chat_shows': '', 'network_secret_found': '', 'notes': ''})
# old build vs new build on the same PDFs (reviewer M8)
for tid, f, exp in [('OLD-C', 'sgt_ch-clean.pdf', 'RED (bug: every PDF blocked)'), ('OLD-S', 'sgt_ch-secret.pdf', 'RED')]:
    trials.append({'trial_id': tid, 'platform': 'ChatGPT', 'url': 'https://chatgpt.com', 'mode': 'v58.0 extension (old)', 'action': f'With the OLD v58.0 extension loaded, attach files/{f}',
                   'expected_screen': exp, 'expected_chat': 'NOTHING', 'screen': '', 'chat_shows': '', 'network_secret_found': '', 'notes': ''})
with open(os.path.join(OUT, 'trial_log_582.csv'), 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(trials[0].keys())); w.writeheader(); w.writerows(trials)
open(os.path.join(OUT, 'paste_and_type.txt'), 'w').write('\n'.join(lines))
json.dump(manifest, open(os.path.join(OUT, 'secrets_manifest.json'), 'w'), indent=1)
# 100 KB benign text with one secret near the end, for redaction latency in the browser
rows = [json.loads(l) for l in open(sys.argv[2])]
benign = '\n\n'.join(r['text'] for r in rows if r['subset'] == 'real_benign' and len(r['text']) > 200)
big = benign[:100 * 1024 - 400]
open(os.path.join(OUT, 'big_text_100kb_secret.txt'), 'w').write(big + f'\n\nAlso my config has api_key="sk-proj-lat{rs(45)}" and it fails.\n')
print(len(trials), 'trials')
