"""Download public documents for the long-document experiment (reviewer M6).
python fetch_docs.py <out_dir> [--readmes 300] [--envs 60] [--sources 100] [--emails 60] [--seed 2026] [--token ...]
Writes <out_dir>/files/* and <out_dir>/docs_manifest.jsonl (id, kind, source, file, url, sha256, fetched_utc).
Repositories are drawn at random (fixed seed) from the 1,000 most-starred GitHub repositories, excluding
secret-scanning / security tooling (their docs contain example credentials by design)."""
import os, sys, json, re, random, time, hashlib, argparse, datetime, urllib.request, urllib.error
ap = argparse.ArgumentParser()
ap.add_argument('out'); ap.add_argument('--readmes', type=int, default=300); ap.add_argument('--envs', type=int, default=60)
ap.add_argument('--sources', type=int, default=100); ap.add_argument('--emails', type=int, default=60)
ap.add_argument('--logs', type=int, default=16); ap.add_argument('--seed', type=int, default=2026)
ap.add_argument('--token', default=os.environ.get('GITHUB_TOKEN', '')); ap.add_argument('--repo-list', default='')
a = ap.parse_args()
FILES = os.path.join(a.out, 'files'); os.makedirs(FILES, exist_ok=True)
rng = random.Random(a.seed)
NOW = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%MZ')
EXCLUDE = re.compile(r'secret|leak|scan|credential|password|vault|gitleaks|trufflehog|detect-secrets|security|pentest|hack|exploit|malware|ctf|phish', re.I)
HDR = {'User-Agent': 'secure-gpt-paper2-docs'}
if a.token: HDR['Authorization'] = 'Bearer ' + a.token

def get(url, raw=True, tries=2):
    for t in range(tries):
        try:
            req = urllib.request.Request(url, headers=HDR)
            with urllib.request.urlopen(req, timeout=20) as r:
                b = r.read()
                return b.decode('utf-8', errors='replace') if raw else json.loads(b)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and not raw: time.sleep(8)
            elif e.code == 404: return None
        except Exception:
            time.sleep(1)
    return None

# ---------- repository list ----------
repos = []
if a.repo_list and os.path.exists(a.repo_list):
    repos = [json.loads(l) for l in open(a.repo_list)]
else:
    for page in range(1, 11):
        js = get(f'https://api.github.com/search/repositories?q=stars:%3E1000&sort=stars&order=desc&per_page=100&page={page}', raw=False, tries=3)
        if not js or 'items' not in js: print('search API stopped at page', page); break
        for it in js['items']:
            repos.append({'full_name': it['full_name'], 'branch': it['default_branch'], 'stars': it['stargazers_count'],
                          'desc': it.get('description') or '', 'topics': it.get('topics') or [], 'lang': it.get('language') or ''})
        time.sleep(7)       # unauthenticated search limit: 10 requests / minute
    json.dump(repos, open(os.path.join(a.out, 'top_repos.json'), 'w'))
print('repositories listed:', len(repos))
pool = [r for r in repos if not EXCLUDE.search(r['full_name'] + ' ' + r['desc'] + ' ' + ' '.join(r['topics']))]
print('after excluding security/secret tooling:', len(pool))
rng.shuffle(pool)

manifest = []
def save(kind, source, url, text):
    h = hashlib.sha256(text.encode('utf-8')).hexdigest()
    fid = f'{kind}_{len(manifest):04d}'
    fn = fid + '.txt'
    open(os.path.join(FILES, fn), 'w', encoding='utf-8').write(text)
    manifest.append({'id': fid, 'kind': kind, 'source': source, 'file': fn, 'url': url, 'sha256': h, 'fetched_utc': NOW, 'bytes': len(text.encode())})

RAW = 'https://raw.githubusercontent.com/{r}/{b}/{p}'
# README files
n = 0
for r in pool:
    if n >= a.readmes: break
    for p in ['README.md', 'readme.md', 'README.rst', 'README.markdown', 'README', 'Readme.md']:
        t = get(RAW.format(r=r['full_name'], b=r['branch'], p=p))
        if t and len(t) > 500:
            save('readme', r['full_name'], RAW.format(r=r['full_name'], b=r['branch'], p=p), t); n += 1; break
print('readmes:', n)
# .env examples
n = 0
for r in pool:
    if n >= a.envs: break
    for p in ['.env.example', '.env.sample', 'example.env', '.env.template', '.env.dist']:
        t = get(RAW.format(r=r['full_name'], b=r['branch'], p=p))
        if t and len(t) > 40:
            save('env_example', r['full_name'], RAW.format(r=r['full_name'], b=r['branch'], p=p), t); n += 1; break
print('env examples:', n)
# source files (common entry points; with a token the tree API is used instead)
n = 0
COMMON = ['setup.py', 'manage.py', 'app.py', 'main.py', 'src/main.py', 'config.py', 'settings.py', 'index.js', 'src/index.js',
          'src/app.js', 'server.js', 'src/index.ts', 'main.go', 'cmd/main.go', 'src/main.rs', 'src/lib.rs', 'build.gradle', 'docker-compose.yml']
for r in pool[::-1]:
    if n >= a.sources: break
    paths = COMMON
    if a.token:
        js = get(f"https://api.github.com/repos/{r['full_name']}/git/trees/{r['branch']}?recursive=1", raw=False)
        if js and 'tree' in js:
            cand = [x['path'] for x in js['tree'] if x['type'] == 'blob' and re.search(r'\.(py|js|ts|go|java|rb|php|yml|yaml|json|toml|ini|cfg)$', x['path'])
                    and x.get('size', 0) < 120_000 and not re.search(r'test|spec|vendor|node_modules|dist/|min\.js', x['path'], re.I)]
            if cand: paths = [rng.choice(cand)]
    for p in paths:
        t = get(RAW.format(r=r['full_name'], b=r['branch'], p=p))
        if t and len(t) > 300:
            save('source', r['full_name'], RAW.format(r=r['full_name'], b=r['branch'], p=p), t); n += 1; break
print('source files:', n)
# system logs (LogHub, 2k-line samples)
n = 0
for s in ['Android', 'Apache', 'BGL', 'Hadoop', 'HDFS', 'HealthApp', 'HPC', 'Linux', 'Mac', 'OpenSSH', 'OpenStack', 'Proxifier',
          'Spark', 'Thunderbird', 'Windows', 'Zookeeper'][:a.logs]:
    u = f'https://raw.githubusercontent.com/logpai/loghub/master/{s}/{s}_2k.log'
    t = get(u)
    if t: save('log', 'loghub/' + s, u, t); n += 1
print('logs:', n)
# e-mails (AESLC, Enron e-mail bodies) - optional
if a.emails:
    try:
        from datasets import load_dataset
        ds = load_dataset('Yale-LILY/aeslc', split='test')
        idx = list(range(len(ds))); rng.shuffle(idx); n = 0
        for i in idx:
            body = ds[i]['email_body']
            if len(body) > 400: save('email', 'aeslc/test/' + str(i), 'hf://Yale-LILY/aeslc', body); n += 1
            if n >= a.emails: break
        print('emails:', n)
    except Exception as e:
        print('emails skipped:', str(e)[:120])
with open(os.path.join(a.out, 'docs_manifest.jsonl'), 'w') as f:
    for m in manifest: f.write(json.dumps(m) + '\n')
print('documents total:', len(manifest))
