"""Task-relevant prompts for the LLM utility test (reviewer M5). All secrets are invented.
Type a: the secret is incidental (code or log around it is what the user needs help with).
Type b: the secret is the object of the task (format / validate / decode it) - redaction should hurt.
Type c: configuration debugging (connection strings, .env) - in between.
python gen_utility.py out.jsonl [seed]"""
import json, random, sys, string, base64
rng = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 7)
A = string.ascii_letters + string.digits
def rs(n, alpha=A): return ''.join(rng.choice(alpha) for _ in range(n))
def luhn_card(prefix='4', n=16):
    d = [int(c) for c in prefix] + [rng.randrange(10) for _ in range(n - len(prefix) - 1)]
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 0: x *= 2; x -= 9 if x > 9 else 0
        s += x
    return ''.join(map(str, d + [(10 - s % 10) % 10]))
D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
     [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
Pm = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
      [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
INV = [0,4,3,2,1,5,6,7,8,9]
def aadhaar():
    d = [rng.randrange(2, 10)] + [rng.randrange(10) for _ in range(10)]
    c = 0
    for i, x in enumerate(reversed(d)): c = D[c][Pm[(i + 1) % 8][x]]
    return ''.join(map(str, d + [INV[c]]))
def phone(): return f"+91 {rng.randrange(6,10)}{rng.randrange(1000,9999)} {rng.randrange(10000,99999)}"
def okey(): return 'sk-proj-' + rs(48)
def aws(): return 'AKIA' + rs(16, string.ascii_uppercase + string.digits)
def jwt():
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
    p = base64.urlsafe_b64encode(json.dumps({"sub": str(rng.randrange(10**6)), "role": "admin", "exp": 1767225600}).encode()).decode().rstrip('=')
    return f"{h}.{p}.{rs(43, A + '-_')}"
def pw(): return rng.choice(['Tiger', 'Mango', 'River', 'Falcon']) + rs(3, string.digits) + rng.choice('!@#$')

out = []
# ---- type a: incidental ----
a_t = [
 lambda: f"My script fails with 'openai.RateLimitError'. How do I add exponential backoff?\n\nimport openai, time\nclient = openai.OpenAI(api_key=\"{okey()}\")\nfor q in questions:\n    r = client.chat.completions.create(model=\"gpt-4o-mini\", messages=[{{\"role\":\"user\",\"content\":q}}])\n    print(r.choices[0].message.content)",
 lambda: f"Why does boto3 say the bucket does not exist? The bucket is in ap-south-1.\n\nimport boto3\ns3 = boto3.client('s3', aws_access_key_id='{aws()}', aws_secret_access_key='{rs(40)}')\ns3.upload_file('report.csv', 'acme-reports', 'q3/report.csv')",
 lambda: f"Refactor this function to use async/await instead of .then chains:\n\nconst KEY = \"{okey()}\";\nfunction getUser(id) {{\n  return fetch('/api/users/' + id, {{ headers: {{ Authorization: 'Bearer ' + KEY }} }})\n    .then(r => r.json())\n    .then(u => u.profile)\n    .catch(e => console.error(e));\n}}",
 lambda: f"Explain this stack trace and tell me which line is the problem.\n\nTraceback (most recent call last):\n  File \"app.py\", line 42, in <module>\n    db = connect(user='admin', password='{pw()}')\n  File \"app.py\", line 17, in connect\n    return psycopg2.connect(host=HOST, user=user, password=password, dbname=DB)\npsycopg2.OperationalError: could not translate host name \"db.internal\" to address",
 lambda: f"Add type hints and a docstring to this function:\n\ndef send_alert(msg):\n    token = \"xoxb-{rng.randrange(10**11,10**12)}-{rng.randrange(10**11,10**12)}-{rs(24)}\"\n    requests.post('https://slack.com/api/chat.postMessage', headers={{'Authorization': f'Bearer {{token}}'}}, json={{'channel': '#ops', 'text': msg}})",
 lambda: f"Write a unit test with pytest for this helper (mock the network call):\n\nSTRIPE_KEY = 'sk_live_{rs(24)}'\ndef refund(charge_id):\n    return stripe.Refund.create(charge=charge_id, api_key=STRIPE_KEY)",
 lambda: f"My GitHub Action fails at the checkout step. What is wrong with this YAML?\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          token: ghp_{rs(36)}\n      - run: npm ci\n       - run: npm test",
 lambda: f"Translate this Python snippet to Go:\n\nheaders = {{'x-api-key': 'AIza{rs(35)}'}}\nresp = requests.get('https://maps.googleapis.com/maps/api/geocode/json?address=Mohali', headers=headers, timeout=5)\nprint(resp.json()['results'][0]['geometry'])",
]
# ---- type b: secret is the object ----
b_t = [
 lambda: "Format these customer phone numbers in E.164 and sort them:\n" + "\n".join(phone() for _ in range(5)),
 lambda: f"Is this card number valid according to the Luhn check? Show the steps: {luhn_card()}",
 lambda: (lambda a: f"Check whether this Aadhaar number passes the Verhoeff checksum and explain how: {a[:4]} {a[4:8]} {a[8:]}")(aadhaar()),
 lambda: f"Decode the payload of this JWT and tell me which user and role it carries:\n{jwt()}",
 lambda: f"Which AWS account type and key type is this access key ID? {aws()}",
 lambda: "Remove duplicates from this mailing list and give me a comma-separated list:\n" + "\n".join(f"{rng.choice(['asha','ravi','meera','john','li'])}.{rng.choice(['k','s','p'])}{rng.randrange(10,99)}@{rng.choice(['brightlane.co','acme.in','mailbox.org'])}" for _ in range(6)),
 lambda: f"Mask this card number for display so only the last four digits show: {luhn_card('5')}",
 lambda: f"My password is {pw()} - is it strong enough? Rate it and explain.",
]
# ---- type c: config debugging ----
c_t = [
 lambda: f"Django cannot connect with this DATABASE_URL. What is wrong?\nDATABASE_URL=postgres://app_user:{pw()}@pg-prod-02.acme.internal:5432/attendance?sslmode=require\nError: FATAL: no pg_hba.conf entry for host",
 lambda: f"My .env is not being read by dotenv in Node. Here it is:\nPORT=8080\nDB_PASSWORD = {pw()}\nJWT_SECRET={rs(32)}\nWhy does process.env.DB_PASSWORD come out undefined?",
 lambda: f"MongoDB Atlas refuses this connection string. What did I do wrong?\nmongodb+srv://neha:{pw()}@cluster0.ab12c.mongodb.net/app?retryWrites=true",
 lambda: f"Redis says NOAUTH. Is my config right?\nREDIS_URL=redis://default:{rs(20)}@redis-123.cloud.redislabs.com:6379\nclient = redis.from_url(os.environ['REDIS_URL'])",
 lambda: f"docker compose ignores my secret. Here is the file:\nservices:\n  api:\n    image: acme/api:2.1\n    environment:\n      SECRET_KEY: \"{rs(40)}\"\n      DEBUG: \"false\"\n    ports: [\"8000:8000\"]",
 lambda: f"settings.py raises ImproperlyConfigured. Why?\nSECRET_KEY = 'django-insecure-{rs(40, A + '!@#$%^&*-_=+')}'\nDEBUG = Flase\nALLOWED_HOSTS = ['*']",
 lambda: f"My SMTP login fails with 535. Config:\nMAIL_HOST=smtp.gmail.com\nMAIL_PORT=465\nMAIL_USER=alerts@acme.in\nMAIL_PASSWORD={pw()}\nMAIL_ENCRYPTION=tls",
 lambda: f"Is this nginx basic-auth line correct?\nproxy_set_header Authorization \"Basic {base64.b64encode(f'admin:{pw()}'.encode()).decode()}\";",
]
for typ, temps in (('a', a_t), ('b', b_t), ('c', c_t)):
    for rep in range(2):
        for i, t in enumerate(temps):
            out.append({'id': f'{typ}{rep}{i}', 'type': typ, 'prompt': t()})
with open(sys.argv[1], 'w') as f:
    for o in out: f.write(json.dumps(o) + '\n')
print(len(out), 'prompts')
