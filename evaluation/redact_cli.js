// node redact_cli.js <sgpt582.js> <in.jsonl> <out.jsonl> [field=prompt]
const fs = require('fs'), path = require('path');
const E = require(path.resolve(process.argv[2])); const field = process.argv[5] || 'prompt';
const R = fs.readFileSync(process.argv[3], 'utf8').split('\n').filter(Boolean).map(JSON.parse);
const out = R.map(r => { const v = E.scanText(r[field]); const x = v ? E.redactText(r[field]) : { text: r[field], clean: true, count: 0 };
  return { ...r, label: v, redacted: x.text, redact_clean: x.clean, n_spans: x.count }; });
fs.writeFileSync(process.argv[4], out.map(o => JSON.stringify(o)).join('\n') + '\n'); console.log(out.length, 'rows');
