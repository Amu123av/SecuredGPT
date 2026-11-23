"""Extract the frozen engine (v58) and the 58.2 redactor from the extension's content.js.
python extract_engine.py <content.js> <out_dir>  -> engine_v58.js, sgpt582.js, freeze_582.json"""
import sys, hashlib, json, os
src = open(sys.argv[1], encoding='utf-8').read(); out = sys.argv[2]; os.makedirs(out, exist_ok=True)
a = src.index('// ==== SECURE-GPT ENGINE BEGIN ===='); b = src.index('// ==== SECURE-GPT ENGINE END ====')
eng = src[a:b]
engine_file = ('// Block between the ENGINE BEGIN/END markers of Secure-GPT extension v58.0 content.js, copied verbatim.\n'
               + eng + '\nmodule.exports = { scanText, ENGINE_DEFAULTS };\n')
c = src.index('// ==== SECURE-GPT REDACTOR BEGIN ===='); d = src.index('// ==== SECURE-GPT REDACTOR END ====') + len('// ==== SECURE-GPT REDACTOR END ====')
red = src[c:d]
open(os.path.join(out, 'engine_v58.js'), 'w', encoding='utf-8').write(engine_file)
open(os.path.join(out, 'sgpt582.js'), 'w', encoding='utf-8').write(
    eng + '\n' + red + '\nmodule.exports = { scanText, ENGINE_DEFAULTS, redactText, collectSpans, absorbTails };\n')
h = lambda s: hashlib.sha256(s.encode('utf-8')).hexdigest()
freeze = {'engine_v58_sha256': h(engine_file), 'redactor_582_sha256': h(red), 'content_js_sha256': h(src)}
json.dump(freeze, open(os.path.join(out, 'freeze_582.json'), 'w'), indent=1); print(json.dumps(freeze, indent=1))
assert freeze['engine_v58_sha256'] == '229419ce8c5e8f775521bad68cc078ad40c3d38abac6ada1ee0dec7c96d57f7d', 'engine differs from paper 1!'
