"""LLM utility test (reviewer M5). Runs on a Colab GPU (T4 is enough); everything stays inside the runtime.
python utility_llm.py <redacted.jsonl> <out_dir> [--gen Qwen/Qwen2.5-3B-Instruct] [--judge microsoft/Phi-3.5-mini-instruct]"""
import sys, os, json, re, random, argparse, csv, gc
ap = argparse.ArgumentParser(); ap.add_argument('inp'); ap.add_argument('out')
ap.add_argument('--gen', default='Qwen/Qwen2.5-3B-Instruct'); ap.add_argument('--judge', default='microsoft/Phi-3.5-mini-instruct')
ap.add_argument('--max-new', type=int, default=320); ap.add_argument('--batch', type=int, default=8); ap.add_argument('--n', type=int, default=0)
a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
R = [json.loads(l) for l in open(a.inp) if l.strip()]
if a.n: R = R[:a.n]

def load(name):
    tok = AutoTokenizer.from_pretrained(name); tok.padding_side = 'left'
    if tok.pad_token is None: tok.pad_token = tok.eos_token
    m = AutoModelForCausalLM.from_pretrained(name, torch_dtype=torch.float16, device_map='auto'); m.eval()
    return tok, m

def chat(tok, m, prompts, max_new, system=None):
    outs = []
    for i in range(0, len(prompts), a.batch):
        batch = prompts[i:i + a.batch]
        msgs = [([{'role': 'system', 'content': system}] if system else []) + [{'role': 'user', 'content': p}] for p in batch]
        texts = [tok.apply_chat_template(x, tokenize=False, add_generation_prompt=True) for x in msgs]
        enc = tok(texts, return_tensors='pt', padding=True).to(m.device)
        with torch.no_grad():
            g = m.generate(**enc, max_new_tokens=max_new, do_sample=False, pad_token_id=tok.pad_token_id)
        outs += [tok.decode(x[enc['input_ids'].shape[1]:], skip_special_tokens=True).strip() for x in g]
        print(f'  {min(i + a.batch, len(prompts))}/{len(prompts)}', flush=True)
    return outs

print('generating with', a.gen)
tok, m = load(a.gen)
A_ = chat(tok, m, [r['prompt'] for r in R], a.max_new, 'You are a helpful assistant.')
B_ = chat(tok, m, [r['redacted'] for r in R], a.max_new, 'You are a helpful assistant.')
del m; gc.collect(); torch.cuda.empty_cache()

JUDGE = ("You compare two answers to the same user request. The user's request is shown first. Answer A was written for the full request; "
         "answer B was written for a copy of the request in which some values were replaced by placeholders such as [REDACTED:APIKEY].\n\n"
         "USER REQUEST:\n{req}\n\nANSWER A:\n{a}\n\nANSWER B:\n{b}\n\n"
         "How well does answer B accomplish what the user asked, compared with answer A? 5 = just as useful, 4 = nearly as useful, "
         "3 = partly useful, 2 = mostly not useful, 1 = useless for the user's request. Reply with a single digit only.")
print('judging with', a.judge)
tok, m = load(a.judge)
J = chat(tok, m, [JUDGE.format(req=r['prompt'], a=x, b=y) for r, x, y in zip(R, A_, B_)], 4)
del m; gc.collect(); torch.cuda.empty_cache()
with open(os.path.join(a.out, 'utility_results.jsonl'), 'w') as f:
    for r, x, y, j in zip(R, A_, B_, J):
        d = re.search(r'[1-5]', j)
        f.write(json.dumps({**r, 'answer_original': x, 'answer_redacted': y, 'judge_raw': j, 'judge_score': int(d.group()) if d else None,
                            'gen_model': a.gen, 'judge_model': a.judge}) + '\n')
rng = random.Random(11); idx = list(range(len(R))); rng.shuffle(idx)
with open(os.path.join(a.out, 'utility_manual_check.csv'), 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['id', 'type', 'original_prompt', 'redacted_prompt', 'answer_original', 'answer_redacted', 'judge_score', 'manual_ok'])
    for i in sorted(idx[:24]):
        r = R[i]; d = re.search(r'[1-5]', J[i])
        w.writerow([r['id'], r['type'], r['prompt'], r['redacted'], A_[i], B_[i], d.group() if d else '', ''])
print('done')
