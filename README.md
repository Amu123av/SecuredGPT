# Secure-GPT

Secure-GPT is a Chrome extension (Manifest V3) that scans a prompt on the user's own machine, before it is sent,
and flags credentials and personal identifiers in browser-based LLM chat interfaces. It runs on ChatGPT, Gemini,
Claude and Perplexity. Nothing leaves the browser.

This repository holds the code and evaluation material behind two papers:

1. **Detection** - Secure-GPT: Detecting Sensitive Data Leakage in Browser-Based LLM Chat Interfaces (detection engine v58).
2. **Response** - Real-Time Prompt Redaction for Secure LLM Chat (release 58.2: monitor, warn, block and redact on the unchanged detector).

## Contents

| Path | What it is |
|---|---|
| `extension/` | The extension, release 58.2. Load it unpacked in Chrome. |
| `extension/content.js` | Detection engine v58 (between the `ENGINE BEGIN` and `ENGINE END` markers) and the response modes (`REDACTOR BEGIN` / `REDACTOR END`). |
| `evaluation/` | Scripts used to run and analyse the experiments (`exp_core.js`, `docs_exp.js`, `analyze_core.py`, `analyze_extra.py`, `gen_utility.py`, ...). |
| `evaluation/data/corpus_v2_synthetic_part.jsonl` | The invented secrets of the 3,335-case corpus (875 sensitive cases: id, category, secret) and the 460 hard negatives. |
| `evaluation/data/utility_prompts.jsonl` | The 48 prompts of the LLM-utility test. |
| `evaluation/browser_kit/` | Files and trial sheet for the live trials on the four services. |

## Install

1. Open `chrome://extensions` and switch on Developer mode.
2. Choose Load unpacked and select the `extension` folder.
3. Click the extension icon, choose the response mode (monitor, warn, block or redact) and press Save.

## The corpus

The full corpus has 3,335 cases (SHA-256 starting `ff3addf1`). Its 875 sensitive cases are invented, format-valid secrets
placed inside real prompts from WildChat. The real WildChat text is not redistributed here; the WildChat logs are
available from their authors (Zhao et al., ICLR 2024). This repository contains the invented secrets, the category
labels and the hard negatives. The full corpus file can be shared on request.

All secrets in this repository are made up. None belongs to a real account.

## Licence

MIT. Third-party libraries in `extension/` (pdf.js, mammoth.js) keep their own licences.
