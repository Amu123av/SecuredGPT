# Browser kit — Secure-GPT release 58.2 (Paper 2)

Sab secrets nakli hain, har platform ke alag. Kisi asli account ki key nahi hai.

## Setup (10 min)
1. chrome://extensions → Developer mode ON → purana Secure-GPT **Remove** → Load unpacked → `secure-gpt-v58.2` folder.
2. Extension icon (puzzle 🧩 → pin) → popup mein **Response mode** chuno → **Save**. Har trial se pehle mode check karo.
3. Popup → **Clear log** (ek baar shuru mein).

## Trials (har platform pe 9; ChatGPT, Gemini, Claude, www.perplexity.ai)
`trial_log_582.csv` Excel mein kholo. Har row ke liye `action` karo, phir bharo:
- **screen**: RED / YELLOW / BLUE / GREEN / NONE  (BLUE = "REDACTED" notice, YELLOW = warn dialog ya banner)
- **chat_shows**: chat mein jo message/file gaya —  SECRET (asli key/number dikha) / PLACEHOLDER ([REDACTED:...] dikha) / NOTHING (kuch nahi gaya) / CLEAN (normal file/message gaya)
- **network_secret_found** (optional, sirf ChatGPT pe R1, R3, W2): DevTools (F12) → Network → Ctrl+F → secret ke pehle 12 characters search → Y/N
Lines `paste_and_type.txt` mein hain. Platform code: ch, ge, cl, pe.

## Old vs new PDF (2 trials, sirf ChatGPT)
v58.2 ko remove karke purana **v58.0** load karo → OLD-C aur OLD-S karo → wapas v58.2 load karo.

## Latency (har platform, 2 min)
Mode = **Redact**. `big_text_100kb_secret.txt` → Ctrl+A, Ctrl+C → chat box mein Ctrl+V. BLUE notice aana chahiye. **Send mat karna.**
Box khaali karo.

## Khatam hone pe
Popup → **Export CSV** (event log). Ye CSV aur bhara hua `trial_log_582.csv` Google Drive ke
`MyDrive/secure_gpt_paper2/uploads/browser/` mein daalo, notebook **Run all**.
