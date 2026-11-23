// PDF extraction + scan time with pdfjs-dist 3.11.174 (the version release 58.2 ships), Node.
// node pdf_timing.js <sgpt582.js> <pdf_dir> <pdfjs_legacy_build_dir> <out.json> [runs]
const fs = require('fs'), path = require('path');
const E = require(path.resolve(process.argv[2]));
const pdfjs = require(path.join(path.resolve(process.argv[4]), 'pdf.js'));
const RUNS = +(process.argv[6] || 10);
(async () => {
  const res = [];
  for (const f of fs.readdirSync(process.argv[3]).filter(f => f.endsWith('.pdf')).sort()) {
    const data = fs.readFileSync(path.join(process.argv[3], f));
    const ex = [], sc = []; let verdict = null, pages = 0;
    for (let r = 0; r < RUNS + 2; r++) {
      const t0 = performance.now();
      const pdf = await pdfjs.getDocument({ data: new Uint8Array(data), disableWorker: true, isEvalSupported: false }).promise;
      let text = ''; pages = pdf.numPages;
      for (let i = 1; i <= pdf.numPages; i++) { const pg = await pdf.getPage(i); const tc = await pg.getTextContent(); text += tc.items.map(x => x.str).join(' ') + ' '; }
      const t1 = performance.now(); verdict = E.scanText(text); const t2 = performance.now();
      if (r >= 2) { ex.push(t1 - t0); sc.push(t2 - t1); }
      await pdf.destroy();
    }
    const med = a => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
    res.push({ file: f, pages, kb: Math.round(data.length / 1024), extract_med_ms: med(ex), scan_med_ms: med(sc), verdict });
    console.log(f, pages, 'p', med(ex).toFixed(1), 'ms extract,', med(sc).toFixed(2), 'ms scan ->', verdict);
  }
  fs.writeFileSync(process.argv[5], JSON.stringify(res, null, 1));
})();
