"""Generate test PDFs: n-page text documents (clean) and the same with one Aadhaar line on the last page.
python make_pdfs.py <out_dir>"""
import sys, os, random
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
out = sys.argv[1]; os.makedirs(out, exist_ok=True); rng = random.Random(5)
WORDS = ('project schedule budget review team meeting report quarter customer delivery design module test release '
         'training feedback planning resource risk milestone summary update policy process quality').split()
def mk(path, pages, secret=None):
    c = canvas.Canvas(path, pagesize=A4)
    for p in range(pages):
        y = 800
        for line in range(42):
            c.drawString(50, y, ' '.join(rng.choice(WORDS) for _ in range(12))); y -= 18
        if secret and p == pages - 1: c.drawString(50, 40, secret)
        c.showPage()
    c.save()
for n in (1, 10, 50, 100):
    mk(os.path.join(out, f'clean_{n}p.pdf'), n)
    mk(os.path.join(out, f'secret_{n}p.pdf'), n, 'Applicant Aadhaar: 8687 4995 7789')
print('ok')
