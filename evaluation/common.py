"""Shared helpers: Wilson intervals and CSV + LaTeX table writer."""
import os, math
TAB = '.'
def set_tab(d):
    global TAB; TAB = d; os.makedirs(d, exist_ok=True)
def wilson(k, n, z=1.96):
    if n == 0: return (float('nan'),) * 2
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d * 100, (c + h) / d * 100)
def write(name, header, rows, caption, label, colspec=None):
    import csv
    with open(os.path.join(TAB, name + '.csv'), 'w', newline='') as f:
        w = csv.writer(f); w.writerow(header); w.writerows(rows)
    esc = lambda s: str(s).replace('%', r'\%').replace('&', r'\&').replace('_', r'\_').replace('–', '--').replace('#', r'\#')
    colspec = colspec or ('l' + 'r' * (len(header) - 1))
    tex = [r'\begin{table}[!t]', r'\centering', r'\caption{' + caption + '}', r'\label{' + label + '}', r'\footnotesize',
           r'\setlength{\tabcolsep}{3pt}', r'\begin{tabular}{' + colspec + '}', r'\hline',
           ' & '.join(r'\textbf{' + esc(h) + '}' for h in header) + r' \\', r'\hline']
    for r in rows:
        if r and r[0] == '__hline__': tex.append(r'\hline'); continue
        tex.append(' & '.join(esc(c) for c in r) + r' \\')
    tex += [r'\hline', r'\end{tabular}', r'\end{table}']
    open(os.path.join(TAB, name + '.tex'), 'w').write('\n'.join(tex) + '\n')

