import openpyxl, os
from pathlib import Path

root = Path(r'C:\Users\PwC\Desktop\Advisory API\Codebase')
path = root / 'reports' / 'daily' / 'Daily_Advisories_2026-11-03.xlsx'
print('PATH', path)
print('EXISTS', path.exists())
out = root / 'summary_dump.txt'
if not path.exists():
    out.write_text('WORKBOOK MISSING\n', encoding='utf-8')
else:
    wb = openpyxl.load_workbook(path, data_only=True)
    lines = [f'SHEETS: {wb.sheetnames}']
    for ws in wb.worksheets:
        lines.append(f'--- SHEET {ws.title} rows={ws.max_row} cols={ws.max_column} ---')
        for r in range(1, min(ws.max_row, 20) + 1):
            vals = []
            for c in range(1, min(ws.max_column, 12) + 1):
                v = ws.cell(r, c).value
                vals.append('' if v is None else str(v))
            lines.append(' | '.join(vals))
    out.write_text('\n'.join(lines), encoding='utf-8')
    print(f'WROTE {out}')
