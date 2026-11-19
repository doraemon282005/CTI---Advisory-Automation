import os, zipfile, xml.etree.ElementTree as ET
from pathlib import Path

xlsx_path = Path(r'C:\Users\PwC\Desktop\Advisory API\Codebase\Revised Corrections.xlsx')
out_path = Path(r'C:\Users\PwC\Desktop\Advisory API\Codebase\revised_corrections_dump.txt')

if not xlsx_path.exists():
    out_path.write_text('MISSING FILE\n')
    raise SystemExit(0)

with zipfile.ZipFile(xlsx_path) as zf:
    names = zf.namelist()
    with out_path.open('w', encoding='utf-8') as f:
        f.write('FILES\n')
        for n in names:
            f.write(n + '\n')
        f.write('\nSHEETS\n')
        # read workbook relationships and sheet xml
        wb = ET.fromstring(zf.read('xl/workbook.xml'))
        ns = {'a': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
              'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
        rels = ET.fromstring(zf.read('xl/_rels/workbook.xml.rels'))
        rel_map = {r.attrib['Id']: r.attrib['Target'] for r in rels if r.tag.endswith('Relationship')}
        for sheet in wb.findall('a:sheets/a:sheet', ns):
            name = sheet.attrib['name']
            rel_id = sheet.attrib.get('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id')
            target = rel_map.get(rel_id)
            f.write(f'{name} -> {target}\n')
            s_path = 'xl/' + target if not target.startswith('xl/') else target
            if s_path.startswith('/'):
                s_path = s_path[1:]
            try:
                sheet_xml = ET.fromstring(zf.read(s_path))
            except Exception as e:
                f.write(f'ERROR reading {s_path}: {e}\n')
                continue
            rows = sheet_xml.findall('.//a:sheetData/a:row', ns)
            f.write(f'rows={len(rows)}\n')
            for row in rows[:50]:
                cells = []
                for c in row.findall('a:c', ns):
                    val = c.attrib.get('t')
                    v = c.find('a:v', ns)
                    if v is None:
                        texts = ''
                    else:
                        texts = v.text or ''
                    cells.append(f'{c.attrib.get("r")}={texts}')
                f.write(' | '.join(cells) + '\n')
            f.write('---\n')
print('done')
