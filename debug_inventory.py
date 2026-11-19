from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from config import Config
from inventory_manager import ApplicationInventory

cfg = Config()
inv_path = Path(cfg.get('paths','inventory_excel'))
print('INV_PATH', inv_path)
print('EXISTS', inv_path.exists())
inv = ApplicationInventory(str(inv_path))
print('APP_COUNT', len(inv.applications))
print('TERM_COUNT', len(inv.term_to_app_map))
for app in inv.applications[:10]:
    print('APP', app)

samples = [
    ('Cisco IOS XR Software BGP Memory Exhaustion Denial of Service Vulnerability (CVE-2026-38291)', 'A vulnerability in the Border Gateway Protocol (BGP) implementation of Cisco IOS XR Software could allow ... CVSS Base Score: 8.6 (High).'),
    ('Oracle Database Server Remote Network Code Execution via TNS Listener (CVE-2026-2810)', 'Vulnerability in Oracle Database Core RDBMS / TNS Listener ...'),
]
for title, body in samples:
    matches = inv.match(title, body)
    print('MATCH', title, '->', matches[:3])
