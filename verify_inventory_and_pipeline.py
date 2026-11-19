import sys
from pathlib import Path

base = Path(__file__).resolve().parent
sys.path.insert(0, str(base / 'src'))

from config import Config
from inventory_manager import ApplicationInventory

cfg = Config()
inv_cfg = Path(cfg.get('paths', 'inventory_excel'))
resolved = inv_cfg if inv_cfg.is_absolute() else base / inv_cfg
print('CONFIG_INVENTORY', str(inv_cfg))
print('RESOLVED', str(resolved))
print('EXISTS', resolved.exists())

inventory = ApplicationInventory(str(resolved))
print('APP_COUNT', len(inventory.applications))
print('TERM_COUNT', len(inventory.term_to_app_map))
