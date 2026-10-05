"""Use the same snapshot contract for every client; no Windows business fork."""
from pathlib import Path
import json

def distribution_metadata(snapshot_root):
    path=Path(snapshot_root)/'runtime-contract.json'
    if not path.is_file():return {}  # Historical snapshots remain historical.
    data=json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema')!=1 or not isinstance(data.get('deployment_contract'),int) or not isinstance(data.get('runtime_abi'),str):raise ValueError('Invalid snapshot runtime contract')
    return {'deployment_contract':data['deployment_contract'],'runtime_abi':data['runtime_abi']}
