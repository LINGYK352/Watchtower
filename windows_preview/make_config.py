"""Generate fresh preview configuration; never import an existing deployment's secrets."""
from pathlib import Path
import secrets
from urllib.parse import quote
import yaml

root = Path('/preview')
config = root/'docker/config/config.yaml'
if not config.exists():
    sample = yaml.safe_load((root/'config/config.yaml.example').read_text())
    sample['MONGO'] = {'URI': 'mongodb://mongo:27017/', 'DB': 'watchtower_preview'}
    broker_password = secrets.token_hex(24)
    sample['CELERY'] = {'BROKER_URL': 'amqp://sentinel:'+quote(broker_password, safe='')+'@rabbitmq:5672/'+quote('/sentinelhost', safe='')}
    import json
    account_path=Path('/bootstrap/admin-init.json')
    if not account_path.is_file():raise RuntimeError('请在安装器设置首次管理员账号')
    account=json.loads(account_path.read_text())
    sample['SENTINEL'].update(API_KEY=secrets.token_hex(32), SALT=secrets.token_hex(32),
                              DEFAULT_ADMIN_USER=account['username'], DEFAULT_ADMIN_PASS=account['password'])
    sample['SYSTEM'] = {'VERSION': (root/'version.txt').read_text().strip()}
    sample['UPDATE'].update(CHECK_REMOTE=False, KEY='', SOURCE_URL='https://watchtowers.info/')
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(yaml.safe_dump(sample, allow_unicode=True, sort_keys=False))
    config.chmod(0o600)
    env = root/'docker/.env'
    env.write_text('WT_BROKER_PASSWORD='+broker_password+'\n')
    env.chmod(0o600)
    print('fresh preview configuration created; authentication and activation policy preserved')
else:
    print('existing preview configuration retained')
