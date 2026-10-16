#!/usr/bin/env bash
# Host-side repair for an already committed signed Web guardian (172+).
# No image download, database reset, activation replacement or code overwrite.
set -euo pipefail
root=${1:-/opt/sentinel/sentinel}
if [[ ! -d "$root/docker" || ! -f "$root/version.txt" ]]; then
  echo "Invalid Watchtower installation root: $root" >&2; exit 2
fi
root=$(cd "$root" && pwd -P)
if ! docker version >/dev/null 2>&1; then
  echo 'Run this script on the host with access to its Docker daemon.' >&2; exit 3
fi
if docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
  compose=(docker-compose)
else
  echo 'A working host Compose implementation is required.' >&2; exit 4
fi
if [[ ! -f "$root/.update_stage/guardian/installation.json" || ! -f "$root/docker/docker-compose.override.yml" ]]; then
  echo 'The signed guardian migration has not been prepared. This repair does not guess or replace program files.' >&2; exit 5
fi
cd "$root/docker"
worker=$("${compose[@]}" ps -q worker)
if [[ -z "$worker" || "$worker" == *$'\n'* ]]; then
  echo 'Exactly one running worker for this installation is required for a safe preflight.' >&2; exit 6
fi
mount=$(docker inspect "$worker" --format '{{range .Mounts}}{{if eq .Destination "/opt/sentinel/current"}}{{.Source}}{{end}}{{end}}')
if [[ ! -d "$mount" || $(cd "$mount" && pwd -P) != "$root" ]]; then
  echo 'The worker code mount does not match the requested installation root.' >&2; exit 7
fi
# Existing worker Python validates the signed local carrier and checks queues.
# No supplied key/password is put on the command line or printed.
docker exec -i "$worker" python - <<'PY'
from pathlib import Path
import json,base64,hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from celery import Celery
from sentinel_platform.core import get_config
root=Path('/opt/sentinel/current');home=root/'.update_stage/guardian'
state=json.loads((home/'installation.json').read_text());generation=state['generation']
if len(generation)!=16 or any(c not in '0123456789abcdef' for c in generation):raise SystemExit('Invalid guardian pointer')
folder=home/'generations'/generation;envelope=json.loads((folder/'manifest.json').read_text());data=envelope['descriptor']
canonical=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
Ed25519PublicKey.from_public_bytes(base64.b64decode('REbZ+VtgBKKmbIwUb6vnIaYWOe8LecIKpUxUKV/qW00=')).verify(base64.b64decode(envelope['signature']),canonical)
for name,digest in data['files'].items():
 p=folder/name;p.resolve().relative_to(folder.resolve())
 if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise SystemExit('Guardian source validation failed')
inspect=Celery('watchtower_repair_preflight',broker=get_config().section('CELERY','BROKER_URL')).control.inspect(timeout=4)
active=inspect.active();reserved=inspect.reserved()
if active is None or reserved is None:raise SystemExit('Could not confirm running jobs; do not interrupt live work')
if any(active.values()) or any(reserved.values()):raise SystemExit('Live jobs must finish before repair')
print('Signed controller verified; no active or reserved jobs')
PY
if [[ ${2:-} == --check-only ]]; then
  echo 'Repair prerequisites passed; no runtime was changed.';exit 0
fi
backup="$root/.update_stage/rescue-backups/host-repair-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup";chmod 700 "$backup"
cp -p "$root/docker/docker-compose.override.yml" "$backup/compose.override.yml"
cp -p "$root/.update_stage/guardian/installation.json" "$backup/installation.json"
if [[ -f "$root/.update_stage/.chain_state.json" ]]; then cp -p "$root/.update_stage/.chain_state.json" "$backup/chain-state.json";fi
"${compose[@]}" up -d --no-deps --force-recreate web worker scheduler
echo "Runtime recreated with the host Compose implementation. Configuration, activation, database and update cursor were retained."
echo "Backup: $backup"
echo 'Open the update page after the runtime is ready; the saved chain resumes automatically.'
