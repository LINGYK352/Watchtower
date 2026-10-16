#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
payload=/mnt/watchtower-payload
root=/opt/sentinel/sentinel
mkdir -p /opt/watchtower-preview "$root"
exec >>/opt/watchtower-preview/bootstrap.log 2>&1
trap 'echo "bootstrap failed at line $LINENO" > /opt/watchtower-preview/error' ERR
echo "$(date -Is) verifying preview payload"
cd "$payload"
sha256sum -c payload.sha256
if ! command -v docker >/dev/null; then
  echo "Prepared runtime is missing Docker; refusing network-dependent first install"
  exit 1
fi
systemctl enable --now docker
install -D -m 755 "$payload/docker-compose" /usr/libexec/docker/cli-plugins/docker-compose
images_ready=true
for image in sentinel:base mongo:5.0 rabbitmq:3.9 nginx:1.23-alpine; do
  docker image inspect "$image" >/dev/null 2>&1 || images_ready=false
done
if [ "$images_ready" = false ]; then
  echo "$(date -Is) loading offline application images"
  gzip -dc "$payload/images.tar.gz" | docker load
fi
if ! docker image inspect sentinel:runtime-v1 >/dev/null 2>&1; then
  mkdir -p /opt/watchtower-preview/image
  cp "$payload/Dockerfile.runtime" /opt/watchtower-preview/image/Dockerfile
  docker build -q -t sentinel:runtime-v1 /opt/watchtower-preview/image
fi
if [ ! -f /opt/watchtower-preview/source-ready ]; then
  tar -xzf "$payload/source.tar.gz" -C "$root"
  tar -xzf "$payload/core.tar.gz" -C "$root"
  touch /opt/watchtower-preview/source-ready
fi
cp "$payload/make_config.py" /opt/watchtower-preview/make_config.py
docker run --rm -v "$root":/preview -v /opt/watchtower-preview:/bootstrap --entrypoint python sentinel:base /bootstrap/make_config.py
cd "$root/docker"
docker compose -p docker -f docker-compose.yml up -d --no-build --pull never
echo "$(date -Is) application services started"
touch /opt/watchtower-preview/ready
rm -f /opt/watchtower-preview/error
