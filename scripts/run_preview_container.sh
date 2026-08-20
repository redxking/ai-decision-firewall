#!/bin/sh
set -eu

image="adf-stage-a-preview:local"
docker build --tag "$image" .
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700 \
  --tmpfs /preview:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700 \
  --entrypoint python \
  "$image" /opt/adf/run_preview.py demo --root /preview
