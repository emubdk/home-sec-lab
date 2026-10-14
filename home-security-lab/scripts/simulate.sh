#!/usr/bin/env bash
# Run the whole attack story: scan, SSH guessing, web attacks,
# then "post-exploitation" steps on the victim (new user, root shell via sudo).
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose --profile attack run --rm attacker

echo "[5] Persistence: create a local user on the victim"
docker compose exec -T victim useradd -m "backdoor$RANDOM"

echo "[6] Privilege escalation: root shell via sudo"
docker compose exec -T victim su labuser -c "echo labpassword | sudo -S -p '' /bin/bash -c id" >/dev/null

echo "Done. Alerts appear in the lab-alerts index within ~30 s."
