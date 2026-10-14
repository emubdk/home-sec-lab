# Windows PowerShell version of simulate.sh
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

docker compose --profile attack run --rm attacker

Write-Host "[5] Persistence: create a local user on the victim"
docker compose exec -T victim useradd -m ("backdoor" + (Get-Random -Maximum 99999))

Write-Host "[6] Privilege escalation: root shell via sudo"
docker compose exec -T victim su labuser -c "echo labpassword | sudo -S -p '' /bin/bash -c id" | Out-Null

Write-Host "Done. Alerts appear in the lab-alerts index within ~30 s."
