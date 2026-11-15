#!/usr/bin/env bash

set -euo pipefail

services=(suricata bind9 nginx)

# Check installation first; abort before starting anything.
for service in "${services[@]}"; do
    if ! dpkg-query -W -f='${db:Status-Status}' "$service" 2>/dev/null | grep -qx "installed"; then
        echo "[ERROR] $service is not installed. Aborting."
        exit 1
    fi
done

echo "[INFO] All required packages are installed."

# Check and start service.
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "[OK] $service is already running."
    else
        echo "[INFO] Starting $service..."
        systemctl start "$service"
    fi
done

echo "[SUCCESS] All services are running."