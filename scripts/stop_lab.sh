#!/usr/bin/env bash

set -euo pipefail

services=(suricata bind9 nginx)

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "[INFO] Stopping $service..."
        systemctl stop "$service"
    else
        echo "[OK] $service stopped."
    fi
done

echo "[SUCCESS] All services are stopped."