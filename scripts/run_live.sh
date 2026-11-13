#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib/suricata.sh"

unit=suricata-ids-lab.service
usage='Cách dùng: scripts/run_live.sh start INTERFACE | stop | status'

require_systemd() {
  systemctl show --property=Version --value >/dev/null || die 'Không kết nối được systemd trên Server.'
}

live_directory() {
  systemctl show --property=WorkingDirectory --value "$unit"
}

lock_live() {
  (( EUID != 0 )) || die 'Chạy script bằng tài khoản thường. Script tự gọi sudo để điều khiển service.'
  mkdir -p -- "$results_dir"
  exec 8>"$results_dir/.suricata-live.lock"
  flock -n 8 || die 'Đang có lệnh start hoặc stop khác chạy.'
}

case ${1:-} in
  start)
    (( $# == 2 )) || die "$usage"
    require_systemd
    iface=$2
    ip link show dev "$iface" >/dev/null || die "Không tìm thấy interface: $iface"
    lock_live
    if systemctl is-active --quiet "$unit"; then
      die 'Đang có phiên live. Dùng lệnh status hoặc stop trước khi mở phiên mới.'
    fi
    if systemctl is-active --quiet suricata.service; then
      die 'Service Suricata mặc định đang chạy. Trên Server lab, chạy sudo systemctl disable --now suricata.'
    fi
    case_dir=$(prepare_run live)
    set_suricata_args "$case_dir"
    if systemctl is-failed --quiet "$unit"; then
      sudo systemctl reset-failed "$unit"
    fi

    if ! sudo systemd-run --unit="$unit" --expand-environment=no \
      --uid="$(id -u)" --gid="$(id -g)" --working-directory="$case_dir" \
      --property=Type=exec --property=KillSignal=SIGINT --property=TimeoutStopSec=60s \
      --property=StandardOutput=journal --property=StandardError=journal \
      --property='AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN' \
      --property='CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN' \
      --property=NoNewPrivileges=yes -- \
      "$(command -v suricata)" "${suricata_args[@]}" --pcap="$iface" -l "$case_dir"; then
      die "Không khởi động được $unit. Kiểm tra journal của service."
    fi

    invocation=$(systemctl show --property=InvocationID --value "$unit")
    for (( attempt = 0; attempt < 20; attempt++ )); do
      systemctl is-active --quiet "$unit" || break
      if sudo journalctl --boot --quiet --no-pager --output=cat \
        "_SYSTEMD_INVOCATION_ID=$invocation" | grep -Fi 'engine started' >/dev/null; then
        systemctl is-active --quiet "$unit" || break
        printf 'Live đang chạy trên %s\nEVE: %s/eve.json\n' "$iface" "$case_dir"
        exit 0
      fi
      sleep 0.5
    done

    if systemctl is-active --quiet "$unit"; then
      sudo systemctl stop "$unit"
    fi
    die "Suricata chưa sẵn sàng. Xem sudo journalctl -u $unit -b."
    ;;
  stop)
    (( $# == 1 )) || die "$usage"
    require_systemd
    lock_live
    if systemctl is-failed --quiet "$unit"; then
      sudo systemctl reset-failed "$unit"
      die "Phiên live trước đã thoát lỗi. Xem sudo journalctl -u $unit -b."
    fi
    if ! systemctl is-active --quiet "$unit"; then
      printf 'Không có phiên live đang chạy.\n'
      exit 0
    fi
    case_dir=$(live_directory)
    if ! sudo systemctl stop "$unit" || systemctl is-failed --quiet "$unit"; then
      if systemctl is-failed --quiet "$unit"; then
        sudo systemctl reset-failed "$unit"
      fi
      die "Phiên live không dừng sạch. EVE có thể chưa đầy đủ tại $case_dir/eve.json."
    fi
    [[ -f $case_dir/eve.json ]] || die "Phiên đã dừng nhưng không tìm thấy $case_dir/eve.json"
    printf 'Live đã dừng. EVE: %s/eve.json\n' "$case_dir"
    ;;
  status)
    (( $# == 1 )) || die "$usage"
    require_systemd
    if systemctl is-active --quiet "$unit"; then
      printf 'Live đang chạy. EVE: %s/eve.json\n' "$(live_directory)"
    elif systemctl is-failed --quiet "$unit"; then
      die "Phiên live đã thoát lỗi. Xem sudo journalctl -u $unit -b."
    else
      printf 'Không có phiên live đang chạy.\n'
    fi
    ;;
  --help|-h)
    printf '%s\n' "$usage"
    ;;
  *)
    die "$usage"
    ;;
esac
