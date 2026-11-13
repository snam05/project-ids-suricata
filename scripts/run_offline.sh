#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/lib/suricata.sh"

usage='Cách dùng: scripts/run_offline.sh PCAP [PCAP ...]'
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  printf '%s\n' "$usage"
  exit 0
fi
(( $# > 0 )) || die "$usage"
(( EUID != 0 )) || die 'Chạy offline bằng tài khoản thường.'

pcaps=()
for pcap in "$@"; do
  pcaps+=("$(realpath -m -- "$pcap")")
done

run_dir=$(prepare_run offline "${pcaps[@]}")
set_suricata_args "$run_dir"
cd -- "$run_dir"
printf 'Lượt offline: %s\n' "$run_dir"

index=0
for pcap in "${pcaps[@]}"; do
  index=$((index + 1))
  printf -v case_number '%03d' "$index"
  case_dir="$run_dir/$case_number"
  printf '[%s] %s\n' "$case_number" "$pcap"
  suricata "${suricata_args[@]}" -r "$case_dir/input.pcap" -l "$case_dir"
  [[ -f $case_dir/eve.json ]] || die "Suricata chưa ghi EVE cho $pcap"
  printf 'EVE: %s/eve.json\n' "$case_dir"
done
