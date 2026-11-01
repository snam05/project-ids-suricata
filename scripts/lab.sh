#!/usr/bin/env bash
# TV2 — công cụ kiểm tra bộ khung; dựng/vận hành lab còn TODO.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:---help}" in
  --help|-h)
    printf '%s\n' 'Dùng: bash scripts/lab.sh check' 'check: chỉ kiểm tra bộ khung, không sửa hệ thống.' 'TODO TV2: cài đặt, cấu hình, capture, start/stop và SSH Client.'
    ;;
  check)
    cd "$repo_root"
    python3 scripts/check_scaffold.py
    ;;
  *) printf '%s\n' 'TODO TV2: thao tác lab này chưa triển khai.' >&2; exit 2 ;;
esac
