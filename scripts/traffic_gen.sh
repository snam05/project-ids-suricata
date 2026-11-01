#!/usr/bin/env bash
# KHUNG. Không tự sinh traffic hoặc sudo khi chưa triển khai.
# Input dự kiến: test_id, target IP private, tham số từ input_spec trong CSV.
# Output dự kiến: exit code, stdout/stderr, thời gian và lệnh cho manifest.
# TODO: thống nhất CLI/JSON; validate đích lab; curl/dig/Nmap;
# T12 đúng 3 request; T13 20 cổng trong 10s; T14 1 SYN không retry;
# kiểm tra PCAP tại Server, không suy ra traffic_valid chỉ từ mã thoát.
set -euo pipefail
case "${1:---help}" in
  --help|-h)
    printf '%s\n' 'traffic_gen.sh — bộ khung, chưa triển khai sinh traffic.' 'Danh mục: python3 -m src.run_tests --list (từ repo root).' 'Hợp đồng: tests/tests.csv và README.md.'
    ;;
  *) printf '%s\n' 'TODO: chưa chạy traffic; không có dữ liệu thực nghiệm được tạo.' >&2; exit 2 ;;
esac
