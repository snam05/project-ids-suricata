#!/usr/bin/env bash
# TV3 — KHUNG. Không tự sinh traffic hoặc sudo khi chưa triển khai.
# Input dự kiến: test_id, target IP private, tham số từ input_spec trong CSV.
# Output dự kiến: exit code, stdout/stderr, thời gian và lệnh cho manifest.
# TODO: TV1/TV3 thống nhất CLI/JSON; validate đích lab; curl/dig/Nmap;
# T12 đúng 3 request; T13 20 cổng trong 10s; T14 1 SYN không retry;
# kiểm tra PCAP tại Server, không suy ra traffic_valid chỉ từ mã thoát.
set -euo pipefail
case "${1:---help}" in
  --help|-h)
    printf '%s\n' 'traffic_gen.sh — bộ khung của TV3, chưa triển khai sinh traffic.' 'Danh mục: python3 -m src.run_tests --list (từ repo root).' 'Hợp đồng: tests/tests.csv và docs/data-contract.md.'
    ;;
  *) printf '%s\n' 'TODO TV3: chưa chạy traffic; không có dữ liệu thực nghiệm được tạo.' >&2; exit 2 ;;
esac
