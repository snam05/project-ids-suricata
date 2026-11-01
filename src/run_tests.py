"""TV1 — điều phối. Đã có: đọc/kiểm tra/liệt kê danh mục.

Đầu vào dự kiến: tests.csv, mode, số lượt, cấu hình lab, PCAP theo test_id.
Đầu ra dự kiến: results/<mode>_<run_id>/<test_id>/ và bảng tổng hợp.
TODO: run_id duy nhất; lock lab live; SSH tới Client (TV2 chuẩn bị);
khởi động/capture/đợi engine; manifest; xác minh bằng chứng; gọi TV4/TV1.
Hiện không tạo traffic, không khởi động Suricata, không ghi kết quả giả.
"""
import argparse
import csv
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

from .contracts import GROUP_SIDS, TEST_FIELDS, parse_sids, format_sids

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class TestCase:
    test_id: str
    description: str
    protocol: str
    target_ip: str
    target_port: int
    input_spec: dict
    expected_sids: frozenset[int]


def load_catalog(path: Path) -> list[TestCase]:
    cases = []
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(TEST_FIELDS):
            raise ValueError("Header tests.csv phải đúng hợp đồng TEST_FIELDS")
        for row in reader:
            if None in row or any(v is None for v in row.values()):
                raise ValueError("Dòng CSV thừa/thiếu cột")
            expected = parse_sids(row["expected_sids"])
            if not expected <= GROUP_SIDS:
                raise ValueError("Expected SID ngoài 4 SID của nhóm")
            ipaddress.IPv4Address(row["target_ip"])
            port = int(row["target_port"])
            if not 1 <= port <= 65535:
                raise ValueError("Cổng không hợp lệ")
            if row["protocol"] not in {"HTTP", "DNS", "TCP_SYN"}:
                raise ValueError("Protocol không được hỗ trợ")
            spec = json.loads(row["input_spec"])
            if not isinstance(spec, dict):
                raise ValueError("input_spec phải là JSON object")
            if not row["description"].strip():
                raise ValueError("Thiếu mô tả ca thử")
            cases.append(TestCase(
                row["test_id"], row["description"], row["protocol"],
                row["target_ip"], port, spec, expected,
            ))
    if [c.test_id for c in cases] != [f"T{i:02}" for i in range(1, 15)]:
        raise ValueError("Cần đúng T01–T14 theo thứ tự, không trùng hoặc thiếu")
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "tests/tests.csv")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list", action="store_true", help="Liệt kê 14 ca; không chạy mạng")
    action.add_argument("--check", action="store_true", help="Kiểm tra hợp đồng CSV")
    action.add_argument("--mode", choices=["live", "offline"], help="TODO: chưa triển khai")
    args = parser.parse_args()
    try:
        cases = load_catalog(args.catalog)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.mode:
        parser.error("TODO TV1/TV2/TV3: runner live/offline chưa triển khai")
    if args.list:
        for case in cases:
            print(f"{case.test_id} | {case.protocol:7} | {format_sids(case.expected_sids) or '(không SID)'} | {case.description}")
    else:
        print(f"OK: {len(cases)} ca thử đúng hợp đồng CSV (chưa kiểm tra traffic).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
