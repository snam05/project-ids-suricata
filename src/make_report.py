"""Khung tạo báo cáo HTML tĩnh, CHƯA triển khai.

Input: results.csv đã đánh giá, metrics.json, manifest liên kết bằng chứng.
Output: report.html trong thư mục một run, tách live/offline và đánh dấu mock.
TODO: đọc/kiểm tra schema; escape HTML; N/A; bảng PASS/FAIL/INVALID;
hiển thị số ca khác số alert; liên kết bằng chứng tương đối; không chèn secret.
"""
import argparse
from pathlib import Path


def make_report(results_csv: Path, metrics_json: Path, output: Path) -> None:
    raise NotImplementedError("TODO: đọc dữ liệu đã đánh giá và tạo HTML")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    parser.error("TODO: chưa triển khai; chưa có report.html thực nghiệm")


if __name__ == "__main__":
    raise SystemExit(main())
