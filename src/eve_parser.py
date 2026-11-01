"""TV4 — bộ đọc EVE JSON Lines tối thiểu, đã có kiểm thử với dữ liệu mock.

Input: một eve.json đã đóng của MỘT ca/lượt, do runner cung cấp ngữ cảnh.
Output: ParseResult gồm alert, số dòng, danh sách lỗi kèm số dòng.
TODO: runner xử lý lỗi I/O; chọn log đúng ca/thời gian/IP; lưu chẩn đoán;
kiểm tra EVE hoàn chỉnh sau engine dừng. Parser không xác nhận traffic hợp lệ.
EVE không tự có run_id/test_id; không suy ra PASS từ tập alert rỗng.
"""
import json
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path


@dataclass(frozen=True)
class Alert:
    sid: int
    timestamp: str
    src_ip: str
    dest_ip: str
    line_number: int


@dataclass(frozen=True)
class ParseResult:
    alerts: tuple[Alert, ...]
    line_count: int
    errors: tuple[str, ...]

    @property
    def observed_sids(self) -> frozenset[int]:
        # Giữ cả SID lạ để evaluator không âm thầm bỏ qua cảnh báo ngoài dự kiến.
        return frozenset(alert.sid for alert in self.alerts)


def parse_eve(path: Path) -> ParseResult:
    alerts, errors = [], []
    count = 0
    # Lỗi encoding/I/O được ném cho runner; không chuyển thành tập alert rỗng.
    with path.open(encoding="utf-8") as stream:
        for count, line in enumerate(stream, start=1):
            try:
                event = json.loads(line)
                if not isinstance(event, dict) or not isinstance(event.get("event_type"), str):
                    raise ValueError("thiếu event_type/object")
                if event["event_type"] != "alert":
                    continue
                sid = event["alert"]["signature_id"]
                if type(sid) is not int or sid <= 0:
                    raise ValueError("signature_id phải là số nguyên dương")
                timestamp = event["timestamp"]
                if not isinstance(timestamp, str) or not timestamp.strip():
                    raise ValueError("thiếu timestamp")
                for field in ("src_ip", "dest_ip"):
                    if not isinstance(event[field], str):
                        raise ValueError("địa chỉ IP phải là chuỗi")
                    ip_address(event[field])
                alerts.append(Alert(sid, timestamp, event["src_ip"], event["dest_ip"], count))
            except (ValueError, KeyError, TypeError) as exc:
                # Không lưu raw line để tránh chép dữ liệu nhạy cảm vào chẩn đoán.
                errors.append(f"Dòng {count}: {type(exc).__name__}")
    return ParseResult(tuple(alerts), count, tuple(errors))
