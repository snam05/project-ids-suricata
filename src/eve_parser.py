"""Bộ đọc EVE JSON Lines của Suricata, trích xuất cảnh báo và chẩn đoán log.

Input: một eve.json đã đóng của MỘT ca/lượt, do runner cung cấp ngữ cảnh.
Output: ParseResult gồm danh sách alert, số dòng, lỗi từng dòng, thống kê event_type
và thông tin stats cuối cùng (nếu có).
Parser không tự suy ra PASS từ tập alert rỗng và không thay thế bước xác minh PCAP.
"""
import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

_TZ_COMPACT_RE = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_timestamp(value: str) -> datetime:
    """Kiểm tra và phân tích chuỗi thời gian ISO-8601 có múi giờ từ Suricata EVE."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("thiếu timestamp")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    else:
        normalized = _TZ_COMPACT_RE.sub(r"\1:\2", normalized)
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("timestamp thiếu thông tin múi giờ (timezone)")
    return dt


def _optional_int(obj: dict, key: str, *, min_value: int = 0, max_value: int | None = None) -> int | None:
    if key not in obj or obj[key] is None:
        return None
    val = obj[key]
    if type(val) is not int or val < min_value:
        raise ValueError(f"trường {key} phải là số nguyên >= {min_value}")
    if max_value is not None and val > max_value:
        raise ValueError(f"trường {key} vượt quá {max_value}")
    return val


def _optional_str(obj: dict, key: str) -> str | None:
    if key not in obj or obj[key] is None:
        return None
    val = obj[key]
    if not isinstance(val, str):
        raise ValueError(f"trường {key} phải là chuỗi")
    return val


@dataclass(frozen=True)
class Alert:
    sid: int
    timestamp: str
    src_ip: str
    dest_ip: str
    line_number: int
    src_port: int | None = None
    dest_port: int | None = None
    proto: str | None = None
    app_proto: str | None = None
    signature: str | None = None
    gid: int | None = None
    rev: int | None = None
    severity: int | None = None
    action: str | None = None
    flow_id: int | None = None
    in_iface: str | None = None
    pkt_src: str | None = None
    direction: str | None = None

    @property
    def parsed_timestamp(self) -> datetime:
        return parse_timestamp(self.timestamp)


@dataclass(frozen=True)
class ParseResult:
    alerts: tuple[Alert, ...]
    line_count: int
    errors: tuple[str, ...]
    event_counts: dict[str, int] = field(default_factory=dict)
    last_stats: dict | None = None

    @property
    def observed_sids(self) -> frozenset[int]:
        # Giữ cả SID lạ để evaluator không âm thầm bỏ qua cảnh báo ngoài dự kiến.
        return frozenset(alert.sid for alert in self.alerts)

    @property
    def observed_sids_csv(self) -> str:
        return ";".join(str(sid) for sid in sorted(self.observed_sids))

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def has_stats(self) -> bool:
        return self.event_counts.get("stats", 0) > 0

    def filter(
        self,
        *,
        src_ip: str | None = None,
        dest_ip: str | None = None,
        dest_port: int | None = None,
        start_time: datetime | str | None = None,
        end_time: datetime | str | None = None,
    ) -> "ParseResult":
        """Lọc danh sách alert theo phạm vi IP/cổng/thời gian của ca thử."""
        norm_src = str(ip_address(src_ip)) if src_ip is not None else None
        norm_dest = str(ip_address(dest_ip)) if dest_ip is not None else None
        if dest_port is not None and (type(dest_port) is not int or not 1 <= dest_port <= 65535):
            raise ValueError("dest_port không hợp lệ")
        start_dt = parse_timestamp(start_time) if isinstance(start_time, str) else start_time
        end_dt = parse_timestamp(end_time) if isinstance(end_time, str) else end_time
        if start_dt is not None and (not isinstance(start_dt, datetime) or start_dt.tzinfo is None):
            raise ValueError("start_time phải có timezone")
        if end_dt is not None and (not isinstance(end_dt, datetime) or end_dt.tzinfo is None):
            raise ValueError("end_dt phải có timezone")
        if start_dt is not None and end_dt is not None and start_dt > end_dt:
            raise ValueError("start_time không được lớn hơn end_time")

        filtered = []
        for alert in self.alerts:
            if norm_src is not None and str(ip_address(alert.src_ip)) != norm_src:
                continue
            if norm_dest is not None and str(ip_address(alert.dest_ip)) != norm_dest:
                continue
            if dest_port is not None and alert.dest_port != dest_port:
                continue
            if start_dt is not None or end_dt is not None:
                ts = alert.parsed_timestamp
                if start_dt is not None and ts < start_dt:
                    continue
                if end_dt is not None and ts > end_dt:
                    continue
            filtered.append(alert)
        return ParseResult(
            tuple(filtered),
            self.line_count,
            self.errors,
            dict(self.event_counts),
            self.last_stats,
        )

    def to_dict(self) -> dict:
        """Xuất thông tin tóm tắt chẩn đoán phục vụ manifest hoặc kiểm tra log."""
        return {
            "line_count": self.line_count,
            "alert_count": len(self.alerts),
            "observed_sids": sorted(self.observed_sids),
            "observed_sids_csv": self.observed_sids_csv,
            "error_count": len(self.errors),
            "errors": list(self.errors),
            "event_counts": dict(self.event_counts),
            "has_stats": self.has_stats,
            "alerts": [
                {
                    "sid": alert.sid,
                    "timestamp": alert.timestamp,
                    "src_ip": alert.src_ip,
                    "dest_ip": alert.dest_ip,
                    "line_number": alert.line_number,
                    "src_port": alert.src_port,
                    "dest_port": alert.dest_port,
                    "proto": alert.proto,
                    "app_proto": alert.app_proto,
                    "signature": alert.signature,
                }
                for alert in self.alerts
            ],
        }


def parse_eve(
    path: Path | str,
    *,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    dest_port: int | None = None,
    start_time: datetime | str | None = None,
    end_time: datetime | str | None = None,
) -> ParseResult:
    eve_path = Path(path)
    alerts: list[Alert] = []
    errors: list[str] = []
    event_counts: dict[str, int] = {}
    last_stats: dict | None = None
    count = 0

    # Lỗi encoding/I/O được ném cho runner; không chuyển thành tập alert rỗng.
    with eve_path.open(encoding="utf-8") as stream:
        for count, line in enumerate(stream, start=1):
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("dòng EVE phải là JSON object")
                event_type = event.get("event_type")
                if not isinstance(event_type, str) or not event_type.strip():
                    raise ValueError("thiếu event_type/object")

                if "timestamp" in event:
                    parse_timestamp(event["timestamp"])

                if event_type != "alert":
                    for ip_field in ("src_ip", "dest_ip"):
                        if ip_field in event and event[ip_field] is not None:
                            if not isinstance(event[ip_field], str):
                                raise ValueError("địa chỉ IP phải là chuỗi")
                            ip_address(event[ip_field])
                    if event_type == "stats":
                        stats_obj = event.get("stats")
                        if stats_obj is not None and not isinstance(stats_obj, dict):
                            raise ValueError("trường stats phải là object")
                        if isinstance(stats_obj, dict):
                            last_stats = stats_obj
                    event_counts[event_type] = event_counts.get(event_type, 0) + 1
                    continue

                alert_obj = event.get("alert")
                if not isinstance(alert_obj, dict):
                    raise ValueError("thiếu đối tượng alert")
                sid = alert_obj["signature_id"]
                if type(sid) is not int or sid <= 0:
                    raise ValueError("signature_id phải là số nguyên dương")

                timestamp = event["timestamp"]
                parse_timestamp(timestamp)

                for field_name in ("src_ip", "dest_ip"):
                    if not isinstance(event[field_name], str):
                        raise ValueError("địa chỉ IP phải là chuỗi")
                    ip_address(event[field_name])

                alert = Alert(
                    sid=sid,
                    timestamp=timestamp,
                    src_ip=event["src_ip"],
                    dest_ip=event["dest_ip"],
                    line_number=count,
                    src_port=_optional_int(event, "src_port", min_value=1, max_value=65535),
                    dest_port=_optional_int(event, "dest_port", min_value=1, max_value=65535),
                    proto=_optional_str(event, "proto"),
                    app_proto=_optional_str(event, "app_proto"),
                    signature=_optional_str(alert_obj, "signature"),
                    gid=_optional_int(alert_obj, "gid", min_value=1),
                    rev=_optional_int(alert_obj, "rev", min_value=1),
                    severity=_optional_int(alert_obj, "severity", min_value=1),
                    action=_optional_str(alert_obj, "action"),
                    flow_id=_optional_int(event, "flow_id", min_value=0),
                    in_iface=_optional_str(event, "in_iface"),
                    pkt_src=_optional_str(event, "pkt_src"),
                    direction=_optional_str(event, "direction"),
                )
                alerts.append(alert)
                event_counts["alert"] = event_counts.get("alert", 0) + 1
            except (ValueError, KeyError, TypeError) as exc:
                # Không lưu raw line để tránh chép dữ liệu nhạy cảm vào chẩn đoán.
                errors.append(f"Dòng {count}: {type(exc).__name__}")

    result = ParseResult(tuple(alerts), count, tuple(errors), event_counts, last_stats)
    if any(v is not None for v in (src_ip, dest_ip, dest_port, start_time, end_time)):
        return result.filter(
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            start_time=start_time,
            end_time=end_time,
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eve_path", type=Path, help="Đường dẫn tới file eve.json cần phân tích")
    parser.add_argument("--src-ip", help="Lọc alert theo IP nguồn")
    parser.add_argument("--dest-ip", help="Lọc alert theo IP đích")
    parser.add_argument("--dest-port", type=int, help="Lọc alert theo cổng đích")
    parser.add_argument("--start-time", help="Lọc alert từ thời điểm ISO-8601 (có timezone)")
    parser.add_argument("--end-time", help="Lọc alert đến thời điểm ISO-8601 (có timezone)")
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Định dạng xuất kết quả (mặc định: text)",
    )
    args = parser.parse_args(argv)

    try:
        result = parse_eve(
            args.eve_path,
            src_ip=args.src_ip,
            dest_ip=args.dest_ip,
            dest_port=args.dest_port,
            start_time=args.start_time,
            end_time=args.end_time,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    if args.format == "json":
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    elif args.format == "csv":
        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(["eve_path", "line_count", "alert_count", "observed_sids", "error_count"])
        writer.writerow([
            str(args.eve_path),
            result.line_count,
            result.alert_count,
            result.observed_sids_csv,
            result.error_count,
        ])
    else:
        print(f"File: {args.eve_path}")
        print(f"Số dòng: {result.line_count} | Số alert: {result.alert_count} | Số lỗi: {result.error_count}")
        print(f"SID quan sát: {result.observed_sids_csv or '(không có)'}")
        if result.errors:
            print("Lỗi từng dòng:")
            for err in result.errors:
                print(f"  - {err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
