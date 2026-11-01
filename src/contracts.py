"""Hợp đồng dùng chung; sửa có thống nhất TV1–TV4 trước khi chạy chính thức."""
GROUP_SIDS = frozenset({1000001, 1000002, 1000003, 1000004})
TEST_FIELDS = (
    "test_id", "description", "protocol", "target_ip", "target_port",
    "input_spec", "expected_sids",
)
RESULT_FIELDS = (
    "run_id", "test_id", "expected_sids", "observed_sids",
    "traffic_valid", "status", "evidence_dir",
)


def parse_sids(value: str) -> frozenset[int]:
    """CSV dùng dấu ;, ô rỗng nghĩa là tập rỗng. Không bỏ qua token lỗi."""
    if not value.strip():
        return frozenset()
    parts = value.split(";")
    if any(not p.strip().isascii() or not p.strip().isdigit() for p in parts):
        raise ValueError(f"SID không hợp lệ: {value!r}")
    sids = frozenset(int(p) for p in parts)
    if any(s <= 0 for s in sids):
        raise ValueError("SID phải là số nguyên dương")
    return sids


def format_sids(sids: frozenset[int]) -> str:
    return ";".join(str(sid) for sid in sorted(sids))
