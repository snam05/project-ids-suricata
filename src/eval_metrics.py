"""TV1 — phép đánh giá tập SID và ma trận theo ca–SID (đã có unit test).

Input: SID kỳ vọng, SID quan sát; ngữ cảnh và kết luận xác minh của runner.
Output: CaseResult; aggregate_metrics trả dict để sau này ghi metrics.json.
TODO: kiểm chứng manifest/PCAP/hash/exit code thực tế; đọc/ghi results.csv;
chống trùng ca–lượt; tách mode live/offline trước khi tổng hợp.
Các cờ True là kết luận từ bước xác minh, không phải mặc định tự suy ra.
"""
from dataclasses import dataclass
from .contracts import GROUP_SIDS


@dataclass(frozen=True)
class CaseResult:
    run_id: str
    test_id: str
    expected_sids: frozenset[int]
    observed_sids: frozenset[int]
    traffic_valid: bool
    status: str
    evidence_dir: str


def evaluate_case(
    run_id: str, test_id: str, expected: frozenset[int], observed: frozenset[int],
    traffic_valid: bool, evidence_dir: str, *, engine_ok: bool = False,
    evidence_complete: bool = False, parser_errors: int = 0,
) -> CaseResult:
    if not expected <= GROUP_SIDS:
        raise ValueError("Expected SID ngoài bộ luật nhóm")
    if parser_errors < 0:
        raise ValueError("Số lỗi parser không thể âm")
    valid = (traffic_valid is True and engine_ok is True
             and evidence_complete is True and parser_errors == 0
             and bool(run_id) and bool(test_id) and bool(evidence_dir))
    status = ("PASS" if expected == observed else "FAIL") if valid else "INVALID"
    return CaseResult(run_id, test_id, expected, observed, traffic_valid, status, evidence_dir)


def aggregate_metrics(results: list[CaseResult]) -> dict:
    """Chỉ dùng sau khi caller xác nhận cùng mode; INVALID bị loại khỏi ma trận."""
    totals = dict(TP=0, FP=0, TN=0, FN=0)
    per_sid = {str(sid): dict(TP=0, FP=0, TN=0, FN=0) for sid in sorted(GROUP_SIDS)}
    counts = dict(PASS=0, FAIL=0, INVALID=0)
    for result in results:
        if result.status not in counts:
            raise ValueError("Status không hợp lệ")
        counts[result.status] += 1
        if result.status == "INVALID":
            continue
        for sid in GROUP_SIDS:
            exp, obs = sid in result.expected_sids, sid in result.observed_sids
            key = ("TP" if obs else "FN") if exp else ("FP" if obs else "TN")
            totals[key] += 1
            per_sid[str(sid)][key] += 1
    for bucket in [totals, *per_sid.values()]:
        bucket["precision"] = bucket["TP"] / (bucket["TP"] + bucket["FP"]) if bucket["TP"] + bucket["FP"] else None
        bucket["recall"] = bucket["TP"] / (bucket["TP"] + bucket["FN"]) if bucket["TP"] + bucket["FN"] else None
    # JSON null = N/A; renderer TV4 phải hiển thị N/A, không đổi thành 0.
    return {"case_counts": counts, "overall": totals, "per_sid": per_sid}
