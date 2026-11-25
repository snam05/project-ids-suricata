"""Bộ tạo báo cáo HTML tĩnh từ bảng kết quả và chỉ số đã đánh giá.

Input: results.csv đã đánh giá, metrics.json, manifest/eve liên kết bằng chứng (nếu có).
Output: report.html trong thư mục một run, tách live/offline và đánh dấu mock.
Đảm bảo: kiểm tra schema; escape HTML; hiển thị N/A khi mẫu số bằng 0;
bảng PASS/FAIL/INVALID; phân biệt số ca thử và số dòng alert; liên kết tương đối an toàn.
"""
import argparse
import csv
import html
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path

from .eval_metrics import CaseResult, GROUP_SIDS, aggregate_metrics
from .eve_parser import parse_eve
from .run_tests import format_sids, parse_sids

RESULT_FIELDS = (
    "run_id",
    "test_id",
    "expected_sids",
    "observed_sids",
    "traffic_valid",
    "status",
    "evidence_dir",
)

_SECRET_PATTERNS = (".env", ".pem", ".key", "id_rsa", "id_ed25519", "credentials", "secret", "token")


@dataclass(frozen=True)
class CaseEvidenceMeta:
    alert_line_count: int | None
    parser_error_count: int | None
    relative_link: str


def _parse_bool_strict(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"traffic_valid phải là 'true' hoặc 'false', nhận được: {value!r}")


def _detect_run_mode(run_ids: set[str], evidence_dirs: list[str]) -> str:
    has_live = any(r.startswith("live_") or r == "live" for r in run_ids)
    has_offline = any(r.startswith("offline_") or r == "offline" for r in run_ids)
    if has_live and has_offline:
        raise ValueError("Không được trộn kết quả live và offline trong cùng một báo cáo")
    is_mock = (
        any("mock" in r.lower() for r in run_ids)
        or any("fixtures" in d.lower() or "not_real_evidence" in d.lower() for d in evidence_dirs)
    )
    if is_mock:
        return "MOCK"
    if has_live:
        return "LIVE"
    if has_offline:
        return "OFFLINE"
    return "CUSTOM"


def _sanitize_relative_link(evidence_dir: str, output_dir: Path) -> str:
    raw = evidence_dir.strip().replace("\\", "/")
    if not raw:
        raise ValueError("evidence_dir không được rỗng")
    lower = raw.lower()
    if lower.startswith(("javascript:", "data:", "vbscript:", "http://", "https://", "file://")):
        raise ValueError(f"evidence_dir không được dùng URI scheme ngoài/động: {evidence_dir!r}")
    parts = [p for p in raw.split("/") if p]
    for part in parts:
        p_low = part.lower()
        if any(pat in p_low for pat in _SECRET_PATTERNS):
            raise ValueError(f"Từ chối liên kết chứa tên nhạy cảm/secret: {evidence_dir!r}")

    cand = Path(raw)
    if cand.is_absolute():
        try:
            rel = cand.resolve().relative_to(output_dir.resolve())
            return rel.as_posix()
        except ValueError as exc:
            raise ValueError(f"evidence_dir tuyệt đối nằm ngoài thư mục báo cáo: {evidence_dir!r}") from exc

    norm = os.path.normpath(raw).replace("\\", "/")
    if norm.startswith("../") or norm == "..":
        raise ValueError(f"evidence_dir không được vượt ra ngoài thư mục gốc: {evidence_dir!r}")
    return norm


def load_results_csv(path: Path) -> list[CaseResult]:
    """Đọc và kiểm tra hợp đồng schema của results.csv."""
    results: list[CaseResult] = []
    seen_pairs: set[tuple[str, str]] = set()

    with Path(path).open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(RESULT_FIELDS):
            raise ValueError("Header results.csv phải đúng hợp đồng RESULT_FIELDS")
        for line_no, row in enumerate(reader, start=2):
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f"Dòng {line_no} trong results.csv thừa hoặc thiếu cột")
            run_id = row["run_id"].strip()
            test_id = row["test_id"].strip()
            evidence_dir = row["evidence_dir"].strip()
            if not run_id or not test_id or not evidence_dir:
                raise ValueError(f"Dòng {line_no}: run_id, test_id và evidence_dir không được rỗng")

            pair = (run_id, test_id)
            if pair in seen_pairs:
                raise ValueError(f"Trùng cặp (run_id, test_id) tại dòng {line_no}: {pair}")
            seen_pairs.add(pair)

            expected = parse_sids(row["expected_sids"])
            if not expected <= GROUP_SIDS:
                raise ValueError(f"Dòng {line_no}: expected_sids chứa SID ngoài 4 SID của nhóm")
            observed = parse_sids(row["observed_sids"])
            traffic_valid = _parse_bool_strict(row["traffic_valid"].strip())
            status = row["status"].strip()
            if status not in {"PASS", "FAIL", "INVALID"}:
                raise ValueError(f"Dòng {line_no}: status không hợp lệ: {status!r}")

            if not traffic_valid and status != "INVALID":
                raise ValueError(f"Dòng {line_no}: traffic_valid=false nhưng status={status!r}")
            if status == "PASS" and expected != observed:
                raise ValueError(f"Dòng {line_no}: status=PASS nhưng expected_sids khác observed_sids")
            if status == "FAIL" and expected == observed:
                raise ValueError(f"Dòng {line_no}: status=FAIL nhưng expected_sids bằng observed_sids")

            results.append(
                CaseResult(
                    run_id=run_id,
                    test_id=test_id,
                    expected_sids=expected,
                    observed_sids=observed,
                    traffic_valid=traffic_valid,
                    status=status,
                    evidence_dir=evidence_dir,
                )
            )

    if not results:
        raise ValueError("results.csv không có dữ liệu ca thử nào")

    _detect_run_mode({r.run_id for r in results}, [r.evidence_dir for r in results])
    return results


def _metrics_equal(actual: dict, expected: dict) -> bool:
    if not isinstance(actual, dict):
        return False
    if actual.get("case_counts") != expected.get("case_counts"):
        return False

    def _bucket_matches(b_act: object, b_exp: dict) -> bool:
        if not isinstance(b_act, dict):
            return False
        for k in ("TP", "FP", "TN", "FN"):
            if type(b_act.get(k)) is not int or b_act.get(k) != b_exp[k]:
                return False
        for k in ("precision", "recall"):
            v_act, v_exp = b_act.get(k), b_exp[k]
            if v_exp is None:
                if v_act is not None:
                    return False
            else:
                if type(v_act) not in (int, float) or not math.isclose(float(v_act), float(v_exp), rel_tol=1e-9, abs_tol=1e-9):
                    return False
        return True

    if not _bucket_matches(actual.get("overall"), expected["overall"]):
        return False
    per_sid_act = actual.get("per_sid")
    if not isinstance(per_sid_act, dict) or set(per_sid_act.keys()) != set(expected["per_sid"].keys()):
        return False
    for sid_key, exp_bucket in expected["per_sid"].items():
        if not _bucket_matches(per_sid_act.get(sid_key), exp_bucket):
            return False
    return True


def load_and_verify_metrics(metrics_json: Path, results: list[CaseResult]) -> dict:
    """Đọc metrics.json và đối chiếu với kết quả tính từ results.csv."""
    with Path(metrics_json).open(encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("metrics.json phải là JSON object")
    expected = aggregate_metrics(results)
    if not _metrics_equal(data, expected):
        raise ValueError("Dữ liệu trong metrics.json không khớp với kết quả tính từ results.csv")
    return expected


def _inspect_case_evidence(result: CaseResult, base_dir: Path, output_dir: Path) -> CaseEvidenceMeta:
    rel_link = _sanitize_relative_link(result.evidence_dir, output_dir)
    candidates = [base_dir / result.evidence_dir, output_dir / rel_link]
    for cand_dir in candidates:
        manifest_path = cand_dir / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if isinstance(manifest, dict):
                    alert_cnt = manifest.get("alert_count")
                    err_cnt = manifest.get("parser_errors")
                    if type(alert_cnt) is int and alert_cnt >= 0:
                        return CaseEvidenceMeta(
                            alert_line_count=alert_cnt,
                            parser_error_count=err_cnt if type(err_cnt) is int else None,
                            relative_link=rel_link,
                        )
            except (OSError, ValueError, TypeError):
                pass
        eve_path = cand_dir / "eve.json"
        if eve_path.is_file():
            try:
                parsed = parse_eve(eve_path)
                return CaseEvidenceMeta(
                    alert_line_count=parsed.alert_count,
                    parser_error_count=parsed.error_count,
                    relative_link=rel_link,
                )
            except OSError:
                pass
    return CaseEvidenceMeta(alert_line_count=None, parser_error_count=None, relative_link=rel_link)


def format_metric(value: float | None) -> str:
    """Định dạng chỉ số: JSON null hiển thị N/A, không đổi thành 0."""
    if value is None:
        return "N/A"
    return f"{value:.4f} ({value * 100:.1f}%)"


def make_report(results_csv: Path, metrics_json: Path, output: Path) -> None:
    """Đọc results.csv và metrics.json đã xác minh để sinh báo cáo HTML tĩnh."""
    results_path = Path(results_csv)
    metrics_path = Path(metrics_json)
    output_path = Path(output)

    results = load_results_csv(results_path)
    metrics = load_and_verify_metrics(metrics_path, results)

    run_ids = sorted({r.run_id for r in results})
    mode = _detect_run_mode(set(run_ids), [r.evidence_dir for r in results])
    base_dir = results_path.parent
    output_dir = output_path.parent

    evidence_metas = [_inspect_case_evidence(r, base_dir, output_dir) for r in results]
    known_alert_counts = [m.alert_line_count for m in evidence_metas if m.alert_line_count is not None]
    total_alert_lines_str = str(sum(known_alert_counts)) if len(known_alert_counts) == len(results) else "N/A (chưa có đủ eve.json)"
    cases_with_alerts = sum(1 for r in results if len(r.observed_sids) > 0)

    counts = metrics["case_counts"]
    overall = metrics["overall"]
    per_sid = metrics["per_sid"]

    run_label = html.escape(", ".join(run_ids), quote=True)
    mode_badge_map = {
        "LIVE": ("mode-live", "LIVE — Chạy trực tiếp trên Lab"),
        "OFFLINE": ("mode-offline", "OFFLINE — Đọc lại từ PCAP chuẩn"),
        "MOCK": ("mode-mock", "MOCK — Dữ liệu giả kiểm thử code (Không dùng làm số liệu báo cáo)"),
        "CUSTOM": ("mode-custom", "CUSTOM — Lượt chạy tùy chỉnh"),
    }
    mode_class, mode_text = mode_badge_map[mode]

    mock_banner = ""
    if mode == "MOCK":
        mock_banner = (
            '<div class="banner-mock" role="alert">'
            "<strong>CẢNH BÁO DỮ LIỆU MOCK:</strong> Báo cáo này được tạo từ dữ liệu giả lập "
            "(<code>MOCK_ONLY</code> / <code>fixtures</code>) chỉ nhằm kiểm thử mã nguồn Python, "
            "tuyệt đối không dùng làm số liệu thực nghiệm trong báo cáo chính thức."
            "</div>"
        )

    per_sid_rows = []
    for sid in sorted(GROUP_SIDS):
        b = per_sid[str(sid)]
        per_sid_rows.append(
            f"<tr>"
            f"<td><code>{sid}</code></td>"
            f"<td>{b['TP']}</td>"
            f"<td>{b['FP']}</td>"
            f"<td>{b['TN']}</td>"
            f"<td>{b['FN']}</td>"
            f"<td>{html.escape(format_metric(b['precision']), quote=True)}</td>"
            f"<td>{html.escape(format_metric(b['recall']), quote=True)}</td>"
            f"</tr>"
        )

    case_rows = []
    for res, meta in zip(results, evidence_metas):
        exp_str = html.escape(format_sids(res.expected_sids) or "(không SID)", quote=True)
        obs_str = html.escape(format_sids(res.observed_sids) or "(không SID)", quote=True)
        traffic_str = "true" if res.traffic_valid else "false"
        status_cls = f"status-{res.status.lower()}"
        alert_cnt_cell = str(meta.alert_line_count) if meta.alert_line_count is not None else "N/A"
        safe_href = html.escape(meta.relative_link, quote=True)
        case_rows.append(
            f"<tr>"
            f"<td><code>{html.escape(res.run_id, quote=True)}</code></td>"
            f"<td><strong>{html.escape(res.test_id, quote=True)}</strong></td>"
            f"<td><code>{exp_str}</code></td>"
            f"<td><code>{obs_str}</code></td>"
            f"<td>{html.escape(alert_cnt_cell, quote=True)}</td>"
            f"<td><code>{traffic_str}</code></td>"
            f'<td><span class="badge {status_cls}">{html.escape(res.status, quote=True)}</span></td>'
            f'<td><a href="{safe_href}"><code>{safe_href}</code></a></td>'
            f"</tr>"
        )

    html_doc = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Báo cáo Kiểm chứng IDS Suricata — {run_label}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --card: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #475569;
      --pass-bg: #dcfce7;
      --pass-fg: #166534;
      --fail-bg: #fee2e2;
      --fail-fg: #991b1b;
      --invalid-bg: #fef3c7;
      --invalid-fg: #92400e;
    }}
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }}
    .container {{
      max-width: 1120px;
      margin: 0 auto;
    }}
    header {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px 24px;
      margin-bottom: 20px;
    }}
    h1 {{
      margin: 0 0 8px 0;
      font-size: 1.5rem;
    }}
    h2 {{
      font-size: 1.15rem;
      margin: 24px 0 12px 0;
    }}
    .meta {{
      color: var(--muted);
      font-size: 0.95rem;
    }}
    .banner-mock {{
      background: #fffbeb;
      border: 2px solid #f59e0b;
      color: #78350f;
      padding: 14px 18px;
      border-radius: 8px;
      margin-bottom: 20px;
    }}
    .mode-badge {{
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      font-weight: 600;
      font-size: 0.85rem;
    }}
    .mode-live {{ background: #dbeafe; color: #1e40af; }}
    .mode-offline {{ background: #e0e7ff; color: #3730a3; }}
    .mode-mock {{ background: #fef3c7; color: #92400e; }}
    .mode-custom {{ background: #f1f5f9; color: #334155; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
    }}
    .card .label {{
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .card .value {{
      font-size: 1.4rem;
      font-weight: 700;
      margin-top: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 20px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      font-size: 0.92rem;
    }}
    th {{
      background: #f1f5f9;
      font-weight: 600;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 0.8rem;
    }}
    .status-pass {{ background: var(--pass-bg); color: var(--pass-fg); }}
    .status-fail {{ background: var(--fail-bg); color: var(--fail-fg); }}
    .status-invalid {{ background: var(--invalid-bg); color: var(--invalid-fg); }}
    .note {{
      font-size: 0.88rem;
      color: var(--muted);
      margin-top: -10px;
      margin-bottom: 20px;
    }}
  </style>
</head>
<body>
  <div class="container">
    {mock_banner}
    <header>
      <h1>Báo cáo Kiểm chứng Hệ thống Phát hiện Xâm nhập Suricata</h1>
      <div class="meta">
        Mã lượt chạy (Run ID): <code>{run_label}</code> &bull;
        Chế độ: <span class="mode-badge {mode_class}">{html.escape(mode_text, quote=True)}</span>
      </div>
    </header>

    <h2>1. Thống kê tổng quan Ca thử và Cảnh báo</h2>
    <div class="grid">
      <div class="card">
        <div class="label">Tổng số ca thử</div>
        <div class="value">{len(results)}</div>
      </div>
      <div class="card">
        <div class="label">PASS</div>
        <div class="value" style="color: var(--pass-fg);">{counts['PASS']}</div>
      </div>
      <div class="card">
        <div class="label">FAIL</div>
        <div class="value" style="color: var(--fail-fg);">{counts['FAIL']}</div>
      </div>
      <div class="card">
        <div class="label">INVALID (Loại khỏi ma trận)</div>
        <div class="value" style="color: var(--invalid-fg);">{counts['INVALID']}</div>
      </div>
      <div class="card">
        <div class="label">Số ca có sinh SID</div>
        <div class="value">{cases_with_alerts}</div>
      </div>
      <div class="card">
        <div class="label">Tổng số dòng Alert trong EVE</div>
        <div class="value">{html.escape(total_alert_lines_str, quote=True)}</div>
      </div>
    </div>
    <p class="note">
      Lưu ý: Đánh giá PASS/FAIL dựa trên tập SID quan sát được ở từng ca thử, không đếm nhiều dòng alert lặp lại
      (ví dụ ca T12 gửi lặp 3 request) thành nhiều ca thành công. Các ca INVALID không đưa vào ma trận TP/FP/TN/FN.
    </p>

    <h2>2. Ma trận Đánh giá và Chỉ số (Tính trên 4 SID của nhóm)</h2>
    <table>
      <thead>
        <tr>
          <th>Phạm vi / SID</th>
          <th>TP</th>
          <th>FP</th>
          <th>TN</th>
          <th>FN</th>
          <th>Precision</th>
          <th>Recall</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Tổng hợp (Overall)</strong></td>
          <td><strong>{overall['TP']}</strong></td>
          <td><strong>{overall['FP']}</strong></td>
          <td><strong>{overall['TN']}</strong></td>
          <td><strong>{overall['FN']}</strong></td>
          <td><strong>{html.escape(format_metric(overall['precision']), quote=True)}</strong></td>
          <td><strong>{html.escape(format_metric(overall['recall']), quote=True)}</strong></td>
        </tr>
        {"".join(per_sid_rows)}
      </tbody>
    </table>

    <h2>3. Bảng Kết quả Chi tiết theo Ca kiểm thử</h2>
    <table>
      <thead>
        <tr>
          <th>Run ID</th>
          <th>Test ID</th>
          <th>SID Kỳ vọng</th>
          <th>SID Quan sát</th>
          <th>Số dòng Alert</th>
          <th>Traffic hợp lệ</th>
          <th>Trạng thái</th>
          <th>Thư mục Bằng chứng</th>
        </tr>
      </thead>
      <tbody>
        {"".join(case_rows)}
      </tbody>
    </table>
  </div>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_doc, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True, help="Đường dẫn tới file results.csv")
    parser.add_argument("--metrics", type=Path, required=True, help="Đường dẫn tới file metrics.json")
    parser.add_argument("--output", type=Path, required=True, help="Đường dẫn xuất file report.html")
    args = parser.parse_args(argv)

    try:
        make_report(args.results, args.metrics, args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Đã tạo báo cáo HTML: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
