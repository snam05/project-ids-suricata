#!/usr/bin/env python3
"""Kiểm tra bộ khung bằng standard library; không gọi mạng hoặc Suricata."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.run_tests import load_catalog  # noqa: E402

REQUIRED = (
    "README.md", ".gitignore", ".env.example", "requirements.txt",
    "config/suricata.yaml", "config/nginx.conf", "config/dnsmasq.conf",
    "rules/local.rules", "scripts/lab.sh", "scripts/traffic_gen.sh",
    "src/__init__.py", "src/contracts.py", "src/run_tests.py",
    "src/eve_parser.py", "src/eval_metrics.py", "src/make_report.py",
    "tests/tests.csv", "tests/pcaps/README.md", "tests/fixtures/README.md",
    "tests/fixtures/mock_eve.json", "tests/fixtures/mock_results.csv",
    "tests/test_eve_parser.py", "tests/test_eval_metrics.py",
    "results/README.md", "report/README.md", "slides/README.md",
    "demo/demo_script.md", "docs/data-contract.md", "docs/lab-setup.md",
    "docs/team-plan.md",
)


def main() -> int:
    missing = [name for name in REQUIRED if not (ROOT / name).is_file()]
    if missing:
        print("Thiếu file: " + ", ".join(missing), file=sys.stderr)
        return 1
    try:
        cases = load_catalog(ROOT / "tests/tests.csv")
        expected = [{1000001}, set(), {1000002}, set(), {1000003}, set(),
                    set(), set(), set(), set(), {1000001, 1000002},
                    {1000001}, {1000004}, set()]
        if [set(c.expected_sids) for c in cases] != expected:
            raise ValueError("Kỳ vọng 14 ca khác danh mục đã chốt")
        if cases[11].input_spec.get("repeat") != 3:
            raise ValueError("T12 cần đúng 3 request")
        if cases[12].input_spec != dict(ports="8000-8019", syn_packets=20,
                                        max_window_seconds=10, retries=0):
            raise ValueError("T13 sai điều kiện SYN")
        if cases[13].input_spec != dict(ports="8000", syn_packets=1, retries=0):
            raise ValueError("T14 sai điều kiện một SYN")
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("OK: cấu trúc và 14 ca thử; không phải kiểm chứng Suricata/traffic thật.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
