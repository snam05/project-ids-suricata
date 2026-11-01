"""TV1 — kiểm tra logic tập SID; mock không được dùng làm kết quả lab."""
import unittest
from src.eval_metrics import evaluate_case, aggregate_metrics
from src.contracts import parse_sids


def valid_case(expected, observed, **kwargs):
    options = dict(engine_ok=True, evidence_complete=True)
    options.update(kwargs)
    return evaluate_case("MOCK_ONLY", "T01", frozenset(expected), frozenset(observed),
                         True, "tests/fixtures/NOT_REAL_EVIDENCE", **options)


class EvaluationTests(unittest.TestCase):
    def test_wrong_sid_is_one_fn_and_one_fp(self):
        result = valid_case({1000001}, {1000002})
        self.assertEqual(result.status, "FAIL")
        overall = aggregate_metrics([result])["overall"]
        self.assertEqual((overall["TP"], overall["FP"], overall["TN"], overall["FN"]), (0, 1, 2, 1))

    def test_exact_sets_and_repeated_alert_sid(self):
        self.assertEqual(valid_case({1000001, 1000002}, {1000002, 1000001}).status, "PASS")
        self.assertEqual(valid_case({1000001}, [1000001] * 3).status, "PASS")
        self.assertEqual(valid_case(set(), set()).status, "PASS")

    def test_invalid_is_excluded_and_zero_denominator_is_na(self):
        invalid = valid_case({1000001}, set(), parser_errors=1)
        self.assertEqual(invalid.status, "INVALID")
        summary = aggregate_metrics([invalid])
        self.assertEqual(summary["case_counts"]["INVALID"], 1)
        self.assertEqual(summary["overall"]["FN"], 0)
        self.assertIsNone(summary["overall"]["precision"])
        self.assertIsNone(summary["overall"]["recall"])

    def test_negative_case_needs_traffic_and_evidence(self):
        result = evaluate_case("MOCK_ONLY", "T02", frozenset(), frozenset(), False,
                               "tests/fixtures/NOT_REAL_EVIDENCE", engine_ok=True, evidence_complete=True)
        self.assertEqual(result.status, "INVALID")
        self.assertEqual(valid_case(set(), set(), evidence_complete=False).status, "INVALID")
        self.assertEqual(valid_case(set(), set(), engine_ok=False).status, "INVALID")
        # Mặc định không có bằng chứng/engine OK: không thể PASS.
        self.assertEqual(evaluate_case("MOCK_ONLY", "T02", frozenset(), frozenset(), True,
                                      "tests/fixtures/NOT_REAL_EVIDENCE").status, "INVALID")

    def test_unknown_observed_sid_fails_but_matrix_uses_four_group_sids(self):
        result = valid_case(set(), {9999999})
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(aggregate_metrics([result])["overall"]["TN"], 4)

    def test_precision_recall_and_per_sid(self):
        results = [valid_case({1000001}, {1000001}),
                   valid_case({1000001}, set()), valid_case(set(), {1000001})]
        summary = aggregate_metrics(results)
        self.assertEqual(summary["overall"]["precision"], 0.5)
        self.assertEqual(summary["overall"]["recall"], 0.5)
        self.assertEqual(summary["per_sid"]["1000001"]["TP"], 1)
        self.assertEqual(sum(summary["overall"][k] for k in ("TP", "FP", "TN", "FN")), 12)

    def test_sid_csv_contract_rejects_bad_tokens(self):
        self.assertEqual(parse_sids("1000002;1000001"), {1000001, 1000002})
        self.assertEqual(parse_sids(""), set())
        for value in ("1;", "zero", "0", "1;;2"):
            with self.assertRaises(ValueError):
                parse_sids(value)
