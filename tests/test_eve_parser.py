"""TV4 — mock/unit test, không phải số liệu thực nghiệm Suricata."""
import json
import tempfile
import unittest
from pathlib import Path
from src.eve_parser import parse_eve

FIXTURE = Path(__file__).parent / "fixtures/mock_eve.json"


class EveParserTests(unittest.TestCase):
    def parse_text(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            path.write_text(text, encoding="utf-8")
            return parse_eve(path)

    def test_duplicate_alerts_are_one_sid_set_and_nonalerts_are_ignored(self):
        result = parse_eve(FIXTURE)
        self.assertEqual(len(result.alerts), 2)
        self.assertEqual(result.observed_sids, {1000001})
        self.assertEqual(result.line_count, 3)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.alerts[0].src_ip, "10.10.10.10")
        self.assertEqual(result.alerts[0].line_number, 1)

    def test_bad_json_and_schema_are_counted_without_hiding_valid_lines(self):
        valid = FIXTURE.read_text(encoding="utf-8").splitlines()[0]
        result = self.parse_text('not-json\n[]\n{"event_type":"alert"}\n' + valid + '\n')
        self.assertEqual(result.line_count, 4)
        self.assertEqual(len(result.errors), 3)
        self.assertEqual(result.observed_sids, {1000001})
        self.assertTrue(result.errors[0].startswith("Dòng 1:"))

    def test_boolean_sid_bad_ip_and_empty_timestamp_are_errors(self):
        base = json.loads(FIXTURE.read_text().splitlines()[0])
        events = []
        for field, value in [("sid", True), ("src_ip", "not-an-ip"), ("src_ip", 10), ("timestamp", "")]:
            event = json.loads(json.dumps(base))
            if field == "sid":
                event["alert"]["signature_id"] = value
            else:
                event[field] = value
            events.append(json.dumps(event))
        result = self.parse_text("\n".join(events) + "\n")
        self.assertEqual(len(result.errors), 4)
        self.assertEqual(result.observed_sids, set())

    def test_unknown_sid_is_preserved(self):
        event = json.loads(FIXTURE.read_text().splitlines()[0])
        event["alert"]["signature_id"] = 9999999
        self.assertEqual(self.parse_text(json.dumps(event)).observed_sids, {9999999})

    def test_missing_file_raises_instead_of_faking_no_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                parse_eve(Path(directory) / "missing.json")
