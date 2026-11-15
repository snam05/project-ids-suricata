"""Mock/unit test cho eve_parser.py và make_report.py (không phải số liệu thực nghiệm Suricata)."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from src.eval_metrics import aggregate_metrics
from src.eve_parser import main as parser_main, parse_eve, parse_timestamp
from src.make_report import load_results_csv, make_report

FIXTURE = Path(__file__).parent / "fixtures/mock_eve.json"
MOCK_RESULTS = Path(__file__).parent / "fixtures/mock_results.csv"


class EveParserTests(unittest.TestCase):
    def parse_text(self, text, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            path.write_text(text, encoding="utf-8")
            return parse_eve(path, **kwargs)

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

    def test_real_suricata_eve_schema_and_multi_sid(self):
        lines = [
            json.dumps({
                "timestamp": "2026-11-13T10:23:17.514966+0000",
                "event_type": "stats",
                "stats": {"uptime": 8, "detect": {"alert": 2}},
            }),
            json.dumps({
                "timestamp": "2026-11-13T10:25:00.070568+0000",
                "flow_id": 1135448769804255,
                "in_iface": "ens5",
                "event_type": "alert",
                "src_ip": "10.10.10.10",
                "src_port": 33290,
                "dest_ip": "10.10.10.20",
                "dest_port": 80,
                "proto": "TCP",
                "pkt_src": "wire/pcap",
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 1000001,
                    "rev": 1,
                    "signature": "IDS LAB exact HTTP URI marker",
                    "severity": 3,
                },
                "app_proto": "http",
                "direction": "to_server",
            }),
            json.dumps({
                "timestamp": "2026-11-13T10:25:00.070600+0000",
                "flow_id": 1135448769804255,
                "in_iface": "ens5",
                "event_type": "alert",
                "src_ip": "10.10.10.10",
                "src_port": 33290,
                "dest_ip": "10.10.10.20",
                "dest_port": 80,
                "proto": "TCP",
                "pkt_src": "wire/pcap",
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 1000002,
                    "rev": 1,
                    "signature": "IDS LAB exact User-Agent marker",
                    "severity": 3,
                },
                "app_proto": "http",
                "direction": "to_server",
            }),
            json.dumps({
                "timestamp": "2026-11-13T10:25:09.050346+0000",
                "flow_id": 1135448769804255,
                "in_iface": "ens5",
                "event_type": "flow",
                "src_ip": "10.10.10.10",
                "src_port": 33290,
                "dest_ip": "10.10.10.20",
                "dest_port": 80,
                "proto": "TCP",
                "app_proto": "http",
            }),
        ]
        result = self.parse_text("\n".join(lines) + "\n")
        self.assertEqual(result.errors, ())
        self.assertEqual(result.observed_sids, {1000001, 1000002})
        self.assertEqual(result.observed_sids_csv, "1000001;1000002")
        self.assertTrue(result.has_stats)
        self.assertEqual(result.event_counts, {"stats": 1, "alert": 2, "flow": 1})
        first = result.alerts[0]
        self.assertEqual(first.src_port, 33290)
        self.assertEqual(first.dest_port, 80)
        self.assertEqual(first.proto, "TCP")
        self.assertEqual(first.app_proto, "http")
        self.assertEqual(first.signature, "IDS LAB exact HTTP URI marker")

    def test_filter_by_ip_port_and_time_window(self):
        lines = [
            json.dumps({
                "timestamp": "2026-11-13T10:25:00.000000+0000",
                "event_type": "alert",
                "src_ip": "10.10.10.10",
                "dest_ip": "10.10.10.20",
                "dest_port": 80,
                "alert": {"signature_id": 1000001},
            }),
            json.dumps({
                "timestamp": "2026-11-13T10:26:00.000000+0000",
                "event_type": "alert",
                "src_ip": "10.10.10.99",
                "dest_ip": "10.10.10.20",
                "dest_port": 53,
                "alert": {"signature_id": 1000003},
            }),
        ]
        res_ip = self.parse_text("\n".join(lines) + "\n", src_ip="10.10.10.10")
        self.assertEqual(res_ip.observed_sids, {1000001})
        res_time = self.parse_text(
            "\n".join(lines) + "\n",
            start_time="2026-11-13T10:25:30+0000",
            end_time="2026-11-13T10:26:30+0000",
        )
        self.assertEqual(res_time.observed_sids, {1000003})

    def test_naive_timestamp_and_corrupt_optional_fields_are_counted_as_errors(self):
        base = json.loads(FIXTURE.read_text(encoding="utf-8").splitlines()[0])
        bad_naive = dict(base, timestamp="2026-11-02T10:00:00")
        bad_port = dict(base, src_port=70000)
        bad_alert_null = dict(base, alert=None)
        result = self.parse_text(
            "\n".join(json.dumps(x) for x in (bad_naive, bad_port, bad_alert_null)) + "\n"
        )
        self.assertEqual(result.error_count, 3)
        self.assertEqual(result.observed_sids, set())
        self.assertIsNotNone(parse_timestamp("2026-11-13T10:25:00.070568Z").tzinfo)

    def test_cli_json_and_csv_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = parser_main([str(FIXTURE), "--format", "csv"])
        self.assertEqual(rc, 0)
        out_lines = buf.getvalue().strip().splitlines()
        self.assertEqual(len(out_lines), 2)
        self.assertIn("1000001", out_lines[1])


class MakeReportTests(unittest.TestCase):
    def test_make_report_renders_mock_banner_na_and_counts(self):
        results = load_results_csv(MOCK_RESULTS)
        metrics = aggregate_metrics(results)
        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            metrics_path = temp_dir / "metrics.json"
            output_path = temp_dir / "report.html"
            metrics_path.write_text(json.dumps(metrics), encoding="utf-8")
            make_report(MOCK_RESULTS, metrics_path, output_path)
            html_text = output_path.read_text(encoding="utf-8")
            self.assertIn("CẢNH BÁO DỮ LIỆU MOCK", html_text)
            self.assertIn("N/A", html_text)
            self.assertIn("PASS", html_text)
            self.assertIn("FAIL", html_text)
            self.assertIn("INVALID", html_text)

    def test_make_report_escapes_html_and_counts_alert_lines_from_eve(self):
        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            ev_dir = temp_dir / "T12"
            ev_dir.mkdir()
            (ev_dir / "eve.json").write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

            csv_path = temp_dir / "results.csv"
            csv_path.write_text(
                "run_id,test_id,expected_sids,observed_sids,traffic_valid,status,evidence_dir\n"
                "offline_20261115_<tag>,T12,1000001,1000001,true,PASS,T12\n",
                encoding="utf-8",
            )
            results = load_results_csv(csv_path)
            metrics_path = temp_dir / "metrics.json"
            metrics_path.write_text(json.dumps(aggregate_metrics(results)), encoding="utf-8")
            output_path = temp_dir / "report.html"
            make_report(csv_path, metrics_path, output_path)
            html_text = output_path.read_text(encoding="utf-8")
            self.assertIn("offline_20261115_&lt;tag&gt;", html_text)
            self.assertNotIn("<tag>", html_text)
            self.assertIn("OFFLINE", html_text)
            self.assertIn(">2<", html_text)

    def test_make_report_rejects_mixed_modes_bad_metrics_and_secret_links(self):
        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            mixed_csv = temp_dir / "mixed.csv"
            mixed_csv.write_text(
                "run_id,test_id,expected_sids,observed_sids,traffic_valid,status,evidence_dir\n"
                "live_01,T01,1000001,1000001,true,PASS,T01\n"
                "offline_01,T02,,,true,PASS,T02\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_results_csv(mixed_csv)

            secret_csv = temp_dir / "secret.csv"
            secret_csv.write_text(
                "run_id,test_id,expected_sids,observed_sids,traffic_valid,status,evidence_dir\n"
                "offline_01,T01,1000001,1000001,true,PASS,suricata_key.pem\n",
                encoding="utf-8",
            )
            results = load_results_csv(secret_csv)
            metrics_path = temp_dir / "metrics.json"
            metrics_path.write_text(json.dumps(aggregate_metrics(results)), encoding="utf-8")
            with self.assertRaises(ValueError):
                make_report(secret_csv, metrics_path, temp_dir / "report.html")
