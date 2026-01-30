import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path


# Allow importing backend-local modules (backend/reporting.py) as top-level.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND_DIR))

import reporting  # noqa: E402


class ReportingTests(unittest.TestCase):
    def test_compute_scan_summary_counts(self):
        scan = {
            "id": "scan-1",
            "target": "http://example.com",
            "status": "done",
            "created_at": datetime(2026, 1, 1, 0, 0, 0),
            "triggered_by": "local",
        }

        t0 = datetime(2026, 1, 1, 0, 0, 1)
        tool_runs = [
            {
                "id": "r1",
                "tool": "nuclei",
                "status": "success",
                "attempt": 1,
                "queued_at": t0,
                "started_at": t0,
                "finished_at": t0 + timedelta(seconds=2),
                "duration_ms": 2000,
                "exit_code": 0,
            },
            {
                "id": "r2",
                "tool": "nikto",
                "status": "failed",
                "attempt": 1,
                "queued_at": t0 + timedelta(seconds=3),
                "started_at": t0 + timedelta(seconds=3),
                "finished_at": t0 + timedelta(seconds=4),
                "duration_ms": 1000,
                "exit_code": 2,
                "short_error": "boom",
            },
        ]

        findings = [
            {"tool": "nuclei", "payload": {"ok": True}, "created_at": t0 + timedelta(seconds=2)},
            {"tool": "nikto_error", "payload": {"error": "boom"}, "created_at": t0 + timedelta(seconds=4)},
        ]

        out = reporting.compute_scan_summary(scan=scan, tool_runs=tool_runs, findings=findings)
        self.assertEqual(out["tool_runs"]["total"], 2)
        self.assertEqual(out["tool_runs"]["unique_tools"], 2)
        self.assertEqual(out["tool_runs"]["status_counts"]["success"], 1)
        self.assertEqual(out["tool_runs"]["status_counts"]["failed"], 1)
        self.assertEqual(out["findings"]["total"], 2)
        self.assertEqual(out["findings"]["by_category"]["result"], 1)
        self.assertEqual(out["findings"]["by_category"]["error"], 1)
        self.assertIsInstance(out["timeline"]["duration_ms"], int)

    def test_render_scan_report_md_smoke(self):
        scan = {
            "id": "scan-2",
            "target": "juiceshop",
            "status": "queued",
            "created_at": datetime(2026, 1, 2, 0, 0, 0),
            "triggered_by": "local",
        }
        md = reporting.render_scan_report_md(scan=scan, tool_runs=[], findings=[])
        self.assertIn("# Scan Report", md)
        self.assertIn("## Live Targets", md)
        self.assertIn("## Tool Runs", md)
        self.assertIn("## Findings", md)
        self.assertIn("scan-2", md)

    def test_render_scan_report_md_live_targets_from_httpx(self):
        scan = {
            "id": "scan-3",
            "target": "juiceshop",
            "status": "done",
            "created_at": datetime(2026, 1, 3, 0, 0, 0),
            "triggered_by": "local",
        }

        findings = [
            {
                "tool": "httpx",
                "payload": {
                    "count": 1,
                    "results": [{"url": "http://juiceshop:3000"}],
                    "tool_run_id": "run-1",
                    "attempt": 1,
                },
                "created_at": datetime(2026, 1, 3, 0, 0, 1),
            }
        ]

        md = reporting.render_scan_report_md(scan=scan, tool_runs=[], findings=findings)
        self.assertIn("## Live Targets", md)
        self.assertIn("http://juiceshop:3000", md)

    def test_render_scan_report_md_discovered_endpoints_from_katana(self):
        scan = {
            "id": "scan-4",
            "target": "juiceshop",
            "status": "done",
            "created_at": datetime(2026, 1, 4, 0, 0, 0),
            "triggered_by": "local",
        }

        findings = [
            {
                "tool": "katana",
                "payload": {
                    "count": 2,
                    "urls": ["http://juiceshop:3000/#/login", "http://juiceshop:3000/robots.txt"],
                    "urls_truncated": False,
                    "tool_run_id": "run-2",
                    "attempt": 1,
                },
                "created_at": datetime(2026, 1, 4, 0, 0, 1),
            }
        ]

        md = reporting.render_scan_report_md(scan=scan, tool_runs=[], findings=findings)
        self.assertIn("## Discovered Endpoints", md)
        self.assertIn("http://juiceshop:3000/robots.txt", md)

    def test_render_scan_report_md_vulnerabilities_from_nuclei(self):
        scan = {
            "id": "scan-5",
            "target": "juiceshop",
            "status": "done",
            "created_at": datetime(2026, 1, 5, 0, 0, 0),
            "triggered_by": "local",
        }

        findings = [
            {
                "tool": "nuclei",
                "payload": {
                    "severity": "high",
                    "title": "Example vuln",
                    "template_id": "http/misconfig/example",
                    "matched_at": "http://juiceshop:3000/robots.txt",
                    "tool_run_id": "run-3",
                    "attempt": 1,
                },
                "created_at": datetime(2026, 1, 5, 0, 0, 1),
            }
        ]

        md = reporting.render_scan_report_md(scan=scan, tool_runs=[], findings=findings)
        self.assertIn("## Vulnerabilities", md)
        self.assertIn("Example vuln", md)
        self.assertIn("http/misconfig/example", md)

    def test_render_scan_report_md_includes_mitre_mappings(self):
        scan = {
            "id": "scan-6",
            "target": "example",
            "status": "done",
            "created_at": datetime(2026, 1, 6, 0, 0, 0),
            "triggered_by": "local",
        }

        findings = [
            {
                "tool": "nuclei",
                "payload": {"title": "SQL injection"},
                "mitre": [
                    {
                        "technique_id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access",
                        "tactics": [
                            {"tactic_id": "TA0001", "shortname": "initial-access", "name": "Initial Access"}
                        ],
                        "confidence": 0.9,
                        "reason": "rule match",
                        "source": "rules",
                    }
                ],
                "created_at": datetime(2026, 1, 6, 0, 0, 1),
            }
        ]

        md = reporting.render_scan_report_md(scan=scan, tool_runs=[], findings=findings)
        self.assertIn("MITRE ATT&CK", md)
        self.assertIn("T1190", md)


if __name__ == "__main__":
    unittest.main()
