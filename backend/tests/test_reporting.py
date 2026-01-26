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
        self.assertIn("## Tool Runs", md)
        self.assertIn("## Findings", md)
        self.assertIn("scan-2", md)


if __name__ == "__main__":
    unittest.main()
