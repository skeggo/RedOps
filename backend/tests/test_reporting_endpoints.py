import os
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock


# Allow importing backend-local modules as top-level.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND_DIR))


class ReportingEndpointTests(unittest.TestCase):
    def _import_main(self):
        # main.py requires DATABASE_URL at import time. Use a harmless in-memory DB URL
        # since tests patch DB access anyway.
        with mock.patch.dict(os.environ, {"DATABASE_URL": "sqlite+pysqlite:///:memory:"}, clear=False):
            import importlib

            import main  # type: ignore

            return importlib.reload(main)

    def test_summary_endpoint_smoke(self):
        main = self._import_main()

        scan = {
            "id": "scan-123",
            "target": "http://example.com",
            "status": "done",
            "created_at": datetime(2026, 1, 1, 0, 0, 0),
            "triggered_by": "local",
            "api_key_id": "local",
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
                "finished_at": t0 + timedelta(seconds=1),
                "duration_ms": 1000,
                "exit_code": 0,
                "stdout_path": "/tmp/stdout.txt",
                "stderr_path": "/tmp/stderr.txt",
                "artifact_path": "/tmp/artifacts",
                "args": {},
                "metadata": {},
            }
        ]
        findings = [{"tool": "nuclei", "payload": {"ok": True}, "created_at": t0 + timedelta(seconds=1)}]

        with mock.patch.object(main, "_get_scan_bundle", return_value=(scan, tool_runs, findings)):
            out = main.get_scan_summary("scan-123")

        self.assertEqual(out["scan"]["id"], "scan-123")
        self.assertEqual(out["tool_runs"]["total"], 1)
        self.assertEqual(out["findings"]["total"], 1)

    def test_report_md_endpoint_smoke(self):
        main = self._import_main()

        scan = {
            "id": "scan-abc",
            "target": "juiceshop",
            "status": "queued",
            "created_at": datetime(2026, 1, 2, 0, 0, 0),
            "triggered_by": "local",
        }

        with mock.patch.object(main, "_get_scan_bundle", return_value=(scan, [], [])):
            resp = main.get_scan_report_md("scan-abc")

        # FastAPI response object
        self.assertTrue(hasattr(resp, "media_type"))
        self.assertIn("text/markdown", resp.media_type)
        body = resp.body.decode("utf-8", errors="replace")
        self.assertIn("# Scan Report", body)
        self.assertIn("scan-abc", body)


if __name__ == "__main__":
    unittest.main()
