import os
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock


# Allow importing backend-local modules as top-level.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND_DIR))


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _FakeConn:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _stmt, _params=None):
        return _FakeResult(self._rows)


class _BeginCtx:
    def __init__(self, rows):
        self._rows = rows

    def __enter__(self):
        return _FakeConn(self._rows)

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeEngine:
    def __init__(self, rows):
        self._rows = rows

    def begin(self):
        return _BeginCtx(self._rows)


class ScanListTests(unittest.TestCase):
    def _import_main(self):
        with mock.patch.dict(os.environ, {"DATABASE_URL": "sqlite+pysqlite:///:memory:"}, clear=False):
            import importlib

            import main  # type: ignore

            return importlib.reload(main)

    def test_list_scans_smoke(self):
        main = self._import_main()

        rows = [
            {
                "id": "scan-1",
                "target": "t1",
                "api_key_id": "local",
                "triggered_by": "local",
                "concurrency_cap": 10,
                "status": "queued",
                "created_at": datetime(2026, 1, 1, 0, 0, 0),
            }
        ]

        with mock.patch.object(main, "engine", _FakeEngine(rows)):
            out = main.list_scans(limit=50, offset=0, status=None)

        self.assertEqual(len(out["scans"]), 1)
        self.assertEqual(out["scans"][0]["id"], "scan-1")

    def test_list_scans_validates_limit(self):
        main = self._import_main()
        with self.assertRaises(Exception):
            main.list_scans(limit=0, offset=0, status=None)


if __name__ == "__main__":
    unittest.main()
