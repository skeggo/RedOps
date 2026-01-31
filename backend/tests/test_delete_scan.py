import os
import sys
import unittest
from pathlib import Path
from unittest import mock


# Allow importing backend-local modules as top-level.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND_DIR))


class _FakeExecResult:
    def __init__(self, first_row=None):
        self._first_row = first_row

    def first(self):
        return self._first_row


class _FakeConn:
    def __init__(self, exists: bool):
        self.exists = exists
        self.statements: list[str] = []

    def execute(self, stmt, params=None):
        s = str(stmt)
        self.statements.append(s)

        if "SELECT 1 FROM scans" in s:
            return _FakeExecResult((1,) if self.exists else None)
        return _FakeExecResult(None)


class _BeginCtx:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeEngine:
    def __init__(self, conn):
        self._conn = conn

    def begin(self):
        return _BeginCtx(self._conn)


class DeleteScanTests(unittest.TestCase):
    def _import_main(self):
        with mock.patch.dict(os.environ, {"DATABASE_URL": "sqlite+pysqlite:///:memory:"}, clear=False):
            import importlib

            import main  # type: ignore

            return importlib.reload(main)

    def test_delete_scan_missing_returns_404(self):
        main = self._import_main()

        conn = _FakeConn(exists=False)
        with mock.patch.object(main, "engine", _FakeEngine(conn)):
            with mock.patch.object(main, "authenticate_request", lambda _req: ("local", "secret")):
                with self.assertRaises(Exception):
                    main.delete_scan("nope", request=mock.Mock())

    def test_delete_scan_executes_deletes(self):
        main = self._import_main()

        conn = _FakeConn(exists=True)
        with mock.patch.object(main, "engine", _FakeEngine(conn)):
            with mock.patch.object(main, "authenticate_request", lambda _req: ("local", "secret")):
                out = main.delete_scan("scan-1", request=mock.Mock())

        self.assertEqual(out["deleted"], True)
        joined = "\n".join(conn.statements)
        self.assertIn("DELETE FROM tool_runs", joined)
        self.assertIn("DELETE FROM findings", joined)
        self.assertIn("DELETE FROM endpoints", joined)
        self.assertIn("DELETE FROM assets", joined)
        self.assertIn("DELETE FROM scans", joined)


if __name__ == "__main__":
    unittest.main()
