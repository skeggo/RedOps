import os
import sys
import unittest
from pathlib import Path
from unittest import mock


# Allow importing backend-local modules (backend/scope_controls.py) as top-level.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND_DIR))

import scope_controls  # noqa: E402


class ScopeControlsTests(unittest.TestCase):
    def test_load_allowlist_requires_value(self):
        with mock.patch.dict(os.environ, {"SCAN_ALLOWLIST": ""}, clear=False):
            with self.assertRaises(scope_controls.ScopeError):
                scope_controls.load_allowlist()

    def test_domain_allowlist_allows_subdomains(self):
        with mock.patch.dict(os.environ, {"SCAN_ALLOWLIST": "example.com"}, clear=False):
            al = scope_controls.load_allowlist()

        # Avoid DNS dependence.
        with mock.patch.object(scope_controls, "_resolve_ips", return_value=[]):
            out = scope_controls.validate_target("foo.example.com", allowlist=al, lab_mode=False)
        self.assertEqual(out["host"], "foo.example.com")

    def test_wildcard_domain_allowlist(self):
        with mock.patch.dict(os.environ, {"SCAN_ALLOWLIST": "*.example.com"}, clear=False):
            al = scope_controls.load_allowlist()

        with mock.patch.object(scope_controls, "_resolve_ips", return_value=[]):
            out = scope_controls.validate_target("a.b.example.com", allowlist=al, lab_mode=False)
        self.assertEqual(out["host"], "a.b.example.com")

    def test_service_name_allowlist_exact_match(self):
        with mock.patch.dict(os.environ, {"SCAN_ALLOWLIST": "juiceshop"}, clear=False):
            al = scope_controls.load_allowlist()

        with mock.patch.object(scope_controls, "_resolve_ips", return_value=[]):
            out = scope_controls.validate_target("http://juiceshop:3000", allowlist=al, lab_mode=False)
        self.assertEqual(out["host"], "juiceshop")

    def test_ip_literal_must_be_in_cidr(self):
        with mock.patch.dict(os.environ, {"SCAN_ALLOWLIST": "1.2.3.0/24"}, clear=False):
            al = scope_controls.load_allowlist()

        out = scope_controls.validate_target("1.2.3.4", allowlist=al, lab_mode=False)
        self.assertEqual(out["host"], "1.2.3.4")

        with self.assertRaises(scope_controls.ScopeError):
            scope_controls.validate_target("1.2.4.1", allowlist=al, lab_mode=False)

    def test_private_ip_blocked_unless_lab_mode(self):
        with mock.patch.dict(os.environ, {"SCAN_ALLOWLIST": "10.0.0.0/8"}, clear=False):
            al = scope_controls.load_allowlist()

        with self.assertRaises(scope_controls.ScopeError):
            scope_controls.validate_target("10.0.0.5", allowlist=al, lab_mode=False)

        out = scope_controls.validate_target("10.0.0.5", allowlist=al, lab_mode=True)
        self.assertEqual(out["host"], "10.0.0.5")

    def test_private_dns_resolution_blocked_unless_lab_mode(self):
        with mock.patch.dict(os.environ, {"SCAN_ALLOWLIST": "example.com"}, clear=False):
            al = scope_controls.load_allowlist()

        # Force a private resolved IP.
        with mock.patch.object(scope_controls, "_resolve_ips") as resolve:
            resolve.return_value = [scope_controls.ipaddress.ip_address("192.168.1.10")]
            with self.assertRaises(scope_controls.ScopeError):
                scope_controls.validate_target("https://example.com", allowlist=al, lab_mode=False)

            out = scope_controls.validate_target("https://example.com", allowlist=al, lab_mode=True)
            self.assertEqual(out["resolved_ips"], ["192.168.1.10"])


if __name__ == "__main__":
    unittest.main()
