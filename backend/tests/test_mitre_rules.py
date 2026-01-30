import sys
import unittest
from pathlib import Path


# Allow importing project modules.
_ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT_DIR))

from common.mitre_rules import map_finding_to_mitre  # noqa: E402


class MitreRulesTests(unittest.TestCase):
    def test_maps_sqli_to_t1190(self):
        out = map_finding_to_mitre(tool="nuclei", payload={"title": "SQL Injection"})
        tids = {m.get("technique_id") for m in out}
        self.assertIn("T1190", tids)

    def test_maps_exposed_login_to_t1190(self):
        out = map_finding_to_mitre(tool="katana", payload={"title": "Exposed admin panel", "url": "https://example.com/admin"})
        tids = {m.get("technique_id") for m in out}
        self.assertIn("T1190", tids)

    def test_maps_command_injection_to_t1059(self):
        out = map_finding_to_mitre(tool="nuclei", payload={"title": "OS command injection"})
        tids = {m.get("technique_id") for m in out}
        self.assertIn("T1059", tids)

    def test_maps_rce_to_t1203(self):
        out = map_finding_to_mitre(tool="nuclei", payload={"title": "Remote Code Execution"})
        tids = {m.get("technique_id") for m in out}
        self.assertIn("T1203", tids)

    def test_maps_exposed_secrets_to_t1552(self):
        out = map_finding_to_mitre(tool="nuclei", payload={"title": "Exposed secrets in config", "evidence": "hardcoded API key"})
        tids = {m.get("technique_id") for m in out}
        self.assertIn("T1552", tids)


if __name__ == "__main__":
    unittest.main()
