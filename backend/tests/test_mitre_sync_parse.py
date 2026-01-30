import sys
import unittest
from datetime import datetime
from pathlib import Path


# Allow importing project modules.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND_DIR))

import mitre_sync  # noqa: E402


class MitreSyncParseTests(unittest.TestCase):
    def test_parse_bundle_extracts_tactics_and_techniques(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--x",
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--1",
                    "name": "Initial Access",
                    "description": "desc",
                    "x_mitre_shortname": "initial-access",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "TA0001", "url": "https://attack.mitre.org/tactics/TA0001/"}
                    ],
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Exploit Public-Facing Application",
                    "description": "desc",
                    "modified": "2024-01-02T00:00:00.000Z",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1190", "url": "https://attack.mitre.org/techniques/T1190/"}
                    ],
                },
            ],
        }

        tactics, techniques = mitre_sync.parse_enterprise_attack_bundle(bundle)
        self.assertEqual(len(tactics), 1)
        self.assertEqual(tactics[0].tactic_id, "TA0001")
        self.assertEqual(tactics[0].shortname, "initial-access")
        self.assertIsInstance(tactics[0].modified, datetime)

        self.assertEqual(len(techniques), 1)
        self.assertEqual(techniques[0].technique_id, "T1190")
        self.assertIn("initial-access", techniques[0].tactic_shortnames)
        self.assertEqual(techniques[0].url, "https://attack.mitre.org/techniques/T1190/")

    def test_parse_bundle_handles_missing_objects(self):
        tactics, techniques = mitre_sync.parse_enterprise_attack_bundle({"type": "bundle"})
        self.assertEqual(tactics, [])
        self.assertEqual(techniques, [])


if __name__ == "__main__":
    unittest.main()
