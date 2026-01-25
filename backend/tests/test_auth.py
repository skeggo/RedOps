import os
import unittest

from backend import auth


class AuthTests(unittest.TestCase):
    def setUp(self):
        # Clear cached env parsing between tests.
        auth.load_api_keys.cache_clear()

    def test_load_api_keys_requires_env(self):
        os.environ.pop("API_KEYS", None)
        with self.assertRaises(auth.AuthConfigError):
            auth.load_api_keys()

    def test_load_api_keys_parses_equals(self):
        os.environ["API_KEYS"] = "a=1,b=2"
        keys = auth.load_api_keys()
        self.assertEqual(keys["a"], "1")
        self.assertEqual(keys["b"], "2")

    def test_load_api_keys_parses_colon(self):
        os.environ["API_KEYS"] = "a:1"
        keys = auth.load_api_keys()
        self.assertEqual(keys, {"a": "1"})

    def test_load_api_keys_rejects_duplicates(self):
        os.environ["API_KEYS"] = "a=1,a=2"
        with self.assertRaises(auth.AuthConfigError):
            auth.load_api_keys()


if __name__ == "__main__":
    unittest.main()
