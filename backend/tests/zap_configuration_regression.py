"""Configuration-only tests: no application, scanner, HTTP or database."""
from pathlib import Path
import tempfile
import unittest

from zap_configuration import load_zap_configuration


class ConfigurationTests(unittest.TestCase):
    def test_missing_local_file_does_not_invent_a_key(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_zap_configuration({}, Path(directory) / 'absent'),
                             ('http://127.0.0.1:8080', ''))

    def test_private_local_fallback_preserves_development_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.json'
            path.write_text('{"ZAP_URL":"http://127.0.0.1:8080", "ZAP_API_KEY":"fixture-key"}', encoding='utf-8')
            self.assertEqual(load_zap_configuration({}, path)[1], 'fixture-key')

    def test_company_environment_overrides_local_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.json'
            path.write_text('{"ZAP_API_KEY":"fixture-local"}', encoding='utf-8')
            self.assertEqual(load_zap_configuration({'ZAP_URL': 'https://zap.internal',
                'ZAP_API_KEY': 'fixture-service'}, path), ('https://zap.internal', 'fixture-service'))

    def test_credentials_or_paths_in_url_are_rejected(self):
        for base in ('http://user:pass@localhost:8080', 'http://localhost/path',
                     'file:///tmp/test', 'http://localhost?key=anything'):
            with self.assertRaises(ValueError):
                load_zap_configuration({'ZAP_URL': base})

    def test_header_injection_is_rejected(self):
        with self.assertRaises(ValueError):
            load_zap_configuration({'ZAP_API_KEY': 'fixture\r\nheader'})

    def test_malformed_private_file_is_explicit_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.json'
            path.write_text('[]', encoding='utf-8')
            with self.assertRaises(ValueError):
                load_zap_configuration({}, path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
