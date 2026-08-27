import unittest
from unittest.mock import patch
from app import analyze

class Response:
    status = 200
    headers = {'Content-Security-Policy':'default-src none', 'X-Content-Type-Options':'nosniff'}
    def __enter__(self): return self
    def __exit__(self, *args): pass

class TestHeaderEdgeCases(unittest.TestCase):
    @patch('app.open_no_redirect', return_value=Response())
    @patch('security_utils.assert_public_resolution')
    def test_reports_present_and_missing_headers(self, _resolve, _open):
        result = analyze({'url':'https://example.com'})
        self.assertIn('CSP', result['present'])
        self.assertIn('HSTS', result['missing'])
        self.assertFalse(result['redirects_followed'])

if __name__ == '__main__': unittest.main()
