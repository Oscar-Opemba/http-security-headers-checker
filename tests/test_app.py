import unittest
from app import analyze

class TestHeaders(unittest.TestCase):
    def test_rejects_non_url(self):
        self.assertIn('error', analyze({'url': 'not-a-url'}))

if __name__ == '__main__': unittest.main()
