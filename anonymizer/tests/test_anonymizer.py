import unittest
import sys
import os

# Add the 'app' directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../app')))

from anonymizer import anonymize_text

class TestAnonymizer(unittest.TestCase):

    def test_anonymize_text_with_all_types(self):
        text = "Contact me at test@example.com or 555-123-4567. My IP is 192.168.1.1."
        expected = "Contact me at [EMAIL_REDACTED] or [PHONE_REDACTED]. My IP is [IP_REDACTED]."
        self.assertEqual(anonymize_text(text), expected)

    def test_anonymize_text_with_no_sensitive_info(self):
        text = "This is a clean text."
        self.assertEqual(anonymize_text(text), text)

    def test_anonymize_text_with_only_emails(self):
        text = "My email is test@example.com."
        expected = "My email is [EMAIL_REDACTED]."
        self.assertEqual(anonymize_text(text), expected)

    def test_anonymize_text_with_only_phones(self):
        text = "My phone is 555-123-4567."
        expected = "My phone is [PHONE_REDACTED]."
        self.assertEqual(anonymize_text(text), expected)

    def test_anonymize_text_with_only_ips(self):
        text = "My IP is 192.168.1.1."
        expected = "My IP is [IP_REDACTED]."
        self.assertEqual(anonymize_text(text), expected)

    def test_anonymize_text_with_empty_string(self):
        text = ""
        self.assertEqual(anonymize_text(text), "")

if __name__ == '__main__':
    unittest.main()
