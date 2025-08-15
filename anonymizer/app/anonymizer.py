import re

def anonymize_text(text: str) -> str:
    """
    Anonymize email addresses, phone numbers, and IP addresses in a given text.
    """
    text = anonymize_emails(text)
    text = anonymize_phones(text)
    text = anonymize_ips(text)
    return text

def anonymize_emails(text: str) -> str:
    """
    Masks email addresses in the text.
    """
    # A more robust email regex
    email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
    return email_regex.sub('[EMAIL_REDACTED]', text)

def anonymize_phones(text: str) -> str:
    """
    Masks phone numbers in the text.
    """
    # A simple phone regex for North American numbers
    phone_regex = re.compile(r'(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})')
    return phone_regex.sub('[PHONE_REDACTED]', text)

def anonymize_ips(text: str) -> str:
    """
    Masks IPv4 addresses in the text.
    """
    # A simple IPv4 regex
    ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return ip_regex.sub('[IP_REDACTED]', text)
