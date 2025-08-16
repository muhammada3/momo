import sys
import re

def mask_iban(match):
    """
    Partially masks an IBAN value found by re.sub.
    It keeps the last 4 non-space characters.
    """
    # The match object m contains the full matched string, e.g., iban="..."
    full_match = match.group(0)
    # Extract the value from within the quotes
    try:
        iban_val = full_match.split('"')[1]
    except IndexError:
        return full_match # Should not happen with the given regex

    # Get last 4 non-space characters
    last_four = "".join(iban_val.split())[-4:]

    # Per user spec, format the replacement string
    masked_iban_val = f"**** **** **** {last_four}"

    return f'iban="{masked_iban_val}"'

def mask_hostname(match):
    """
    Conditionally redacts a hostname value found by re.sub.
    """
    full_match = match.group(0) # e.g., "hostname: dbdnprod51"
    try:
        # Split on ': ' to get the value part
        hostname_val = full_match.split(': ')[1]
    except IndexError:
        return full_match # Should not happen with the given regex

    if 'prod51' in hostname_val or 'prod31' in hostname_val or hostname_val.endswith('.cdc.fr'):
        return 'hostname: [HOSTNAME_REDACTED]'
    else:
        # If no redaction rule matches, return the original string
        return full_match

def anonymize_log_file(filename):
    """
    Reads a log file and redacts it based on a set of detailed rules.
    """
    try:
        with open(filename, 'r') as f:
            for line in f:
                # Rule: Keep 'adresse' as is. No action needed.

                # Rule: Redact 'login' (user) completely with [REDACTED]
                line = re.sub(r'user=\S+', 'user=[REDACTED]', line)

                # Rule: Redact 'ip' completely with [IP_REDACTED]
                line = re.sub(r'ip=\S+', 'ip=[IP_REDACTED]', line)

                # Rule: Redact 'email' completely with [EMAIL_REDACTED]
                line = re.sub(r'email="[^"]*"', 'email="[EMAIL_REDACTED]"', line)

                # Rule: Redact 'password' field completely with [PASSWORD_REDACTED]
                line = re.sub(r'\bpassword=\S+', 'password=[PASSWORD_REDACTED]', line)

                # Rule: Redact 'mot_de_passe' for security with [PASSWORD_REDACTED]
                line = re.sub(r'mot_de_passe="[^"]*"', 'mot_de_passe="[PASSWORD_REDACTED]"', line)

                # Rule: Partially mask 'iban'
                line = re.sub(r'iban="[^"]*"', mask_iban, line)

                # Rule: Conditionally redact 'hostname'
                line = re.sub(r'hostname: \S+', mask_hostname, line)

                print(line, end='')

    except FileNotFoundError:
        print(f"Error: File not found at '{filename}'", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <logfile>", file=sys.stderr)
        sys.exit(1)

    log_file = sys.argv[1]
    anonymize_log_file(log_file)
