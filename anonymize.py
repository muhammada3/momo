import sys
import re

def anonymize_log_file(filename):
    """
    Reads a log file, redacts sensitive information (user, email, IP, address, IBAN, password, and hostname),
    and prints the anonymized content to standard output.
    """
    try:
        with open(filename, 'r') as f:
            for line in f:
                # Redact user
                line = re.sub(r'user=\S+', 'user=[REDACTED]', line)
                # Redact email
                line = re.sub(r'email="[^"]*"', 'email="[REDACTED]"', line)
                # Redact IP address
                line = re.sub(r'ip=\S+', 'ip=[REDACTED]', line)
                # Redact address
                line = re.sub(r'adresse="[^"]*"', 'adresse="[REDACTED]"', line)
                # Redact IBAN
                line = re.sub(r'iban="[^"]*"', 'iban="[REDACTED]"', line)
                # Redact password
                line = re.sub(r'mot_de_passe="[^"]*"', 'mot_de_passe="[REDACTED]"', line)
                # Redact hostname
                line = re.sub(r'hostname: \S+', 'hostname: [REDACTED]', line)
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
