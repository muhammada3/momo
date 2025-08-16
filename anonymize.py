import sys
import re

def anonymize_log_file(filename):
    """
    Reads a log file, redacts sensitive information (IBAN and password),
    and prints the anonymized content to standard output.
    """
    try:
        with open(filename, 'r') as f:
            for line in f:
                # Redact IBAN
                line = re.sub(r'iban="[^"]*"', 'iban="[REDACTED]"', line)
                # Redact password
                line = re.sub(r'mot_de_passe="[^"]*"', 'mot_de_passe="[REDACTED]"', line)
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
