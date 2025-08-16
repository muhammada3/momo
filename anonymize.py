import sys
import re
import json
import csv

# --- Redaction Rules and Patterns ---

# Field-specific rules
REDACTION_RULES = {
    'login': {'type': 'full', 'placeholder': '[REDACTED]'},
    'ip': {'type': 'full', 'placeholder': '[IP_REDACTED]'},
    'email': {'type': 'full', 'placeholder': '[EMAIL_REDACTED]'},
    'adresse': {'type': 'full', 'placeholder': '[ADRESSE_REDACTED]'},
    'mot_de_passe': {'type': 'full', 'placeholder': '[PASSWORD_REDACTED]'},
    'password': {'type': 'full', 'placeholder': '[PASSWORD_REDACTED]'},
    'iban': {'type': 'partial_iban'},
    'hostname': {'type': 'conditional_hostname'},
}

# Regex for scanning unknown fields for sensitive data
SENSITIVE_PATTERNS = {
    'Email': re.compile(r'[\w\.-]+@[\w\.-]+\.\w+'),
    'IPv4': re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b'),
    'IBAN': re.compile(r'[A-Z]{2}\d{2}(?:\s?\d{4}){4,5}'),
}

# --- Helper Functions for Complex Redactions ---

def redact_partial_iban(value):
    """Returns a partially masked IBAN, keeping the last 4 digits."""
    last_four = "".join(filter(str.isalnum, value))[-4:]
    return f"**** **** **** {last_four}"

def redact_conditional_hostname(value):
    """Conditionally redacts a hostname based on specific patterns."""
    if 'prod51' in value or 'prod31' in value or value.endswith('.cdc.fr'):
        return '[HOSTNAME_REDACTED]'
    return value

# --- Core Anonymization Logic ---

def anonymize_record(record):
    """
    Anonymizes a single record (represented as a dictionary) based on the defined rules.
    Returns the anonymized record and a list of logs for the redactions performed.
    """
    redacted_record = record.copy()
    redaction_logs = []

    # Apply field-specific rules
    for key, value in record.items():
        # Map 'user' field to 'login' rule for redaction
        rule_key = 'login' if key == 'user' else key

        if rule_key in REDACTION_RULES:
            rule = REDACTION_RULES[rule_key]
            original_value = str(value)
            redacted_value = None

            if rule['type'] == 'full':
                redacted_value = rule['placeholder']
                redaction_logs.append(f"Redacted field '{key}' (as '{rule_key}')")
            elif rule['type'] == 'partial_iban':
                redacted_value = redact_partial_iban(original_value)
                redaction_logs.append(f"Partially masked field '{key}'")
            elif rule['type'] == 'conditional_hostname':
                redacted_value = redact_conditional_hostname(original_value)
                if original_value != redacted_value:
                    redaction_logs.append(f"Conditionally redacted field '{key}'")

            if redacted_value is not None:
                redacted_record[key] = redacted_value

    # Scan for sensitive data in unknown fields
    for key, value in record.items():
        # Map 'user' to 'login' to avoid re-checking a field that's already handled
        rule_key = 'login' if key == 'user' else key
        if rule_key not in REDACTION_RULES and isinstance(value, str):
            for name, pattern in SENSITIVE_PATTERNS.items():
                if pattern.search(value):
                    redacted_record[key] = '[SENSITIVE_REDACTED]'
                    redaction_logs.append(f"Redacted sensitive pattern '{name}' in field '{key}'")
                    break # Move to the next key once a pattern is found

    return redacted_record, redaction_logs

# --- Input Format Processors ---

def parse_log_line(line):
    """Parses a line from a log file into a dictionary."""
    # This parser is specific to the user's log format (key=value or key: value)
    record = {}
    # Regex to find key=value or key="value" or key: value
    pattern = re.compile(r'(\w+)=("([^"]*)"|(\S+))|\b(\w+): (\S+)')
    matches = pattern.finditer(line)
    for match in matches:
        if match.group(1): # key=value pattern
            key = match.group(1)
            # Value can be quoted (group 3) or not quoted (group 4)
            value = match.group(3) if match.group(3) is not None else match.group(4)
            record[key] = value
        elif match.group(5): # key: value pattern
            key = match.group(5)
            value = match.group(6)
            record[key] = value
    return record

def process_log_file(filepath):
    """Processes a text log file line by line, preserving the original line structure."""
    print(f"--- Processing Log File: {filepath} ---")
    with open(filepath, 'r') as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue

            record = parse_log_line(line)
            redacted_record, logs = anonymize_record(record)

            redacted_line = line
            # Replace original values with redacted ones to preserve line format
            for key, original_value in record.items():
                redacted_value = redacted_record.get(key)

                # Ensure we only replace if the value has actually changed
                if original_value and str(original_value) != str(redacted_value):
                    # This handles different quoting and spacing styles (e.g., key="value", key=value, key: value)
                    # It escapes the original value to handle special regex characters safely.
                    escaped_original = re.escape(str(original_value))

                    # Try to replace key="value" or key=value
                    redacted_line = re.sub(f'{key}=("?){escaped_original}("?)', f'{key}=\\1{redacted_value}\\2', redacted_line)
                    # Try to replace key: value
                    redacted_line = re.sub(f'{key}: {escaped_original}', f'{key}: {redacted_value}', redacted_line)

            print(f"Record {i} (Original): {line.strip()}")
            print(f"Record {i} (Anonymized): {redacted_line.strip()}")
            for log in logs:
                print(f"  - {log}")
            print("-" * 20)

def process_json_file(filepath):
    """Processes a JSON file."""
    print(f"--- Processing JSON File: {filepath} ---")
    with open(filepath, 'r') as f:
        data = json.load(f)
        # Handle both a single JSON object and a list of objects
        records = data if isinstance(data, list) else [data]
        for i, record in enumerate(records, 1):
            redacted_record, logs = anonymize_record(record)
            print(f"Record {i} (Original): {json.dumps(record)}")
            print(f"Record {i} (Anonymized): {json.dumps(redacted_record)}")
            for log in logs:
                print(f"  - {log}")
            print("-" * 20)

def process_csv_file(filepath):
    """Processes a CSV file."""
    print(f"--- Processing CSV File: {filepath} ---")
    with open(filepath, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for i, record in enumerate(reader, 1):
            redacted_record, logs = anonymize_record(record)
            print(f"Record {i} (Original): {dict(record)}")
            print(f"Record {i} (Anonymized): {redacted_record}")
            for log in logs:
                print(f"  - {log}")
            print("-" * 20)

# --- Main Execution ---

def main():
    """Main function to handle CLI arguments and trigger processing."""
    args = sys.argv[1:]
    if len(args) != 3 or args[0] != '--type':
        print("Usage: python anonymize.py --type <format> <filepath>")
        print("Supported formats: json, csv, log")
        sys.exit(1)

    file_type = args[1]
    filepath = args[2]

    if file_type == 'json':
        process_json_file(filepath)
    elif file_type == 'csv':
        process_csv_file(filepath)
    elif file_type == 'log':
        process_log_file(filepath)
    else:
        print(f"Error: Unsupported file type '{file_type}'")
        print("Supported formats: json, csv, log")
        sys.exit(1)

if __name__ == '__main__':
    main()
