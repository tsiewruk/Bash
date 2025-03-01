# Secret Scanner

A comprehensive tool for detecting secrets and sensitive information in code repositories.

## Overview

This script is a comprehensive secret scanner that helps identify potential secrets and sensitive information in code repositories. It uses regex pattern matching combined with entropy calculation to detect secrets while minimizing false positives.

## Features

- **Multiple Secret Detection**: Detects various types of secrets including API keys, passwords, tokens, and private keys
- **Entropy Analysis**: Uses Shannon entropy calculation to filter out low-entropy strings that are likely false positives
- **Context-Aware Reporting**: Shows surrounding lines of code for each finding to help understand the context
- **Comprehensive Reporting**: Generates reports in both JSON and HTML formats
- **Configurable**: Supports custom patterns, adjustable entropy thresholds, and severity levels
- **CI/CD Integration**: Returns non-zero exit code when secrets are found, enabling integration with CI/CD pipelines

## Installation

```bash
# Clone the repository
git clone https://github.com/tsiewruk/secret-scanner.git
cd secret-scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python secrets.py /path/to/repository [options]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `path` | Path to scan (required) |
| `--output`, `-o` | Output file path (default: secret_scan_report.json) |
| `--entropy`, `-e` | Entropy threshold for secret detection (default: 4.5) |
| `--config`, `-c` | Path to configuration file with additional patterns |
| `--verbose`, `-v` | Enable verbose logging |
| `--severity`, `-s` | Scan severity level: low, medium, high (default: medium) |

### Examples

Basic scan of a repository:
```bash
python secrets.py /path/to/repo
```

Generate report with a specific name:
```bash
python secrets.py /path/to/repo --output my_report.json
```

Use custom patterns and high severity:
```bash
python secrets.py /path/to/repo --config custom_patterns.json --severity high
```

## Configuration

You can define custom secret patterns in a JSON configuration file:

```json
{
  "company_token": "COMPANY_[0-9a-zA-Z]{20}",
  "custom_api_key": "API_KEY_[a-zA-Z0-9+/=]{32}"
}
```

## Severity Levels

The tool supports three severity levels which adjust the entropy threshold:

- **low**: Uses a higher entropy threshold (5.5), detecting only high-confidence secrets
- **medium**: Default setting with moderate entropy threshold (4.5)
- **high**: Uses a lower entropy threshold (3.5), detecting more potential secrets but may include more false positives

## Output

The scanner generates two report files:

1. **JSON Report**: Contains detailed information about all findings
2. **HTML Report**: A user-friendly visual representation of the findings

Additionally, a summary is displayed in the console after scanning.

## Exit Codes

- **0**: No secrets found
- **1**: Secrets found

The non-zero exit code when secrets are found enables easy integration with CI/CD pipelines.

## Supported Secret Types

The scanner detects various types of secrets including:

- AWS access and secret keys
- GitHub tokens
- Generic API keys
- Private keys and certificates
- Passwords in code
- Database connection strings
- OAuth tokens
- JWT tokens
- Azure, Slack, Stripe, Twilio and many other service tokens

## License

MIT License
