"""
Secret Scanner - A tool for detecting secrets and sensitive information in code repositories

This script scans repositories or directories for potential secrets and sensitive information
such as API keys, passwords, tokens, and private keys. It uses pattern matching and entropy
calculation to identify potential secrets while minimizing false positives.

Features:
- **Multiple Secret Detection**: Detects various types of secrets including API keys, passwords, tokens, and private keys
- **Entropy Analysis**: Uses Shannon entropy calculation to filter out low-entropy strings that are likely false positives
- **Context-Aware Reporting**: Shows surrounding lines of code for each finding to help understand the context
- **Comprehensive Reporting**: Generates reports in both JSON and HTML formats
- **Configurable**: Supports custom patterns, adjustable entropy thresholds, and severity levels
- **CI/CD Integration**: Returns non-zero exit code when secrets are found, enabling integration with CI/CD pipelines

Usage:
    python secrets.py /path/to/repository --output report.json --severity high
"""

import os
import re
from pathlib import Path
import argparse
from typing import List, Dict, Set
import json
from datetime import datetime
import math
import logging

class SecretScanner:
    """
    A class that scans code repositories for secrets and sensitive information.
    
    This scanner uses regex patterns to identify potential secrets and calculates
    entropy to reduce false positives. It can generate detailed reports and supports
    custom patterns for organization-specific secrets.
    """
    
    def __init__(self, custom_patterns=None, entropy_threshold=4.5):
        """
        Initialize the SecretScanner with patterns and configuration.
        
        Args:
            custom_patterns (dict, optional): Dictionary of additional regex patterns.
            entropy_threshold (float, optional): Minimum entropy threshold for identifying secrets.
        """
        # Patterns for different types of secrets
        self.patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'github_token': r'gh[pousr]_[0-9a-zA-Z]{36}',
            'generic_api_key': r'[aA][pP][iI][-_]?[kK][eE][yY].*[=:]\s*[\'"]*[0-9a-zA-Z]{32,45}[\'"]*',
            'private_key': r'-----BEGIN\s+PRIVATE\s+KEY-----',
            'password_in_code': r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]((?!\{\{)[^\'"])+[\'"]',
            'connection_string': r'(?i)(mongodb|postgresql|mysql)://[^\s<>"\']+',
            'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            # Additional secret patterns
            'azure_key': r'[0-9a-zA-Z+/]{88}(==)?',
            'slack_token': r'xox[pbar]-[0-9a-zA-Z]{10,48}',
            'stripe_api_key': r'sk_live_[0-9a-zA-Z]{24}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'ssh_private_key': r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
            'firebase_api_key': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'mailchimp_api_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'heroku_api_key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'pem_certificate': r'-----BEGIN\s+CERTIFICATE-----',
        }
        
        # Add custom patterns if provided
        if custom_patterns:
            self.patterns.update(custom_patterns)
            
        # Entropy threshold for secret detection
        self.entropy_threshold = entropy_threshold
        
        # List of file extensions to exclude
        self.exclude_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', 
                                 '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip', 
                                 '.tar', '.gz', '.7z', '.pyc', '.class', '.o', '.so',
                                 '.exe', '.dll', '.obj', '.bin', '.ttf', '.woff', '.woff2'}
        
        # List of directories to exclude
        self.exclude_dirs = {'.git', 'node_modules', 'venv', '.env', '__pycache__', 
                           'build', 'dist', '.idea', '.vscode', 'vendor', 'bower_components'}
        
        # Logger configuration
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('secret_scan.log')
            ]
        )
        self.logger = logging.getLogger('SecretScanner')
        
        # Patterns that may cause false positives (documentation examples, etc.)
        self.false_positive_patterns = [
            r'example',
            r'sample',
            r'placeholder',
            r'your_',
            r'test_key',
            r'dummy',
            r'demo'
        ]

    def is_binary(self, file_path: str) -> bool:
        """
        Check if a file is binary.
        
        Args:
            file_path (str): Path to the file to check.
            
        Returns:
            bool: True if the file is binary, False otherwise.
        """
        try:
            with open(file_path, 'tr') as check_file:
                check_file.read(1024)
                return False
        except UnicodeDecodeError:
            return True

    def should_skip_file(self, file_path: str) -> bool:
        """
        Check if a file should be skipped based on extension or directory.
        
        Args:
            file_path (str): Path to the file to check.
            
        Returns:
            bool: True if the file should be skipped, False otherwise.
        """
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension in self.exclude_extensions:
            return True
        
        path_parts = Path(file_path).parts
        return any(part in self.exclude_dirs for part in path_parts)
    
    def calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy for a string.
        
        Higher entropy indicates a more random string, which is more likely to be a secret.
        
        Args:
            string (str): The string to calculate entropy for.
            
        Returns:
            float: The calculated entropy value.
        """
        if not string:
            return 0
            
        entropy = 0
        string_length = len(string)
        char_count = {}
        
        for char in string:
            if char in char_count:
                char_count[char] += 1
            else:
                char_count[char] = 1
                
        for count in char_count.values():
            probability = count / string_length
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def is_likely_false_positive(self, match_string: str) -> bool:
        """
        Check if a matched string is likely a false positive.
        
        Args:
            match_string (str): The matched string to check.
            
        Returns:
            bool: True if likely a false positive, False otherwise.
        """
        lower_match = match_string.lower()
        for pattern in self.false_positive_patterns:
            if re.search(pattern, lower_match):
                return True
        return False

    def scan_file(self, file_path: str) -> Dict[str, List[str]]:
        """
        Scan a single file for secrets.
        
        Args:
            file_path (str): Path to the file to scan.
            
        Returns:
            dict: Dictionary of findings organized by secret type.
        """
        if self.should_skip_file(file_path) or self.is_binary(file_path):
            return {}

        findings = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for secret_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    match_text = match.group()
                    
                    # Filter false positives
                    if self.is_likely_false_positive(match_text):
                        continue
                        
                    # If it's a potential secret, check entropy
                    if len(match_text) > 8 and secret_type != 'private_key' and secret_type != 'pem_certificate':
                        entropy = self.calculate_entropy(match_text)
                        if entropy < self.entropy_threshold:
                            continue
                    
                    line_number = content.count('\n', 0, match.start()) + 1
                    context_lines = []
                    
                    # Add line context (2 lines before and after)
                    lines = content.split('\n')
                    start_line = max(0, line_number - 3)
                    end_line = min(len(lines), line_number + 2)
                    
                    for i in range(start_line, end_line):
                        if i == line_number - 1:  # Current line (subtract 1 because we index from 0)
                            context_lines.append(f"--> {i+1}: {lines[i]}")
                        else:
                            context_lines.append(f"    {i+1}: {lines[i]}")
                    
                    if secret_type not in findings:
                        findings[secret_type] = []
                    
                    findings[secret_type].append({
                        "line": line_number,
                        "match": match_text,
                        "entropy": round(self.calculate_entropy(match_text), 2) if len(match_text) > 3 else "N/A",
                        "context": "\n".join(context_lines)
                    })
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")
            
        return findings

    def scan_directory(self, directory: str) -> Dict[str, Dict[str, List[str]]]:
        """
        Scan an entire directory recursively for secrets.
        
        Args:
            directory (str): Path to the directory to scan.
            
        Returns:
            dict: Dictionary of findings organized by file path and secret type.
        """
        all_findings = {}
        
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                findings = self.scan_file(file_path)
                
                if findings:
                    relative_path = os.path.relpath(file_path, directory)
                    all_findings[relative_path] = findings
                    
        return all_findings

    def print_console_summary(self, findings: Dict[str, Dict[str, List[str]]]):
        """
        Display a readable summary in the console.
        
        Args:
            findings (dict): Dictionary of findings to summarize.
        """
        total_files = len(findings)
        total_secrets = sum(len(secrets) for file_findings in findings.values() for secrets in file_findings.values())
        
        # Count secrets by type
        secret_type_counts = {}
        files_per_type = {}
        for file_findings in findings.values():
            for secret_type, secrets in file_findings.items():
                if secret_type not in secret_type_counts:
                    secret_type_counts[secret_type] = 0
                    files_per_type[secret_type] = 0
                secret_type_counts[secret_type] += len(secrets)
                files_per_type[secret_type] += 1
        
        # Determine risk level
        risk_level = "LOW"
        if total_secrets > 10:
            risk_level = "MEDIUM"
        if total_secrets > 30:
            risk_level = "HIGH"
        if total_secrets > 50:
            risk_level = "CRITICAL"
        
        print("\n" + "="*60)
        print(f"SECRET SCANNING REPORT")
        print("="*60)
        print(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Number of files with secrets: {total_files}")
        print(f"Total number of secrets found: {total_secrets}")
        print(f"Risk level: {risk_level}")
        print("\nSUMMARY BY TYPE:")
        for secret_type in sorted(secret_type_counts.keys()):
            print(f"- {secret_type}:")
            print(f"  * Found in {files_per_type[secret_type]} files")
            print(f"  * Number of occurrences: {secret_type_counts[secret_type]}")
        print("-"*60)
        
        if findings:
            for file_path, file_findings in findings.items():
                print(f"\nFile: {file_path}")
                for secret_type, matches in file_findings.items():
                    print(f"  {secret_type}:")
                    for match in matches:
                        print(f"    - {match}")
                print("-"*40)
        else:
            print("\nNo secrets found.")
        
        print("="*60)

    def generate_report(self, findings: Dict[str, Dict[str, List[str]]], output_file: str):
        """
        Generate reports in JSON and HTML formats and display console summary.
        
        Args:
            findings (dict): Dictionary of findings to report.
            output_file (str): Path to save the JSON report file.
        """
        # Display console summary
        self.print_console_summary(findings)
        
        # Generate JSON report
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_files_with_secrets': len(findings),
            'findings': findings
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        # Generate HTML report
        html_output = output_file.replace('.json', '.html')
        html_content = self._generate_html_report(findings)
        with open(html_output, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\nReports have been saved to:")
        print(f"- JSON: {output_file}")
        print(f"- HTML: {html_output}")

    def _generate_html_report(self, findings: Dict[str, Dict[str, List[str]]]) -> str:
        """
        Generate HTML report.
        
        Args:
            findings (dict): Dictionary of findings to include in the HTML report.
            
        Returns:
            str: HTML content as a string.
        """
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Secrets Scanning Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                h1 {{ color: #333; text-align: center; }}
                .summary {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .file-section {{ margin-bottom: 30px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .file-header {{ background-color: #007bff; color: white; padding: 10px; border-radius: 3px; margin-bottom: 10px; }}
                .secret-type {{ margin: 10px 0; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #28a745; }}
                .secret-instance {{ margin-left: 20px; color: #dc3545; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Secrets Scanning Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>Number of files with secrets: {len(findings)}</p>
                </div>
        """
        
        for file_path, file_findings in findings.items():
            html += f"""
                <div class="file-section">
                    <div class="file-header">
                        <h3>{file_path}</h3>
                    </div>
            """
            
            for secret_type, matches in file_findings.items():
                html += f"""
                    <div class="secret-type">
                        <h4>{secret_type}</h4>
                """
                for match in matches:
                    html += f'<div class="secret-instance">{match}</div>'
                html += "</div>"
            
            html += "</div>"
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html

def main():
    """
    Main function that parses command-line arguments and runs the secret scanner.
    """
    parser = argparse.ArgumentParser(description='Secret Scanner for Code Repositories')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--output', '-o', default='secret_scan_report.json',
                       help='Output file path (default: secret_scan_report.json)')
    parser.add_argument('--entropy', '-e', type=float, default=4.5, 
                      help='Entropy threshold for secret detection (default: 4.5)')
    parser.add_argument('--config', '-c', 
                      help='Path to configuration file with additional patterns')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Enable verbose logging')
    parser.add_argument('--severity', '-s', choices=['low', 'medium', 'high'], default='medium',
                      help='Scan severity level (default: medium)')
    
    args = parser.parse_args()
    
    # Configure logging level
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.getLogger('SecretScanner').setLevel(log_level)
    
    # Load custom patterns if configuration file specified
    custom_patterns = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                custom_patterns = json.load(f)
                print(f"Loaded {len(custom_patterns)} custom patterns from {args.config}")
        except Exception as e:
            print(f"Error loading configuration file: {str(e)}")
    
    # Adjust entropy threshold based on severity level
    entropy_threshold = args.entropy
    if args.severity == 'low':
        entropy_threshold = 5.5
    elif args.severity == 'high':
        entropy_threshold = 3.5
    
    scanner = SecretScanner(custom_patterns=custom_patterns, entropy_threshold=entropy_threshold)
    print(f"Starting scan: {args.path}")
    
    findings = scanner.scan_directory(args.path)
    scanner.generate_report(findings, args.output)
    
    # Return error code if secrets found (useful for CI/CD)
    if findings:
        exit(1)

if __name__ == '__main__':
    main()
