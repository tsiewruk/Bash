import os
import re
from pathlib import Path
import argparse
from typing import List, Dict, Set
import json
from datetime import datetime

class SecretScanner:
    def __init__(self):
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
        }
        
        # List of file extensions to skip
        self.exclude_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', 
                                 '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip', 
                                 '.tar', '.gz', '.7z', '.pyc', '.class', '.o', '.so'}
        
        # List of directories to skip
        self.exclude_dirs = {'.git', 'node_modules', 'venv', '.env', '__pycache__', 
                           'build', 'dist', '.idea', '.vscode'}

    def is_binary(self, file_path: str) -> bool:
        """Checks if the file is binary."""
        try:
            with open(file_path, 'tr') as check_file:
                check_file.read(1024)
                return False
        except UnicodeDecodeError:
            return True

    def should_skip_file(self, file_path: str) -> bool:
        """Checks if the file should be skipped."""
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension in self.exclude_extensions:
            return True
        
        path_parts = Path(file_path).parts
        return any(part in self.exclude_dirs for part in path_parts)

    def scan_file(self, file_path: str) -> Dict[str, List[str]]:
        """Scans a single file for secrets."""
        if self.should_skip_file(file_path) or self.is_binary(file_path):
            return {}

        findings = {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for secret_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_number = content.count('\n', 0, match.start()) + 1
                    if secret_type not in findings:
                        findings[secret_type] = []
                    findings[secret_type].append(f"Line {line_number}: {match.group()}")
        except Exception as e:
            print(f"Error while scanning file {file_path}: {str(e)}")
            
        return findings

    def scan_directory(self, directory: str) -> Dict[str, Dict[str, List[str]]]:
        """Scans the entire repository recursively."""
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
        """Displays a clear summary in the console."""
        total_files = len(findings)
        total_secrets = sum(len(secrets) for file_findings in findings.values() for secrets in file_findings.values())
        
        # Counting secrets by type
        secret_type_counts = {}
        files_per_type = {}
        for file_findings in findings.values():
            for secret_type, secrets in file_findings.items():
                if secret_type not in secret_type_counts:
                    secret_type_counts[secret_type] = 0
                    files_per_type[secret_type] = 0
                secret_type_counts[secret_type] += len(secrets)
                files_per_type[secret_type] += 1
        
        print("\n" + "="*60)
        print(f"SECRETS SCANNING REPORT")
        print("="*60)
        print(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Number of scanned files with secrets: {total_files}")
        print(f"Total number of secrets found: {total_secrets}")
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
        """Generates reports in JSON and HTML formats and displays console summary."""
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
        """Generates HTML report."""
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
    parser = argparse.ArgumentParser(description='Repository secrets scanner')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--output', '-o', default='secret_scan_report.json',
                       help='Output file path (default: secret_scan_report.json)')
    
    args = parser.parse_args()
    
    scanner = SecretScanner()
    print(f"Starting scan: {args.path}")
    
    findings = scanner.scan_directory(args.path)
    scanner.generate_report(findings, args.output)

if __name__ == '__main__':
    main()
