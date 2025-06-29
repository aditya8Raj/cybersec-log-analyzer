"""
Utility functions for the Log Analyzer Tool
This module contains helper functions for parsing logs, extracting data, and formatting output.
"""

import re
import json
import csv
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, Counter
from datetime import datetime


def read_log_file(file_path: str) -> List[str]:
    """
    Read log file and return list of lines.
    
    Args:
        file_path (str): Path to the log file
        
    Returns:
        List[str]: List of log lines
        
    Raises:
        FileNotFoundError: If the log file doesn't exist
        IOError: If there's an error reading the file
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {file_path}")
    except IOError as e:
        raise IOError(f"Error reading log file: {e}")


def extract_ip_address(log_line: str) -> Optional[str]:
    """
    Extract IP address from a log line using regex.
    
    Args:
        log_line (str): Single log line
        
    Returns:
        Optional[str]: IP address if found, None otherwise
    """
    # Regex pattern to match IPv4 addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, log_line)
    return match.group() if match else None


def is_failed_login(log_line: str) -> bool:
    """
    Check if log line represents a failed login attempt.
    
    Args:
        log_line (str): Single log line
        
    Returns:
        bool: True if failed login, False otherwise
    """
    failed_patterns = [
        r'Failed password',
        r'Invalid user',
        r'authentication failure'
    ]
    
    return any(re.search(pattern, log_line, re.IGNORECASE) for pattern in failed_patterns)


def is_successful_login(log_line: str) -> bool:
    """
    Check if log line represents a successful login.
    
    Args:
        log_line (str): Single log line
        
    Returns:
        bool: True if successful login, False otherwise
    """
    success_patterns = [
        r'Accepted password',
        r'session opened'
    ]
    
    return any(re.search(pattern, log_line, re.IGNORECASE) for pattern in success_patterns)


def is_root_login_attempt(log_line: str) -> bool:
    """
    Check if log line represents a root login attempt.
    
    Args:
        log_line (str): Single log line
        
    Returns:
        bool: True if root login attempt, False otherwise
    """
    return re.search(r'\broot\b', log_line, re.IGNORECASE) is not None


def extract_username(log_line: str) -> Optional[str]:
    """
    Extract username from log line.
    
    Args:
        log_line (str): Single log line
        
    Returns:
        Optional[str]: Username if found, None otherwise
    """
    # Pattern to match username after "for" keyword
    patterns = [
        r'Invalid user (\w+)',
        r'for (?:invalid )?user (\w+)',
        r'for (\w+)(?:\s+from)',
        r'for (\w+)\b'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, log_line, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


def get_timestamp(log_line: str) -> Optional[str]:
    """
    Extract timestamp from log line.
    
    Args:
        log_line (str): Single log line
        
    Returns:
        Optional[str]: Timestamp if found, None otherwise
    """
    # Pattern for common syslog timestamp format
    timestamp_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    match = re.search(timestamp_pattern, log_line)
    return match.group(1) if match else None


def detect_brute_force(failed_attempts: Dict[str, int], threshold: int = 5) -> List[str]:
    """
    Detect brute force attacks based on failed login attempts.
    
    Args:
        failed_attempts (Dict[str, int]): Dictionary of IP addresses and their failed attempt counts
        threshold (int): Minimum number of failed attempts to consider as brute force
        
    Returns:
        List[str]: List of IP addresses flagged as brute force attackers
    """
    return [ip for ip, count in failed_attempts.items() if count > threshold]


def format_summary_report(analysis_results: Dict) -> str:
    """
    Format analysis results into a readable summary report.
    
    Args:
        analysis_results (Dict): Results from log analysis
        
    Returns:
        str: Formatted summary report
    """
    report = []
    report.append("=" * 60)
    report.append("          LOG ANALYSIS SECURITY REPORT")
    report.append("=" * 60)
    report.append("")
    
    # Overview
    report.append("📊 OVERVIEW:")
    report.append(f"Total log entries processed: {analysis_results.get('total_lines', 0)}")
    report.append(f"Total failed login attempts: {analysis_results.get('total_failed', 0)}")
    report.append(f"Total successful logins: {analysis_results.get('total_successful', 0)}")
    report.append(f"Unique IP addresses: {len(analysis_results.get('unique_ips', []))}")
    report.append("")
    
    # Brute force attacks
    brute_force_ips = analysis_results.get('brute_force_ips', [])
    report.append("🚨 BRUTE FORCE ATTACKS DETECTED:")
    if brute_force_ips:
        for ip in brute_force_ips:
            failed_count = analysis_results.get('failed_attempts', {}).get(ip, 0)
            report.append(f"   • {ip} → {failed_count} failed attempts ❌")
        report.append(f"\nTotal brute-force IPs: {len(brute_force_ips)}")
    else:
        report.append("   ✅ No brute force attacks detected")
    report.append("")
    
    # Root login attempts
    root_attempts = analysis_results.get('root_attempts', {})
    if root_attempts:
        report.append("⚠️  ROOT LOGIN ATTEMPTS:")
        for ip, count in root_attempts.items():
            report.append(f"   • {ip} → {count} root login attempts")
        report.append("")
    
    # Top attacking IPs
    failed_attempts = analysis_results.get('failed_attempts', {})
    if failed_attempts:
        report.append("🔍 TOP ATTACKING IPs:")
        top_attackers = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, count in top_attackers:
            status = "🚨 BRUTE FORCE" if ip in brute_force_ips else "⚠️  SUSPICIOUS"
            report.append(f"   • {ip} → {count} attempts ({status})")
        report.append("")
    
    # Successful logins
    successful_logins = analysis_results.get('successful_logins', {})
    if successful_logins:
        report.append("✅ SUCCESSFUL LOGINS:")
        for ip, users in successful_logins.items():
            users_str = ", ".join(users) if isinstance(users, list) else str(users)
            report.append(f"   • {ip} → Users: {users_str}")
        report.append("")
    
    report.append("=" * 60)
    report.append(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("=" * 60)
    
    return "\n".join(report)


def export_to_csv(analysis_results: Dict, output_file: str) -> None:
    """
    Export analysis results to CSV file.
    
    Args:
        analysis_results (Dict): Results from log analysis
        output_file (str): Path to output CSV file
    """
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow(['IP Address', 'Failed Attempts', 'Is Brute Force', 'Root Attempts', 'Successful Logins'])
        
        # Collect all unique IPs
        all_ips = set()
        all_ips.update(analysis_results.get('failed_attempts', {}).keys())
        all_ips.update(analysis_results.get('successful_logins', {}).keys())
        all_ips.update(analysis_results.get('root_attempts', {}).keys())
        
        # Write data for each IP
        brute_force_ips = analysis_results.get('brute_force_ips', [])
        for ip in sorted(all_ips):
            failed_count = analysis_results.get('failed_attempts', {}).get(ip, 0)
            is_brute_force = ip in brute_force_ips
            root_count = analysis_results.get('root_attempts', {}).get(ip, 0)
            successful_users = analysis_results.get('successful_logins', {}).get(ip, [])
            successful_str = ', '.join(successful_users) if successful_users else ''
            
            writer.writerow([ip, failed_count, is_brute_force, root_count, successful_str])


def export_to_json(analysis_results: Dict, output_file: str) -> None:
    """
    Export analysis results to JSON file.
    
    Args:
        analysis_results (Dict): Results from log analysis
        output_file (str): Path to output JSON file
    """
    # Prepare data for JSON export
    export_data = {
        'summary': {
            'total_lines': analysis_results.get('total_lines', 0),
            'total_failed_attempts': analysis_results.get('total_failed', 0),
            'total_successful_logins': analysis_results.get('total_successful', 0),
            'unique_ips_count': len(analysis_results.get('unique_ips', [])),
            'brute_force_ips_count': len(analysis_results.get('brute_force_ips', [])),
            'analysis_timestamp': datetime.now().isoformat()
        },
        'failed_attempts': analysis_results.get('failed_attempts', {}),
        'successful_logins': analysis_results.get('successful_logins', {}),
        'root_attempts': analysis_results.get('root_attempts', {}),
        'brute_force_ips': analysis_results.get('brute_force_ips', []),
        'unique_ips': analysis_results.get('unique_ips', [])
    }
    
    with open(output_file, 'w', encoding='utf-8') as jsonfile:
        json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)


def validate_ip_address(ip: str) -> bool:
    """
    Validate if string is a valid IPv4 address.
    
    Args:
        ip (str): IP address string to validate
        
    Returns:
        bool: True if valid IPv4, False otherwise
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        
        return True
    except:
        return False
