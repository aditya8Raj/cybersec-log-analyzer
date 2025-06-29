"""
Log Analyzer Tool for SOC Analysts
==================================

A comprehensive Python tool for analyzing system logs to detect suspicious activities
such as brute-force attacks, failed SSH logins, and unauthorized access attempts.

Author: @aditya8raj
Date: June 2025
Version: 1.0
"""

import argparse
import sys
import os
from typing import Dict, List, Tuple
from collections import defaultdict, Counter

# Import utility functions
from utils import (
    read_log_file, extract_ip_address, is_failed_login, is_successful_login,
    is_root_login_attempt, extract_username, get_timestamp, detect_brute_force,
    format_summary_report, export_to_csv, export_to_json, validate_ip_address
)


class LogAnalyzer:
    """
    Main Log Analyzer class for processing and analyzing security logs.
    """
    
    def __init__(self, log_file_path: str, brute_force_threshold: int = 5):
        """
        Initialize the Log Analyzer.
        
        Args:
            log_file_path (str): Path to the log file to analyze
            brute_force_threshold (int): Minimum failed attempts to flag as brute force
        """
        self.log_file_path = log_file_path
        self.brute_force_threshold = brute_force_threshold
        self.log_lines = []
        self.analysis_results = {}
        
    def load_logs(self) -> bool:
        """
        Load log file into memory.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            print(f"📂 Loading log file: {self.log_file_path}")
            self.log_lines = read_log_file(self.log_file_path)
            print(f"✅ Successfully loaded {len(self.log_lines)} log entries")
            return True
        except Exception as e:
            print(f"❌ Error loading log file: {e}")
            return False
    
    def analyze_logs(self) -> Dict:
        """
        Perform comprehensive analysis of loaded logs.
        
        Returns:
            Dict: Analysis results containing various security metrics
        """
        if not self.log_lines:
            print("❌ No log data loaded. Please load logs first.")
            return {}
        
        print("🔍 Analyzing logs for suspicious activities...")
        
        # Initialize counters and collections
        failed_attempts = defaultdict(int)
        successful_logins = defaultdict(list)
        root_attempts = defaultdict(int)
        unique_ips = set()
        total_failed = 0
        total_successful = 0
        
        # Process each log line
        for line_num, line in enumerate(self.log_lines, 1):
            try:
                # Extract IP address
                ip = extract_ip_address(line)
                if ip and validate_ip_address(ip):
                    unique_ips.add(ip)
                    
                    # Check for failed login attempts
                    if is_failed_login(line):
                        failed_attempts[ip] += 1
                        total_failed += 1
                        
                        # Check for root login attempts
                        if is_root_login_attempt(line):
                            root_attempts[ip] += 1
                    
                    # Check for successful logins
                    elif is_successful_login(line):
                        username = extract_username(line)
                        if username:
                            successful_logins[ip].append(username)
                        total_successful += 1
                        
            except Exception as e:
                print(f"⚠️  Warning: Error processing line {line_num}: {e}")
                continue
        
        # Detect brute force attacks
        brute_force_ips = detect_brute_force(failed_attempts, self.brute_force_threshold)
        
        # Compile results
        self.analysis_results = {
            'total_lines': len(self.log_lines),
            'total_failed': total_failed,
            'total_successful': total_successful,
            'failed_attempts': dict(failed_attempts),
            'successful_logins': dict(successful_logins),
            'root_attempts': dict(root_attempts),
            'brute_force_ips': brute_force_ips,
            'unique_ips': list(unique_ips),
            'brute_force_threshold': self.brute_force_threshold
        }
        
        print("✅ Log analysis completed successfully!")
        return self.analysis_results
    
    def print_summary(self) -> None:
        """
        Print a detailed summary of the analysis results.
        """
        if not self.analysis_results:
            print("❌ No analysis results available. Please run analysis first.")
            return
        
        summary_report = format_summary_report(self.analysis_results)
        print(summary_report)
    
    def export_results(self, output_format: str = 'csv', output_file: str = None) -> None:
        """
        Export analysis results to file.
        
        Args:
            output_format (str): Export format ('csv' or 'json')
            output_file (str): Output file path (optional)
        """
        if not self.analysis_results:
            print("❌ No analysis results available. Please run analysis first.")
            return
        
        if not output_file:
            output_file = f"log_analysis_results.{output_format}"
        
        try:
            if output_format.lower() == 'csv':
                export_to_csv(self.analysis_results, output_file)
                print(f"📊 Results exported to CSV: {output_file}")
            elif output_format.lower() == 'json':
                export_to_json(self.analysis_results, output_file)
                print(f"📊 Results exported to JSON: {output_file}")
            else:
                print(f"❌ Unsupported export format: {output_format}")
        except Exception as e:
            print(f"❌ Error exporting results: {e}")
    
    def get_top_attackers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top attacking IP addresses by failed attempt count.
        
        Args:
            limit (int): Maximum number of results to return
            
        Returns:
            List[Tuple[str, int]]: List of (IP, failed_attempts) tuples
        """
        if not self.analysis_results:
            return []
        
        failed_attempts = self.analysis_results.get('failed_attempts', {})
        return sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """
        Check reputation and activity summary for a specific IP.
        
        Args:
            ip (str): IP address to check
            
        Returns:
            Dict: IP reputation summary
        """
        if not self.analysis_results:
            return {}
        
        return {
            'ip_address': ip,
            'failed_attempts': self.analysis_results.get('failed_attempts', {}).get(ip, 0),
            'successful_logins': self.analysis_results.get('successful_logins', {}).get(ip, []),
            'root_attempts': self.analysis_results.get('root_attempts', {}).get(ip, 0),
            'is_brute_force': ip in self.analysis_results.get('brute_force_ips', []),
            'threat_level': self._calculate_threat_level(ip)
        }
    
    def _calculate_threat_level(self, ip: str) -> str:
        """
        Calculate threat level for an IP address.
        
        Args:
            ip (str): IP address
            
        Returns:
            str: Threat level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        failed_count = self.analysis_results.get('failed_attempts', {}).get(ip, 0)
        root_count = self.analysis_results.get('root_attempts', {}).get(ip, 0)
        is_brute_force = ip in self.analysis_results.get('brute_force_ips', [])
        
        if is_brute_force and root_count > 0:
            return "CRITICAL"
        elif is_brute_force:
            return "HIGH"
        elif failed_count > 2 or root_count > 0:
            return "MEDIUM"
        else:
            return "LOW"


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Log Analyzer Tool for SOC Analysts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s logs/auth.log                          # Basic analysis
  %(prog)s logs/auth.log --threshold 10           # Custom brute-force threshold
  %(prog)s logs/auth.log --export csv             # Export to CSV
  %(prog)s logs/auth.log --export json --output results.json
  %(prog)s logs/auth.log --top-attackers 5       # Show top 5 attackers
  %(prog)s logs/auth.log --check-ip 192.168.1.10 # Check specific IP
        """
    )
    
    parser.add_argument(
        'log_file',
        help='Path to the log file to analyze'
    )
    
    parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=5,
        help='Brute-force detection threshold (default: 5)'
    )
    
    parser.add_argument(
        '--export', '-e',
        choices=['csv', 'json'],
        help='Export results to file format'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path for export'
    )
    
    parser.add_argument(
        '--top-attackers',
        type=int,
        metavar='N',
        help='Show top N attacking IPs'
    )
    
    parser.add_argument(
        '--check-ip',
        metavar='IP_ADDRESS',
        help='Check reputation for specific IP address'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress detailed output'
    )
    
    return parser.parse_args()


def main():
    """
    Main function to run the log analyzer.
    """
    print("🔒 Log Analyzer Tool for SOC Analysts")
    print("=" * 50)
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Check if log file exists
    if not os.path.exists(args.log_file):
        print(f"❌ Error: Log file not found: {args.log_file}")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = LogAnalyzer(args.log_file, args.threshold)
    
    # Load and analyze logs
    if not analyzer.load_logs():
        sys.exit(1)
    
    results = analyzer.analyze_logs()
    if not results:
        print("❌ Analysis failed!")
        sys.exit(1)
    
    # Handle specific IP check
    if args.check_ip:
        ip_info = analyzer.check_ip_reputation(args.check_ip)
        if ip_info:
            print(f"\n🔍 IP Reputation Check: {args.check_ip}")
            print(f"Failed Attempts: {ip_info['failed_attempts']}")
            print(f"Root Attempts: {ip_info['root_attempts']}")
            print(f"Successful Logins: {', '.join(ip_info['successful_logins']) if ip_info['successful_logins'] else 'None'}")
            print(f"Brute Force: {'Yes' if ip_info['is_brute_force'] else 'No'}")
            print(f"Threat Level: {ip_info['threat_level']}")
        else:
            print(f"❌ No data found for IP: {args.check_ip}")
        return
    
    # Handle top attackers display
    if args.top_attackers:
        top_attackers = analyzer.get_top_attackers(args.top_attackers)
        print(f"\n🎯 Top {args.top_attackers} Attacking IPs:")
        for i, (ip, count) in enumerate(top_attackers, 1):
            threat_level = analyzer._calculate_threat_level(ip)
            print(f"{i:2d}. {ip} → {count} attempts ({threat_level})")
        return
    
    # Display summary unless quiet mode
    if not args.quiet:
        analyzer.print_summary()
    
    # Export results if requested
    if args.export:
        analyzer.export_results(args.export, args.output)
    
    print("\n✅ Analysis completed successfully!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
