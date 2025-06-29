"""
Help and Usage Guide for the Log Analyzer Tool
This script provides examples and guidance for using the log analyzer
"""

import os
import sys


def print_header():
    """Print the tool header."""
    print("🔒 Log Analyzer Tool - Usage Guide")
    print("=" * 60)
    print("A comprehensive Python tool for SOC analysts to detect")
    print("suspicious activities in system logs.")
    print("=" * 60)


def print_basic_usage():
    """Print basic usage examples."""
    print("\n📋 BASIC USAGE:")
    print("-" * 30)
    print("# Analyze a log file")
    print("python analyzer.py logs/auth.log")
    print()
    print("# Set custom brute-force threshold")
    print("python analyzer.py logs/auth.log --threshold 10")
    print()
    print("# Quiet mode (minimal output)")
    print("python analyzer.py logs/auth.log --quiet")


def print_export_options():
    """Print export functionality examples."""
    print("\n📊 EXPORT OPTIONS:")
    print("-" * 30)
    print("# Export to CSV")
    print("python analyzer.py logs/auth.log --export csv")
    print()
    print("# Export to JSON with custom filename")
    print("python analyzer.py logs/auth.log --export json --output report.json")
    print()
    print("# Quiet analysis with export")
    print("python analyzer.py logs/auth.log --quiet --export csv")


def print_analysis_options():
    """Print analysis-specific options."""
    print("\n🔍 ANALYSIS OPTIONS:")
    print("-" * 30)
    print("# Show top 5 attacking IPs")
    print("python analyzer.py logs/auth.log --top-attackers 5")
    print()
    print("# Check specific IP reputation")
    print("python analyzer.py logs/auth.log --check-ip 192.168.1.10")
    print()
    print("# Low threshold for sensitive environments")
    print("python analyzer.py logs/auth.log --threshold 3 --export csv")


def print_programmatic_usage():
    """Print programmatic usage examples."""
    print("\n🐍 PROGRAMMATIC USAGE:")
    print("-" * 30)
    print("from analyzer import LogAnalyzer")
    print()
    print("# Initialize analyzer")
    print("analyzer = LogAnalyzer('logs/auth.log', brute_force_threshold=5)")
    print()
    print("# Load and analyze")
    print("analyzer.load_logs()")
    print("results = analyzer.analyze_logs()")
    print()
    print("# Get top attackers")
    print("top_attackers = analyzer.get_top_attackers(10)")
    print()
    print("# Check IP reputation")
    print("ip_info = analyzer.check_ip_reputation('192.168.1.10')")


def print_use_cases():
    """Print common use cases."""
    print("\n🎯 COMMON USE CASES:")
    print("-" * 30)
    print("1. Daily Security Monitoring:")
    print("   python analyzer.py /var/log/auth.log --export csv")
    print()
    print("2. Incident Response:")
    print("   python analyzer.py incident_logs.log --threshold 1 --top-attackers 20")
    print()
    print("3. Threat Hunting:")
    print("   python analyzer.py logs/auth.log --check-ip 1.2.3.4")
    print()
    print("4. Automated Reports:")
    print("   python analyzer.py logs/auth.log --quiet --export json --output daily_report.json")


def print_detection_info():
    """Print information about what the tool detects."""
    print("\n🚨 DETECTION CAPABILITIES:")
    print("-" * 30)
    print("• Failed SSH login attempts")
    print("• Brute-force attacks (configurable threshold)")
    print("• Root login attempts")
    print("• Invalid user attempts")
    print("• Successful login tracking")
    print("• IP-based threat assessment")
    print("• Geographic anomaly detection (future)")


def print_threat_levels():
    """Print threat level explanations."""
    print("\n⚠️  THREAT LEVELS:")
    print("-" * 30)
    print("🔴 CRITICAL: Brute-force + Root attempts")
    print("🟠 HIGH:     Brute-force attacks detected")
    print("🟡 MEDIUM:   Multiple failed attempts OR root attempts")
    print("🟢 LOW:      Minimal suspicious activity")


def print_file_formats():
    """Print supported file formats."""
    print("\n📁 SUPPORTED LOG FORMATS:")
    print("-" * 30)
    print("Standard syslog format for SSH authentication:")
    print("Jun 29 10:34:00 server sshd[1999]: Failed password for user from IP port PORT ssh2")
    print()
    print("Example:")
    print("Jun 29 10:34:00 ubuntu sshd[1999]: Failed password for invalid user root from 192.168.1.10 port 445 ssh2")


def print_troubleshooting():
    """Print troubleshooting tips."""
    print("\n🛠️  TROUBLESHOOTING:")
    print("-" * 30)
    print("• File not found: Check file path and permissions")
    print("• No results: Verify log format matches expected pattern")
    print("• Permission denied: Run with appropriate privileges")
    print("• Low detection: Try lowering the threshold (--threshold 3)")


def print_vs_code_tasks():
    """Print VS Code tasks information."""
    print("\n⚡ VS CODE INTEGRATION:")
    print("-" * 30)
    print("Available tasks (Ctrl+Shift+P → 'Tasks: Run Task'):")
    print("• Run Log Analyzer")
    print("• Run Log Analyzer - Export CSV")
    print("• Run Log Analyzer - Export JSON")
    print("• Run Log Analyzer - Top Attackers")
    print("• Run Log Analyzer - Custom Threshold")
    print("• Check IP Reputation")


def main():
    """Main function to display help."""
    print_header()
    print_basic_usage()
    print_export_options()
    print_analysis_options()
    print_programmatic_usage()
    print_use_cases()
    print_detection_info()
    print_threat_levels()
    print_file_formats()
    print_troubleshooting()
    print_vs_code_tasks()
    
    print("\n" + "=" * 60)
    print("🚀 Ready to analyze logs? Start with:")
    print("python analyzer.py logs/auth.log")
    print("=" * 60)
    print()
    
    # Check if sample log exists
    if os.path.exists("logs/auth.log"):
        print("✅ Sample log file found: logs/auth.log")
    else:
        print("⚠️  Sample log file not found. Create logs/auth.log to get started.")
    
    # Check if help is requested via CLI
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        return
    
    # Ask user if they want to run a demo
    print("\n🎯 Would you like to run a demonstration? (y/n)")
    try:
        choice = input().lower().strip()
        if choice in ['y', 'yes']:
            print("\n🚀 Running demonstration...")
            os.system("python demo.py")
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")


if __name__ == "__main__":
    main()
