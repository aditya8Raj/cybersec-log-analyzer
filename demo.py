"""
Demonstration script for the Log Analyzer Tool
This script shows how to use the log analyzer programmatically
"""

import sys
import os

# Add the current directory to the path to import local modules
sys.path.insert(0, os.path.dirname(__file__))

from analyzer import LogAnalyzer


def demo_basic_analysis():
    """Demonstrate basic log analysis functionality."""
    print("🎯 Demo: Basic Log Analysis")
    print("=" * 50)
    
    # Initialize analyzer
    analyzer = LogAnalyzer("logs/auth.log", brute_force_threshold=5)
    
    # Load and analyze logs
    if analyzer.load_logs():
        results = analyzer.analyze_logs()
        if results:
            print(f"✅ Found {len(results['brute_force_ips'])} brute-force attackers")
            print(f"✅ Detected {results['total_failed']} failed login attempts")
            print(f"✅ Tracked {results['total_successful']} successful logins")
    
    return analyzer


def demo_top_attackers():
    """Demonstrate top attackers functionality."""
    print("\n🎯 Demo: Top Attackers Analysis")
    print("=" * 50)
    
    analyzer = LogAnalyzer("logs/auth.log")
    analyzer.load_logs()
    analyzer.analyze_logs()
    
    top_attackers = analyzer.get_top_attackers(3)
    print("Top 3 attacking IPs:")
    for i, (ip, count) in enumerate(top_attackers, 1):
        threat_level = analyzer._calculate_threat_level(ip)
        print(f"{i}. {ip} → {count} attempts ({threat_level})")


def demo_ip_reputation():
    """Demonstrate IP reputation checking."""
    print("\n🎯 Demo: IP Reputation Check")
    print("=" * 50)
    
    analyzer = LogAnalyzer("logs/auth.log")
    analyzer.load_logs()
    analyzer.analyze_logs()
    
    test_ips = ["192.168.1.10", "10.0.0.5", "203.0.113.50"]
    
    for ip in test_ips:
        reputation = analyzer.check_ip_reputation(ip)
        print(f"\n📍 {ip}:")
        print(f"   Failed Attempts: {reputation['failed_attempts']}")
        print(f"   Root Attempts: {reputation['root_attempts']}")
        print(f"   Successful Logins: {len(reputation['successful_logins'])}")
        print(f"   Threat Level: {reputation['threat_level']}")


def demo_export_functionality():
    """Demonstrate export functionality."""
    print("\n🎯 Demo: Export Functionality")
    print("=" * 50)
    
    analyzer = LogAnalyzer("logs/auth.log")
    analyzer.load_logs()
    analyzer.analyze_logs()
    
    # Export to CSV
    analyzer.export_results('csv', 'demo_results.csv')
    print("✅ Exported results to demo_results.csv")
    
    # Export to JSON
    analyzer.export_results('json', 'demo_results.json')
    print("✅ Exported results to demo_results.json")


def main():
    """Run all demonstrations."""
    print("🔒 Log Analyzer Tool - Demonstration Script")
    print("=" * 60)
    
    try:
        # Check if log file exists
        if not os.path.exists("logs/auth.log"):
            print("❌ Error: Sample log file not found!")
            return
        
        # Run demonstrations
        demo_basic_analysis()
        demo_top_attackers()
        demo_ip_reputation()
        demo_export_functionality()
        
        print("\n" + "=" * 60)
        print("✅ All demonstrations completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")


if __name__ == "__main__":
    main()
