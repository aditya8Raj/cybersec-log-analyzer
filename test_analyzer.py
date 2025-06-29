"""
Unit tests for the Log Analyzer Tool
This file contains basic tests for the utility functions
"""

import unittest
import tempfile
import os
from utils import (
    extract_ip_address, is_failed_login, is_successful_login,
    is_root_login_attempt, extract_username, detect_brute_force,
    validate_ip_address, read_log_file
)


class TestLogAnalyzerUtils(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_extract_ip_address(self):
        """Test IP address extraction from log lines."""
        test_cases = [
            ("Jun 29 10:34:00 ubuntu sshd[1999]: Failed password for invalid user root from 192.168.1.10 port 445 ssh2", "192.168.1.10"),
            ("Failed login from 10.0.0.1", "10.0.0.1"),
            ("No IP address in this line", None),
            ("Multiple IPs 192.168.1.1 and 10.0.0.1", "192.168.1.1"),  # Returns first match
        ]
        
        for log_line, expected in test_cases:
            with self.subTest(log_line=log_line):
                result = extract_ip_address(log_line)
                self.assertEqual(result, expected)
    
    def test_is_failed_login(self):
        """Test failed login detection."""
        failed_lines = [
            "Failed password for user test",
            "Invalid user admin",
            "authentication failure for root"
        ]
        
        success_lines = [
            "Accepted password for user test",
            "session opened for user test",
            "Regular log message"
        ]
        
        for line in failed_lines:
            with self.subTest(line=line):
                self.assertTrue(is_failed_login(line))
        
        for line in success_lines:
            with self.subTest(line=line):
                self.assertFalse(is_failed_login(line))
    
    def test_is_successful_login(self):
        """Test successful login detection."""
        success_lines = [
            "Accepted password for user test",
            "session opened for user test"
        ]
        
        failed_lines = [
            "Failed password for user test",
            "Invalid user admin",
            "Regular log message"
        ]
        
        for line in success_lines:
            with self.subTest(line=line):
                self.assertTrue(is_successful_login(line))
        
        for line in failed_lines:
            with self.subTest(line=line):
                self.assertFalse(is_successful_login(line))
    
    def test_is_root_login_attempt(self):
        """Test root login attempt detection."""
        root_lines = [
            "Failed password for root",
            "Accepted password for root",
            "Invalid user root"
        ]
        
        non_root_lines = [
            "Failed password for user test",
            "Accepted password for admin",
            "Regular log message"
        ]
        
        for line in root_lines:
            with self.subTest(line=line):
                self.assertTrue(is_root_login_attempt(line))
        
        for line in non_root_lines:
            with self.subTest(line=line):
                self.assertFalse(is_root_login_attempt(line))
    
    def test_extract_username(self):
        """Test username extraction from log lines."""
        test_cases = [
            ("Failed password for user john", "john"),
            ("Failed password for invalid user admin", "admin"),
            ("Accepted password for alice", "alice"),
            ("Invalid user test", "test"),
            ("No username in this line", None)
        ]
        
        for log_line, expected in test_cases:
            with self.subTest(log_line=log_line):
                result = extract_username(log_line)
                self.assertEqual(result, expected)
    
    def test_detect_brute_force(self):
        """Test brute force detection algorithm."""
        failed_attempts = {
            "192.168.1.10": 8,
            "10.0.0.5": 3,
            "203.0.113.50": 6,
            "198.51.100.10": 2
        }
        
        # Test with default threshold (5)
        brute_force_ips = detect_brute_force(failed_attempts)
        expected = ["192.168.1.10", "203.0.113.50"]
        self.assertEqual(sorted(brute_force_ips), sorted(expected))
        
        # Test with custom threshold (3)
        brute_force_ips = detect_brute_force(failed_attempts, threshold=3)
        expected = ["192.168.1.10", "203.0.113.50"]
        self.assertEqual(sorted(brute_force_ips), sorted(expected))
        
        # Test with high threshold (10)
        brute_force_ips = detect_brute_force(failed_attempts, threshold=10)
        self.assertEqual(brute_force_ips, [])
    
    def test_validate_ip_address(self):
        """Test IP address validation."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]
        
        invalid_ips = [
            "256.1.1.1",
            "192.168.1",
            "192.168.1.1.1",
            "not.an.ip.address",
            "192.168.-1.1",
            ""
        ]
        
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(validate_ip_address(ip))
        
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(validate_ip_address(ip))
    
    def test_read_log_file(self):
        """Test log file reading functionality."""
        # Create a temporary log file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as temp_file:
            test_content = """Line 1
Line 2
Line 3

Line 5"""
            temp_file.write(test_content)
            temp_file_path = temp_file.name
        
        try:
            # Test successful reading
            lines = read_log_file(temp_file_path)
            expected = ["Line 1", "Line 2", "Line 3", "Line 5"]
            self.assertEqual(lines, expected)
            
            # Test file not found
            with self.assertRaises(FileNotFoundError):
                read_log_file("nonexistent_file.log")
        
        finally:
            # Clean up
            os.unlink(temp_file_path)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete analysis workflow."""
    
    def test_sample_log_analysis(self):
        """Test analysis with the sample log file."""
        log_file = "logs/auth.log"
        
        # Skip if sample log doesn't exist
        if not os.path.exists(log_file):
            self.skipTest("Sample log file not found")
        
        from analyzer import LogAnalyzer
        
        analyzer = LogAnalyzer(log_file, brute_force_threshold=5)
        self.assertTrue(analyzer.load_logs())
        
        results = analyzer.analyze_logs()
        self.assertIsInstance(results, dict)
        self.assertIn('total_failed', results)
        self.assertIn('brute_force_ips', results)
        self.assertGreater(results['total_failed'], 0)


def run_tests():
    """Run all tests and display results."""
    print("🧪 Running Log Analyzer Unit Tests")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✅ All tests passed!")
    else:
        print(f"❌ {len(result.failures)} test(s) failed")
        print(f"❌ {len(result.errors)} error(s) occurred")
    print("=" * 50)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()
