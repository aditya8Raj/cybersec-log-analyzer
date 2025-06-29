# 🔒 Log Analyzer Tool for SOC Analysts

A comprehensive Python-based tool designed for Security Operations Center (SOC) analysts to detect and analyze suspicious activities in system logs, particularly SSH authentication logs.

## 🎯 Features

- **Brute-Force Detection**: Automatically identifies IP addresses with multiple failed login attempts
- **Failed SSH Login Analysis**: Parses and analyzes SSH authentication failures
- **Root Login Monitoring**: Tracks unauthorized root access attempts
- **Successful Login Tracking**: Monitors legitimate authentication events
- **IP Reputation Analysis**: Provides threat level assessment for each IP address
- **Multiple Export Formats**: Export results to CSV or JSON for further analysis
- **Command-Line Interface**: Easy-to-use CLI with multiple options
- **Modular Design**: Clean, maintainable code structure with separate utility functions

## 📁 Project Structure

```
cybersec_project/
├── logs/
│   └── auth.log              # Sample log file
├── analyzer.py               # Main analysis script
├── utils.py                  # Utility functions
├── README.md                 # This file
└── requirements.txt          # Dependencies (optional)
```

## 🚀 Quick Start

### Basic Usage

```bash
# Analyze log file with default settings
python analyzer.py logs/auth.log

# Custom brute-force threshold (default is 5)
python analyzer.py logs/auth.log --threshold 10

# Export results to CSV
python analyzer.py logs/auth.log --export csv

# Export results to JSON with custom filename
python analyzer.py logs/auth.log --export json --output security_report.json
```

### Advanced Usage

```bash
# Show top 10 attacking IPs
python analyzer.py logs/auth.log --top-attackers 10

# Check reputation for specific IP
python analyzer.py logs/auth.log --check-ip 192.168.1.10

# Quiet mode (minimal output)
python analyzer.py logs/auth.log --quiet --export csv
```

## 🔧 Command-Line Options

| Option            | Description                     | Example                |
| ----------------- | ------------------------------- | ---------------------- |
| `log_file`        | Path to log file (required)     | `logs/auth.log`        |
| `--threshold, -t` | Brute-force detection threshold | `--threshold 10`       |
| `--export, -e`    | Export format (csv/json)        | `--export csv`         |
| `--output, -o`    | Output file path                | `--output results.csv` |
| `--top-attackers` | Show top N attacking IPs        | `--top-attackers 5`    |
| `--check-ip`      | Check specific IP reputation    | `--check-ip 1.2.3.4`   |
| `--quiet, -q`     | Suppress detailed output        | `--quiet`              |

## 📊 Sample Output

```
🔒 Log Analyzer Tool for SOC Analysts
==================================================
📂 Loading log file: logs/auth.log
✅ Successfully loaded 30 log entries
🔍 Analyzing logs for suspicious activities...
✅ Log analysis completed successfully!

============================================================
          LOG ANALYSIS SECURITY REPORT
============================================================

📊 OVERVIEW:
Total log entries processed: 30
Total failed login attempts: 23
Total successful logins: 3
Unique IP addresses: 6

🚨 BRUTE FORCE ATTACKS DETECTED:
   • 192.168.1.10 → 8 failed attempts ❌
   • 10.0.0.15 → 7 failed attempts ❌
   • 45.33.32.156 → 7 failed attempts ❌

Total brute-force IPs: 3

⚠️  ROOT LOGIN ATTEMPTS:
   • 192.168.1.10 → 1 root login attempts
   • 203.0.113.50 → 3 root login attempts

🔍 TOP ATTACKING IPs:
   • 192.168.1.10 → 8 attempts (🚨 BRUTE FORCE)
   • 10.0.0.15 → 7 attempts (🚨 BRUTE FORCE)
   • 45.33.32.156 → 7 attempts (🚨 BRUTE FORCE)
   • 203.0.113.50 → 3 attempts (⚠️  SUSPICIOUS)
   • 198.51.100.10 → 2 attempts (⚠️  SUSPICIOUS)

✅ SUCCESSFUL LOGINS:
   • 10.0.0.5 → Users: john
   • 192.168.1.100 → Users: alice
   • 172.16.0.10 → Users: bob

============================================================
Report generated on: 2025-06-30 15:30:45
============================================================
```

## 🔍 Detection Capabilities

### 1. Failed Login Detection

- Identifies patterns like "Failed password"
- Detects "Invalid user" attempts
- Tracks authentication failures

### 2. Brute-Force Attack Detection

- Configurable threshold (default: 5 failed attempts)
- IP-based attack pattern recognition
- Threat level assessment

### 3. Root Access Monitoring

- Tracks root login attempts
- Identifies privilege escalation attempts
- Flags unauthorized administrative access

### 4. Successful Login Tracking

- Monitors legitimate authentications
- Tracks user activity patterns
- Correlates with failed attempts

## 📈 Threat Level Classification

| Level        | Criteria                            | Description                                        |
| ------------ | ----------------------------------- | -------------------------------------------------- |
| **CRITICAL** | Brute-force + Root attempts         | High-priority threat requiring immediate attention |
| **HIGH**     | Brute-force attacks                 | Sustained attack pattern detected                  |
| **MEDIUM**   | 3+ failed attempts OR root attempts | Suspicious activity requiring monitoring           |
| **LOW**      | Minimal failed attempts             | Normal or low-risk activity                        |

## 💾 Export Formats

### CSV Export

Contains columns:

- IP Address
- Failed Attempts
- Is Brute Force
- Root Attempts
- Successful Logins

### JSON Export

Structured format with:

- Summary statistics
- Detailed IP analysis
- Timestamp information
- Raw data for integration

## 🛠️ Technical Details

### Log Format Support

Currently supports standard syslog format for SSH authentication:

```
Jun 29 10:34:00 ubuntu sshd[1999]: Failed password for invalid user root from 192.168.1.10 port 445 ssh2
```

### Regex Patterns

- **IP Address**: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
- **Failed Login**: `Failed password|Invalid user|authentication failure`
- **Successful Login**: `Accepted password|session opened`
- **Username**: `for (?:invalid user )?(\w+)`

## 🧪 Testing

Test the tool with the provided sample log file:

```bash
# Run basic analysis
python analyzer.py logs/auth.log

# Test with different thresholds
python analyzer.py logs/auth.log --threshold 3
python analyzer.py logs/auth.log --threshold 10

# Test export functionality
python analyzer.py logs/auth.log --export csv --output test_results.csv
python analyzer.py logs/auth.log --export json --output test_results.json
```

## 🔧 Customization

### Adding New Detection Patterns

Edit `utils.py` to add new regex patterns:

```python
def is_custom_attack(log_line: str) -> bool:
    """Detect custom attack patterns"""
    custom_patterns = [
        r'your_custom_pattern',
        r'another_pattern'
    ]
    return any(re.search(pattern, log_line, re.IGNORECASE) for pattern in custom_patterns)
```

### Extending Analysis

Add new analysis functions to the `LogAnalyzer` class in `analyzer.py`:

```python
def custom_analysis(self) -> Dict:
    """Implement custom analysis logic"""
    # Your custom analysis code here
    pass
```

## 🛡️ Security Considerations

- **Log File Access**: Ensure proper permissions for log file access
- **Data Privacy**: Be mindful of sensitive information in logs
- **False Positives**: Adjust thresholds based on your environment
- **Regular Updates**: Keep detection patterns updated for new threats

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📋 Requirements

- Python 3.6+
- Standard library modules only (no external dependencies required)
- Read access to log files

## 🆘 Troubleshooting

### Common Issues

1. **File Not Found Error**

   ```bash
   python analyzer.py /correct/path/to/logfile.log
   ```

2. **Permission Denied**

   ```bash
   sudo python analyzer.py /var/log/auth.log
   ```

3. **No Results Found**
   - Check log file format
   - Verify log entries contain expected patterns
   - Try lowering the threshold

## 📞 Support

For issues or questions:

- Check the troubleshooting section
- Review the sample log format
- Ensure proper file permissions

## 📄 License

This project is released under the MIT License. See LICENSE file for details.

---

**Created for SOC Analysts by SOC Analysts** 🛡️

_Stay vigilant, stay secure!_
