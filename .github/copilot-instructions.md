<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Copilot Instructions for Log Analyzer Tool

This is a Python-based cybersecurity project designed for SOC (Security Operations Center) analysts. The tool analyzes system logs to detect suspicious activities like brute-force attacks, failed SSH logins, and unauthorized access attempts.

## Project Context

- **Primary Language**: Python 3.6+
- **Domain**: Cybersecurity, Log Analysis, Threat Detection
- **Target Users**: SOC Analysts, Security Engineers, System Administrators
- **Architecture**: Modular CLI tool with utility functions

## Code Style Guidelines

- Follow PEP 8 Python style guidelines
- Use clear, descriptive function and variable names
- Include comprehensive docstrings for all functions
- Add type hints for better code clarity
- Use meaningful comments for complex regex patterns and security logic

## Security Focus Areas

When suggesting code improvements or additions, prioritize:

- **Accuracy**: Minimize false positives in threat detection
- **Performance**: Efficient log parsing for large files
- **Reliability**: Robust error handling for malformed logs
- **Extensibility**: Easy to add new detection patterns
- **Documentation**: Clear explanations for security logic

## Key Components

1. **utils.py**: Utility functions for log parsing, IP extraction, pattern matching
2. **analyzer.py**: Main analysis engine and CLI interface
3. **Log Detection Patterns**: Regex patterns for SSH authentication events
4. **Export Functions**: CSV and JSON output formatting
5. **Threat Assessment**: IP reputation and risk scoring

## When Writing Code

- Prefer standard library modules over external dependencies
- Use regex patterns that are both accurate and performant
- Include error handling for file operations and malformed data
- Add validation for IP addresses and log format compatibility
- Consider scalability for processing large log files

## Security Patterns to Recognize

- SSH brute-force attacks (multiple failed logins from same IP)
- Root login attempts (privilege escalation indicators)
- Invalid user attempts (reconnaissance activities)
- Geographic anomalies in login patterns
- Time-based attack patterns

## Testing Considerations

- Test with various log formats and edge cases
- Validate regex patterns against real-world log samples
- Ensure proper handling of IPv4 addresses
- Test export functionality with different data sizes
- Verify threshold-based detection accuracy
