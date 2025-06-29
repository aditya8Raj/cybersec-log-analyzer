---
name: Bug report
about: Create a report to help us improve the Log Analyzer Tool
title: '[BUG] '
labels: 'bug'
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. With log file '...'
3. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Sample Log Entry**
If applicable, provide a sample log entry that causes the issue:
```
Jun 29 10:34:00 ubuntu sshd[1999]: Failed password for invalid user root from 192.168.1.10 port 445 ssh2
```

**Error Output**
If applicable, add the complete error message:
```
Error output here
```

**Environment (please complete the following information):**
 - OS: [e.g. Ubuntu 20.04, Windows 10, macOS 11]
 - Python Version: [e.g. 3.8.5]
 - Tool Version: [e.g. 1.0.0]

**Command Used**
The exact command you ran:
```bash
python analyzer.py logs/auth.log --export csv
```

**Log File Information**
- Log file size: [e.g. 1MB, 500KB]
- Number of entries: [approximate]
- Log format: [e.g. standard syslog, custom format]

**Additional context**
Add any other context about the problem here. Include any workarounds you've found.
