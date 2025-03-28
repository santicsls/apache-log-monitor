# Apache Log Monitor

A Python tool to monitor Apache logs in real-time, detect malicious requests, and log them to SQLite. Reads `/var/log/apache2/access.log` and charts top URLs.

## Purpose
- Monitors live requests
- Flags suspicious activity (e.g., `.env`, SQL injections)
- Scalable for future features

## Education
- Teaches log analysis and security basics
- Ideal for learning Python and attack patterns

## Attack Mitigation
- Spots threats early
- Logs for forensics

## Future
- Reports in PDF/HTML
- Data export

## Usage
1. Install: `pip install tailer matplotlib`
2. Run: `screen -dm python3 apache_log_monitor.py`
3. Stop: `Ctrl+C`

Requires Python 3 and log access.

## Contributions
Open to PRs and issues.

## License
MIT
