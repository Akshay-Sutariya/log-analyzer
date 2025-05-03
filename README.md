# Log Analyzer  🛡️

A Python-based log analysis tool to detect and analyze failed login attempts from `auth.log` files.  
This tool helps cybersecurity analysts quickly identify top offending IPs, usernames, and geographical locations using GeoIP integration.

---

## 📂 Project Structure

```
log-analyzer/
├── auth.log               # Sample SSH log file for testing
├── log_analyzer_v2.py     # added Basic failed login extraction
├── log_analyzer_v3.py     # added show Top 5 IPs attempts
├── log_analyzer_v4.py     # GeoIP location added to analysis
├── log_analyzer_v5.py     # Email alert added for fast action
├── log_analyzer_v6.py     # added Auto ip blocking using iptables
├── log_analyzer_v7.py     # added Gnerate HTML report
├── log_analyzer_v8.py     # added Fetch AbuseIPDB Score using API
├── README.md              # Project documentation
```

---

## 🚀 Features

- Extracts failed SSH login attempts.
- Lists IP addresses and usernames.
- Displays the top offending IP addresses.
- GeoIP integration: Find country and city of attackers.
- Send email alert to admin if threshold is exceed.
- Auto block ips if set threshold is exceeded.
- Gnerate clean HTML report and show after scan.
- Fetch AbuseIPDB Score using API
- Output results into a text file (optional).

---

## ⚙️ How to Use

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Akshay-Sutariya/log-analyzer.git
   cd log-analyzer
   ```

2. **Download GeoLite2 City Database:**
   - Download from [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
   - Place the `.mmdb` file in your project directory.

3. **Run the Analyzer:**
   ```bash
   python log_analyzer_v4.py
   ```

---

## ✨ Version Highlights

| Version | Changes |
| :------ | :------ |
| V2 | Extracted failed login attempts (IP + username) |
| V3 | Counted and displayed top 5 offending IPs |
| V4 | Integrated GeoIP database to locate IP addresses (Country, City) |
| V5 | Set an email alert to admin if threshold exceeded for one ip address |
| V6 | Auto block suspicious ip after alerting admin |
| V7 | Added Gnerate HTML report |
| V8 | added Fetch AbuseIPDB Score using API |

---


## ⚙️ Requirements:

- Python 3.x
- `smtplib` (built-in for emails)
- `email` (built-in)
- `argparse` (built-in)
- `geoip2` (install via pip)
- `re` and `os` (built-in)
- `subprocess` (built-in)
- `PrettyTable` (built-in)
- `webbrowser` (built-in)

Install external dependencies:
```bash
pip install geoip2
pip install requests
```

---


## 🤝 Contributing

Pull requests are welcome!  
For major changes, please open an issue first to discuss what you would like to change.

---

## 🔗 Connect with Me

- LinkedIn: [Akshay Sutariya](https://www.linkedin.com/in/akshay-sutariya2404/)
- GitHub: [Akshay-Sutariya](https://github.com/Akshay-Sutariya)

---


## 🧪 How to Use

```bash
python3 log_analyzer.py
