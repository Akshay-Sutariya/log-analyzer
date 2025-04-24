# Log Analyzer 

A Python-based log analyzer that reads Linux SSH authentication logs, extracts failed login attempts, and identifies top attacking IP addresses using regular expressions.

## 🚀 Features

- Filters failed SSH login attempts from `auth.log`
- Extracts:
  - IP addresses
  - Usernames (valid/invalid users)
- Shows top IPs by number of failed attempts
- Saves filtered logs to `failed_logins.txt`

## 📁 Files

| File               | Description                              |
|--------------------|------------------------------------------|
| `log_analyzer.py` | Main Python script                      |
| `auth.log`         | Sample SSH log for testing               |
| `failed_logins.txt`| Output: All failed login attempts found  |
| `README.md`        | This documentation file                  |

## 📦 Requirements

- Python 3.x  
- Works on Kali Linux (or any Linux system with `auth.log`)

## 🧪 How to Use

```bash
python3 log_analyzer.py
