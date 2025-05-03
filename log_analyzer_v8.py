# Adding AbuseIPDB scoring using API. 

import requests 
import webbrowser
import subprocess
import os
import geoip2.database
import argparse
import re
import smtplib
from datetime import datetime
from prettytable import PrettyTable
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter

# Read data from database 
reader = geoip2.database.Reader("GeoLite2-City.mmdb")

# Fetch AbuseIPDBn API
API_KEY = 'Your AbuseIPDB API' 

# Email setup
sender_email = "sender@gmail.com"
receiver_email = "reciever@gmail.com"
password = "abc def ghi jkl"  # Not your Gmail password!
THRESHOLD = 2
BLOCKED_IPS_FILE = 'blocked_ips.txt'

# Show help and handle errors 
def parse_args():

	parser = argparse.ArgumentParser(description="Analyze failed SSH login attempts.")
	parser.add_argument("--logfile", type=str, default="auth.log", help="Path to the log file.")
	parser.add_argument("--top", type=int, default=5, help="Display number of top Failed attempts IPs.")
	parser.add_argument("--output", type=str, default="failed_logins.txt", help="Output file name")
	
	return parser.parse_args()  


# Check AbuseIPDB Score
def check_ip_reputation(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    if response.status_code == 200:
        abuse_score = data['data']['abuseConfidenceScore']
        return abuse_score
    else:
        return None
        
        
        
# Email Sending Function
def send_email_alert(ip_address):
    message = MIMEMultipart("alternative")
    message["Subject"] = f"Alert: Multiple Failed Logins from {ip_address}"
    message["From"] = sender_email
    message["To"] = receiver_email

    text = f"""\
    Hi Akshay,
    We detected {THRESHOLD} or more failed login attempts from IP address: {ip_address}.
    This could indicate a potential security issue.
    """
    
    part = MIMEText(text, "plain")
    message.attach(part)

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        print(f"✅ Email sent successfully for IP {ip_address}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")



# Find location of public ip address	
def get_location(ip):
	try:
		response = reader.city(ip)
		country = response.country.name
		city = response.city.name
		
		return country,city
		
	except:
		return "Unknown","Unknown"

# Capture tool action and save in log file
def log_action(message,log_file="alerts.log"):
	timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	with open(log_file,"a") as f:
		f.write(f"[{timestamp}] {message}\n")

 
# Load already blocked IPs
def load_blocked_ips():
    if not os.path.exists(BLOCKED_IPS_FILE):
        return set()
    with open(BLOCKED_IPS_FILE, 'r') as f:
        return set(f.read().splitlines())

# Save newly blocked IP
def save_blocked_ip(ip):
    with open(BLOCKED_IPS_FILE, 'a') as f:
        f.write(ip + '\n')
        
        
# Generate html report
def generate_html_report(data, filename="report.html"):
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SSH Log Report</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: center; }
        th { background-color: #eee; }
    </style>
</head>
<body>
    <h1>SSH Log Analyzer Report</h1>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Attempts</th>
            <th>Location</th>
            <th>Action</th>
            <th>AbuseIDPB Score</th>
        </tr>
    """
    for entry in data:
        ip, count, country, action, AbuseIDPB_Score = entry
        html += f"""
        <tr>
            <td>{ip}</td>
            <td>{count}</td>
            <td>{country}</td>
            <td>{action}</td>
            <td>{AbuseIDPB_Score}</td>
        </tr>
        """
    html += """
    </table>
</body>
</html>
"""
	
    with open(filename, 'w') as f:
        f.write(html)
    webbrowser.open(filename)
    
# Open and extract failed login attempts from log file and count ips.
def analyze_log(log_file,top,output_file):
	
	pattern = re.compile(  r"(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*sshd\[.*\]: Failed password for( invalid user)? (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)" )
	ip_counter = Counter()
	failed_attempts = []
	table = PrettyTable(["IP Address", "Attempts", "Location", "Action", "AbuseIPDB Score"])
	blocked_ips = load_blocked_ips()
	AbuseDPIB_Score = []
	
	# Extact failed login attempts
	with open(log_file,'r') as l_file:
		for line in l_file:
			match = pattern.search(line)
			if match:
				ip = match.group("ip")
				ip_counter[ip] += 1
				failed_attempts.append(line.strip())	
	
	# Write failed attempts in a file
	with open(output_file,'w') as f_out:
		for line in failed_attempts:
			f_out.write(line + "\n")
			
	print(f"Output saved in {output_file}...\n\nSending Alert for Suspicious IP adresses...:")
	result = []
	for ip, count in ip_counter.most_common(top):  #count ips
	
		country, city = get_location(ip) # Get ip location
		
		if count >= THRESHOLD:
		
			send_email_alert(ip) # Send email alert 
			log_action(f"Alert sent for IP {ip} with {count} failed attempts ({country})")
			
			# Block and Save ip in file
			if ip not in blocked_ips:
				subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
				log_action(f"Blocked IP {ip} with {count} failed attempts ({country})")
				save_blocked_ip(ip) 
				action = "Blocked"
			else:
				action = "Already Blocked"
		else:
			action = "Not Suspicious"
		
		# Check AbuseIPDB Score
		score = check_ip_reputation(ip)
		log_action(f"Fetch AbuseIPDB score for IP:{ip}")
		if score is not None:
			AbuseIPDB_Score = score
		else:
			print("[-] Failed to retrieve threat intel.")
		
		# Print in table format
		table.add_row([ip, count, country, action, AbuseIPDB_Score])
		result.append([ip, count, country, action, AbuseIPDB_Score])
	print(table)
	
	generate_html_report(result) # Generate html report 
	
	 	
if __name__ == "__main__":
	
	args = parse_args()
	
	analyze_log(args.logfile,args.top,args.output) # Read and extract log from file 
	
