# Sending alert by mail if failed login attempt exceed than 2 for one ip address.

import subprocess
import os
import geoip2.database
import argparse
import re
import smtplib
from prettytable import PrettyTable
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter

# Read data from database 
reader = geoip2.database.Reader("GeoLite2-City.mmdb")

# Email setup
sender_email = "sender@gmail.com"
receiver_email = "receiver@gmail.com"
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
        
	
# Open and extract failed login attempts from log file and count ips.
def analyze_log(log_file,top,output_file):
	
	pattern = re.compile(  r"(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*sshd\[.*\]: Failed password for( invalid user)? (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)" )
	ip_counter = Counter()
	failed_attempts = []
	table = PrettyTable(["IP Address", "Attempts", "Location", "Action"])
	blocked_ips = load_blocked_ips()
	
	with open(log_file,'r') as l_file:
		for line in l_file:
			match = pattern.search(line)
			if match:
				ip = match.group("ip")
				ip_counter[ip] += 1
				failed_attempts.append(line.strip())	
	
	with open(output_file,'w') as f_out:
		for line in failed_attempts:
			f_out.write(line + "\n")
			
	print(f"Output saved in {output_file}...\n\nTop {top} IPs with failed login attempts:")
	
	for ip, count in ip_counter.most_common(top):
		country, city = get_location(ip)
		#print(f"IP Address: {ip} | Count: {count} | Country: {country} | City: {city}")
		if count >= THRESHOLD:
			send_email_alert(ip)
			if ip not in blocked_ips:
				subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
				save_blocked_ip(ip)
				action = "Blocked"
			else:
				action = "Already Blocked"
		else:
			action = "Not Suspicious"
		table.add_row([ip, count, country, action])
	print(table)
	
			
	
	 	
if __name__ == "__main__":
	
	args = parse_args()
	
	analyze_log(args.logfile,args.top,args.output)
	
