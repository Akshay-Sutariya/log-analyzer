
import re
from collections import Counter

def failed_logins(log_file):
	
	with open(log_file,'r') as file:
		lines = file.readlines()
		
	failed_attempts = []
	
	for line in lines:
		if "Failed password" in line:
			failed_attempts.append(line.strip())
	
	return failed_attempts
	

def extract_ip_user_from_logs(lines):

	ip_pattern = r"from (\d{1,3}(?:\.\d{1,3}){3})"
	username_pattern = r"for (?:invalid user )?(\w+)"
	
	ips = []
	user = []
	
	for line in lines:
		ip_match = re.search(ip_pattern,line)
		user_match = re.search(username_pattern,line)
	
		if ip_match:
			ips.append(ip_match.group(1))
		if user_match:
			user.append(user_match.group(1))
	
	return ips,user
	
def display_top_ips(ips):

	counter = Counter(ips)
	print("\n🔐 Top Suspicious IPs:")
	for ip,count in counter.most_common(5):
		print(f"{ip} → {count} failed attempts")	
	

if __name__ == "__main__" :
	
	log_file = "auth.log"
	
	failed_attempts = failed_logins(log_file)
	
	print("[+]Failed Login attempts: ",len(failed_attempts))
	 
	ips, users = extract_ip_user_from_logs(failed_attempts)
	
	display_top_ips(ips)

	with open("Failed_Logins.txt",'w') as file:
		for line in failed_attempts:
			file.write(line + "\n")
			
	print("Failed Attempts Saved in Failed_logins.txt File")
		
