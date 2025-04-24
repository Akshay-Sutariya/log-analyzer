# Enhancing error handling and user arguments using 'argparse' 

import argparse
import re
from collections import Counter

def parse_args():

	parser = argparse.ArgumentParser(description="Analyze failed SSH login attempts.")
	parser.add_argument("--logfile", type=str, default="auth.log", help="Path to the log file.")
	parser.add_argument("--top", type=int, default=5, help="Display number of top Failed attempts IPs.")
	parser.add_argument("--output", type=str, default="failed_logins.txt", help="Output file name")
	
	return parser.parse_args()  
	
	
def analyze_log(log_file,top,output_file):
	
	pattern = re.compile(  r"(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*sshd\[.*\]: Failed password for( invalid user)? (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)" )
	
	ip_counter = Counter()
	
	failed_attempts = []
	
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
			
	print(f"Output saved in {output_file}\nTop {top} IPs with failed login attempts:")
	
	for ip, count in ip_counter.most_common(top):
         	print(f"{ip}: {count} attempts")
			
	
	 
		
		
		
if __name__ == "__main__":
	
	args = parse_args()
	
	analyze_log(args.logfile,args.top,args.output)
	
