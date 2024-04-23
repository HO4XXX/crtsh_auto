#!/usr/bin/python3
import os
import requests
import argparse
import re
import dns.resolver


def extract_subdomains(text, domain):
	pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+{}(?=\s|\b)'.format(re.escape(domain))
#	pattern = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
	dup= re.findall(pattern, text)
	return set(dup)

def queryCrtSh(domain):
	print("[+] Query crt.sh")
	x= requests.get(f"https://crt.sh/?Identity={domain}&exclude=expired")
	if x.status_code == 200:

		domains = x.text
		xtracted_doms = extract_subdomains(x.text, domain)
		for sub in xtracted_doms:
			print("\t\t"+str(sub))
		print(f"[+] Found {len(xtracted_doms)} Subdomains")
		return xtracted_doms
	else:
		print(f"[-] crt.sh returns {x.status_code}")
		print("[-] Error reading crt.sh, Bye!")
		exit(0)

# TODO: Implement Read From CSV
def readFromCSV(filepath):
	
	file = open(filepath, "r")

	all = file.read()
	all = all.replace(";", "\n")


	setted = []
	for line in all.split("\n"):
		if len(line) > 0 and "hilton.io" in line:
			setted.append(line)

	setted = set(setted)
	print(f"[+] Read {len(setted)} subdomains from CSV {filepath}")
	return setted


# TODO: Implement Read From TextFile
def readFromTXT(filepath):
	file = open(filepath, "r")
	all = file.read()
	doms = all.split("\n")
	setted = set(doms)
	print(f"[+] Read {len(setted)} subdomains from TXT {filepath}")
	return setted

def get_ip_addresses(answer):
    ip_addresses = []
    for rdata in answer:
        if rdata.rdtype == dns.rdatatype.A:
            ip_addresses.append(rdata.address)
        elif rdata.rdtype == dns.rdatatype.AAAA:
            ip_addresses.append(rdata.address)
        elif rdata.rdtype == dns.rdatatype.CNAME:
            cname_answer = dns.resolver.resolve(rdata.target, 'A')
            ip_addresses.extend(get_ip_addresses(cname_answer))
    return ip_addresses
	

# TODO: Implement DNS HEalth check
def dnsHealthCheck(domains, records):
	print(f"[+] DNS Health check against Record Types: {records}")
	domains_with_records = list()
	for domain in domains:
		resolver = dns.resolver.Resolver()
		for record_type in records:
			try:
				answer=resolver.resolve(domain)
				
				
				#TODO Get Answer ip
				ips = get_ip_addresses(answer)	
				print(f"\t\t{domain} with {record_type} ips: {ips}")
				domains_with_records.append(domain + "|" + str(record_type) + "|" + str(ips))
				pass
			except dns.resolver.NoAnswer:
				continue 
	print(f"[+] Found {len(domains_with_records)} domains with dns record")
	return domains_with_records
				

# TODO: Implement get & POST to url

# TODO: Implement Custom HEADER

def getDomains(args):
	# Program Flow
	domains = {f'{args.domain}'}
	# query crt.sh
	if not args.no_crtsh:
		domains.update(queryCrtSh(args.domain))
		
		
	if args.txt == None and args.csv == None and not args.no_crtsh:
		print("[-] Error no subdomain input found.")

	# parse txt file	
	if args.txt != None:
		domains.update(readFromTXT(args.txt))
		
	# parse csv file
	if args.csv != None:
		domains.update(readFromCSV(args.csv))
	
	return domains




# Print banner

print('''


             )        )                      )                     
     (    ( /(     ( /(          )    (   ( /(                (    
  (  )(   )\())(   )\())      ( /(   ))\  )\()) (      `  )   )\ ) 
  )\(()\ (_))/ )\ ((_)\       )(_)) /((_)(_))/  )\     /(/(  (()/( 
 ((_)((_)| |_ ((_)| |(_)     ((_)_ (_))( | |_  ((_)   ((_)_\  )(_))
/ _|| '_||  _|(_-<| ' \      / _` || || ||  _|/ _ \ _ | '_ \)| || |
\__||_|   \__|/__/|_||_|_____\__,_| \_,_| \__|\___/(_)| .__/  \_, |
                       |_____|                        |_|     |__/ 


''')

parser = argparse.ArgumentParser()
parser.add_argument("domain", help="the domain you want to enumerate for subs")
parser.add_argument("--no-crtsh", action="store_true", help="if this is set no requests to crt.sh will be made. _csv or -txt must be set")
parser.add_argument("-txt" ,help="txt file of subdomains to enumerate")
parser.add_argument("-csv", help="csv file containing ONLY Domains!")
parser.add_argument("-oD", help="File to output found domains to. !NOT ONLY! domains with dns entry!")
parser.add_argument("-oDwD", help="File to output found domains incl record type as csv")
args = parser.parse_args()

print(args)
# get Domains
print("[+] getting domains!")
domains = getDomains(args)
if len(domains) <=0:
	print(f"[-] Error no domains found!")
	exit(0)
else:
	print(f"[+] Found {len(domains)} Domains:")
	for dom in domains:
		print(f"\t\t {dom}")

if args.oD:
	file=open(args.oD, "w")
	file.write(domains)

# check Domains (DNS)
print(f"[+] Checking {len(domains)} Domains via DNS")
#IMPORTANT: format = <domain>|<reocrd_type>
domains_with_dns = dnsHealthCheck(domains, ['A'])

if args.oDwD:
	file = open(args.oDwD, "w")
	file.write(domains_with_dns.replace("|", ";") )


# Check http / https with Get & POST and Save


# Check requests made for anomalies, custom headers etc




