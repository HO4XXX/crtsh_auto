#!/usr/bin/python3
import os
import requests
import argparse
import re
import dns.resolver
import json

requests.packages.urllib3.disable_warnings() 

def extract_subdomains(text, domain):
	pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+{}(?=\s|\b)'.format(re.escape(domain))
#	pattern = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
	dup= re.findall(pattern, text)
	return set(dup)

def queryCrtSh(domain):
	print(f"[+] Start Query crt.sh for {domain}... ")
	url=""
	if args.all:
		url=f"https://crt.sh/?Identity={domain}&output=json"
	else:
		url=f"https://crt.sh/?Identity={domain}&exclude=expired&output=json"
	
	x= requests.get(url)
	if x.status_code == 200:
		domains = json.loads(x.text)
		xtracted_doms = list()
		
		for entry in domains:
			xtracted_doms.append(entry['common_name'])
			##print(entry['common_name'])
			var = entry['name_value'].split("\n")
			#print(var)
			#input()
			xtracted_doms.extend(list(entry['name_value'].split("\n")))
			#print(xtracted_doms)
		xtracted_doms = set(xtracted_doms)
		for sub in xtracted_doms:
			print("\t\t"+str(sub))
		print(f"[+] Found {len(xtracted_doms)} Subdomains")
		return xtracted_doms
	else:
		print(f"[-] crt.sh returns {x.status_code}")
		print("[-] Error reading crt.sh, Bye!")
		exit(0)
			
def queryCrtShhtml(domain):
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
			except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
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
		
		
	if args.txt == None and args.csv == None and args.no_crtsh:
		print("[-] Error no subdomain input found.")

	# parse txt file	
	if args.txt != None:
		domains.update(readFromTXT(args.txt))
		
	# parse csv file
	if args.csv != None:
		domains.update(readFromCSV(args.csv))
	
	return domains


def verifyDomains(domains, args):
	print(f"[+] Verifying {len(domains)} hosts ...")
	verifyed_domains = list()
	
	print(f"[+] starting HTTP GET")
	for domain in domains:
		try:
			x = requests.get(f"http://{domain}")
			verifyed_domains[domain] = {"http": { "get" : x}}
			
			print(f"\t\t GET -> {domain} returns {x.status_code}")
			
		except:
			print(f"\t\t No Response from {domain}")
			pass
		
	print(f"[+] starting HTTPS GET")
	for domain in domains:
		try:
			x = requests.get(f"https://{domain}")
			verifyed_domains.append(list(f"https://{domain}", x))
			print(f"\t\t GET -> {domain} returns {x.status_code}")
			
		except:
			print(f"\t\t No Response from {domain}")
			pass
		
	print(f"[+] starting HTTP POST")
	for domain in domains:
		try:
			x = requests.post(f"https://{domain}")
			verifyed_domains.append(list(f"https://{domain}", x))
			print(f"\t\t GET -> {domain} returns {x.status_code}")
			
		except:
			print(f"\t\t No Response from {domain}")
			pass



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
#parser.add_argument("-verify", action="store_true", help="Verify found domains with http & https GT & POST requests")
#parser.add_argument("-all" , action="store_true", help="if enabled checks for expired certs too" )
args = parser.parse_args()


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
	file.write('\n'.join([s.replace('|', ';') for s in domains_with_dns]))


# Check http / https with Get & POST and Save
if args.verify:
	verifyDomains(domains, args)

# Check requests made for anomalies, custom headers etc




