#!/usr/bin/python3
import os
import requests
import argparse
import re
import dns.resolver
import json
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

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
			except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.SERVFAIL):
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

def capture_screenshot_and_get_headers(domain, subdomain, protocol, args):
    # Fetch the webpage to get the response headers
 

	response = None
	timeout = 20
	if args.timeout:
		timeout = args.timeout
		
	try:
		if args.U:

			response = requests.get(f"{protocol}://{subdomain}/", headers = {"User-Agent" : args.U}, timeout = timeout)

	   
		else:
			response = requests.get(f"{protocol}://{subdomain}/", timeout=timeout)
	except:
		return None
	
	headers = response.headers
	code = response.status_code
	print(f"\t\t{subdomain} - {protocol} - {code}")
 
	if args.screenshot:
	# Set up Selenium WebDriver to capture the screenshot
		chrome_options = Options()
		chrome_options.add_argument("--headless")  # Run Chrome in headless mode (no GUI)
		    
		chrome_options.add_argument(f"User-Agent={args.U}")
		   
		driver = webdriver.Chrome(options=chrome_options)
		
		try:
				# Open the URL in Chrome
			print(1)
			driver.get(f"{protocol}://{subdomain}/")
			print(1)
			# Capture the screenshot
			screenshot_path = f"./{domain}/{protocol}.{code}.{subdomain}.png"
			driver.save_screenshot(screenshot_path)
			print("Screenshot captured successfully.")
		except Exception as e:
			print("Error capturing screenshot:", e)
		finally:
			driver.quit()  # Close the WebDriver session
    
	return response

def verifyDomains(domains, args):
	print(f"[+] Verifying {len(domains)} hosts ...")
	verifyed_domains = list()
	
	for domain in domains:
		#print(domain)
		current= {}
		https = capture_screenshot_and_get_headers(args.domain, domain, "https", args)
		
		if args.rate_limit != None:
			time.sleep(1/args.rate_limit)
		http= capture_screenshot_and_get_headers(args.domain, domain, "http", args)
		if args.rate_limit != None:
			time.sleep(1/args.rate_limit)
		
		
		if https != None:
		
			https_serial = {"status_code": https.status_code, "text": https.text, "headers": dict(https.headers)}
		else:
			https_serial = None
			
		if http != None:
			
			http_serial = {"status_code": http.status_code, "text": http.text, "headers": dict(http.headers)}
			
		else:
			http_serial = None
			
		current=dict({"subdomain": domain, "https": https_serial, "http": http_serial})
		verifyed_domains.append( current)
	
	return verifyed_domains
	


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
parser.add_argument("-verify", action="store_true", help="Verify found domains with http & https")
parser.add_argument("--out-txt" ,action="store_true", help="Save file type. If set, output od -oDwD will be text file only containing the domains!")
parser.add_argument("--out-fullresponses", help="save json file to defined file containing all responses. Only works with verify")
parser.add_argument("-all" , action="store_true", help="if enabled checks for expired certs too" )
parser.add_argument("-U", help="define custom user Agent to send in Http requests")
parser.add_argument("--rate-limit" , type = int, help="Limit requests to n per Second")
parser.add_argument("-screenshot", action="store_true", help="Use Selenium only if this is activated. Screenshots are saved in a new generated directory with the name of the scanned domain.")
parser.add_argument("-timeout", type=int, help="define http timeout in seconds (default 20)")
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
domains = [s.split('|')[0] for s in domains_with_dns]

if args.oDwD:
	file = open(args.oDwD, "w")
	if args.out_txt:
		file.write('\n'.join([s.split('|')[0] for s in domains_with_dns]))
	else:
		file.write('\n'.join([s.replace('|', ';') for s in domains_with_dns]))


# Check http / https with Get & POST and Save
print(f"[+] Verifying {len(domains)} Domains via HTTP / HTTPS")
if args.verify:
	verifyed_domains=verifyDomains(domains, args)
	if args.out_fullresponses:
		file = open(args.out_fullresponses, "w")
		file.write(json.dumps(verifyed_domains))

	
# Check requests made for anomalies, custom headers etc




