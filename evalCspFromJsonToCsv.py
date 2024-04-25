import json
f = open("./hilton.com.json", "r")
json_obj = json.load(f)

for elem in json_obj:
	http_csp = None
	https_csp= None
	
	domain= elem["subdomain"]
	if elem["http"] != None:
		if "Content-Security-Policy" in elem["http"]["headers"]:
			http_csp =elem["http"]["headers"]["Content-Security-Policy"]

	if elem["https"] != None:
		
		#print(elem["https"]["headers"])
		if "Content-Security-Policy" in elem["https"]["headers"]:
			https_csp= elem["https"]["headers"]["Content-Security-Policy"]
	print(f"{domain}; {http_csp}; {https_csp}")


#print(json_obj)
