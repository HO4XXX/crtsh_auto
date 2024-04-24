# crtsh_auto

```


             )        )                      )                     
     (    ( /(     ( /(          )    (   ( /(                (    
  (  )(   )\())(   )\())      ( /(   ))\  )\()) (      `  )   )\ ) 
  )\(()\ (_))/ )\ ((_)\       )(_)) /((_)(_))/  )\     /(/(  (()/( 
 ((_)((_)| |_ ((_)| |(_)     ((_)_ (_))( | |_  ((_)   ((_)_\  )(_))
/ _|| '_||  _|(_-<| ' \      / _` || || ||  _|/ _ \ _ | '_ \)| || |
\__||_|   \__|/__/|_||_|_____\__,_| \_,_| \__|\___/(_)| .__/  \_, |
                       |_____|                        |_|     |__/ 



usage: crtsh_auto.py [-h] [--no-crtsh] [-txt TXT] [-csv CSV] [-oD OD] [-oDwD ODWD] [-verify] [--out-txt] [--out-fullresponses OUT_FULLRESPONSES] [-all] [-U U] [--rate-limit RATE_LIMIT] [-screenshot] [-timeout TIMEOUT] domain

positional arguments:
  domain                the domain you want to enumerate for subs

options:
  -h, --help            show this help message and exit
  --no-crtsh            if this is set no requests to crt.sh will be made. _csv or -txt must be set
  -txt TXT              txt file of subdomains to enumerate
  -csv CSV              csv file containing ONLY Domains!
  -oD OD                File to output found domains to. !NOT ONLY! domains with dns entry!
  -oDwD ODWD            File to output found domains incl record type as csv
  -verify               Verify found domains with http & https
  --out-txt             Save file type. If set, output od -oDwD will be text file only containing the domains!
  --out-fullresponses OUT_FULLRESPONSES
                        save json file to defined file containing all responses. Only works with verify
  -all                  if enabled checks for expired certs too
  -U U                  define custom user Agent to send in Http requests
  --rate-limit RATE_LIMIT
                        Limit requests to n per Second
  -screenshot           Use Selenium only if this is activated. Screenshots are saved in a new generated directory with the name of the scanned domain.
  -timeout TIMEOUT      define http timeout in seconds (default 20)

```
## What it does:

1. get all subdomains from crt.sh
2. read txt/csv file from disk and add it to found domains (optional)
3. deduplicate all found domains
4. check domain via DNS. Is there a A record? 
5. Check if domains answer to http / https (default ports) (optional)


## Json Format:
the output json loks like this: 
```
[
{
    "subdomain": "test.test.com",
    "https": {
      "status_code": 404,
      "text": "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\n </BODY>\n</HTML>\n",                                                               
      "headers": {
        "Server": "AkamaiGHost",
        "Mime-Version": "1.0",
        "Content-Type": "text/html",
        "Connection": "close"
      }
    },
    "http": {
      "status_code": 403,
      "text": "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\</BODY>\n</HTML>\n",                                                               
      "headers": {
        "Server": "AkamaiGHost",
        "Mime-Version": "1.0",
        "Content-Type": "text/html",
        "Connection": "close"
      }
    }
  }, 
  ...
]
```

## Examples

#### Enumerarte subdomains and write file raw txt file with unchecked Domains:

```
./crtsh_auto.py -oD <output> example.com
```

#### Enumerate subdomains and only write domains with active A record to file (csv output containing domain, record type and ip)
```
./crtsh_auto.py -oDwD <output> example.com
```



