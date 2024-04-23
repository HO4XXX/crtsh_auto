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



usage: crtsh_auto.py [-h] [--no-crtsh] [-txt TXT] [-csv CSV] [-oD OD] [-oDwD ODWD] domain

positional arguments:
  domain      the domain you want to enumerate for subs

options:
  -h, --help  show this help message and exit
  --no-crtsh  if this is set no requests to crt.sh will be made. _csv or -txt must be set
  -txt TXT    txt file of subdomains to enumerate
  -csv CSV    csv file containing ONLY Domains!
  -oD OD      File to output found domains to. !NOT ONLY! domains with dns entry!
  -oDwD ODWD  File to output found domains incl record type as csv

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



