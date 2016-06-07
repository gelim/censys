Python code to query the Censys public scan database.
This script is made around library censys-python (https://github.com/Censys/censys-python)
and is inteded to make censys queries quick & easy from command-line.

Requirements
------------

You need to create an account on https://censys.io and get your
API key and secret at https://censys.io/account

Important note: your queries will be throttled.
What is allowed is 0.2 tokens/second (60.0 per 5 minute bucket).

`$ pip install censys-python`

Usage
-----

```
usage: censys_io.py [-h] [-m MATCH] [-f FILTER] [--count] [-r REPORT]
                    [-c COUNTRY] [-o CERT_ORG] [-i CERT_ISSUER] [-s CERT_HOST]
                    [-S HTTP_SERVER] [-t HTML_TITLE] [-T TAGS]
                    [--api_id API_ID] [--api_secret API_SECRET] [-d] [-v]
                    [-l LIMIT] [-H]
                    [arguments [arguments ...]]

Censys query via command line

-- gelim

positional arguments:
  arguments             Censys query

optional arguments:
  -h, --help            show this help message and exit
  -m MATCH, --match MATCH
                        Highlight a string within an existing query result
  -f FILTER, --filter FILTER
                        Filter the JSON keys to display for each result (use value 'help' for interesting fields)
  --count               Print the count result and exit
  -r REPORT, --report REPORT
                        Stats on given field (use value 'help' for listing interesting fields)
  -c COUNTRY, --country COUNTRY
                        Filter with country
  -o CERT_ORG, --cert-org CERT_ORG
                        Cert issued to org
  -i CERT_ISSUER, --cert-issuer CERT_ISSUER
                        Cert issued by org
  -s CERT_HOST, --cert-host CERT_HOST
                        hostname cert is issued to
  -S HTTP_SERVER, --http-server HTTP_SERVER
                        Server header
  -t HTML_TITLE, --html-title HTML_TITLE
                        Filter on html page title
  -T TAGS, --tags TAGS  Filter on specific tags (use keyword 'list' to list usual tags
  --api_id API_ID       Censys API ID (optional if no env defined
  --api_secret API_SECRET
                        Censys API SECRET (optional if no env defined
  -d, --debug           Debug informations
  -v, --verbose         Print raw JSON records
  -l LIMIT, --limit LIMIT
                        Limit to N results
  -H, --html            Renders html elements in a browser

```

For full details about the formatting rules for `arguments` see search syntax in page
https://censys.io/ipv4/help?q=x%3Ax

For a quick and dirty test, you can build queries like:
- `foo AND bar` (will do a smart search by checking all keys with value foo and bar)
- `path.to.key:foo`
- `key:foo` (shortcut of previous, but will give strange results if there are collision with other keys)
- `key:/regex/` (regexp support via operator '/')
- `key:"long string with spaces"` (need to quote those strings)
- `key:[200 TO 300]` (int range queries)
- `key:192.168.0.0/24` (IP range query)

Example of use
--------------

### Generic query IP or host (look for anything matching the string in Censys indexed data)

``` shell
$ censys_io.py "censys.io"
Number of results: 4
72.14.246.220   Title: Error 404 (Not Found)!!1                   SSL: www.censys.io + www.censys.io                AS: GOOGLE (15169)                      Loc: US / Mountain View       OS: N/A        Tags: smtp, pop3s, http, imaps, https
104.237.146.167 Title: CloudPiercer                               SSL: www.cloudpiercer.org + www.cloudpiercer.org  AS: LINODE-AP (63949)                   Loc: US / Absecon             OS: N/A        Tags: http, smtp, ssh, https
2.137.164.240   Title: HACKINGYSEGURIDAD.COM HACKING ETICO Y[...] SSL:                                              AS: TELEFONICA_DE_ESPANA (3352)         Loc: ES /                     OS: N/A        Tags: http
51.254.102.155  Title: F-Hack | Quelques lignes sur la scurit     SSL:                                              AS: OVH (16276)                         Loc: FR /                     OS: N/A        Tags: http
```

### Count how much web servers have 'SAP' in their Server header

``` shell
$ censys_io.py -S SAP --count
3266
```

- Get geo reparition of server with ABAP in their 'Server:' header

``` shell
$ censys_io.py -S ABAP --report location.country.raw
Number of results: 585
138       United States                 
90        Germany                       
39        Brazil                        
27        India                         
23        United Kingdom                
21        Turkey                        
17        China                         
16        Italy                         
14        Australia                     
[...]
```

### Retrieve the hosts that have SSL certificate with organization 'Whatsapp'

```
$ censys_io.py --cert-org Whatsapp --limit 10
Number of results: 408
104.236.63.164  Title: phpinfo()                                  SSL: web.whatsapp.com                             AS: DIGITALOCEAN-ASN-NY3 (393406)       Loc: US / New York            OS: Ubuntu     Tags: http, ssh, https
169.55.74.44    Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: US /                     OS: N/A        Tags: https
169.55.69.140   Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: US /                     OS: N/A        Tags: https
169.45.71.55    Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: NL /                     OS: N/A        Tags: https
169.45.71.118   Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: NL /                     OS: N/A        Tags: https
169.54.210.17   Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: US /                     OS: N/A        Tags: https
169.55.235.181  Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: US /                     OS: N/A        Tags: https
169.45.71.42    Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: NL /                     OS: N/A        Tags: https
158.85.5.217    Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: SOFTLAYER (36351)                   Loc: US / Chantilly           OS: N/A        Tags: https
177.75.8.102    Title: N/A                                        SSL: *.whatsapp.net + *.whatsapp.net              AS: Networld Provedor e Servicos de Internet Ltda, BR (28178)Loc: BR /                     OS: N/A        Tags: https
```

- Dumping raw JSON record from database for a specific request
```
$ censys_io.py ip:8.8.8.8 --verbose
Number of results: 1
{u'53': {u'dns': {u'lookup': {u'additionals': [],
                              u'answers': [{u'name': u'c.afekv.com',
                                            u'response': u'192.150.186.1',
                                            u'type': u'A'},
                                           {u'name': u'c.afekv.com',
                                            u'response': u'74.125.76.6',
                                            u'type': u'A'}],
                              u'authorities': [],
                              u'errors': False,
                              u'metadata': {},
                              u'open_resolver': True,
                              u'questions': [{u'name': u'c.afekv.com',
                                              u'type': u'A'}],
                              u'resolves_correctly': True,
                              u'support': True}}},
 u'autonomous_system': {u'asn': 15169,
                        u'country_code': u'',
                        u'description': u'GOOGLE - Google Inc., US',
                        u'name': u'GOOGLE',
                        u'organization': u'Google Inc., US',
                        u'path': [15169],
                        u'rir': u'unknown',
                        u'routed_prefix': u'8.8.8.0/24'},
 u'ip': u'8.8.8.8',
 u'location': {u'city': u'Mountain View',
               u'continent': u'North America',
               u'country': u'United States',
               u'country_code': u'US',
               u'latitude': 37.386,
               u'longitude': -122.0838,
               u'postal_code': u'94040',
               u'province': u'California',
               u'registered_country': u'United States',
               u'registered_country_code': u'US',
               u'timezone': u'America/Los_Angeles'},
 u'metadata': {},
 u'protocols': [u'53/dns'],
 u'tags': [],
 u'updated_at': u'2016-06-02T06:50:30+00:00'}
```

# Listing example of fields we only want to dump in the records

```
$ censys_io.py -f list
['location.country',
 'location.country_code',
 'location.city',
 'ip',
 'protocols',
 'autonomous_system.name',
 'autonomous_system.asn',
 '443.https.tls.certificate.parsed.subject.organization',
 '443.https.tls.certificate.parsed.subject.common_name',
 '443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names',
 '993.imaps.tls.tls.certificate.parsed.subject.common_name',
 '993.imaps.tls.tls.certificate.parsed.subject.organization',
 '80.http.get.title',
 '80.http.get.headers.server',
 '80.http.get.body',
 'metadata.os',
 'tags']
```

### Export scanned page content with title "Pastebin" and are located in the US to disk

```
$ censys_io.py -t "Pastebin" -c US -H
Number of results: 22
HTML body dumped to /tmp/tmpx5HjqB
159.203.3.111   Title: Gparent's Pastebin - Pastebin              SSL: paste.gparent.org + paste.gparent.org        AS: DIGITALOCEAN-ASN-CA1 (394362)       Loc: US / Palatine            OS: N/A        Tags: http, ssh, https
50.87.191.76    Title: AAWiki Pastebin                            SSL: www.aawiki.net + www.aawiki.net              AS: UNIFIEDLAYER-AS-1 (46606)           Loc: US / Provo               OS: N/A        Tags: ftp, http, pop3s, smtp, imaps, pop3, ssh, https, imap
69.12.74.50     Title: Anon PasteBin                              SSL:                                              AS: ASN-QUADRANET-GLOBAL (8100)         Loc: US / Los Angeles         OS: N/A        Tags: http, smtp
192.249.61.201  Title: SPBSlamn Pastebin                          SSL: paste.slamn.org                              AS: RAMNODE (3842)                      Loc: US / Smarr               OS: N/A        Tags: http, smtp, ssh, https
104.131.147.94  Title: NullGrounds - encrypted pastebin           SSL:                                              AS: DIGITALOCEAN-ASN (14061)            Loc: US / San Francisco       OS: N/A        Tags: http
52.33.214.192   Title: 0bin - encrypted pastebin                  SSL: *.splunk.com + *.splunk.com                  AS: AMAZON-02 (16509)                   Loc: US / Wilmington          OS: Ubuntu     Tags: http, https
52.33.225.68    Title: 0bin - encrypted pastebin                  SSL: *.splunk.com + *.splunk.com                  AS: AMAZON-02 (16509)                   Loc: US / Wilmington          OS: Ubuntu     Tags: http, https
198.199.89.94   Title: Borland Turbo Pastebin '88                 SSL:                                              AS: SERVERSTACK-ASN (46652)             Loc: US / New York            OS: N/A        Tags: http, ssh
54.214.41.223   Title: HIC - encrypted pastebin                   SSL: *.ehawaii.gov + *.ehawaii.gov                AS: AMAZON-02 (16509)                   Loc: US / Boardman            OS: N/A        Tags: http, https
152.8.144.20    Title: Addpaste - Php-pastebin                    SSL:                                              AS: NCREN (81)                          Loc: US / Greensboro          OS: N/A        Tags: http
104.236.215.209 Title: 0bin - encrypted pastebin                  SSL:                                              AS: DIGITALOCEAN-ASN-NY3 (393406)       Loc: US / New York            OS: N/A        Tags: http, ssh
168.235.68.149  Title: Pastenib: The Friendly Pastebin            SSL: pastenib.com + pastenib.com                  AS: RAMNODE (3842)                      Loc: US / Smarr               OS: N/A        Tags: http, ssh, https
96.127.160.165  Title: Spear One Resources - Secured Pastebin     SSL: *.spearoneresources.com + *.spearoneresources.comAS: SINGLEHOP-LLC (32475)               Loc: US / Chicago             OS: Unix       Tags: ftp, http, pop3s, imaps, pop3, https, imap
104.131.165.43  Title: Pastebin.com - #1 paste tool since 2002!   SSL:                                              AS: DIGITALOCEAN-ASN-NY3 (393406)       Loc: US / New York            OS: N/A        Tags: http, ssh
69.41.160.228   Title: 69.41 private pastebin - collaborativ[...] SSL:                                              AS: WZCOM-US (40824)                    Loc: US / Dallas              OS: Unix       Tags: http, ssh
50.116.52.75    Title: PasteRack: A Racket-evaluating pastebin    SSL:                                              AS: LINODE-AP (63949)                   Loc: US / Absecon             OS: N/A        Tags: http, ssh
52.49.112.122   Title: Pastebin.com - #1 paste tool since 2002!   SSL:                                              AS: AMAZON-02 (16509)                   Loc: US / Wilmington          OS: Ubuntu     Tags: http, ssh
45.32.238.184   Title: NoteHub &mdash; Free Pastebin for One[...] SSL:                                              AS: AS-CHOOPA (20473)                   Loc: US / Matawan             OS: N/A        Tags: http, ssh
66.55.92.8      Title: Pasted.co  - The pastebin that pays y[...] SSL: www.tny.cz + www.tny.cz                      AS: ASN-GIGENET (32181)                 Loc: US / Arlington Heights   OS: CentOS     Tags: http, https
67.55.70.62     Title: Copy Paste Code | personal pastebin -[...] SSL:                                              AS: WEBAIR-INTERNET (27257)             Loc: US / Garden City         OS: Unix       Tags: ftp, http, ssh
107.150.9.214   Title: This domain which you redirect from, [...] SSL: blog.xopr.net                                AS: CRISSIC (62639)                     Loc: US / Jacksonville        OS: N/A        Tags: http, ssh, https
```

We then can browse '/tmp/tmpx5HjqB' like in ![](doc/html_body.png)

Content is available in key '80.http.get.body' and saved to disk for
offline analysis.  **Beware** of malicious content that could be
viewed from the browser. No filtering is done on the content stored
on disk.

### Use tags provided by censys scanner to look at interesting servers

```
$ censys_io.py --tags heartbleed --report location.country.raw
Number of results: 213034
46565     United States                 
26009     China                         
12383     Germany                       
8138      India                         
8004      Russia                        
6471      United Kingdom                
6111      France                        
5817      Italy                         
5387      Republic of Korea             
5257      Japan
```
