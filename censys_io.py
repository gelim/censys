#!/usr/bin/env python
#
# Test of censys python module
# -- gelim

from censys.ipv4     import *
from censys.base     import *
from pprint          import pprint
from urllib          import quote,unquote
from colorama        import Fore, Back, Style
import tempfile
import argparse
import pickle
import time, sys, re, os

# API is time limited
# 0.2 tokens/second (60.0 per 5 minute)
report_buckets=50
filter_fields = ['location.country', 'location.country_code', 'location.city', 'ip', \
                 'protocols', 'autonomous_system.name', \
                 'autonomous_system.asn', \
                 '443.https.tls.certificate.parsed.subject.organization', \
                 '443.https.tls.certificate.parsed.subject.common_name', \
                 '443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names', \
                 '993.imaps.tls.tls.certificate.parsed.subject.common_name', \
                 '993.imaps.tls.tls.certificate.parsed.subject.organization',\
                 '80.http.get.title',\
                 '80.http.get.headers.server',\
                 '80.http.get.body',\
                 'metadata.os', 'tags']
report_fields = ['location.country_code', 'location.country.raw', 'ip', \
                 'autonomous_system.asn', 'autonomous_system.organization.raw', \
                 '443.https.tls.certificate.parsed.subject.common_name.raw', \
                 '993.imaps.tls.tls.certificate.parsed.subject.common_name.raw', \
                 '80.http.get.headers.server.raw', \
                 'metadata.os.raw', 'protocols', 'tags.raw']
# computed from --country US --report tags.raw
tags_available = ['http', 'https', 'ssh', 'ftp', 'smtp', 'pop3', 'imap', 'imaps', 'pop3s',
                  'known-private-key', 'rsa-export', 'dhe-export', 'Update utility',
                  'heartbleed', 'building control', 'scada', 'fox', 'NPM', 'bacnet', 'NPM6',
                  'embedded', 'strip-starttls', 'modbus', 'NPM2', 'remote access', 'JACE',
                  'JACE-7', 'NPM3', 'JACE-403', 'Running DD-WRT', 'JACE-545', 's7', 'dnp3',
                  'Broken installation', 'scada processor', 'touchscreen', 'data center',
                  'ethernet']
help_desc='''
Censys query via command line


-- gelim
'''

# res = complete dict from IPv4 search with generic info
def print_short(res):
    max_title_len = 50
    title_head = 'Title: '
    cut = '[...]'
    http_title = res.get('80.http.get.title', ['N/A'])[0]
    cert_name = res.get('443.https.tls.certificate.parsed.subject.common_name', [''])[0]
    cert_alt = res.get('443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names', [''])[0]
    as_name = res.get('autonomous_system.name', ['N/A'])[0]
    as_num = res.get('autonomous_system.asn', [''])[0]
    loc = '%s / %s' % (res.get('location.country_code', ['N/A'])[0], res.get('location.city', ['N/A'])[0])
    os = res.get('metadata.os', ['N/A'])[0]
    tags = res.get('tags', [])

    http_title = http_title.replace('\n', '\\n')
    http_title = http_title.replace('\r', '\\r')
    # do some destructive encoding to ascii
    http_title = unicode(http_title.encode('UTF-8'), errors='ignore')
    cert_name = unicode(cert_name.encode('UTF-8'), errors='ignore')
    cert_alt = unicode(cert_alt.encode('UTF-8'), errors='ignore')
    tags = [ unicode(t.encode('UTF-8'), errors='ignore') for t in tags]
    as_name = unicode(as_name.encode('UTF-8'), errors='ignore')
    os = unicode(os.encode('UTF-8'), errors='ignore')
    loc = unicode(loc.encode('UTF-8'), errors='ignore')

    if cert_alt != '':
        cert_name = cert_name + ' + ' + cert_alt

    # shortun title if too long
    if len(http_title) > (max_title_len - len(title_head) - 1):
        http_title = http_title[:max_title_len - len(title_head) - len(cut) - 1] + cut
    print res['ip'].ljust(16) + \
        ((title_head + '%s') % http_title).ljust(max_title_len) + \
        ('SSL: %s' % cert_name).ljust(50) + \
        ('AS: %s (%s)' % (as_name,as_num)).ljust(40) + \
        ('Loc: %s' % loc).ljust(30) + \
        ('OS: %s' % os).ljust(15) + \
        ('Tags: %s' % ', '.join(tags))

def print_match(res, m):
    for k in res.keys():
        json_find(res[k], k, list(), m)
    print


def print_report(res):
    r = res['results']
    for e in r:
        print ("%d" % e['doc_count']).ljust(10) + str(e['key']).ljust(30)

def build_query_string(args):
    if len(args.arguments) == 0:
        s = '*'
    else:
        s = args.arguments[0]
    if args.tags:
        s += " AND tags:%s" % args.tags
    if args.cert_org:
        s += " AND 443.https.tls.certificate.parsed.subject.organization:\"%s\"" % args.cert_org
    if args.cert_issuer:
        s += " AND 443.https.tls.certificate.parsed.issuer.organization:\"%s\"" % args.cert_issuer
    if args.cert_host:
        s += " AND 443.https.tls.certificate.parsed.subject.common_name:\"%s\"" % args.cert_host
    if args.country:
        s += " AND location.country_code:%s" % args.country
    if args.http_server:
        s += " AND 80.http.get.headers.server:\"%s\"" % args.http_server
    if args.html_title:
        s += " AND 80.http.get.title:\"%s\"" % args.html_title
    if args.debug:
        print 'Query: %s' % s
    return s

# returns true if b is contained inside a
def is_contained(a, b):
    if type(a) == type(b):
        m = re.search(b, a, re.UNICODE+re.IGNORECASE)
        if m:
            return True
        else:
            return False

def print_res(path, match, val):
    sep = ' '
    pre = '[...]'
    post = pre
    pos = match.lower().index(val.lower()) # dirty
    if len(match) >= 80:
        if pos <35:
            pre = ''
        match_c = Style.DIM + pre + match[pos-35:pos] + Fore.RED+Style.BRIGHT + match[pos:pos+len(val)] + \
                Style.RESET_ALL+Style.DIM + match[pos+len(val):pos+35] + post + Style.RESET_ALL
        match = pre + match[pos-35:pos+35] + post
    else:
        match_c = Style.DIM + match[:pos] + Fore.RED+Style.BRIGHT + match[pos:pos+len(val)] + \
                Style.RESET_ALL+Style.DIM + match[pos+len(val):] + Style.RESET_ALL

    match_c = match_c.replace('\n', '\\n')
    match_c = match_c.replace('\r', '\\r')
    match = match.replace('\n', '\\n')
    match = match.replace('\r', '\\r')

    if len(path) >= 60:
        sep = '\n\t'
    if sys.stdout.isatty():
        print "  %s:%s%s" % (path, sep, match_c)
    else:
        print "  %s:%s%s" % (path, sep, match)

def append_if_new(l, e):
    if e not in l:
        return l+[e]
    else:
        return l

# recursively find values in dict 'obj' that macthes 'val'
# store the keys to access the matching value in 'path'
def json_find(obj, k, visited, val):
    if visited is None:
        visited = list()

    # case of sub-dict : recursivity
    if isinstance(obj, dict):
        visited = append_if_new(visited, k)
        #visited = visited + [k]
        for key in obj.keys():
            visited = json_find(obj[key], key, visited, val)

    # case of list : check all members
    elif isinstance(obj, list):
        for e in obj:
            if is_contained(e, val):
                print_res('.'.join(visited+[k]), e, val)

    # finally easiest case, leaf
    elif is_contained(obj, val):
        print_res('.'.join(visited+[k]), obj, val)

    # remove nodes already visited before returning
    if k in visited:
        visited.pop()
    return visited

def print_html(e):
    # html content can be found in several places
    return

def dump_html_to_file(d, rec):
    html = rec.get('80.http.get.body')
    if html:
        filename = "%s/%s.html" % (d, rec['ip'])
        open(filename, "w").write(html[0].encode('UTF-8'))

def conf_get_censys_api(args):
    conf_file = "%s/.censys.p" % os.environ.get('HOME')
    api = dict()
    # command-line API key get precedence other methods
    if args.api_id and args.api_secret:
        api['id'] = args.api_id
        api['secret'] = args.api_secret
        pickle.dump(api, open(conf_file, "wb"))
        return api

    # if conf file exists, load it
    if os.path.isfile(conf_file):
        try:
            api = pickle.load(open(conf_file, "rw"))
        except:
            print "Pickle file corrupted."
            sys.exit(-1)
        if not api.get('id') or not api.get('secret'):
            print "Pickle file structure mismatch."
            sys.exit(-2)
        return api

    # if environment variable exists, store it in file
    if 'CENSYS_API_ID' in os.environ and 'CENSYS_API_SECRET' in os.environ:
        api['id'] = os.environ.get('CENSYS_API_ID')
        api['secret'] = os.environ.get('CENSYS_API_SECRET')
        pickle.dump(api, open(conf_file, "wb"))
        return api

    # warn that apparently nothing worked
    print "You need to give API id and secret either through environment variables with:"
    print "  export CENSYS_API_ID=xxxx; export CENSYS_API_SECRET=yyyy"
    print "or by giving command-line arguments '--api_id xxx' AND '--api_secret yyyy'"
    print
    sys.exit(-2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-m', '--match', default=None, help='Highlight a string within an existing query result')
    parser.add_argument('-f', '--filter', default=None, help='Filter the JSON keys to display for each result (use value \'help\' for interesting fields)')
    parser.add_argument('--count', action='store_true', help='Print the count result and exit')
    parser.add_argument('-r', '--report', default=None, help='Stats on given field (use value \'help\' for listing interesting fields)')
    # query filter shortcuts
    parser.add_argument('-c', '--country', default=None, help='Filter with country')
    parser.add_argument('-o', '--cert-org', default=None, help='Cert issued to org')
    parser.add_argument('-i', '--cert-issuer', default=None, help='Cert issued by org')
    parser.add_argument('-s', '--cert-host', default=None, help='hostname cert is issued to')
    parser.add_argument('-S', '--http-server', default=None, help='Server header')
    parser.add_argument('-t', '--html-title', default=None, help='Filter on html page title')
    parser.add_argument('-T', '--tags', default=None, help='Filter on specific tags (use keyword \'list\' to list usual tags')

    parser.add_argument('--api_id', default=None, help='Censys API ID (optional if no env defined')
    parser.add_argument('--api_secret', default=None, help='Censys API SECRET (optional if no env defined')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug informations')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print raw JSON records')
    parser.add_argument('-l', '--limit', default=float('inf'), help='Limit to N results')
    parser.add_argument('-H', '--html', action='store_true', help='Renders html elements in a browser')
    parser.add_argument('arguments', metavar='arguments', nargs='*', help='Censys query')
    args = parser.parse_args()
    match = unicode(args.match)

    # fire help before doing any request
    if args.tags in ['list', 'help']:
        pprint(tags_available)
        sys.exit(0)
    if args.report in ['list', 'help']:
        pprint(report_fields)
        sys.exit(0)
    if args.filter in ['list', 'help']:
        pprint(filter_fields)
        sys.exit(0)

    # handle API key/secret
    api = conf_get_censys_api(args)

    # build up query
    q = CensysIPv4(api_id=api['id'], api_secret=api['secret'])
    s = build_query_string(args)

    # count the number of results
    try:
        count =  q.report(s, 'ip')['metadata']['count']
    except CensysException as e:
        print e.message
        sys.exit(-1)

    # in reporting/stat mode?
    if args.report:
        try:
            r = q.report(s, args.report, report_buckets)
        except CensysException as e:
            print e.message
            sys.exit(-1)
        print "Number of results: %d" % count
        print_report(r)
        sys.exit(0)

    # count the numbmer of results
    if args.count:
        print count
        sys.exit(0)
    else:
        print "Number of results: %d" % count

    # prepare temp dir for html files
    if args.html:
        htmldir = tempfile.mkdtemp()
        open(htmldir+"/README", "w").write("html body dumped via command:"+' '.join(sys.argv))
        print "HTML body dumped to %s" % htmldir

    # else hit the 'search' API
    if args.filter: filter_fields = args.filter.split(',')
    r = q.search(s, fields=filter_fields)
    i = 0
    for e in r:
        if i >= float(args.limit):
            break
        if args.verbose:
            pprint(q.view(e['ip']))
        elif args.filter:
            pprint(e)
        else:
            print_short(e)
            if args.html: dump_html_to_file(htmldir, e)
            if match != 'None': print_match(q.view(e['ip']), match)
        i += 1


