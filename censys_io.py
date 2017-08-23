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
                 'autonomous_system.description.raw', \
                 '443.https.tls.certificate.parsed.subject.common_name.raw', \
                 '993.imaps.tls.tls.certificate.parsed.subject.common_name.raw', \
                 '80.http.get.headers.server.raw', \
                 "80.http.get.title.raw", \
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

# 11.07.2017: not anymore used with new API, yeah!
# res: input dict
# key: full dotted key path like '80.http.get.title'
# returns if it exists the value, else 'N/A'
#def get_subkey(dic, key, default):
#    keys_l = key.split('.')
#    val = str()
#    for k in keys_l:
#        if dic != None:
#            dic = dic.get(k)
#        else:
#            return default
#    if dic == None:
#        return default
#    else:
#        if isinstance(dic, list):
#            return ','.join(dic)
#        return str(dic)


def print_tsv(res):
    bl_filter_fields = ["80.http.get.body"]
    final_line = str.encode('utf-8')
    for k in filter_fields:
        if k not in bl_filter_fields:
            v = res.get(k, "")
            if isinstance(v, list):
                v = ','.join(v)
            if isinstance(v, int):
                v = str(v)
            if ';' in v: v = v.replace('\t', ' ')
            final_line += v + "\t"
    print final_line.encode('utf-8').strip('\t')

# res = complete dict from IPv4 search with generic info
def print_short(res):
    max_title_len = 50
    title_head = 'Title: '
    cut = '[...]'
    http_title = res.get('80.http.get.title', 'N/A')
    cert_name = res.get('443.https.tls.certificate.parsed.subject.common_name', '')
    cert_alt = res.get('443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names', '')
    as_name = res.get('autonomous_system.name', 'N/A')
    as_num = res.get('autonomous_system.asn', '')
    loc = '%s / %s' % (res.get('location.country_code', 'N/A'), res.get('location.city', 'N/A'))
    os = res.get('metadata.os', 'N/A')
    tags = res.get('tags', '')
    ip = res.get('ip', 'N/A')

    http_title = http_title.replace('\n', '\\n')
    http_title = http_title.replace('\r', '\\r')

    # quick cleanup of list values, atm just show the first element
    # or the first followed with a "+" sign to indicate there are more
    if isinstance(cert_name, list):
        if len(cert_name) > 1: cert_name = cert_name[0] + "+"
        else: cert_name = cert_name[0]
    if isinstance(cert_alt, list):
        if len(cert_alt) > 1: cert_alt = cert_alt[0] + "+"
        else: cert_alt = cert_alt[0]
    
    # do some destructive encoding to UTF-8
    http_title = unicode(http_title.encode('UTF-8'), errors='ignore')
    cert_name = unicode(cert_name.encode('UTF-8'), errors='ignore')
    cert_alt = unicode(cert_alt.encode('UTF-8'), errors='ignore')
    tags = ', '.join([ unicode(t.encode('UTF-8'), errors='ignore') for t in tags ])
    as_name = unicode(as_name.encode('UTF-8'), errors='ignore')
    os = unicode(os.encode('UTF-8'), errors='ignore')
    loc = unicode(loc.encode('UTF-8'), errors='ignore')

    if cert_alt != '' and cert_alt != cert_name:
        cert_name = cert_name + ' + ' + cert_alt

    # shortun title if too long
    if len(http_title) > (max_title_len - len(title_head) - 1):
        http_title = http_title[:max_title_len - len(title_head) - len(cut) - 1] + cut
    print ip.ljust(16) + \
        ((title_head + '%s') % http_title).ljust(max_title_len) + \
        ('SSL: %s' % cert_name).ljust(50) + \
        ('AS: %s (%s)' % (as_name,as_num)).ljust(40) + \
        ('Loc: %s' % loc).ljust(30) + \
        ('OS: %s' % os).ljust(15) + \
        ('Tags: %s' % tags)

def print_match(res, m):
    for k in res.keys():
        json_find(res[k], k, list(), m)
    print


def print_report(res, key):
    r = res['results']
    print "count".ljust(10) + "\t" + key.split(".")[-1]
    for e in r:
        print ("%d" % e['doc_count']).ljust(10) + "\t" + unicode(e['key']).ljust(30)

def build_query_string(args):
    if len(args.arguments) == 0:
        s = '*'
    else:
        s = "(" + args.arguments[0] + ")"
    if args.tags:
        if ',' in args.tags:
            tags_l = args.tags.split(',')
            tags_q = " AND tags:" + " AND tags:".join(tags_l)
        else:
            tags_q = " AND tags:%s" % args.tags
        s += tags_q
    if args.asn:
        s += " AND autonomous_system.asn:%s" % args.asn
    if args.cert_org:
        s += " AND 443.https.tls.certificate.parsed.subject.organization:%s" % args.cert_org
    if args.cert_issuer:
        s += " AND 443.https.tls.certificate.parsed.issuer.organization:%s" % args.cert_issuer
    if args.cert_host:
        s += " AND 443.https.tls.certificate.parsed.subject.common_name:%s" % args.cert_host
    if args.country:
        s += " AND location.country_code:%s" % args.country
    if args.http_server:
        s += " AND 80.http.get.headers.server:%s" % args.http_server
    if args.html_title:
        if " " in args.html_title: title = "\"%s\"" % args.html_title
        else: title = args.html_title
        s += " AND 80.http.get.title:%s" % title
    if args.html_body:
        if " " in args.html_body: body = "\"%s\"" % args.html_body
        else: body = args.html_body
        s += " AND 80.http.get.body:%s" % body
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
        open(filename, "w").write(html.encode('UTF-8', errors='ignore'))

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
    parser.add_argument('-B', '--report_bucket', default=report_buckets, help='Bucket len in report mode (default: %s)' % report_buckets)
    # query filter shortcuts
    parser.add_argument('-a', '--asn', default=None, help='Filter with ASN (ex: 25408 for Westcall-SPB AS)')
    parser.add_argument('-c', '--country', default=None, help='Filter with country')
    parser.add_argument('-o', '--cert-org', default=None, help='Cert issued to org')
    parser.add_argument('-i', '--cert-issuer', default=None, help='Cert issued by org')
    parser.add_argument('-s', '--cert-host', default=None, help='hostname cert is issued to')
    parser.add_argument('-S', '--http-server', default=None, help='Server header')
    parser.add_argument('-t', '--html-title', default=None, help='Filter on html page title')
    parser.add_argument('-b', '--html-body', default=None, help='Filter on html body content')
    parser.add_argument('-T', '--tags', default=None, help='Filter on specific tags. E.g: -T tag1,tag2,... (use keyword \'list\' to list usual tags')

    parser.add_argument('--api_id', default=None, help='Censys API ID (optional if no env defined)')
    parser.add_argument('--api_secret', default=None, help='Censys API SECRET (optional if no env defined)')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug informations')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print raw JSON records')
    parser.add_argument('-l', '--limit', default=float('inf'), help='Limit to N results')
    parser.add_argument('-H', '--html', action='store_true', help='Renders html elements in a browser')
    parser.add_argument('--tsv', action='store_true', help='Export result of search in TSV format')
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

    if args.report_bucket:
        report_buckets = args.report_bucket

    # handle API key/secret
    api = conf_get_censys_api(args)

    # build up query
    q = CensysIPv4(api_id=api['id'], api_secret=api['secret'])
    s = build_query_string(args)

    # count the number of results
    try:
        # they changed something, "ip" don't work anymore
        # so I selecte a (random) field that should always exists
        count =  q.report(s, "updated_at")['metadata']['count']
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
        sys.stderr.write("Number of results: %d\n" % count)
        print_report(r, args.report)
        sys.exit(0)

    # count the numbmer of results
    if args.count:
        print count
        sys.exit(0)
    else:
        sys.stderr.write("Number of results: %d\n" % count)

    # prepare temp dir for html files
    if args.html:
        htmldir = tempfile.mkdtemp()
        open(htmldir+"/README", "w").write("html body dumped via command:"+' '.join(sys.argv))
        print "HTML body dumped to %s" % htmldir

    # else hit the 'search' API
    if args.filter: filter_fields = args.filter.split(',')
    r = q.search(s, fields=filter_fields)
    i = 0
    if args.tsv:
        print '\t'.join(filter_fields)
    for e in r:
        if i >= float(args.limit):
            break
        if args.verbose:
            pprint(q.view(e['ip']))
        elif args.filter:
            print e # FIXME: by default we dump raw JSON if filters are used
        else:
            if args.tsv:
                print_tsv(e)
            else:
                print_short(e)
            if args.html: dump_html_to_file(htmldir, e)
            if match != 'None': print_match(q.view(e['ip']), match)
        i += 1


