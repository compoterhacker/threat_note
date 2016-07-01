import json

import whois
from ipwhois import IPWhois
from dbcache import dbcache

# IPv4 Whois

@dbcache
def ipwhois(entity):
    obj = IPWhois(entity)
    whoisdata = obj.lookup()
    return whoisdata

# Domain Whois

@dbcache
def domainwhois(entity):
    domain = json.loads(str(whois.whois(entity)))
    for k, v in domain.iteritems():
        if type(v) == list:
            domain[k] = ', '.join(v)
    if 'city' not in domain.keys():
        domain['city'] = 'N/A'
    return domain
