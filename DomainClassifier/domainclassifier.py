#!/usr/bin/env python
"""DomainClassifier is a simple Python library to extract and classify Internet
domains from raw text files following their existence, localization or
attributes.
"""

import re
import dns.resolver
import IPy
import socket

__author__ = "Alexandre Dulaunoy"
__copyright__ = "Copyright 2012, Alexandre Dulaunoy"
__license__ = "AGPL version 3"
__version__ = "0.0.3"



class Extract:

    """DomainClassifier Extract class is the base class for extracting domains
    from a rawtext stream. When call, the rawtext parameter is a string
    containing the raw data to be process."""


    def __init__(self, rawtext = None):
        self.rawtext = rawtext
        self.presolver = dns.resolver.Resolver()
        self.presolver.nameservers = ['8.8.8.8','149.13.33.69']
        self.presolver.lifetime = 1.0
        self.bgprankingserver = 'pdns.circl.lu'
        self.vdomain = []

    """__origin is a private function to the ASN lookup for an IP address via
    the Team Cymru DNS interface. ipadd is a string contain the IP address in a
    decimal form."""

    def __origin(self, ipaddr=None):

        if ipaddr:
            clook = IPy.IP(str(ipaddr)).reverseName().replace('.in-addr.arpa.','.origin.asn.cymru.com')
            try: a = self.presolver.query(clook, 'TXT')
            except dns.resolver.NXDOMAIN: return None
            except dns.exception.Timeout: return None
        if a:
		x = str(a[0]).split("|")
		# why so many spaces?
		x = map (lambda t: t.replace("\"","").strip(), x)
		return (x[0],x[2],a[0])
        else:
		return None
    """__bgpanking return the ranking the float value of an ASN.
    """
    def __bgpranking(self, asn=None):
        if asn:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.bgprankingserver,43))
            s.send(asn+"\r\n")
            r = ''
            while True:
                d = s.recv(2048)
                r = r + d
                if d == '':
                    break
            s.close()
            if len(r) > 0:
                try: rr = r.split("\n")[1].split(",")
		except IndexError: return None 
		if len(rr) > 1:
			rank = rr[1]
			return float(rank)
		else:
			return None
            else:
                return None

    """domain method extracts potential domains matching any
    string that is a serie of string with maximun 63 character separated by a
    dot. The method used the rawtext defined at the instantiation of the class.
    This return a list of a potential domain."""

    def domain(self):
        self.domain = []
        domain = re.compile(r'\b([a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+)\b')
        for x in domain.findall(self.rawtext):
            if x[0]:
                self.domain.append(x[0])

        return self.domain

    """validdomain method used the extracted domains from the domain method to
    generate a list of valid domain (at least existing in the authoritative DNS
    server". The records type used are A, AAAA, SOA, MX and CNAME records. This
    returns a list of existing domain. If the extended flag is true, a set is
    return with the associated DNS resources found."""

    def validdomain(self, rtype=['A','AAAA','SOA','MX','CNAME'], extended=True):
        if extended is False:
            self.validdomain = set()
        else:
            self.validdomain = []

        for domain in self.domain:
            for dnstype in rtype:
                try:
                    answers = self.presolver.query(domain, dnstype)
                except:
                    pass
                else:
                    self.vdomain.append(domain)
                    if extended is False:
                        self.validdomain.add((domain))
                    else:
                        self.validdomain.append((domain,dnstype,answers[0]))
        return self.validdomain

    """ipaddress method extracts from the domain list the valid IPv4 addresses"""

    def ipaddress(self, extended=False):
        if extended is False:
            self.ipaddresses = []
        else:
            self.ipaddresses = set()

        for d in self.domain:
            try:
                socket.inet_aton(d)
            except:
                pass
            else:
                if extended is False:
                    self.ipaddresses.append((d))
                else:
                    orig = self.__origin(ipaddr=d)
                    self.ipaddresses.add((d,str(orig)))

        return self.ipaddresses

    """localizedomain method use the validdomain list (in extended format) to
    localize per country code the associated resources. The cc argument specifies the
    country code in ISO 3166-1 alpha-2 format to check for."""

    def localizedomain(self, cc=None):
        self.localdom = []

        for dom in self.validdomain:
            if dom[1] == 'A':
                ip = dom[2]
                try:
                    orig = self.__origin(ipaddr=dom[2])[1]
                except:
                    continue
                if(orig == cc): self.localdom.append(dom)
            elif dom[1] == 'CNAME':
                cname = str(dom[2])
                ip = socket.gethostbyname(cname)
                try:
                    orig = self.__origin(ipaddr=ip)[1]
                except:
                    continue
                if(orig == cc): self.localdom.append(dom)
        return self.localdom

    """rankdomain method use the validdomain list (in extended format to rank
    each domain with an IP address. Return a sorted list of tuples (ranking,
    domain).
    """

    def rankdomain(self):
        self.rankdom = []

        if self.validdomain:
            for dom in self.validdomain:
                rank = None
                asn = None
                if dom[1] == 'A':
                    ip = dom[2]
                    o = self.__origin(ipaddr=dom[2])
                    if o:
                        asn = o[0]
                    rank = self.__bgpranking(asn)
                    t = (rank, dom[0])
                    self.rankdom.append(t)
                elif dom[1] == 'CNAME':
                    cname = str(dom[2])
                    try: ip = socket.gethostbyname(cname)
                    except: continue
                    try: asn = self.__origin(ipaddr=ip)[0]
                    except TypeError: continue
                    rank = self.__bgpranking(asn)
                    t = (rank, dom[0])
                    self.rankdom.append(t)
            return sorted(self.rankdom, key=lambda d: d[0])



    """exclude domains from a regular expression. If validdomain was called,
    it's only on the valid domain list."""

    def exclude(self,expression=None):
        self.cleandomain = []

        excludefilter = re.compile(expression)

        if not self.vdomain:
            domains = self.domain
        else:
            domains = self.vdomain

        for dom in domains:
            if excludefilter.search(dom):
                pass
            else:
                self.cleandomain.append(dom)
        return self.cleandomain

    """include domains from a regular expression. If validdomain was called,
    it's only on the valid domain list."""

    def include(self,expression=None):
        self.cleandomain = []

        includefilter = re.compile(expression)

        if not self.vdomain:
            domains = self.domain
        else:
            domains = self.vdomain

        for dom in domains:
            if includefilter.search(dom):
                self.cleandomain.append(dom)

        return self.cleandomain


