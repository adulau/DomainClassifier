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
__version__ = "0.0.1"


class Extract:
    def __init__(self, rawtext = None):
        self.rawtext = rawtext
        self.presolver = dns.resolver.Resolver()
        self.presolver.nameservers = ['149.13.33.69']

    def __origin(self, ipaddr=None):

        if ipaddr:
            clook = IPy.IP(str(ipaddr)).reverseName().replace('.in-addr.arpa.','.origin.asn.cymru.com')
            a = self.presolver.query(clook, 'TXT')
            if a:
                x = str(a[0]).split("|")
                return x[2].strip()
            else:
                return None

    def domain(self):
        self.domain = []
        domain = re.compile(r'\b([a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+)\b')
        for x in domain.findall(self.rawtext):
            if x[0]:
                self.domain.append(x[0])

        return self.domain

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
                    if extended is False:
                        self.validdomain.add((domain))
                    else:
                        self.validdomain.append((domain,dnstype,answers[0]))
        return self.validdomain

    def localizedomain(self, cc=None):
        self.localdom = []

        for dom in self.validdomain:
            if dom[1] == 'A':
                ip = dom[2]
                orig = self.__origin(ipaddr=dom[2])
                if(orig == cc): self.localdom.append(dom)
            elif dom[1] == 'CNAME':
                cname = str(dom[2])
                ip = socket.gethostbyname(cname)
                orig = self.__origin(ipaddr=ip)
                if(orig == cc): self.localdom.append(dom)
        return self.localdom

    def filterdomain(self,filter=None):
        pass


