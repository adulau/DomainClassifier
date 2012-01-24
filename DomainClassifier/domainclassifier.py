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

    """DomainClassifier Extract class is the base class for extracting domains
    from a rawtext stream. When call, the rawtext parameter is a string
    containing the raw data to be process."""


    def __init__(self, rawtext = None):
        self.rawtext = rawtext
        self.presolver = dns.resolver.Resolver()
        self.presolver.nameservers = ['149.13.33.69']

    """__origin is a private function to the ASN lookup for an IP address via
    the Team Cymru DNS interface. ipadd is a string contain the IP address in a
    decimal form."""

    def __origin(self, ipaddr=None):

        if ipaddr:
            clook = IPy.IP(str(ipaddr)).reverseName().replace('.in-addr.arpa.','.origin.asn.cymru.com')
            a = self.presolver.query(clook, 'TXT')
            if a:
                x = str(a[0]).split("|")
                return x[2].strip()
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
                    if extended is False:
                        self.validdomain.add((domain))
                    else:
                        self.validdomain.append((domain,dnstype,answers[0]))
        return self.validdomain

    """localizedomain method use the validdomain list (in extended format) to
    localize per country code the associated resources. The cc argument specifies the
    country code in ISO 3166-1 alpha-2 format to check for."""

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


