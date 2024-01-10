#!/usr/bin/env python
"""DomainClassifier is a simple Python library to extract and classify Internet
domains from raw text files following their existence, localization or
attributes.
"""

import re
import dns.resolver
import IPy
import redis
import socket
import time
from datetime import date, timedelta
import os
import sys
from uuid import uuid4

from multiprocessing import Process as Proc

try:
    # python 3
    import urllib.request as urllib
except:
    # python 2
    import urllib2 as urllib

try:
    from pybgpranking import BGPRanking
except:
    print("pybgpranking is not installed - ranking of ASN values won't be possible")
__author__ = "Alexandre Dulaunoy"
__copyright__ = "Copyright 2012-2024, Alexandre Dulaunoy"
__license__ = "AGPL version 3"
__version__ = "1.1"


class Extract:

    """DomainClassifier Extract class is the base class for extracting domains
    from a rawtext stream. When call, the rawtext parameter is a string
    containing the raw data to be process."""

    def __init__(self, rawtext=None, nameservers=['8.8.8.8'], port=53, redis_host='', redis_port=6379, redis_db=0, expire_time=3600, re_timeout=-1):
        self.rawtext = rawtext
        self.presolver = dns.resolver.Resolver()
        self.presolver.nameservers = nameservers
        self.presolver.port = port
        self.presolver.lifetime = 1.0
        self.bgprankingserver = 'pdns.circl.lu'
        self.vdomain = []
        self.listtld = []

        self.re_domain = re.compile(r'\b([a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+)\b')

        if redis_host and redis_port:
            self.redis = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
            self.uuid = str(uuid4())
            self.re_timeout = re_timeout
        else:
            self.redis = None
        self.expire_time = expire_time

        self.domain = self.potentialdomain()

    """__origin is a private function to the ASN lookup for an IP address via
    the Team Cymru DNS interface. ipadd is a string contain the IP address in a
    decimal form."""

    def __origin(self, ipaddr=None):

        if ipaddr:
            clook = (
                IPy.IP(str(ipaddr))
                .reverseName()
                .replace('.in-addr.arpa.', '.origin.asn.cymru.com')
            )
            try:
                a = self.presolver.query(clook, 'TXT')
            except dns.resolver.NXDOMAIN:
                return None
            except dns.exception.Timeout:
                return None
        if a:
            x = str(a[0]).split("|")
            # why so many spaces?
            x = list(map(lambda t: t.replace("\"", "").strip(), x))
            return (x[0], x[2], a[0])
        else:
            return None

    """__bgpanking return the ranking the float value of an ASN.
    """

    def __bgpranking(self, asn=None):
        if asn:
            bgpranking = BGPRanking()
            value = bgpranking.query(
                asn, date=(date.today() - timedelta(1)).isoformat()
            )
            return value['response']['ranking']['rank']

    def __updatelisttld(self, force=False):
        ianatldlist = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
        userdir = os.path.expanduser("~")
        cachedir = os.path.join(userdir, ".DomainClassifier")
        if not os.path.exists(cachedir):
            os.mkdir(cachedir)
        tldcache = os.path.join(cachedir, "tlds")
        if not os.path.exists(tldcache):
            print(tldcache)
            req = urllib.Request(ianatldlist)
            req.add_header(
                'User-Agent',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
            )
            tlds = (urllib.urlopen(req).read()).decode('utf8')
            f = open(tldcache, "wb")
            f.write(tlds.encode("utf-8"))
            f.close()

        f = open(tldcache, "r")
        tlds = f.read()
        f.close()
        tlds = tlds.split("\n")
        for tld in tlds:
            self.listtld.append(tld.lower())

    def __listtld(self):
        if not self.listtld:
            self.__updatelisttld()
        self.cleandomain = []
        if self.domain is None:
            return False
        for domain in self.domain:
            lastpart = domain.rsplit(".")[-1:][0]
            for tld in self.listtld:
                if lastpart == tld:
                    self.cleandomain.append(domain)

        return self.cleandomain

    def __re_findall(self, rawtext):
        for x in re.findall(self.re_domain, rawtext):
            if x[0]:
                self.redis.sadd('cache:regex:{}'.format(self.uuid), x[0])
        self.redis.expire('cache:regex:{}'.format(self.uuid), 360)

    def __regex_findall(self, rawtext, timeout):
        proc = Proc(target=self.__re_findall, args=(rawtext,))
        try:
            proc.start()
            proc.join(timeout)
            if proc.is_alive():
                proc.terminate()
                print('regex: processing timeout')
                return []
            else:
                domains = self.redis.smembers('cache:regex:{}'.format(self.uuid))
                self.redis.delete('cache:regex:{}'.format(self.uuid))
                proc.terminate()
                return domains
        except KeyboardInterrupt:
            print("Caught KeyboardInterrupt, terminating workers")
            proc.terminate()
            sys.exit(0)

    def text(self, rawtext=''):
        if rawtext:
            self.rawtext = rawtext
            self.domain = self.potentialdomain()
            self.vdomain = []
            return True
        return False

    """potentialdomain method extracts potential domains matching any
    string that is a serie of string with maximum 63 character separated by a
    dot. The method used the rawtext defined at the instantiation of the class.
    This return a list of a potential domain."""

    def potentialdomain(self, validTLD=True):
        self.domain = []
        if self.re_timeout > 0 and self.redis:
            self.domain = list(self.__regex_findall(self.rawtext, self.re_timeout))
        else:
            domains = self.re_domain.findall(self.rawtext)
            for x in domains:
                if x[0]:
                    self.domain.append(x[0])
        if validTLD:
            self.domain = self.__listtld()
        return self.domain

    """validdomain method used the extracted domains from the domain method to
    generate a list of valid domain (at least existing in the authoritative DNS
    server". The records type used are A, AAAA, SOA, MX and CNAME records. This
    returns a list of existing domain. If the extended flag is true, a set is
    return with the associated DNS resources found."""

    def validdomain(
        self,
        rtype=['A', 'AAAA', 'SOA', 'MX', 'CNAME'],
        extended=True,
        passive_dns=False,
    ):
        if extended is False:
            self.vdomain = set()
        else:
            self.vdomain = []

        for domain in self.domain:
            if self.redis:
                if self.redis.exists('dom_class:cache:{}'.format(domain)):
                    passive_dns_out = self.redis.smembers('dom_class:cache:{}'.format(domain))
                    for out in passive_dns_out:
                        if extended:
                            out = tuple(out.split('[^]', 2))
                            self.vdomain.append(out)
                        else:
                            self.vdomain.add(out)
            else:

                for dnstype in rtype:
                    try:
                        answers = self.presolver.query(domain, dnstype)
                    except:
                        pass
                    else:
                        # Passive DNS output
                        # timestamp||dns-client ||dns-server||RR class||Query||Query Type||Answer||TTL||Count
                        if passive_dns:
                            rrset = answers.rrset.to_text().splitlines()
                            for dns_resp in rrset:
                                dns_resp = dns_resp.split()
                                passive_dns_out = (
                                    '{}||127.0.0.1||{}||{}||{}||{}||{}||{}||1\n'.format(
                                        time.time(),
                                        self.presolver.nameservers[0],
                                        dns_resp[2],
                                        domain,
                                        dnstype,
                                        dns_resp[4],
                                        answers.ttl,
                                    )
                                )
                                self.vdomain.add((passive_dns_out))
                                if self.redis:
                                    self.redis.sadd('dom_class:cache:{}'.format(domain), passive_dns_out)
                                    self.redis.expire('dom_class:cache:{}'.format(domain), self.expire_time)
                        elif extended:
                            self.vdomain.append((domain, dnstype, answers[0]))
                            if self.redis:
                                self.redis.sadd('dom_class:cache:{}'.format(domain), '{}[^]{}[^]{}'.format(domain, dnstype, answers[0]))
                                self.redis.expire('dom_class:cache:{}'.format(domain), self.expire_time)
                        else:
                            self.vdomain.add((domain))
                            if self.redis:
                                self.redis.sadd('dom_class:cache:{}'.format(domain), domain)
                                self.redis.expire('dom_class:cache:{}'.format(domain), self.expire_time)
        return self.vdomain

    """ipaddress method extracts from the domain list the valid IPv4 addresses"""

    def ipaddress(self, extended=False):

        if extended is False:
            self.ipaddresses = []
        else:
            self.ipaddresses = set()

        for d in self.domain:
            try:
                ip = socket.gethostbyname(d)
            except:
                continue

            if extended is False:
                self.ipaddresses.append((ip))
            else:
                orig = self.__origin(ipaddr=ip)
                self.ipaddresses.add((ip, str(orig)))

        return self.ipaddresses

    """localizedomain method use the validdomain list (in extended format) to
    localize per country code the associated resources. The cc argument specifies the
    country code in ISO 3166-1 alpha-2 format to check for."""

    def localizedomain(self, cc=None):
        self.localdom = []

        for dom in self.vdomain:
            if dom[1] == 'A':
                ip = dom[2]
                try:
                    orig = self.__origin(ipaddr=dom[2])[1]
                except:
                    continue
                if orig == cc:
                    self.localdom.append(dom)
            elif dom[1] == 'CNAME':
                cname = str(dom[2])
                ip = socket.gethostbyname(cname)
                try:
                    orig = self.__origin(ipaddr=ip)[1]
                except:
                    continue
                if orig == cc:
                    self.localdom.append(dom)
        return self.localdom

    """rankdomain method use the validdomain list (in extended format to rank
    each domain with an IP address. Return a sorted list of tuples (ranking,
    domain).
    """

    def rankdomain(self):
        self.rankdom = []

        if self.vdomain:
            for dom in self.vdomain:
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
                    try:
                        ip = socket.gethostbyname(cname)
                    except:
                        continue
                    try:
                        asn = self.__origin(ipaddr=ip)[0]
                    except TypeError:
                        continue
                    rank = self.__bgpranking(asn)
                    t = (rank, dom[0])
                    self.rankdom.append(t)
            return sorted(self.rankdom, key=lambda d: d[0])

    """exclude domains from a regular expression. If validdomain was called,
    it's only on the valid domain list."""

    """exclude domains from a regular expression. If validdomain was called,
    it's only on the valid domain list."""

    def exclude(self, expression=None):
        self.cleandomain = []

        excludefilter = re.compile(expression)

        if not self.vdomain:
            domains = self.domain
        else:
            domains = self.vdomain

        for dom in domains:
            if type(dom) == tuple:
                dom = dom[0]

            if excludefilter.search(dom):
                pass
            else:
                self.cleandomain.append(dom)
        return self.cleandomain

    def include(self, expression=None):
        self.cleandomain = []

        includefilter = re.compile(expression)

        if not self.vdomain:
            domains = self.domain
        else:
            domains = self.vdomain

        for dom in domains:
            if type(dom) == tuple:
                dom = dom[0]
            if includefilter.search(dom):
                self.cleandomain.append(dom)

        return set(self.cleandomain)


if __name__ == "__main__":
    c = Extract(
        rawtext="www.foo.lu www.xxx.com this is a text with a domain called test@foo.lu another test abc.lu something a.b.c.d.e end of 1.2.3.4 foo.be www.belnet.be http://www.cert.be/ www.public.lu www.allo.lu quuxtest www.eurodns.com something-broken-www.google.com www.google.lu trailing test www.facebook.com www.nic.ru www.youporn.com 8.8.8.8 201.1.1.1 abc.dontexist"
    )
    c.text(
        rawtext="www.abc.lu www.xxx.com random text a test bric broc www.lemonde.fr www.belnet.be www.foo.be"
    )
    print(c.potentialdomain())
    print(c.potentialdomain(validTLD=True))
    print(c.validdomain(extended=True))
    print("US:")
    print(c.localizedomain(cc='US'))
    print("LU:")
    print(c.localizedomain(cc='LU'))
    print("BE:")
    print(c.localizedomain(cc='BE'))
    print("Ranking:")
    print(c.rankdomain())
    print("List of ip addresses:")
    print(c.ipaddress(extended=False))
    print("Include dot.lu:")
    print(c.include(expression=r'\.lu$'))
    print("Exclude dot.lu:")
    print(c.exclude(expression=r'\.lu$'))
    c.text(rawtext="www.lwn.net www.undeadly.org")
    print(c.potentialdomain(validTLD=True))
    c.validdomain()
    print(c.localizedomain(cc='US'))
    print(c.validdomain(extended=False, passive_dns=True))
