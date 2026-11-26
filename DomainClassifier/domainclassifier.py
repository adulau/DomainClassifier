#!/usr/bin/env python3
"""DomainClassifier is a simple Python library to extract and classify Internet
domains from raw text files following their existence, localization or
attributes.
"""

import re
import socket
import sys
import time
from datetime import date, timedelta
from multiprocessing import Process
from pathlib import Path
from urllib.request import Request, urlopen
from uuid import uuid4

import dns.exception
import dns.resolver
import IPy
import redis

try:
    from pybgpranking import BGPRanking
except ImportError:
    print("pybgpranking is not installed - ranking of ASN values won't be possible")
__author__ = "Alexandre Dulaunoy"
__copyright__ = "Copyright 2012-2024, Alexandre Dulaunoy"
__license__ = "AGPL version 3"
__version__ = "1.1"


def _store_regex_domains(pattern, rawtext, redis_options, cache_key):
    with redis.StrictRedis(**redis_options) as client:
        for match in pattern.findall(rawtext):
            if match[0]:
                client.sadd(cache_key, match[0])
        client.expire(cache_key, 360)


class Extract:
    """Extract and classify domain names from raw text."""

    def __init__(
        self,
        rawtext=None,
        nameservers=('8.8.8.8',),
        port=53,
        redis_host='',
        redis_port=6379,
        redis_db=0,
        expire_time=3600,
        re_timeout=-1,
    ):
        self.rawtext = rawtext
        self.presolver = dns.resolver.Resolver()
        self.presolver.nameservers = list(nameservers)
        self.presolver.port = port
        self.presolver.lifetime = 1.0
        self.bgprankingserver = 'pdns.circl.lu'
        self.vdomain = []
        self.listtld = []

        self.re_domain = re.compile(r'\b([a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+)\b')

        self.re_timeout = re_timeout
        if redis_host and redis_port:
            self._redis_options = dict(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
            self.redis = redis.StrictRedis(**self._redis_options)
            self.uuid = str(uuid4())
        else:
            self.redis = None
        self.expire_time = expire_time

        self.domain = self.potentialdomain()

    def __origin(self, ipaddr=None):
        """Return ASN and country information from the Team Cymru DNS service."""
        if not ipaddr:
            return None

        lookup = (
            IPy.IP(str(ipaddr))
            .reverseName()
            .replace('.in-addr.arpa.', '.origin.asn.cymru.com')
        )
        try:
            answers = self.presolver.resolve(lookup, 'TXT', search=True)
        except dns.exception.DNSException:
            return None
        if not answers:
            return None

        answer = answers[0]
        fields = [field.strip() for field in str(answer).replace('"', '').split('|')]
        if len(fields) < 3:
            return None
        return fields[0], fields[2], answer

    def __bgpranking(self, asn=None):
        """Return the BGP ranking for an ASN."""
        if asn:
            bgpranking = BGPRanking()
            value = bgpranking.query(
                asn, date=(date.today() - timedelta(1)).isoformat()
            )
            return value['response']['ranking']['rank']

    def __updatelisttld(self):
        cachedir = Path.home() / '.DomainClassifier'
        cachedir.mkdir(exist_ok=True)
        tldcache = cachedir / 'tlds'
        if tldcache.exists():
            tlds = tldcache.read_text(encoding='utf-8')
        else:
            print(tldcache)
            req = Request('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
            req.add_header(
                'User-Agent',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
            )
            with urlopen(req) as response:
                tlds = response.read().decode('utf-8')
            tldcache.write_text(tlds, encoding='utf-8')

        self.listtld.extend(tld.lower() for tld in tlds.splitlines() if tld)

    def __listtld(self):
        if not self.listtld:
            self.__updatelisttld()
        self.cleandomain = []
        if self.domain is None:
            return False
        for domain in self.domain:
            lastpart = domain.rsplit('.', 1)[-1]
            for tld in self.listtld:
                if lastpart == tld:
                    self.cleandomain.append(domain)

        return self.cleandomain

    def __regex_findall(self, rawtext, timeout):
        cache_key = f'cache:regex:{self.uuid}'
        # Spawn and forkserver require a picklable target and arguments.
        proc = Process(
            target=_store_regex_domains,
            args=(self.re_domain, rawtext, self._redis_options, cache_key),
        )
        proc.start()
        try:
            proc.join(timeout)
            if proc.is_alive():
                print('regex: processing timeout')
                return []
            return self.redis.smembers(cache_key)
        except KeyboardInterrupt:
            print("Caught KeyboardInterrupt, terminating workers")
            sys.exit(0)
        finally:
            if proc.is_alive():
                proc.terminate()
                proc.join()
            proc.close()
            self.redis.delete(cache_key)

    def text(self, rawtext=''):
        if rawtext:
            self.rawtext = rawtext
            self.domain = self.potentialdomain()
            self.vdomain = []
            return True
        return False

    def potentialdomain(self, validTLD=True):
        """Extract dotted names, optionally restricting them to known TLDs."""
        if self.re_timeout > 0 and self.redis:
            self.domain = list(self.__regex_findall(self.rawtext, self.re_timeout))
        else:
            self.domain = [match[0] for match in self.re_domain.findall(self.rawtext) if match[0]]
        if validTLD:
            self.domain = self.__listtld()
        return self.domain

    def validdomain(
        self,
        rtype=('A', 'AAAA', 'SOA', 'MX', 'CNAME'),
        extended=True,
        passive_dns=False,
    ):
        """Return DNS record tuples or a set of resolved names or passive DNS lines."""
        if extended is False:
            self.vdomain = set()
        else:
            self.vdomain = []

        for domain in self.domain:
            cache_key = f'dom_class:cache:{domain}'
            if self.redis and self.redis.exists(cache_key):
                cached_records = self.redis.smembers(cache_key)
                if extended:
                    self.vdomain.extend(tuple(record.split('[^]', 2)) for record in cached_records)
                else:
                    self.vdomain.update(cached_records)
                continue

            for dnstype in rtype:
                try:
                    answers = self.presolver.resolve(domain, dnstype, search=True)
                except dns.exception.DNSException:
                    continue

                if passive_dns:
                    for line in answers.rrset.to_text().splitlines():
                        fields = line.split()
                        passive_dns_out = (
                            f'{time.time()}||127.0.0.1||{self.presolver.nameservers[0]}||'
                            f'{fields[2]}||{domain}||{dnstype}||{fields[4]}||{answers.ttl}||1\n'
                        )
                        self.vdomain.add(passive_dns_out)
                        if self.redis:
                            self.redis.sadd(cache_key, passive_dns_out)
                            self.redis.expire(cache_key, self.expire_time)
                    continue

                if extended:
                    answer = answers[0]
                    self.vdomain.append((domain, dnstype, answer))
                else:
                    self.vdomain.add(domain)
                if self.redis:
                    cached_record = f'{domain}[^]{dnstype}[^]{answer}' if extended else domain
                    self.redis.sadd(cache_key, cached_record)
                    self.redis.expire(cache_key, self.expire_time)
        return self.vdomain

    def ipaddress(self, extended=False):
        """Resolve the extracted domains to IPv4 addresses."""
        if extended is False:
            self.ipaddresses = []
        else:
            self.ipaddresses = set()

        for domain in self.domain:
            try:
                ip = socket.gethostbyname(domain)
            except OSError:
                continue

            if extended is False:
                self.ipaddresses.append(ip)
            else:
                orig = self.__origin(ipaddr=ip)
                self.ipaddresses.add((ip, str(orig)))

        return self.ipaddresses

    def localizedomain(self, cc=None):
        """Filter extended DNS records by their ISO 3166-1 alpha-2 country code."""
        self.localdom = []

        for record in self.vdomain:
            if record[1] == 'A':
                ip = record[2]
            elif record[1] == 'CNAME':
                ip = socket.gethostbyname(str(record[2]))
            else:
                continue
            origin = self.__origin(ipaddr=ip)
            if origin and origin[1] == cc:
                self.localdom.append(record)
        return self.localdom

    def rankdomain(self):
        """Return sorted (ranking, domain) pairs from extended DNS records."""
        self.rankdom = []
        if self.vdomain:
            for record in self.vdomain:
                if record[1] == 'A':
                    origin = self.__origin(ipaddr=record[2])
                    asn = origin[0] if origin else None
                elif record[1] == 'CNAME':
                    try:
                        ip = socket.gethostbyname(str(record[2]))
                    except OSError:
                        continue
                    origin = self.__origin(ipaddr=ip)
                    if not origin:
                        continue
                    asn = origin[0]
                else:
                    continue
                self.rankdom.append((self.__bgpranking(asn), record[0]))
            return sorted(self.rankdom, key=lambda ranked: ranked[0])

    def exclude(self, expression=None):
        """Keep names that do not match the regular expression."""
        self.cleandomain = []
        pattern = re.compile(expression)
        for item in self.vdomain or self.domain:
            domain = item[0] if isinstance(item, tuple) else item
            if not pattern.search(domain):
                self.cleandomain.append(domain)
        return self.cleandomain

    def include(self, expression=None):
        """Return the set of names matching the regular expression."""
        self.cleandomain = []
        pattern = re.compile(expression)
        for item in self.vdomain or self.domain:
            domain = item[0] if isinstance(item, tuple) else item
            if pattern.search(domain):
                self.cleandomain.append(domain)
        return set(self.cleandomain)


if __name__ == "__main__":
    c = Extract(
        rawtext=(
            'www.foo.lu www.xxx.com this is a text with a domain called test@foo.lu '
            'another test abc.lu something a.b.c.d.e end of 1.2.3.4 foo.be www.belnet.be '
            'http://www.cert.be/ www.public.lu www.allo.lu quuxtest www.eurodns.com '
            'something-broken-www.google.com www.google.lu trailing test www.facebook.com '
            'www.nic.ru www.youporn.com 8.8.8.8 201.1.1.1 abc.dontexist'
        )
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
