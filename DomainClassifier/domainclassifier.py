import re
import dns.resolver

class Extract:
    def __init__(self, rawtext = None):
        self.rawtext = rawtext
    def domain(self):
        self.domain = []
        domain = re.compile(r'\b([a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+)\b')
        for x in domain.findall(self.rawtext):
            if x[0]:
                self.domain.append(x[0])

        return self.domain

    def validdomain(self, rtype=['A','AAAA','SOA','MX','CNAME'], extended=None):
        if extended is None:
            self.validdomain = set()
        else:
            self.validdomain = []
        for domain in self.domain:
            for dnstype in rtype:
                try:
                    answers = dns.resolver.query(domain, dnstype)
                except:
                    pass
                else:
                    if extended is None:
                        self.validdomain.add((domain))
                    else:
                        self.validdomain.append((domain,dnstype,answers[0]))
        return self.validdomain

