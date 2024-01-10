DomainClassifier
================

DomainClassifier is a simple Python library to extract and classify Internet domains/hostnames/IP addresses from raw unstructured text files following their existence, localization or attributes.

DomainClassifier can be used to extract Internet hosts from any free texts or collected unstructured information. A passive dns output is also available.

![An overview of the DomainClassifier methods](https://raw.github.com/adulau/DomainClassifier/master/doc/domainclassifier-flow.png)

Install
-------

[DomainClassifier](https://pypi.python.org/pypi/DomainClassifier/) is part of the pypi package. It can be installed using the pip command:

`pip install DomainClassifier`

```python

In [11]: c = DomainClassifier.domainclassifier.Extract(rawtext="www.google.com foo.bar ppp.ppp")

In [12]: c.potentialdomain()
Out[12]: ['www.google.com', 'foo.bar']
```

How To Use It
-------------


```python
import DomainClassifier.domainclassifier

c = DomainClassifier.domainclassifier.Extract( rawtext = "www.xxx.com this is a text with a domain called test@foo.lu another test abc.lu something a.b.c.d.e end of 1.2.3.4 foo.be www.belnet.be ht
tp://www.cert.be/ www.public.lu www.allo.lu quuxtest www.eurodns.com something-broken-www.google.com www.google.lu trailing test www.facebook.com www.nic.ru www.youporn.com 8.8.8.
8 201.1.1.1")

# extracting potentially valid domains from rawtext
print(c.potentialdomain())

# reduce set of potentially valid domains to existing domains
# (based on SOA,A,AAAA,CNAME,MX records)
print(c.validdomain(extended=True))

# reduce set of valid domains with DNS records associated to a
# specified country
print("US:")
print(c.localizedomain(cc='US'))
print("LU:")
print(c.localizedomain(cc='LU'))
print("BE:")
print(c.localizedomain(cc='BE'))
print("Ranking:")
print(c.rankdomain())

# extract valid IPv4 addresses (using the potential list of valid domains)
print("List of ip addresses:")
print(c.ipaddress(extended=True))

# some more filtering
print("Include dot.lu:")
print(c.include(expression=r'\.lu$'))
print("Exclude dot.lu:")
print(c.exclude(expression=r'\.lu$'))
```

### Sample output

```python
['www.xxx.com', 'foo.lu', 'abc.lu', 'a.b.c.d.e', '1.2.3.4', 'foo.be', 'www.belnet.be', 'www.cert.be', 'www.public.lu', 'www.allo.lu', 'www.eurodns.com', 'something-broken-www.google.com', 'www.google.lu', 'www.facebook.com', 'www.nic.ru', 'www.youporn.com', '8.8.8.8', '201.1.1.1']
[('www.xxx.com', 'A', <DNS IN A rdata: 67.23.112.226>), ('abc.lu', 'SOA', <DNS IN SOA rdata: neptun.vo.lu. Administrator.vo.lu. 2006063001 86400 7200 2419200 3600>), ('abc.lu', 'MX', <DNS IN MX rdata: 10 proteus.vo.lu.>), ('foo.be', 'A', <DNS IN A rdata: 188.65.217.78>), ('foo.be', 'AAAA', <DNS IN AAAA rdata: 2001:6f8:202:2df::2>), ('foo.be', 'SOA', <DNS IN SOA rdata: ka.quuxlabs.com. adulau.foo.be. 2010121901 21600 3600 604800 86400>), ('foo.be', 'MX', <DNS IN MX rdata: 10 mail.foo.be.>), ('www.belnet.be', 'A', <DNS IN A rdata: 193.190.130.15>), ('www.belnet.be', 'AAAA', <DNS IN AAAA rdata: 2001:6a8:3c80:8300::15>), ('www.belnet.be', 'CNAME', <DNS IN CNAME rdata: fiorano.belnet.be.>), ('www.cert.be', 'A', <DNS IN A rdata: 193.190.198.61>), ('www.cert.be', 'AAAA', <DNS IN AAAA rdata: 2001:6a8:3c80::61>), ('www.cert.be', 'SOA', <DNS IN SOA rdata: ns.belnet.be. hostmaster.belnet.be. 2013053039 360 180 1209600 3600>), ('www.cert.be', 'MX', <DNS IN MX rdata: 10 asp-mxa.belnet.be.>), ('www.cert.be', 'CNAME', <DNS IN CNAME rdata: cert.be.>), ('www.public.lu', 'A', <DNS IN A rdata: 194.154.200.74>), ('www.allo.lu', 'A', <DNS IN A rdata: 80.90.47.69>), ('www.eurodns.com', 'A', <DNS IN A rdata: 80.92.65.165>), ('www.google.lu', 'A', <DNS IN A rdata: 173.194.66.94>), ('www.google.lu', 'AAAA', <DNS IN AAAA rdata: 2a00:1450:400c:c03::5e>), ('www.facebook.com', 'A', <DNS IN A rdata: 31.13.64.1>), ('www.facebook.com', 'AAAA', <DNS IN AAAA rdata: 2a03:2880:10:8f07:face:b00c::1>), ('www.facebook.com', 'MX', <DNS IN MX rdata: 10 msgin.t.facebook.com.>), ('www.facebook.com', 'CNAME', <DNS IN CNAME rdata: star.c10r.facebook.com.>), ('www.nic.ru', 'A', <DNS IN A rdata: 194.85.61.42>), ('www.nic.ru', 'MX', <DNS IN MX rdata: 0 nomail.nic.ru.>), ('www.youporn.com', 'A', <DNS IN A rdata: 31.192.116.24>), ('www.youporn.com', 'SOA', <DNS IN SOA rdata: pdns1.ultradns.net. dns.manwin.com. 2012041840 86400 86400 86400 86400>), ('www.youporn.com', 'MX', <DNS IN MX rdata: 20 smtp-scan01.mx.reflected.net.>), ('www.youporn.com', 'CNAME', <DNS IN CNAME rdata: youporn.com.>)]
US:
[('www.xxx.com', 'A', <DNS IN A rdata: 67.23.112.226>), ('www.google.lu', 'A', <DNS IN A rdata: 173.194.66.94>)]
LU:
[('www.public.lu', 'A', <DNS IN A rdata: 194.154.200.74>), ('www.allo.lu', 'A', <DNS IN A rdata: 80.90.47.69>), ('www.eurodns.com', 'A', <DNS IN A rdata: 80.92.65.165>)]
BE:
[('foo.be', 'A', <DNS IN A rdata: 188.65.217.78>), ('www.belnet.be', 'A', <DNS IN A rdata: 193.190.130.15>), ('www.belnet.be', 'CNAME', <DNS IN CNAME rdata: fiorano.belnet.be.>), ('www.cert.be', 'A', <DNS IN A rdata: 193.190.198.61>), ('www.cert.be', 'CNAME', <DNS IN CNAME rdata: cert.be.>)]
Ranking:
[(1.0, 'www.youporn.com'), (1.0, 'www.youporn.com'), (1.0000120563271599, 'www.belnet.be'), (1.0000120563271599, 'www.belnet.be'), (1.0000120563271599, 'www.cert.be'), (1.0000120563271599, 'www.cert.be'), (1.0000372023809501, 'foo.be'), (1.0001395089285701, 'www.public.lu'), (1.00015419407895, 'www.allo.lu'), (1.0003662109375, 'www.eurodns.com'), (1.0004111842105301, 'www.xxx.com'), (1.0005944293478299, 'www.nic.ru'), (1.0024646577381, 'www.facebook.com'), (1.0024646577381, 'www.facebook.com'), (1.002635288165, 'www.google.lu')]
List of ip addresses:
('15169', 'AU', <DNS IN TXT rdata: "15169 | 1.2.3.0/24 | AU | apnic | 2011-08-11">)
('15169', 'US', <DNS IN TXT rdata: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01">)
('27699', 'BR', <DNS IN TXT rdata: "27699 | 201.1.0.0/17 | BR | lacnic | 2003-12-08">)
set([('201.1.1.1', '(\'27699\', \'BR\', <DNS IN TXT rdata: "27699 | 201.1.0.0/17 | BR | lacnic | 2003-12-08">)'), ('8.8.8.8', '(\'15169\', \'US\', <DNS IN TXT rdata: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01">)'), ('1.2.3.4', '(\'15169\', \'AU\', <DNS IN TXT rdata: "15169 | 1.2.3.0/24 | AU | apnic | 2011-08-11">)')])
Include dot.lu:
['abc.lu', 'abc.lu', 'www.public.lu', 'www.allo.lu', 'www.google.lu', 'www.google.lu']
Exclude dot.lu:
['www.xxx.com', 'foo.be', 'foo.be', 'foo.be', 'foo.be', 'www.belnet.be', 'www.belnet.be', 'www.belnet.be', 'www.cert.be', 'www.cert.be', 'www.cert.be', 'www.cert.be', 'www.cert.be', 'www.eurodns.com', 'www.facebook.com', 'www.facebook.com', 'www.facebook.com', 'www.facebook.com', 'www.nic.ru', 'www.nic.ru', 'www.youporn.com', 'www.youporn.com', 'www.youporn.com', 'www.youporn.com']
```

### Software Required

* Python (tested successfully on version 2.6, 2.7 and 3.5)
* dnspython library - http://www.dnspython.org/
* IPy library
* [pybgpranking](https://github.com/D4-project/BGP-Ranking/tree/master/client) to get malicious ranking of BGP AS number via [BGP Ranking](https://github.com/D4-project/BGP-Ranking)

### Software using DomainClassifier

* [AIL framework - Analysis Information Leak framework](https://github.com/ail-project/ail-framework)

### License

~~~~
Copyright (C) 2012-2023 Alexandre Dulaunoy - a(at)foo.be
Copyright (C) 2021 Aurelien Thirion

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
~~~~
