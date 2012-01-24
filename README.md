DomainClassifier
================

DomainClassifier is a simple Python library to extract and classify Internet
domains from raw text files following their existence, localization or attributes.

How To Use It
-------------

```python
import domainclassifier

c = domainclassifier.Extract( rawtext = "this is a text with a domain called test@foo.lu another test abc.lu something a.b.c.d.e end of 1.2.3.4 foo.be www.belnet.be http://www.cert.be/ www.public.lu www.allo.lu quuxtest www.eurodns.com something-broken-www.google.com www.google.lu trailing test")

# extracting potentially valid domains from rawtext
print c.domain()

# reduce set of potentially valid domains to existing domains
# (based on SOA,A,AAAA,CNAME,MX records)
print c.validdomain(extended=True)

# reduce set of valid domains with DNS records associated to a
# specified country
print "US:"
print c.localizedomain(cc='US')
print "LU:"
print c.localizedomain(cc='LU')
print "BE:"
print c.localizedomain(cc='BE')
```

### Sample output

```python
['foo.lu', 'abc.lu', 'a.b.c.d.e', '1.2.3.4', 'foo.be', 'www.belnet.be', 'www.cert.be', 'www.public.lu', 'www.allo.lu', 'www.eurodns.com', 'something-broken-www.google.com', 'www.google.lu']
[('abc.lu', 'SOA', <DNS IN SOA rdata: neptun.vo.lu. Administrator.vo.lu. 2006063001 86400 7200 2419200 3600>), ('abc.lu', 'MX', <DNS IN MX rdata: 10 proteus.vo.lu.>), ('foo.be', 'A', <DNS IN A rdata: 188.65.217.78>), ('foo.be', 'AAAA', <DNS IN AAAA rdata: 2001:6f8:202:2df::2>), ('foo.be', 'SOA', <DNS IN SOA rdata: ka.quuxlabs.com. adulau.foo.be. 2010121901 21600 3600 604800 86400>), ('foo.be', 'MX', <DNS IN MX rdata: 10 mail.foo.be.>), ('www.belnet.be', 'A', <DNS IN A rdata: 193.190.198.39>), ('www.belnet.be', 'AAAA', <DNS IN AAAA rdata: 2001:6a8:3c80::39>), ('www.belnet.be', 'CNAME', <DNS IN CNAME rdata: fiorano.belnet.be.>), ('www.cert.be', 'A', <DNS IN A rdata: 193.190.198.61>), ('www.cert.be', 'AAAA', <DNS IN AAAA rdata: 2001:6a8:3c80::61>), ('www.cert.be', 'SOA', <DNS IN SOA rdata: ns.belnet.be. hostmaster.belnet.be. 2011121563 3600 1800 1209600 3600>), ('www.cert.be', 'MX', <DNS IN MX rdata: 10 mx2.belnet.be.>), ('www.cert.be', 'CNAME', <DNS IN CNAME rdata: cert.be.>), ('www.public.lu', 'A', <DNS IN A rdata: 194.154.200.74>), ('www.allo.lu', 'A', <DNS IN A rdata: 80.90.47.69>), ('www.eurodns.com', 'A', <DNS IN A rdata: 80.92.65.165>), ('www.google.lu', 'A', <DNS IN A rdata: 173.194.67.94>), ('www.google.lu', 'CNAME', <DNS IN CNAME rdata: www-cctld.l.google.com.>)]
US:
[('www.google.lu', 'A', <DNS IN A rdata: 173.194.67.94>), ('www.google.lu', 'CNAME', <DNS IN CNAME rdata: www-cctld.l.google.com.>)]
LU:
[('www.public.lu', 'A', <DNS IN A rdata: 194.154.200.74>), ('www.allo.lu', 'A', <DNS IN A rdata: 80.90.47.69>), ('www.eurodns.com', 'A', <DNS IN A rdata: 80.92.65.165>)]
BE:
[('foo.be', 'A', <DNS IN A rdata: 188.65.217.78>), ('www.belnet.be', 'A', <DNS IN A rdata: 193.190.198.39>), ('www.belnet.be', 'CNAME', <DNS IN CNAME rdata: fiorano.belnet.be.>), ('www.cert.be', 'A', <DNS IN A rdata: 193.190.198.61>), ('www.cert.be', 'CNAME', <DNS IN CNAME rdata: cert.be.>)]
```

### Software Required

* Python (tested successfully on version 2.6)
* dnspython library - http://www.dnspython.org/
* IPy library

### License

Copyright (C) 2012 Alexandre Dulaunoy - a(at)foo.be 

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
