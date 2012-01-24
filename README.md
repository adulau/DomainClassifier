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
