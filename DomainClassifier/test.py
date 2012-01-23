import domainclassifier

c = domainclassifier.Extract("this is a text with a domain called test@foo.lu another test abc.lu something a.b.c.d.e end of 1.2.3.4 foo.be")
print c.domain()
print c.validdomain(extended=None)
