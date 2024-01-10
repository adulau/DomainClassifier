from setuptools import setup, find_packages
setup(
    name="DomainClassifier",
    version="1.1",
    packages=find_packages(),
    install_requires=['dnspython', 'IPy', 'pybgpranking'],
    author="Alexandre Dulaunoy",
    author_email="a@foo.be",
    description="DomainClassifier is a Python library to extract and classify Internet domains/hostnames/IP addresses from raw unstructured text files following their existence, localization or attributes.",
    license="AGPL",
    keywords="internet mining domain resolver geolocalisation",
    url="http://github.com/adulau/DomainClassifier"
)
