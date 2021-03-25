from setuptools import setup, find_packages
setup(
    name="DomainClassifier",
    version="1.0",
    packages=find_packages(),
    install_requires=['dnspython', 'IPy', 'pybgpranking'],
    dependency_links=[
      'git+https://github.com/D4-project/BGP-Ranking.git/@7e698f87366e6f99b4d0d11852737db28e3ddc62#egg=pybgpranking&subdirectory=client',
    ],
    author="Alexandre Dulaunoy",
    author_email="a@foo.be",
    description="DomainClassifier is a Python library to extract and classify Internet domains/hostnames/IP addresses from raw unstructured text files following their existence, localization or attributes.",
    license="AGPL",
    keywords="internet mining domain resolver geolocalisation",
    url="http://github.com/adulau/DomainClassifier"
)
