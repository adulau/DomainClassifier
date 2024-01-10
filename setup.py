from setuptools import setup, find_packages
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="DomainClassifier",
    version="1.3",
    packages=find_packages(),
    install_requires=['dnspython', 'IPy', 'pybgpranking'],
    author="Alexandre Dulaunoy",
    author_email="a@foo.be",
    description="DomainClassifier is a Python library to extract and classify Internet domains/hostnames/IP addresses from raw unstructured text files following their existence, localization or attributes.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    license="AGPL",
    keywords="internet mining domain resolver geolocalisation",
    url="http://github.com/adulau/DomainClassifier"
)
