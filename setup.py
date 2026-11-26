from pathlib import Path

from setuptools import find_packages, setup

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="DomainClassifier",
    version="1.4",
    packages=find_packages(),
    python_requires=">=3.7",
    classifiers=["Programming Language :: Python :: 3 :: Only"],
    install_requires=["dnspython>=2.0", "IPy", "pybgpranking"],
    author="Alexandre Dulaunoy",
    author_email="a@foo.be",
    description="DomainClassifier is a Python library to extract and classify Internet domains/hostnames/IP addresses from raw unstructured text files following their existence, localization or attributes.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    license="AGPL",
    keywords="internet mining domain resolver geolocalisation",
    url="http://github.com/adulau/DomainClassifier"
)
