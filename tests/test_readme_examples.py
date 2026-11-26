import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import dns.rdata
import dns.resolver
import dns.rrset

from DomainClassifier.domainclassifier import Extract


class ReadmeExamplesTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name)
        cache = self.home / '.DomainClassifier'
        cache.mkdir()
        (cache / 'tlds').write_text('COM\nORG\n', encoding='utf-8')
        with patch.object(Path, 'home', return_value=self.home):
            self.classifier = Extract(rawtext='Visit example.com or email admin@example.org.')

    def test_downloads_and_reuses_the_tld_cache(self):
        cache_file = self.home / '.DomainClassifier' / 'tlds'
        cache_file.unlink()
        cache_file.parent.rmdir()
        response = BytesIO(b'COM\nORG\n')
        with patch.object(Path, 'home', return_value=self.home):
            with patch('DomainClassifier.domainclassifier.urlopen', return_value=response) as download:
                first = Extract(rawtext='example.org')
                second = Extract(rawtext='example.com')

        self.assertEqual(first.potentialdomain(), ['example.org'])
        self.assertEqual(second.potentialdomain(), ['example.com'])
        self.assertEqual(cache_file.read_text(encoding='utf-8'), 'COM\nORG\n')
        self.assertTrue(response.closed)
        download.assert_called_once()

    def test_extracts_and_filters_domains(self):
        self.assertEqual(self.classifier.potentialdomain(), ['example.com', 'example.org'])
        self.assertEqual(self.classifier.include(r'\.org$'), {'example.org'})
        self.assertEqual(self.classifier.exclude(r'\.org$'), ['example.com'])

    def test_can_include_matches_with_unknown_tlds(self):
        self.classifier.text('Visit example.com or example.invalid.')

        self.assertEqual(self.classifier.potentialdomain(), ['example.com'])
        self.assertEqual(
            self.classifier.potentialdomain(validTLD=False),
            ['example.com', 'example.invalid'],
        )

    def test_reports_a_and_aaaa_records_for_resolved_domains(self):
        answers = {
            'A': dns.rdata.from_text('IN', 'A', '192.0.2.10'),
            'AAAA': dns.rdata.from_text('IN', 'AAAA', '2001:db8::10'),
        }

        def resolve(hostname, record_type, *, search):
            self.assertTrue(search)
            if hostname == 'example.org':
                raise dns.resolver.NXDOMAIN
            return [answers[record_type]]

        with patch.object(self.classifier.presolver, 'resolve', side_effect=resolve):
            records = self.classifier.validdomain(rtype=['A', 'AAAA'], extended=True)

        self.assertEqual(
            [(hostname, record_type, str(answer)) for hostname, record_type, answer in records],
            [
                ('example.com', 'A', '192.0.2.10'),
                ('example.com', 'AAAA', '2001:db8::10'),
            ],
        )
        self.assertEqual(self.classifier.include(r'\.org$'), set())
        self.assertEqual(self.classifier.include(r'\.com$'), {'example.com'})

    def test_formats_passive_dns_records(self):
        self.classifier.text('example.com')
        rrset = dns.rrset.from_text('example.com.', 60, 'IN', 'A', '192.0.2.10')
        answer = SimpleNamespace(rrset=rrset, ttl=rrset.ttl)
        with patch.object(self.classifier.presolver, 'resolve', return_value=answer):
            with patch('DomainClassifier.domainclassifier.time.time', return_value=123.0):
                records = self.classifier.validdomain(rtype=['A'], extended=False, passive_dns=True)

        self.assertEqual(records, {'123.0||127.0.0.1||8.8.8.8||IN||example.com||A||192.0.2.10||60||1\n'})

    def test_filters_records_by_country_from_asn_lookup(self):
        self.classifier.text('example.com')
        address = dns.rdata.from_text('IN', 'A', '192.0.2.10')
        origin = dns.rdata.from_text('IN', 'TXT', '"64496 | 192.0.2.0/24 | US | arin | 2001-01-01"')
        with patch.object(self.classifier.presolver, 'resolve', side_effect=[[address], [origin]]) as resolve:
            records = self.classifier.validdomain(rtype=['A'])
            self.assertEqual(self.classifier.localizedomain(cc='US'), records)

        resolve.assert_called_with('10.2.0.192.origin.asn.cymru.com', 'TXT', search=True)

    def test_returns_ipv4_addresses(self):
        addresses = {'example.com': '192.0.2.10', 'example.org': '198.51.100.20'}
        with patch('DomainClassifier.domainclassifier.socket.gethostbyname', side_effect=addresses.__getitem__):
            self.assertEqual(self.classifier.ipaddress(), ['192.0.2.10', '198.51.100.20'])
