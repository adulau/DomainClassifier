import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dns.rdata
import dns.resolver

from DomainClassifier.domainclassifier import Extract


class ReadmeExamplesTest(unittest.TestCase):
    def setUp(self):
        home = self.enterContext(TemporaryDirectory())
        cache = Path(home) / '.DomainClassifier'
        cache.mkdir()
        (cache / 'tlds').write_text('COM\nORG\n', encoding='utf-8')
        with patch('DomainClassifier.domainclassifier.os.path.expanduser', return_value=home):
            self.classifier = Extract(rawtext='Visit example.com or email admin@example.org.')

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

        def query(hostname, record_type):
            if hostname == 'example.org':
                raise dns.resolver.NXDOMAIN
            return [answers[record_type]]

        with patch.object(self.classifier.presolver, 'query', side_effect=query):
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

    def test_returns_ipv4_addresses(self):
        addresses = {'example.com': '192.0.2.10', 'example.org': '198.51.100.20'}
        with patch('DomainClassifier.domainclassifier.socket.gethostbyname', side_effect=addresses.__getitem__):
            self.assertEqual(self.classifier.ipaddress(), ['192.0.2.10', '198.51.100.20'])
