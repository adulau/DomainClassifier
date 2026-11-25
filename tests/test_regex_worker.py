import unittest
from multiprocessing.reduction import ForkingPickler
from unittest.mock import Mock, patch

from DomainClassifier import domainclassifier


class TestRegexWorker(unittest.TestCase):
    def test_redis_backed_extractor_uses_a_picklable_worker(self):
        process = Mock()
        process.is_alive.return_value = False

        def create_process(*, target, args):
            ForkingPickler.dumps((target, args))
            return process

        def load_tlds(extractor):
            extractor.listtld = ['be']

        # Keep the real Redis client on Extract so a bound worker fails to pickle.
        redis_client = domainclassifier.redis.StrictRedis
        with (
            patch.object(domainclassifier, 'Proc', side_effect=create_process),
            patch.object(redis_client, 'smembers', return_value={'foo.be'}),
            patch.object(redis_client, 'delete'),
            patch.object(domainclassifier.Extract, '_Extract__updatelisttld', load_tlds),
        ):
            extractor = domainclassifier.Extract(rawtext='foo.be', redis_host='localhost', re_timeout=30)

        self.assertEqual(extractor.domain, ['foo.be'])
        process.start.assert_called_once_with()
        process.join.assert_called_once_with(30)
