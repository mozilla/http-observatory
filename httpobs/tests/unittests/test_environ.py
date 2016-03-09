from os import environ
from unittest import TestCase


class TestEnvironmentalVariables(TestCase):
    def test_no_broker_url(self):
        def __import_scanner_celeryconfig_no_broker_url():
            if 'BROKER_URL' in environ:
                environ.pop('BROKER_URL')
            import httpobs.scanner.celeryconfig
            if httpobs.scanner.celeryconfig.CELERY_IGNORE_RESULTS:
                pass

        def __import_database_celeryconfig_no_broker_url():
            if 'BROKER_URL' in environ:
                environ.pop('BROKER_URL')
            import httpobs.scanner.celeryconfig
            if httpobs.scanner.celeryconfig.CELERY_IGNORE_RESULTS:
                pass

        self.assertRaises(SystemExit, __import_database_celeryconfig_no_broker_url)
        self.assertRaises(SystemExit, __import_scanner_celeryconfig_no_broker_url)

    # Mock this
    # def test_broker_url(self):
    #     environ['BROKER_URL'] = 'foo'
    #
    #     import httpobs.database.celeryconfig
    #     import httpobs.scanner.celeryconfig
    #
    #     self.assertTrue(httpobs.database.celeryconfig.CELERY_IGNORE_RESULTS)
    #     self.assertTrue(httpobs.scanner.celeryconfig.CELERY_IGNORE_RESULTS)

    def test_no_database_url(self):
        def __import_database_no_database_url():
            if 'HTTPOBS_DATABASE_URL' in environ:
                environ.pop('HTTPOBS_DATABASE_URL')
            import httpobs.database.database
            if httpobs.database.database.conn:
                pass

        self.assertRaises(SystemExit, __import_database_no_database_url)
