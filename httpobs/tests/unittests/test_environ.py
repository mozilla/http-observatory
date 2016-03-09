# TODO: Revisit the SystemExit things when we have time
# from os import environ
# from unittest import TestCase
#
#
# class TestEnvironmentalVariables(TestCase):
#     def test_no_broker_url(self):
#         def __import_scanner_celeryconfig_no_broker_url():
#             import httpobs.scanner.celeryconfig
#             if httpobs.scanner.celeryconfig.CELERY_IGNORE_RESULTS:
#                 pass
#
#         def __import_database_celeryconfig_no_broker_url():
#             import httpobs.scanner.celeryconfig
#             if httpobs.scanner.celeryconfig.CELERY_IGNORE_RESULTS:
#                 pass
#
#         if 'BROKER_URL' in environ:
#             BROKER_URL = environ['BROKER_URL']
#             del environ['BROKER_URL']
#         else:
#             BROKER_URL = None
#
#         self.assertRaises(SystemExit, __import_database_celeryconfig_no_broker_url)
#         self.assertRaises(SystemExit, __import_scanner_celeryconfig_no_broker_url)
#
#         if BROKER_URL:
#             environ['BROKER_URL'] = BROKER_URL
#
#     # Mock this
#     # def test_broker_url(self):
#     #     environ['BROKER_URL'] = 'foo'
#     #
#     #     import httpobs.database.celeryconfig
#     #     import httpobs.scanner.celeryconfig
#     #
#     #     self.assertTrue(httpobs.database.celeryconfig.CELERY_IGNORE_RESULTS)
#     #     self.assertTrue(httpobs.scanner.celeryconfig.CELERY_IGNORE_RESULTS)
#
#     def test_no_database_url(self):
#         def __import_database_no_database_url():
#             import httpobs.database.database
#             if httpobs.database.database.conn:
#                 pass
#
#         if 'HTTPOBS_DATABASE_URL' in environ:
#             HTTPOBS_DATABASE_URL = environ['HTTPOBS_DATABASE_URL']
#             del environ['HTTPOBS_DATABASE_URL']
#         else:
#             HTTPOBS_DATABASE_URL = None
#
#         self.assertRaises(SystemExit, __import_database_no_database_url)
#
#         if HTTPOBS_DATABASE_URL:
#             environ['HTTPOBS_DATABASE_URL'] = HTTPOBS_DATABASE_URL
