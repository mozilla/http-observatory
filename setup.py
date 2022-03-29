#!/usr/bin/env python3

import os

from httpobs import SOURCE_URL, VERSION
from setuptools import setup, find_packages


__dirname = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(__dirname, 'README.md')) as readme:
    README = readme.read()

setup(
    name='httpobs',
    version=VERSION,
    description='HTTP Observatory: a set of tests and tools to scan your website for basic web hygeine.',
    url=SOURCE_URL,
    long_description_content_type='text/markdown',
    long_description=README,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
    ],
    author='April King',
    author_email='april@mozilla.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'amqp==2.3.2',
        'beautifulsoup4==4.6.3',
        'billiard==3.5.0.4',
        'celery==4.2.1',
        'click==7.0',
        'coverage==4.5.2',
        'flake8==3.6.0',
        'httpobs-cli==1.0.2',
        'itsdangerous==1.1.0',
        'kombu==4.2.1',
        'MarkupSafe==1.1.0',
        'mccabe==0.6.1',
        'nose==1.3.7',
        'pep8==1.7.1',
        'pycodestyle==2.4.0',
        'pyflakes==2.0.0',
        'pytz==2018.7',
        'vine==1.1.4',
        'Werkzeug==0.14.1',
        'psycopg2>=2.7,<2.8',
        'redis==2.10.6',
        'psutil==5.9.0',
        'publicsuffixlist==0.7.12',
        'requests==2.27.1',
        'Flask==1.0.2',
        'uWSGI==2.0.17.1'
    ],
    scripts=['httpobs/scripts/httpobs-local-scan',
             'httpobs/scripts/httpobs-mass-scan',
             'httpobs/scripts/httpobs-scan-worker'],
    zip_safe=False,
)
