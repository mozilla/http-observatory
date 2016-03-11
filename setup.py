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
        'Topic :: Internet :: HTTP Servers',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
    ],
    author='April King',
    author_email='april@mozilla.com',
    packages=find_packages(),
    include_package_data=False,
    scripts=['httpobs/scripts/httpobs',
             'httpobs/scripts/httpobs-database-beat',
             'httpobs/scripts/httpobs-mass-scan',
             'httpobs/scripts/httpobs-scan-worker'],
    zip_safe=False,
)
