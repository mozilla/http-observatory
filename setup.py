#!/usr/bin/env python3

import os

from setuptools import setup, find_packages


__dirname = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(__dirname, 'README.md')) as readme:
    README = readme.read()


setup(
    name='httpobs',
    version='0.1.0',
    description='HTTP Observatory: a set of tests and tools to scan your website for basic web hygeine.',
    url='https://github.com/mozilla/http-observatory',
    long_description=README,
    classifiers=[
        "Programming Language :: Python",
        "Framework :: Flask",
        "Topic :: Internet :: WWW/HTTP",
    ],
    author='April King',
    author_email='april@mozilla.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'beautifulsoup4',
        'celery',
        'flask',
        'psycopg2',
        'publicsuffixlist',
        'requests',
    ],
    scripts=['scripts/httpobs.py'],
    zip_safe=False,
)
