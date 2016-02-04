import os

from setuptools import setup, find_packages


__dirname = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(__dirname, 'README.md')) as readme:
    README = readme.read()


setup(
    name='http-observatory',
    version='0.1.0',
    description='A set of tests and tools to scan your website for basic web hygeine.',
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
        'requests',
        'tld',
    ],
    zip_safe=False,
)
