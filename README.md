# Mozilla HTTP Observatory - [![Build Status](https://travis-ci.org/april/http-observatory.svg?branch=master)](https://travis-ci.org/april/http-observatory) [![Requirements Status](https://requires.io/github/mozilla/http-observatory/requirements.svg?branch=master)](https://requires.io/github/mozilla/http-observatory/requirements/?branch=master)

The Mozilla HTTP Observatory is a set of tools to analyze your website and inform you if you are utilizing the many available methods to secure it.

It is split into three projects:

* [http-observatory](https://github.com/mozilla/http-observatory) - scanner/grader
* [observatory-cli](https://github.com/mozilla/observatory-cli) - command line interface
* [http-observatory-website](https://github.com/mozilla/http-observatory-website) - web interface

## Scanning sites with the HTTP Observatory

Sites can be scanned using:

* [observatory.mozilla.org](https://observatory.mozilla.org/) - the online interface
* [observatory-cli](https://github.com/mozilla/observatory-cli) - the official node.js command line interface
* [java-http-observatory-api](https://github.com/stoennies/java-http-observatory-api) - a third party java library and command line interface

## Contributing

### Prerequisites
* Python 3.7
* Git
* pip3

#### Notes

These instructions assume that you have a working Python3.7 development environment with `pip3` installed and capable of building requirements, which may require installing an additional python OS package (`-dev`, `-devel`).

If this is not appropriate for your environment, you may install the appropriate requirements using your OS package manager (or other means) and skip the `pip3 -r requirements` command.

## Running a scan from the local codebase, without DB, for continuous integration
```bash
# Install the HTTP Observatory
$ git clone https://github.com/mozilla/http-observatory.git
$ cd http-observatory
$ pip3 install --upgrade .
$ pip3 install --upgrade -r requirements.txt
```

### Using the local scanner function calls
```python
>>> from httpobs.scanner.local import scan
>>> scan('observatory.mozilla.org')  # a scan with default options
>>> scan('observatory.mozilla.org',  # all the custom options
         http_port=8080,             # http server runs on port 8080
         https_port=8443,            # https server runs on port 8443
         path='/foo/bar',            # don't scan /, instead scan /foo/bar
         cookies={'foo': 'bar'},     # set the "foo" cookie to "bar"
         headers={'X-Foo': 'bar'},   # send an X-Foo: bar HTTP header
         verify=False)               # treat self-signed certs as valid for tests like HSTS/HPKP
```

### The same, but with the local CLI
```bash
$ httpobs-local-scan --http-port 8080 --https-port 8443 --path '/foo/bar' \
    --cookies '{"foo": "bar"}' --headers '{"X-Foo": "bar"}' --no-verify mozilla.org
```

## Running a local scanner with Docker
* Install [Docker Toolbox](https://docs.docker.com/toolbox/overview/) and [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

```bash
# Install the HTTP Observatory client and requests library
$ git clone https://github.com/mozilla/http-observatory.git
$ cd http-observatory
$ pip3 install .
$ pip3 install --upgrade requests

# Create docker machine
$ docker-machine create --driver virtualbox --virtualbox-disk-size "40000" http-observatory

# Save the URL to the API in your .profile, .bash_profile, or whatever
$ echo export HTTPOBS_API_URL=http://$(docker-machine ip http-observatory):57001/api/v1 >> ~/.profile
$ . ~/.profile

# Start up the docker instance and install all the pieces
$ eval $(docker-machine env http-observatory)
$ docker-compose up -d
```

## Creating a local installation (tested on Ubuntu 15)
```
# Install git, postgresql, and redis
# sudo -s
# apt-get install -y git libpq-dev postgresql redis-server

# Clone the repo
# cd /opt
# git clone https://github.com/mozilla/http-observatory.git
# cd http-observatory

# Install the observatory and scanner
# pip install .
# pip3 install -r requirements.txt

# Install the database
# su - postgres
$ createdb http_observatory
$ psql http_observatory < httpobs/database/schema.sql
$ psql http_observatory
http_observatory=# \password httpobsapi
http_observatory=# \password httpobsscanner
# vi /etc/postgresql/9.4/main/postgresql.conf (set max_connections = 512, shared_buffers = 256MB)
# service postgresql restart

# Create the httpobs user, and log/pid directories
# useradd -m httpobs
# install -m 750 -o httpobs -g httpobs -d /var/run/httpobs /var/log/httpobs

# Update the environmental variables
# su - httpobs
$ echo export HTTPOBS_API_URL="http://localhost:57001/api/v1" >> ~/.profile

# Start the scanner
$ cd /opt/http-observatory
$ HTTPOBS_DATABASE_USER="httpobsscanner" HTTPOBS_DATABASE_PASS="....." \
    /opt/http-observatory/httpobs/scripts/httpobs-scan-worker

# Start the API (in another terminal)
# HTTPOBS_DATABASE_USER="httpobsapi" HTTPOBS_DATABASE_PASS="....." \
    uwsgi --http :57001 --wsgi-file httpobs/website/main.py --processes 8 --callable app --master
```

## Authors

* April King

## License

* Mozilla Public License Version 2.0
