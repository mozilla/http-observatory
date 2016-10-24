# Mozilla HTTP Observatory - [![Build Status](https://travis-ci.org/marumari/http-observatory.svg?branch=master)](https://travis-ci.org/marumari/http-observatory) [![Requirements Status](https://requires.io/github/mozilla/http-observatory/requirements.svg?branch=master)](https://requires.io/github/mozilla/http-observatory/requirements/?branch=master)

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
* Python 3
* Git

### Running a local scanner with Docker
* Install [Docker Toolbox](https://www.docker.com/products/docker-toolbox) and [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

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

### Creating a local installation (tested on Ubuntu 15)
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
