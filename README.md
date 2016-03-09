# Mozilla HTTP Observatory

The Mozilla HTTP Observatory is a set of tools to analyze your website and inform you if you are utilizing the many available methods to secure it.

[![Build Status](https://travis-ci.org/marumari/http-observatory.svg?branch=master)](https://travis-ci.org/marumari/http-observatory) [![Requirements Status](https://requires.io/github/mozilla/http-observatory/requirements.svg?branch=master)](https://requires.io/github/mozilla/http-observatory/requirements/?branch=master)

## Getting started with the HTTP Observatory

First, install the client:
```bash
$ pip install requests
$ git clone https://github.com/mozilla/http-observatory
$ ln -s `pwd`/http-observatory/httpobs/scripts/httpobs /usr/local/bin/httpobs
```

And then scan websites to your heart's content, using our hosted service:

```bash
$ httpobs www.mozilla.org
Score: 35 [D-]
Modifiers:
    [  -5] Initial redirection from http to https is to a different host, preventing HSTS
    [  -5] X-Content-Type-Options header not implemented
    [ -10] X-XSS-Protection header not implemented
    [ -20] HTTP Strict Transport Security (HSTS) header is not set
    [ -25] Content Security Policy (CSP) header missing

$ httpobs www.google.com
Score: 45 [D+]
Modifiers:
Modifiers:
    [  +5] Preloaded via the HTTP Public Key Pinning (HPKP) preloading process
    [  -5] X-Content-Type-Options header not implemented
    [ -20] HTTP Strict Transport Security (HSTS) header is not set
    [ -25] Content Security Policy (CSP) header missing
    [ -25] Cookies set without using the Secure flag or set over http

$ httpobs www.github.com
Score: 106 [A+]
Modifiers:
    [  +5] Preloaded via the HTTP Strict Transport Security (HSTS) preloading process
    [  +5] Subresource Integrity (SRI) is implemented and all scripts are loaded from a secure origin
    [  +1] HTTP Public Key Pinning (HPKP) header set to less than 15 days (1296000)
    [  -5] Content Security Policy (CSP) implemented with unsafe-inline inside style-src directive
```

If you want additional options, such as to see the raw scan output, use `httpobs --help`:

```bash
$ httpobs --help
usage: httpobs [options] host

positional arguments:
  host           hostname of the website to scan

optional arguments:
  -h, --help     show this help message and exit
  -d, --debug    output only raw JSON from scan and tests
  -r, --rescan   initiate a rescan instead of showing recent scan results
  -v, --verbose  display progress indicator
  -x, --hidden   don't list scan in the recent scan results
```

## Authors

* April King

## License

* Mozilla Public License Version 2.0