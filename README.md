# Mozilla HTTP Observatory

The Mozilla HTTP Observatory is a set of tools to analyze your website and inform you if you are utilizing the many available methods to secure it.

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
Score: 30 [E]
Modifiers:
    [  -5] Initial redirection from http to https is to a different host, preventing HSTS
    [  -5] X-Content-Type-Options header not implemented
    [ -10] X-XSS-Protection header not implemented
    [ -25] Content Security Policy (CSP) header missing
    [ -25] HTTP Strict Transport Security (HSTS) header is not set

$ httpobs www.google.com
Score: 45 [D+]
Modifiers:
    [  -5] X-Content-Type-Options header not implemented
    [ -25] Content Security Policy (CSP) header missing
    [ -25] Cookies set without using the Secure flag

$ httpobs www.github.com
Score: 95 [A]
Modifiers:
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
```

## Authors

* April King

## License

* Mozilla Public License Version 2.0