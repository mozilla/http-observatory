# HTTP Observatory API Documentation

**Last Updated:** 2016-03-23<br>
**Author:** april@mozilla.com

This document explains the HTTP Observatory API, which is used to test the state of security for websites on the public internet.

## Protocol Overview

The HTTP Observatory API is based on HTTP and JSON. All requests are either done via POST or GET requests, and all responses are in the JSON format.

## Protocol Calls

The primary endpoint of the HTTP Observatory is [https://http-observatory.security.mozilla.org/api/v1](https://http-observatory.security.mozilla.org/api/v1).

### Invoke assessment

Used to invoke a new scan of a website. By default, the HTTP Observatory will return a cached site result if the site has been scanned anytime in the previous 24 hours. Regardless of the value of `rescan`, a site can not be scanned at a frequency greater than every three minutes. It will return a single [scan object](#scan) on success.

**API Call:** `analyze`<br>
**API Method:** `POST`

Parameters:
* `host` hostname (required)

POST parameters:
* `hidden` setting to "true" will hide a scan from public results returned by `getRecentScans`
* `rescan` setting to "true" forces a rescan of a site

Examples:
* `/api/v1/analyze?host=www.mozilla.org`
* `/api/v1/analyze?host=www.privatesite.net`
  * `hidden=true&rescan=true`  (POST data)


### Retrieve assessment

This is used to retrieve the results of an existing, ongoing, or completed scan. Returns a [scan object](#scan) on success.

**API Call:** `analyze`<br>
**API Method:** `GET`

Parameters:

* `host` hostname (required)

Example:
* `/api/v1/analyze?host=www.mozilla.org`

### Retrieve test results

Each scan consists of a variety of subtests, including Content Security Policy, Subresource Integrity, etc.  The results of all these tests can be retrieved once the scan's state has been placed in the `FINISHED` state. It will return a single [tests object](#tests).

**API Call:** `getScanResults`<br>
**API Method:** `GET`

Parameters:

* `scan` scan_id number from the [scan object](#scan)

Example:

* `/api/v1/getScanResults?scan=123456`


### Retrieve recent scans

Retrieve the ten most recent scans that fall within a given score range. Maps hostnames to scores, returning a [recent scans object](#recent-scans).

**API Call:** `getRecentScans`<br>
**API Method:** `GET`

Parameters:
* `min` minimum score
* `max` maximum score

Examples:
* `/api/v1/getRecentScans?max=20` (ten most recent "F" tests)
* `/api/v1/getRecentScans?min=90` (ten most recent "A" or better tests)


### Retrieve host's scan history

Retrieve the ten most recent scans that fall within a given score range. Maps hostnames to scores, returning a [host history object](#host-history).

**API Call:** `getHostHistory`<br>
**API Method:** `GET`

Parameters:
* `host` hostname (required)

Examples:
* `/api/v1/getHostHistory?host=mozilla.org` (scan history for mozilla.org)


### Retrieve overall grade distribution

This returns each possible grade in the HTTP Observatory, as well as how many scans have fallen into that grade. Returns a [grade distribution object](#grade-distribution) object.

**API Call:** `getGradeDistribution`<br>
**API Method:** `GET`

Example:
* `/api/v1/getGradeDistribution`

### Retrieve scanner states

This returns the state of the scanner. It can be useful for determining how busy the HTTP Observatory is. Returns a [Scanner state object](#scanner-state).

**API Call:** `getScannerStates`<br>
**API Method:** `GET`

Example:
* `/api/v1/getScannerStates`


## Response Objects

### Grade distribution

Example:
```json
{
  "A+": 3,
  "A": 6,
  "A-": 2,
  "B+": 8,
  "B": 76,
  "B-": 79,
  "C+": 80,
  "C": 88,
  "C-": 86,
  "D+": 60,
  "D": 110,
  "D-": 215,
  "F": 46770
}
```

### Recent scans

Example:
```json
{
  "site1.mozilla.org": "A",
  "site2.mozilla.org": "B-",
  "site3.mozilla.org": "C+",
  "site4.mozilla.org": "F",
  "site5.mozilla.org": "F",
  "site6.mozilla.org": "B",
  "site7.mozilla.org": "F",
  "site8.mozilla.org": "B+",
  "site9.mozilla.org": "A+",
  "site0.mozilla.org": "A-"
}
```

### Host history

Example:
```json
  [
    {
      "end_time": "Thu, 22 Sep 2016 23:24:28 GMT",
      "end_time_unix_timestamp": 1474586668,
      "grade": "C",
      "scan_id": 1711106,
      "score": 50
    },
    {
      "end_time": "Thu, 09 Feb 2017 01:30:47 GMT",
      "end_time_unix_timestamp": 1486603847,
      "grade": "B+",
      "scan_id": 3292839,
      "score": 80
    },
    {
      "end_time": "Fri, 10 Feb 2017 02:30:08 GMT",
      "end_time_unix_timestamp": 1486693808,
      "grade": "A",
      "scan_id": 3302879,
      "score": 90
    }
  ]
```


### Scan

* `end_time` timestamp for when the scan completed
* `grade` final grade assessed upon a completed scan
* `hidden` whether the scan results are unlisted on the recent results page
* `response_headers` the entirety of the HTTP response headers
* `scan_id` unique ID number assigned to the scan
* `score` final score assessed upon a completed (`FINISHED`) scan
* `likelihood_indicator` Mozilla risk likelihod indicator that is the equivalent of the grade [https://wiki.mozilla.org/Security/Standard_Levels] (https://wiki.mozilla.org/Security/Standard_Levels)
* `start_time` timestamp for when the scan was first requested
* `state` the current state of the scan
* `tests_failed` the number of subtests that were assigned a fail result
* `tests_passed` the number of subtests that were assigned a passing result
* `tests_quantity` the total number of tests available and assessed at the time of the scan

The scan can exist in one of six states:
* `ABORTED` aborted for internal technical reasons
* `FAILED` failed to complete, typically due to the site being unavailable or timing out
* `FINISHED` completed successfully
* `PENDING` issued by the API but not yet picked up by a scanner instance
* `STARTING` assigned to a scanning instance
* `RUNNING` currently in the process of scanning a website

Example:
```json
{
  "end_time": "Tue, 22 Mar 2016 21:51:41 GMT",
  "grade": "A",
  "hidden": false,
  "response_headers": { ... },
  "scan_id": 1,
  "score": 90,
  "likelihood_indicator": "LOW",
  "start_time": "Tue, 22 Mar 2016 21:51:40 GMT",
  "state": "FINISHED",
  "tests_failed": 2,
  "tests_passed": 9,
  "tests_quantity": 11
}
```

### Scanner state

Example:
```json
{
  "ABORTED": 10,
  "FAILED": 281,
  "FINISHED": 46240,
  "PENDING": 122,
  "STARTING": 96,
  "RUNNING": 128,
}
```

### Tests

The tests object contains one test object for each test conducted by the HTTP Observatory. Each test object is contains the following values:
* `expectation` the expectation for a test result going in
* `name` the name of the test; this should be the same as the parent object's name
* `output` artifacts related to the test; these can vary widely between tests and are not guaranteed to be stable over time.
  * `data` generally as close to the raw output of the test as is possible.  For example, in the strict-transport-security test, `output -> data` contains the raw `Strict-Transport-Security` header
  * `????` other values under `output` have keys that vary; for example, the `strict-transport-security` test has a `includeSubDomains` key that is either set to `True` or `False`. Similarly, the `redirection` test contains a `route` key that contains an array of the URLs that were redirected to.  See example below for more available keys.
* `pass` whether the test passed or failed; a test that meets or exceeds the expectation will be marked as passed
* `result` result of the test
* `score_description` short description describing what `result` means
* `score_modifier` how much the result of the test affected the final score; should range between +5 and -50

Example:
```json
{
  "content-security-policy": {
    "expectation": "csp-implemented-with-no-unsafe",
    "name": "content-security-policy",
    "output": {
      "data": {
        "connect-src": [
          "'self'",
          "https://sentry.prod.mozaws.net"
        ],
        "default-src": [
          "'self'"
        ],
        "font-src": [
          "'self'",
          "https://addons.cdn.mozilla.net"
        ],
        "frame-src": [
          "'self'",
          "https://ic.paypal.com",
          "https://paypal.com",
          "https://www.google.com/recaptcha/",
          "https://www.paypal.com"
        ],
        "img-src": [
          "'self'",
          "data:",
          "blob:",
          "https://www.paypal.com",
          "https://ssl.google-analytics.com",
          "https://addons.cdn.mozilla.net",
          "https://static.addons.mozilla.net",
          "https://ssl.gstatic.com/",
          "https://sentry.prod.mozaws.net"
        ],
        "media-src": [
          "https://videos.cdn.mozilla.net"
        ],
        "object-src": [
          "'none'"
        ],
        "report-uri": [
          "/__cspreport__"
        ],
        "script-src": [
          "'self'",
          "https://addons.mozilla.org",
          "https://www.paypalobjects.com",
          "https://apis.google.com",
          "https://www.google.com/recaptcha/",
          "https://www.gstatic.com/recaptcha/",
          "https://ssl.google-analytics.com",
          "https://addons.cdn.mozilla.net"
        ],
        "style-src": [
          "'self'",
          "'unsafe-inline'",
          "https://addons.cdn.mozilla.net"
        ]
      }
    },
    "pass": false,
    "result": "csp-implemented-with-unsafe-inline-in-style-src-only",
    "score_description": "Content Security Policy (CSP) implemented with unsafe-inline inside style-src directive",
    "score_modifier": -5
  },
  "contribute": {
    "expectation": "contribute-json-with-required-keys",
    "name": "contribute",
    "output": {
      "data": {
        "bugs": {
          "list": "https://github.com/mozilla/addons-server/issues",
          "report": "https://github.com/mozilla/addons-server/issues/new"
        },
        "description": "Mozilla's official site for add-ons to Mozilla software, such as Firefox, Thunderbird, and SeaMonkey.",
        "name": "Olympia",
        "participate": {
          "docs": "http://addons-server.readthedocs.org/",
          "home": "https://wiki.mozilla.org/Add-ons/Contribute/AMO/Code",
          "irc": "irc://irc.mozilla.org/#amo",
          "irc-contacts": [
            "andym",
            "cgrebs",
            "kumar",
            "magopian",
            "mstriemer",
            "muffinresearch",
            "tofumatt"
          ]
        },
        "urls": {
          "dev": "https://addons-dev.allizom.org/",
          "prod": "https://addons.mozilla.org/",
          "stage": "https://addons.allizom.org/"
        }
      }
    },
    "pass": true,
    "result": "contribute-json-with-required-keys",
    "score_description": "Contribute.json implemented with the required contact information",
    "score_modifier": 0
  },
  "cookies": {
    "expectation": "cookies-secure-with-httponly-sessions",
    "name": "cookies",
    "output": {
      "data": {
        "sessionid": {
          "domain": ".addons.mozilla.org",
          "expires": null,
          "httponly": true,
          "max-age": null,
          "path": "/",
          "port": null,
          "secure": true
        }
      }
    },
    "pass": true,
    "result": "cookies-secure-with-httponly-sessions",
    "score_description": "All cookies use the Secure flag and all session cookies use the HttpOnly flag",
    "score_modifier": 0
  },
  "cross-origin-resource-sharing": {
    "expectation": "cross-origin-resource-sharing-not-implemented",
    "name": "cross-origin-resource-sharing",
    "output": {
      "data": {
        "acao": null,
        "clientaccesspolicy": null,
        "crossdomain": null
      }
    },
    "pass": true,
    "result": "cross-origin-resource-sharing-not-implemented",
    "score_description": "Content is not visible via cross-origin resource sharing (CORS) files or headers",
    "score_modifier": 0
  },
  "public-key-pinning": {
    "expectation": "hpkp-not-implemented",
    "name": "public-key-pinning",
    "output": {
      "data": null,
      "includeSubDomains": false,
      "max-age": null,
      "numPins": null,
      "preloaded": false
    },
    "pass": true,
    "result": "hpkp-not-implemented",
    "score_description": "HTTP Public Key Pinning (HPKP) header not implemented",
    "score_modifier": 0
  },
  "redirection": {
    "expectation": "redirection-to-https",
    "name": "redirection",
    "output": {
      "destination": "https://addons.mozilla.org/en-US/firefox/",
      "redirects": true,
      "route": [
        "http://addons.mozilla.org/",
        "https://addons.mozilla.org/",
        "https://addons.mozilla.org/en-US/firefox/"
      ],
      "status_code": 200
    },
    "pass": true,
    "result": "redirection-to-https",
    "score_description": "Initial redirection is to https on same host, final destination is https",
    "score_modifier": 0
  },
  "strict-transport-security": {
    "expectation": "hsts-implemented-max-age-at-least-six-months",
    "name": "strict-transport-security",
    "output": {
      "data": "max-age=31536000",
      "includeSubDomains": false,
      "max-age": 31536000,
      "preload": false,
      "preloaded": false
    },
    "pass": true,
    "result": "hsts-implemented-max-age-at-least-six-months",
    "score_description": "HTTP Strict Transport Security (HSTS) header set to a minimum of six months (15768000)",
    "score_modifier": 0
  },
  "subresource-integrity": {
    "expectation": "sri-implemented-and-external-scripts-loaded-securely",
    "name": "subresource-integrity",
    "output": {
      "data": {
        "https://addons.cdn.mozilla.net/static/js/impala-min.js?build=552decc-56eadb2f": {
          "crossorigin": null,
          "integrity": null
        },
        "https://addons.cdn.mozilla.net/static/js/preload-min.js?build=552decc-56eadb2f": {
          "crossorigin": null,
          "integrity": null
        }
      }
    },
    "pass": false,
    "result": "sri-not-implemented-but-external-scripts-loaded-securely",
    "score_description": "Subresource Integrity (SRI) not implemented, but all external scripts are loaded over https",
    "score_modifier": -5
  },
  "x-content-type-options": {
    "expectation": "x-content-type-options-nosniff",
    "name": "x-content-type-options",
    "output": {
      "data": "nosniff"
    },
    "pass": true,
    "result": "x-content-type-options-nosniff",
    "score_description": "X-Content-Type-Options header set to \"nosniff\"",
    "score_modifier": 0
  },
  "x-frame-options": {
    "expectation": "x-frame-options-sameorigin-or-deny",
    "name": "x-frame-options",
    "output": {
      "data": "DENY"
    },
    "pass": true,
    "result": "x-frame-options-sameorigin-or-deny",
    "score_description": "X-Frame-Options (XFO) header set to SAMEORIGIN or DENY",
    "score_modifier": 0
  },
  "x-xss-protection": {
    "expectation": "x-xss-protection-1-mode-block",
    "name": "x-xss-protection",
    "output": {
      "data": "1; mode=block"
    },
    "pass": true,
    "result": "x-xss-protection-enabled-mode-block",
    "score_description": "X-XSS-Protection header set to \"1; mode=block\"",
    "score_modifier": 0
  }
}
```
